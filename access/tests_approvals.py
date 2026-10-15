# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The two-person rule."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from infra.models import TofuProject
from inventory.models import Host, HostGroup
from playbooks.models import Playbook
from runs import plans
from runs.models import Job

from . import approvals
from .models import Approval, GroupGrant, Role


class ApprovalTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.prod = HostGroup.objects.create(name="prod")  # default rule: destroy
        self.web = HostGroup.objects.create(name="prod-web")
        self.web.parents.add(self.prod)
        self.project = TofuProject.objects.create(name="web", host_group=self.web)
        self.admins = Group.objects.create(name="admins")
        GroupGrant.objects.create(team=self.admins, host_group=self.prod, role=Role.ADMIN)
        self.alice = User.objects.create_user("alice")
        self.bob = User.objects.create_user("bob")
        for user in (self.alice, self.bob):
            user.groups.add(self.admins)

    def tofu_plan(self, destroy=0, by=None):
        job = Job.objects.create(
            kind=Job.KIND_TOFU_PLAN, tofu_project=self.project, playbook_name="web: plan",
            status=Job.SUCCESSFUL, created_by=by or self.alice,
            stats={"tofu": {"has_changes": True, "add": 1, "change": 0, "destroy": destroy}},
        )
        job.target_groups.set([self.web])
        return job

    def decide(self, user, plan, decision="approve"):
        self.client.force_login(user)
        with patch("runs.services.dispatch"):
            return self.client.post(reverse("plan_decide", args=[plan.pk]), {"decision": decision, "comment": "ok"})

    def test_a_plan_that_destroys_needs_approval_under_the_default_rule(self):
        self.assertIsNone(approvals.requirement(self.tofu_plan(destroy=0)))
        self.assertIn("destroys", approvals.requirement(self.tofu_plan(destroy=1)))

    def test_the_rule_of_a_parent_group_applies_below_it(self):
        HostGroup.objects.filter(pk=self.prod.pk).update(approval_policy=HostGroup.APPROVAL_CHANGES)
        self.assertIn("prod", approvals.requirement(self.tofu_plan()))

    def test_apply_is_refused_without_approval_whoever_asks(self):
        plan = self.tofu_plan(destroy=2)
        with self.assertRaises(plans.CannotApply):
            plans.apply(plan, self.alice)
        self.client.force_login(self.alice)
        with patch("runs.services.dispatch") as dispatch:
            self.client.post(reverse("plan_apply", args=[plan.pk]))
        dispatch.assert_not_called()
        self.assertFalse(plan.applications.exists())

    def test_the_author_cannot_approve_their_own_plan(self):
        plan = self.tofu_plan(destroy=1)
        self.decide(self.alice, plan)
        self.assertFalse(Approval.objects.exists())
        self.assertFalse(plan.applications.exists())

    def test_another_admin_approves_and_it_applies_at_once(self):
        plan = self.tofu_plan(destroy=1)
        response = self.decide(self.bob, plan)
        approval = Approval.objects.get()
        self.assertEqual((approval.decided_by, approval.approved, approval.comment), (self.bob, True, "ok"))
        applied = plan.applications.get()
        self.assertEqual(applied.created_by, self.bob)
        self.assertRedirects(response, applied.get_absolute_url(), fetch_redirect_response=False)

    def test_a_rejected_plan_stays_unapplied(self):
        plan = self.tofu_plan(destroy=1)
        self.decide(self.bob, plan, "reject")
        with self.assertRaises(plans.CannotApply):
            plans.apply(plan, self.bob)
        # And nobody gets a second go at deciding.
        self.decide(self.bob, plan)
        self.assertEqual(Approval.objects.count(), 1)

    def test_an_operator_cannot_approve(self):
        carol = get_user_model().objects.create_user("carol")
        ops = Group.objects.create(name="ops")
        carol.groups.add(ops)
        GroupGrant.objects.create(team=ops, host_group=self.prod, role=Role.OPERATOR)
        plan = self.tofu_plan(destroy=1)
        self.decide(carol, plan)
        self.assertFalse(Approval.objects.exists())

    def test_the_page_names_who_can_approve_or_says_nobody_can(self):
        plan = self.tofu_plan(destroy=1)
        self.client.force_login(self.alice)
        page = self.client.get(reverse("job_detail", args=[plan.pk]))
        self.assertContains(page, "Waiting for one of: <b>bob</b>")
        self.bob.groups.clear()
        page = self.client.get(reverse("job_detail", args=[plan.pk]))
        self.assertContains(page, "Nobody else can approve this")

    def test_the_approver_sees_it_on_the_overview(self):
        plan = self.tofu_plan(destroy=1)
        self.tofu_plan(destroy=0)
        self.assertEqual(approvals.waiting_for(self.bob), [plan])
        self.assertEqual(approvals.waiting_for(self.alice), [])
        self.client.force_login(self.bob)
        self.assertContains(self.client.get(reverse("dashboard")), "Waiting for your approval")

    def test_run_now_is_off_where_every_change_needs_approval(self):
        HostGroup.objects.filter(pk=self.prod.pk).update(approval_policy=HostGroup.APPROVAL_CHANGES)
        host = Host.objects.create(name="web1", variables={"ansible_connection": "local"})
        host.groups.add(self.web)
        playbook = Playbook.objects.create(name="p")
        self.client.force_login(self.alice)
        data = {"target_groups": [], "target_hosts": [host.pk], "limit": "", "extra_vars": "",
                "tags": "", "skip_tags": "", "forks": 5, "verbosity": 0}
        with patch("runs.services.dispatch") as dispatch:
            response = self.client.post(reverse("job_launch", args=[playbook.pk]), {**data, "action": "run"})
            self.assertContains(response, "go through a preview")
            dispatch.assert_not_called()
            self.client.post(reverse("job_launch", args=[playbook.pk]), {**data, "action": "plan"})
            dispatch.assert_called_once()

    def test_only_superusers_see_the_rule_in_the_group_form(self):
        self.client.force_login(self.alice)
        self.assertNotContains(self.client.get(reverse("group_update", args=[self.prod.pk])), "approval_policy")
        root = get_user_model().objects.create_superuser("root")
        self.client.force_login(root)
        self.assertContains(self.client.get(reverse("group_update", args=[self.prod.pk])), "approval_policy")
