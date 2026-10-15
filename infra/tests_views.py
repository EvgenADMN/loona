# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Who may do what with an OpenTofu project, through the UI."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase
from django.urls import reverse

from access.models import GroupGrant, Role
from inventory.models import Credential, HostGroup
from runs.models import Job

from .models import TofuFile, TofuProject, TofuVariable


class ProjectPermissionTests(TestCase):
    def setUp(self):
        self.group = HostGroup.objects.create(name="lab")
        self.other = HostGroup.objects.create(name="prod")
        self.project = TofuProject.objects.create(name="lab", host_group=self.group)
        TofuFile.objects.create(project=self.project, path="main.tf", content="")
        self.team = Group.objects.create(name="devs")
        self.user = get_user_model().objects.create_user("dev")
        self.user.groups.add(self.team)
        # Writing OpenTofu code is its own right (access.policy.edit_tofu).
        self.code_right = Permission.objects.get(codename="change_tofuproject")
        self.team.permissions.add(self.code_right)
        self.client.force_login(self.user)

    def role(self, role):
        GroupGrant.objects.update_or_create(
            team=self.team, host_group=self.group, defaults={"role": role}
        )

    def url(self, name, *args):
        return reverse(name, args=[self.project.pk, *args])

    @patch("infra.views.dispatch")
    def plan(self, dispatch, destroy=False):
        data = {"destroy": "1"} if destroy else {}
        return self.client.post(self.url("tofu_project_plan"), data)

    def test_an_admin_without_the_code_right_runs_but_does_not_write(self):
        self.team.permissions.remove(self.code_right)
        self.role(Role.ADMIN)
        page = self.client.get(self.url("tofu_project_detail"))
        self.assertNotContains(page, self.url("tofu_project_update"))
        for name in ("tofu_project_update", "tofu_file_create", "tofu_variable_create"):
            self.assertEqual(self.client.get(self.url(name)).status_code, 403, name)
        self.assertEqual(self.client.get(reverse("tofu_project_create")).status_code, 403)
        self.assertEqual(self.plan().status_code, 302)

    def test_without_a_role_the_project_does_not_exist(self):
        self.assertEqual(self.client.get(self.url("tofu_project_detail")).status_code, 404)
        self.assertNotContains(self.client.get(reverse("tofu_project_list")), self.project.get_absolute_url())

    def test_a_viewer_looks_but_does_not_plan(self):
        self.role(Role.VIEWER)
        page = self.client.get(self.url("tofu_project_detail"))
        self.assertEqual(page.status_code, 200)
        self.assertNotContains(page, ">Plan<")
        self.assertEqual(self.plan().status_code, 403)
        self.assertFalse(Job.objects.exists())

    def test_an_operator_plans_but_may_not_destroy(self):
        self.role(Role.OPERATOR)
        self.assertEqual(self.plan().status_code, 302)
        job = Job.objects.get()
        self.assertEqual(job.kind, Job.KIND_TOFU_PLAN)
        self.assertEqual(list(job.target_groups.all()), [self.group])
        self.assertEqual(self.plan(destroy=True).status_code, 403)
        self.assertEqual(Job.objects.count(), 1)

    def test_only_an_admin_applies_a_destroy_plan(self):
        # Roles only; the approval rule has its own tests.
        HostGroup.objects.filter(pk=self.group.pk).update(approval_policy=HostGroup.APPROVAL_NONE)
        self.role(Role.OPERATOR)
        plan = Job.objects.create(
            kind=Job.KIND_TOFU_PLAN, tofu_project=self.project, tofu_destroy=True,
            playbook_name="lab: destroy plan", status=Job.SUCCESSFUL,
            stats={"tofu": {"has_changes": True}},
        )
        plan.target_groups.set([self.group])
        with patch("runs.services.dispatch"):
            response = self.client.post(reverse("plan_apply", args=[plan.pk]))
        self.assertEqual(response.status_code, 403)
        self.role(Role.ADMIN)
        with patch("runs.services.dispatch"):
            self.client.post(reverse("plan_apply", args=[plan.pk]))
        self.assertTrue(Job.objects.filter(plan=plan, kind=Job.KIND_TOFU_APPLY).exists())

    def test_files_and_variables_need_admin(self):
        self.role(Role.OPERATOR)
        for name in ("tofu_file_create", "tofu_variable_create", "tofu_project_update"):
            self.assertEqual(self.client.get(self.url(name)).status_code, 403, name)
        self.role(Role.ADMIN)
        self.client.post(self.url("tofu_file_create"), {"path": "vars.tf", "content": "# x"})
        self.assertTrue(self.project.files.filter(path="vars.tf").exists())

    def test_a_file_cannot_escape_the_project(self):
        self.role(Role.ADMIN)
        response = self.client.post(self.url("tofu_file_create"), {"path": "../../etc/x.tf", "content": ""})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.project.files.filter(path__contains="etc").exists())

    def test_a_hidden_variable_is_never_shown_again(self):
        self.role(Role.ADMIN)
        self.client.post(self.url("tofu_variable_create"),
                         {"kind": "env", "name": "API_TOKEN", "value": "s3cret", "sensitive": "on"})
        variable = TofuVariable.objects.get()
        self.assertEqual(variable.value, "s3cret")
        self.assertNotIn("s3cret", variable.value_encrypted)
        self.assertNotContains(self.client.get(self.url("tofu_project_detail")), "s3cret")
        self.assertNotContains(self.client.get(self.url("tofu_variable_edit", variable.pk)), "s3cret")
        # Saving the form without typing a value keeps it.
        self.client.post(self.url("tofu_variable_edit", variable.pk),
                         {"kind": "env", "name": "API_TOKEN", "value": "", "sensitive": "on"})
        variable.refresh_from_db()
        self.assertEqual(variable.value, "s3cret")

    def test_a_project_goes_only_where_its_creator_is_admin(self):
        self.role(Role.ADMIN)
        GroupGrant.objects.create(team=self.team, host_group=self.other, role=Role.OPERATOR)
        data = {"name": "p2", "description": "", "source": "files", "git_url": "", "git_ref": "main",
                "git_path": "", "git_credential": "",
                "bootstrap_user": "root", "baseline_playbook": ""}
        self.client.post(reverse("tofu_project_create"), {**data, "host_group": self.other.pk})
        self.assertFalse(TofuProject.objects.filter(name="p2").exists())
        self.client.post(reverse("tofu_project_create"), {**data, "host_group": self.group.pk})
        created = TofuProject.objects.get(name="p2")
        self.assertTrue(created.files.filter(path="main.tf").exists())

    def test_git_credentials_must_be_shared_with_the_team(self):
        self.role(Role.ADMIN)
        key = Credential.objects.create(name="deploy", kind=Credential.KIND_SSH_KEY)
        data = {"name": "p3", "description": "", "host_group": self.group.pk, "source": "git",
                "git_url": "git@x:y.git", "git_ref": "main", "git_path": "", "git_credential": key.pk,
                "bootstrap_user": "root", "baseline_playbook": ""}
        self.client.post(reverse("tofu_project_create"), data)
        self.assertFalse(TofuProject.objects.filter(name="p3").exists())
        key.teams.add(self.team)
        self.client.post(reverse("tofu_project_create"), data)
        self.assertTrue(TofuProject.objects.filter(name="p3").exists())

    def test_a_project_still_managing_resources_is_not_deleted(self):
        from .models import TofuStateVersion

        self.role(Role.ADMIN)
        version = TofuStateVersion(project=self.project, serial=3)
        version.data = '{"resources": [{"mode": "managed", "type": "x", "name": "y", "instances": [{}]}]}'
        version.save()
        self.client.post(self.url("tofu_project_delete"))
        self.assertTrue(TofuProject.objects.filter(pk=self.project.pk).exists())
        self.assertEqual(self.project.managed_resources, ["x.y"])

    def test_a_machine_that_was_replaced_can_be_set_up_again(self):
        from django.utils import timezone

        from inventory.models import Host

        self.role(Role.ADMIN)
        host = Host.objects.create(name="app-01", address="10.0.0.5", tofu_project=self.project,
                                   bootstrapped_at=timezone.now())
        host.groups.add(self.group)
        retry = reverse("tofu_host_bootstrap", args=[host.pk])
        with patch("infra.bootstrap.begin") as begin:
            self.client.post(retry)
            begin.assert_called_once()
            # One at a time: a setup still in flight is not started again.
            job = Job.objects.create(kind=Job.KIND_BOOTSTRAP, playbook_name="b", playbook_yaml="---")
            job.target_hosts.add(host)
            self.client.post(retry)
            begin.assert_called_once()
        self.assertContains(self.client.get(reverse("host_detail", args=[host.pk])), "Set up again")
