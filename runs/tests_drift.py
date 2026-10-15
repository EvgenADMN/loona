# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Drift checks and host history."""
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from access.models import GroupGrant, Role
from infra.models import TofuProject
from inventory.history import timeline
from inventory.models import Host, HostGroup
from playbooks.models import Playbook

from . import drift, executor, plans
from .models import DriftCheck, Job


def run_inline(job):
    executor.run_job(job.pk)


class DriftEndToEndTests(TestCase):
    """A real playbook on localhost: in sync, hand-edited, noticed, put back."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        override = override_settings(LOONA_DATA_DIR=f"{self.tmp.name}/jobs")
        override.enable()
        self.addCleanup(override.disable)
        self.motd = Path(self.tmp.name) / "motd"
        self.group = HostGroup.objects.create(name="lab", approval_policy=HostGroup.APPROVAL_NONE)
        self.host = Host.objects.create(name="localhost", variables={"ansible_connection": "local"})
        self.host.groups.add(self.group)
        self.playbook = Playbook.objects.create(
            name="motd", mode=Playbook.MODE_TEXT,
            text_content=(
                "- hosts: all\n  gather_facts: false\n  tasks:\n"
                f"    - name: motd\n      ansible.builtin.copy:\n        dest: {self.motd}\n"
                "        content: \"managed\\n\"\n"
            ),
        )
        self.user = get_user_model().objects.create_superuser("root")
        self.check = DriftCheck.objects.create(name="motd on lab", playbook=self.playbook, host_group=self.group)

    def run_check(self):
        with patch("runs.executor.dispatch", side_effect=run_inline):
            job = drift.start(self.check, user=None)
        self.check.refresh_from_db()
        return job

    def test_the_full_loop(self):
        self.motd.write_text("managed\n")
        job = self.run_check()
        self.assertTrue(job.check_mode)
        self.assertEqual(self.check.status, DriftCheck.IN_SYNC)
        self.assertEqual(self.motd.read_text(), "managed\n", "a check changes nothing")

        self.motd.write_text("edited by hand\n")
        job = self.run_check()
        self.assertEqual(self.check.status, DriftCheck.DRIFTED)
        self.assertEqual(self.check.drifted, ["localhost"])
        self.assertIsNotNone(self.check.status_since)

        # Applying the check's preview puts it back.
        job.refresh_from_db()
        with patch("runs.executor.dispatch", side_effect=run_inline):
            applied = plans.apply(job, self.user)
            executor.run_job(applied.pk)
        self.assertEqual(self.motd.read_text(), "managed\n")
        self.run_check()
        self.assertEqual(self.check.status, DriftCheck.IN_SYNC)

        # The host's history tells the same story, from this host's side.
        entries = timeline(self.host, self.user)
        whats = [(e.what, e.status) for e in entries]
        self.assertEqual(whats[0], ("Drift check", "ok"))
        self.assertIn(("Apply", "warn"), whats)
        self.assertIn(("Drift check", "warn"), whats)

    def test_a_check_that_cannot_run_says_so(self):
        self.playbook.text_content = "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.fail:\n"
        self.playbook.save()
        self.run_check()
        self.assertEqual(self.check.status, DriftCheck.ERROR)


class SchedulingTests(TestCase):
    def setUp(self):
        self.group = HostGroup.objects.create(name="lab")
        self.playbook = Playbook.objects.create(name="p")

    def make(self, minutes_ago=None, interval=60, enabled=True):
        check = DriftCheck.objects.create(
            name="c", playbook=self.playbook, host_group=self.group,
            interval_minutes=interval, enabled=enabled,
        )
        if minutes_ago is not None:
            check.last_run_at = timezone.now() - timedelta(minutes=minutes_ago)
            check.save()
        return check

    def test_what_is_due(self):
        never = self.make()
        overdue = self.make(minutes_ago=61)
        recent = self.make(minutes_ago=10)
        paused = self.make(enabled=False)
        self.assertEqual(set(drift.due()), {never, overdue})

    @patch("runs.executor.dispatch")
    def test_the_tick_starts_due_checks_once(self, dispatch):
        self.make()
        self.assertEqual(drift.run_due(), 1)
        # The first is still running (the worker has not picked it up).
        self.assertEqual(drift.run_due(), 0)
        self.assertEqual(Job.objects.filter(drift_check__isnull=False).count(), 1)

    def test_tofu_results_are_read_from_the_plan(self):
        project = TofuProject.objects.create(name="lab", host_group=self.group)
        check = DriftCheck.objects.create(name="t", tofu_project=project)
        job = Job.objects.create(
            kind=Job.KIND_TOFU_PLAN, tofu_project=project, drift_check=check, status=Job.SUCCESSFUL,
            stats={"tofu": {"has_changes": True, "resources": [{"address": "aws_instance.web"}]}},
        )
        drift.on_finished(job)
        check.refresh_from_db()
        self.assertEqual((check.status, check.drifted), (DriftCheck.DRIFTED, ["aws_instance.web"]))

    def test_a_drift_check_does_not_ask_for_approval_on_the_overview(self):
        from access import approvals

        project = TofuProject.objects.create(name="lab", host_group=self.group)
        check = DriftCheck.objects.create(name="t", tofu_project=project)
        job = Job.objects.create(
            kind=Job.KIND_TOFU_PLAN, tofu_project=project, drift_check=check, status=Job.SUCCESSFUL,
            stats={"tofu": {"has_changes": True, "destroy": 1}},
        )
        job.target_groups.set([self.group])
        root = get_user_model().objects.create_superuser("root")
        self.assertEqual(approvals.waiting_for(root), [])


class DriftPermissionTests(TestCase):
    def setUp(self):
        self.group = HostGroup.objects.create(name="lab")
        self.check = DriftCheck.objects.create(name="c", playbook=Playbook.objects.create(name="p"),
                                               host_group=self.group)
        self.team = Group.objects.create(name="t")
        self.user = get_user_model().objects.create_user("u")
        self.user.groups.add(self.team)
        self.client.force_login(self.user)

    def test_no_role_no_check(self):
        self.assertNotContains(self.client.get(reverse("drift_list")), "Check now")

    def test_a_viewer_sees_but_cannot_run(self):
        GroupGrant.objects.create(team=self.team, host_group=self.group, role=Role.VIEWER)
        self.assertContains(self.client.get(reverse("drift_list")), "c")
        with patch("runs.executor.dispatch") as dispatch:
            response = self.client.post(reverse("drift_run", args=[self.check.pk]))
        self.assertEqual(response.status_code, 403)
        dispatch.assert_not_called()

    def test_an_operator_runs_and_creates(self):
        GroupGrant.objects.create(team=self.team, host_group=self.group, role=Role.OPERATOR)
        with patch("runs.executor.dispatch") as dispatch:
            self.client.post(reverse("drift_run", args=[self.check.pk]))
            self.client.post(reverse("drift_list"), {"name": "second", "playbook": self.check.playbook_id,
                                                     "host_group": self.group.pk, "interval_minutes": 60})
        self.assertEqual(dispatch.call_count, 2)
        self.assertTrue(DriftCheck.objects.filter(name="second").exists())
