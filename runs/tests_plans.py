# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Preview, then apply - against real ansible-runner runs on localhost."""
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse

from access.models import GroupGrant, Role
from inventory.models import Host, HostGroup
from playbooks.models import Playbook

from . import executor, plans
from .models import Job


class PlanApplyTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.target = root / "motd"
        self.target.write_text("old\n")
        data_dir = root / "jobs"
        override = override_settings(LOONA_DATA_DIR=str(data_dir))
        override.enable()
        self.addCleanup(override.disable)

        self.group = HostGroup.objects.create(name="local")
        self.host = Host.objects.create(name="localhost", variables={"ansible_connection": "local"})
        self.host.groups.add(self.group)
        self.playbook = Playbook.objects.create(
            name="motd",
            mode=Playbook.MODE_TEXT,
            text_content=(
                "- hosts: all\n  gather_facts: false\n  tasks:\n"
                f"    - name: write motd\n      ansible.builtin.copy:\n        dest: {self.target}\n"
                "        content: \"new\\n\"\n"
                "    - name: say hi\n      ansible.builtin.command: echo hi\n"
            ),
        )
        self.user = get_user_model().objects.create_superuser("root", password="x")
        self.client.force_login(self.user)

    def launch(self, action):
        # Dispatch runs the job inline, so the test sees it finished.
        with patch("runs.services.dispatch", side_effect=lambda job: executor.run_job(job.pk)):
            self.client.post(
                reverse("job_launch", args=[self.playbook.pk]),
                {"target_groups": [self.group.pk], "target_hosts": [], "limit": "",
                 "extra_vars": "", "tags": "", "skip_tags": "", "forks": 5,
                 "verbosity": 0, "action": action},
            )
        return Job.objects.latest("pk")

    def apply(self, plan):
        with patch("runs.services.dispatch", side_effect=lambda job: executor.run_job(job.pk)):
            response = self.client.post(reverse("plan_apply", args=[plan.pk]), follow=True)
        return response

    def test_a_preview_shows_the_diff_and_touches_nothing(self):
        plan = self.launch("plan")
        self.assertEqual(plan.status, Job.SUCCESSFUL)
        self.assertTrue(plan.is_plan)
        self.assertEqual(self.target.read_text(), "old\n")

        # The log colours a changed task as changed.
        self.assertTrue(plan.events.get(event="runner_on_ok", task="write motd").changed)

        [host] = plans.summarize(plan)
        self.assertEqual(host.host, "localhost")
        [change] = host.changes
        self.assertEqual(change.task, "write motd")
        lines = change.blocks[0]["lines"]
        self.assertIn(("del", "-old"), lines)
        self.assertIn(("add", "+new"), lines)
        # The command did not run in check mode, and the summary says so.
        self.assertEqual(host.skipped, 1)

        page = self.client.get(reverse("job_detail", args=[plan.pk]))
        self.assertContains(page, "Apply these changes")
        self.assertContains(page, "diff-add")

    def test_applying_carries_the_preview_out_once(self):
        plan = self.launch("plan")
        response = self.apply(plan)
        applied = Job.objects.latest("pk")
        self.assertEqual(applied.plan, plan)
        self.assertEqual(applied.status, Job.SUCCESSFUL)
        self.assertFalse(applied.check_mode)
        self.assertEqual(self.target.read_text(), "new\n")
        self.assertContains(response, f"preview #{plan.pk}")

        self.apply(plan)
        self.assertEqual(Job.objects.filter(plan=plan).count(), 1)
        page = self.client.get(reverse("job_detail", args=[plan.pk]))
        self.assertContains(page, f"Applied as")
        self.assertNotContains(page, "Apply these changes")

    def test_apply_runs_the_previewed_playbook_not_the_edited_one(self):
        plan = self.launch("plan")
        self.playbook.text_content = self.playbook.text_content.replace('"new\\n"', '"edited\\n"')
        self.playbook.save()
        page = self.client.get(reverse("job_detail", args=[plan.pk]))
        self.assertContains(page, "the playbook has been edited since")
        self.apply(plan)
        self.assertEqual(self.target.read_text(), "new\n")

    def test_a_host_that_joined_after_the_preview_is_left_alone(self):
        plan = self.launch("plan")
        latecomer = Host.objects.create(name="latecomer", variables={"ansible_connection": "local"})
        latecomer.groups.add(self.group)
        self.apply(plan)
        applied = Job.objects.latest("pk")
        self.assertEqual(applied.resolved_hosts, ["localhost"])

    def test_run_now_skips_the_preview(self):
        job = self.launch("run")
        self.assertFalse(job.check_mode)
        self.assertEqual(self.target.read_text(), "new\n")

    def test_a_failed_preview_cannot_be_applied(self):
        self.playbook.text_content += "    - ansible.builtin.fail:\n        msg: no\n"
        self.playbook.save()
        plan = self.launch("plan")
        self.assertEqual(plan.status, Job.FAILED)
        response = self.apply(plan)
        self.assertContains(response, "did not finish cleanly")
        self.assertFalse(Job.objects.filter(plan=plan).exists())

    def test_a_viewer_cannot_apply(self):
        plan = self.launch("plan")
        viewer = get_user_model().objects.create_user("viewer")
        team = Group.objects.create(name="watchers")
        viewer.groups.add(team)
        GroupGrant.objects.create(team=team, host_group=self.group, role=Role.VIEWER)
        self.client.force_login(viewer)
        response = self.client.post(reverse("plan_apply", args=[plan.pk]))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Job.objects.filter(plan=plan).exists())


class RenderDiffTests(TestCase):
    def test_text_before_and_after(self):
        [block] = plans.render_diff([{"before": "a\nb\n", "after": "a\nc\n",
                                      "after_header": "/etc/x"}])
        self.assertEqual(block["header"], "/etc/x")
        self.assertEqual([k for k, _ in block["lines"]], ["hunk", "ctx", "del", "add"])

    def test_prepared_text_is_shown_as_is(self):
        [block] = plans.render_diff({"prepared": "The following NEW packages will be installed:\n  cowsay"})
        self.assertEqual(block["lines"][1], ("ctx", "  cowsay"))

    def test_attribute_mappings_are_compared_as_yaml(self):
        [block] = plans.render_diff({"before": {"mode": "0644", "path": "/x"},
                                     "after": {"mode": "0600", "path": "/x"}})
        self.assertIn(("add", "+mode: '0600'"), block["lines"])

    def test_nothing_to_show(self):
        self.assertEqual(plans.render_diff(None), [])
        self.assertEqual(plans.render_diff({"before": "same", "after": "same"}), [])

    def test_a_huge_diff_is_trimmed_before_it_is_stored(self):
        huge = {"prepared": "x" * (executor.MAX_DIFF_CHARS * 2)}
        stored = executor._diff_of("runner_on_ok", {"res": {"changed": True, "diff": huge}})
        self.assertLess(len(stored["prepared"]), executor.MAX_DIFF_CHARS + 100)
        self.assertIn("truncated", stored["prepared"])
