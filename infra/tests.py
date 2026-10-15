# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""OpenTofu runs against a live Loona, with the real tofu binary.

Skipped where tofu is not installed; the container image has it:

    docker run --rm -e LOONA_SECRET_KEY=x loona:latest python manage.py test infra
"""
import base64
import shutil
import tempfile
import unittest
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import LiveServerTestCase, TestCase, override_settings

from inventory.models import HostGroup
from runs import executor, plans
from runs.models import Job

from .models import TofuFile, TofuLock, TofuProject, TofuStateVersion, TofuVariable
from .services import start_plan

CONFIG = """
variable "greeting" { type = string }
variable "secret" {
  type      = string
  sensitive = true
}
resource "terraform_data" "note" { input = var.greeting }
resource "terraform_data" "hidden" { input = var.secret }
output "note" { value = terraform_data.note.output }
output "hidden" {
  value     = terraform_data.hidden.output
  sensitive = true
}
"""

HAS_TOFU = shutil.which(settings.LOONA_TOFU_BINARY) is not None


class ProjectMixin:
    def make_project(self):
        self.user = get_user_model().objects.create_superuser("root", password="x")
        # These tests are about OpenTofu; the two-person rule has its own.
        group = HostGroup.objects.create(name="lab", approval_policy=HostGroup.APPROVAL_NONE)
        project = TofuProject.objects.create(name="lab", host_group=group)
        TofuFile.objects.create(project=project, path="main.tf", content=CONFIG)
        greeting = TofuVariable(project=project, name="greeting")
        greeting.value = "hello"
        greeting.save()
        secret = TofuVariable(project=project, name="secret", sensitive=True)
        secret.value = "hunter2"
        secret.save()
        return project

    def set_greeting(self, project, text):
        variable = project.variables.get(name="greeting")
        variable.value = text
        variable.save()


@unittest.skipUnless(HAS_TOFU, "tofu is not installed here")
class TofuRunTests(ProjectMixin, LiveServerTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        override = override_settings(
            LOONA_INTERNAL_URL=self.live_server_url,
            LOONA_DATA_DIR=f"{self.tmp.name}/jobs",
            LOONA_TOFU_PLUGIN_CACHE=f"{self.tmp.name}/plugins",
        )
        override.enable()
        self.addCleanup(override.disable)
        self.project = self.make_project()

    def plan(self, destroy=False):
        job = start_plan(self.project, self.user, destroy=destroy)
        executor.run_job(job.pk)
        job.refresh_from_db()
        return job

    def apply(self, plan):
        job = plans.apply(plan, self.user)
        executor.run_job(job.pk)
        job.refresh_from_db()
        return job

    def test_plan_then_apply(self):
        plan = self.plan()
        self.assertEqual(plan.status, Job.SUCCESSFUL, plan.error_message)
        summary = plan.stats["tofu"]
        self.assertEqual((summary["add"], summary["change"], summary["destroy"]), (2, 0, 0))
        hidden = next(r for r in summary["resources"] if r["address"] == "terraform_data.hidden")
        self.assertEqual(
            next(a for a in hidden["attributes"] if a["name"] == "input")["after"], "(sensitive)"
        )
        self.assertNotIn("hunter2", str(plan.stats))
        self.assertTrue(plan.tofu_plan_encrypted)
        self.assertFalse(TofuStateVersion.objects.exists(), "a plan must not write state")

        applied = self.apply(plan)
        self.assertEqual(applied.status, Job.SUCCESSFUL, applied.error_message)
        outputs = applied.stats["tofu"]["outputs"]
        self.assertEqual(outputs, {"note": "hello", "hidden": "(sensitive)"})
        state = self.project.current_state
        self.assertIn("hello", state.data)
        self.assertNotIn("hello", state.data_encrypted)
        self.assertFalse(TofuLock.objects.exists())
        # Nothing of the run is left on disk.
        self.assertEqual(list(Path(settings.LOONA_DATA_DIR).glob("job_*")), [])

    def test_a_change_shows_before_and_after(self):
        self.apply(self.plan())
        self.set_greeting(self.project, "goodbye")
        plan = self.plan()
        summary = plan.stats["tofu"]
        self.assertEqual(summary["change"] + summary["add"], 1)
        [note] = summary["resources"]
        change = next(a for a in note["attributes"] if a["name"] == "input")
        self.assertEqual((change["before"], change["after"]), ("hello", "goodbye"))

    def test_nothing_to_do_cannot_be_applied(self):
        self.apply(self.plan())
        plan = self.plan()
        self.assertFalse(plan.stats["tofu"]["has_changes"])
        self.assertFalse(plan.can_be_applied)

    def test_a_stale_plan_is_refused(self):
        first = self.plan()
        self.set_greeting(self.project, "second")
        second = self.plan()
        self.apply(second)
        stale = self.apply(first)
        self.assertEqual(stale.status, Job.ERROR)
        self.assertEqual(self.project.current_state.serial, 1)

    def test_apply_uses_the_planned_files_not_edited_ones(self):
        plan = self.plan()
        TofuFile.objects.filter(project=self.project).update(content="this is not valid HCL {")
        applied = self.apply(plan)
        self.assertEqual(applied.status, Job.SUCCESSFUL, applied.error_message)

    def test_destroy(self):
        self.apply(self.plan())
        plan = self.plan(destroy=True)
        self.assertEqual(plan.stats["tofu"]["destroy"], 2)
        self.apply(plan)
        self.assertNotIn("terraform_data", self.project.current_state.data)

    def test_a_broken_configuration_fails_with_the_error_in_the_log(self):
        TofuFile.objects.filter(project=self.project).update(content="resource {")
        plan = self.plan()
        self.assertEqual(plan.status, Job.ERROR)
        self.assertTrue(plan.events.filter(failed=True).exists())


class StateBackendTests(ProjectMixin, TestCase):
    """The backend's gatekeeping, without running tofu."""

    def setUp(self):
        self.project = self.make_project()
        self.job = start_plan(self.project, self.user)
        Job.objects.filter(pk=self.job.pk).update(status=Job.RUNNING)
        from . import state

        self.token = state.issue_token(self.job)
        self.url = f"/infra/state/{self.project.pk}/"

    def auth(self, user, password):
        return {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}

    def call(self, method, body=b"", **extra):
        return self.client.generic(method, self.url, body, content_type="application/json", **extra)

    def test_the_run_gets_in_and_nobody_else_does(self):
        good = self.auth(f"job-{self.job.pk}", self.token)
        self.assertEqual(self.call("GET", **good).status_code, 204)
        self.assertEqual(self.call("GET").status_code, 401)
        self.assertEqual(self.call("GET", **self.auth(f"job-{self.job.pk}", "guess")).status_code, 401)

    def test_the_password_dies_with_the_run(self):
        Job.objects.filter(pk=self.job.pk).update(status=Job.SUCCESSFUL)
        good = self.auth(f"job-{self.job.pk}", self.token)
        self.assertEqual(self.call("GET", **good).status_code, 401)

    def test_a_run_cannot_reach_another_projects_state(self):
        other = TofuProject.objects.create(name="other", host_group=self.project.host_group)
        good = self.auth(f"job-{self.job.pk}", self.token)
        response = self.client.get(f"/infra/state/{other.pk}/", **good)
        self.assertEqual(response.status_code, 401)

    def test_locking(self):
        good = self.auth(f"job-{self.job.pk}", self.token)
        self.assertEqual(self.call("LOCK", b'{"ID": "a", "Who": "me"}', **good).status_code, 200)
        taken = self.call("LOCK", b'{"ID": "b"}', **good)
        self.assertEqual(taken.status_code, 423)
        self.assertEqual(taken.json()["Who"], "me")
        # Writing without the lock's ID is refused; with it, accepted.
        self.assertEqual(self.call("POST", b'{"serial": 1}', **good).status_code, 409)
        self.assertEqual(
            self.client.post(self.url + "?ID=a", b'{"serial": 1}', content_type="application/json", **good).status_code,
            200,
        )
        self.assertEqual(self.call("UNLOCK", b'{"ID": "a"}', **good).status_code, 200)
        self.assertFalse(TofuLock.objects.exists())

    def test_deleting_state_over_http_is_refused(self):
        good = self.auth(f"job-{self.job.pk}", self.token)
        self.assertEqual(self.call("DELETE", **good).status_code, 405)

    def test_a_finished_run_leaves_no_lock_behind(self):
        TofuLock.objects.create(project=self.project, job=self.job, lock_id="x")
        executor._finish(self.job, Job.ERROR, error_message="worker died")
        self.assertFalse(TofuLock.objects.exists())


@unittest.skipUnless(HAS_TOFU and shutil.which("git"), "tofu or git is not installed here")
class GitSourceTests(ProjectMixin, LiveServerTestCase):
    def setUp(self):
        import subprocess

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        override = override_settings(
            LOONA_INTERNAL_URL=self.live_server_url,
            LOONA_DATA_DIR=f"{self.tmp.name}/jobs",
            LOONA_TOFU_PLUGIN_CACHE=f"{self.tmp.name}/plugins",
            # The repository is a local one.
            LOONA_GIT_PROTOCOLS="file",
        )
        override.enable()
        self.addCleanup(override.disable)

        self.repo = Path(self.tmp.name) / "infra-repo"
        (self.repo / "envs" / "lab").mkdir(parents=True)
        (self.repo / "envs" / "lab" / "main.tf").write_text(CONFIG)

        def git(*args):
            subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True,
                           env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                                "GIT_COMMITTER_EMAIL": "t@t", "HOME": self.tmp.name, "PATH": "/usr/bin:/bin"})

        self.git = git
        git("init", "--quiet", "-b", "main")
        git("add", ".")
        git("commit", "--quiet", "-m", "first")

        self.project = self.make_project()
        self.project.files.all().delete()
        self.project.source = TofuProject.SOURCE_GIT
        self.project.git_url = f"file://{self.repo}"
        self.project.git_path = "envs/lab"
        self.project.save()

    def run_job(self, job):
        executor.run_job(job.pk)
        job.refresh_from_db()
        return job

    def test_apply_uses_the_planned_commit_even_after_the_branch_moved(self):
        plan = self.run_job(start_plan(self.project, self.user))
        self.assertEqual(plan.status, Job.SUCCESSFUL, plan.error_message)
        self.assertEqual(len(plan.tofu_revision), 40)

        (self.repo / "envs" / "lab" / "main.tf").write_text("this is not HCL {")
        self.git("commit", "--quiet", "-am", "broken")

        applied = self.run_job(plans.apply(plan, self.user))
        self.assertEqual(applied.status, Job.SUCCESSFUL, applied.error_message)
        self.assertEqual(applied.tofu_revision, plan.tofu_revision)

    def test_a_missing_folder_is_reported(self):
        self.project.git_path = "envs/prod"
        self.project.save()
        plan = self.run_job(start_plan(self.project, self.user))
        self.assertEqual(plan.status, Job.ERROR)
        self.assertIn("envs/prod", plan.error_message)

    def test_an_unknown_branch_is_reported(self):
        self.project.git_ref = "nope"
        self.project.save()
        plan = self.run_job(start_plan(self.project, self.user))
        self.assertEqual(plan.status, Job.ERROR)
        self.assertIn("nope", plan.error_message)
