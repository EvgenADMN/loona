# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from inventory.models import Host, HostGroup
from playbooks.models import Playbook, PlaybookTask

from . import executor
from .models import Job


class JobModelTests(TestCase):
    def test_host_stats_reads_dark_as_unreachable(self):
        job = Job(
            playbook_name="p",
            stats={"ok": {"a": 2}, "dark": {"b": 1}, "changed": {"a": 1}},
        )
        rows = {row["host"]: row for row in job.host_stats}
        self.assertEqual(rows["a"]["ok"], 2)
        self.assertEqual(rows["b"]["unreachable"], 1)
        self.assertTrue(rows["b"]["failed"])


class JobLaunchTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_superuser("tester", password="pw")
        self.client.login(username="tester", password="pw")
        self.playbook = Playbook.objects.create(name="Ping")
        PlaybookTask.objects.create(
            playbook=self.playbook, order=0, module="ansible.builtin.ping"
        )
        self.group = HostGroup.objects.create(name="local")
        host = Host.objects.create(name="localhost", variables={"ansible_connection": "local"})
        host.groups.add(self.group)

    def _post(self, **overrides):
        data = {
            "target_groups": [self.group.pk],
            "target_hosts": [],
            "limit": "",
            "extra_vars": "",
            "tags": "",
            "skip_tags": "",
            "forks": 5,
            "verbosity": 0,
        }
        data.update(overrides)
        return self.client.post(reverse("job_launch", args=[self.playbook.pk]), data)

    def test_launch_without_targets_is_rejected(self):
        response = self._post(target_groups=[])
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "at least one host")
        self.assertEqual(Job.objects.count(), 0)

    @patch("runs.services.dispatch")
    def test_launch_snapshots_the_playbook(self, dispatch):
        response = self._post()
        dispatch.assert_called_once()
        self.assertEqual(response.status_code, 302)
        job = Job.objects.get()
        self.assertIn("ansible.builtin.ping", job.playbook_yaml)
        self.assertEqual(job.created_by, self.user)

    @patch("runs.services.dispatch")
    def test_snapshot_survives_playbook_edits(self, dispatch):
        self._post()
        job = Job.objects.get()
        original = job.playbook_yaml
        self.playbook.tasks.all().delete()
        job.refresh_from_db()
        self.assertEqual(job.playbook_yaml, original)


class ConnectionOverrideTests(TestCase):
    """The password typed in to push a key must not outlive the run."""

    def setUp(self):
        self.job = Job.objects.create(
            playbook_name="p", playbook_yaml="---", kind=Job.KIND_KEY_INSTALL
        )

    def test_the_override_is_encrypted_at_rest(self):
        self.job.connection_override = {"ansible_password": "typed-in"}
        self.job.save()
        stored = Job.objects.get(pk=self.job.pk)
        self.assertNotIn("typed-in", stored.connection_override_encrypted)
        self.assertEqual(stored.connection_override["ansible_password"], "typed-in")

    def test_finishing_a_run_wipes_it(self):
        self.job.connection_override = {"ansible_password": "typed-in"}
        self.job.save()
        executor._finish(self.job, Job.SUCCESSFUL)
        self.assertEqual(Job.objects.get(pk=self.job.pk).connection_override, {})

    def test_a_crash_before_the_run_wipes_it_too(self):
        self.job.connection_override = {"ansible_password": "typed-in"}
        self.job.save()
        with patch.object(executor, "prepare_private_data_dir", side_effect=OSError("no disk")):
            executor.run_job(self.job.pk)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, Job.ERROR)
        self.assertEqual(self.job.connection_override, {})


class SystemJobInventoryTests(TestCase):
    def setUp(self):
        self.host = Host.objects.create(name="web01", address="10.0.0.1")
        self.job = Job.objects.create(
            playbook_name="p", playbook_yaml="---", kind=Job.KIND_KEY_REVOKE
        )
        self.job.target_hosts.add(self.host)

    def _inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            return executor.build_job_inventory(self.job, Path(tmp))

    def test_a_disabled_host_can_still_have_its_key_revoked(self):
        self.host.enabled = False
        self.host.save()
        self.assertIn("web01", self._inventory()["all"]["hosts"])

    def test_a_playbook_run_still_skips_disabled_hosts(self):
        self.host.enabled = False
        self.host.save()
        self.job.kind = Job.KIND_PLAYBOOK
        self.job.save()
        with self.assertRaises(ValueError):
            self._inventory()

    def test_the_override_reaches_the_inventory(self):
        self.job.connection_override = {"ansible_user": "root", "ansible_password": "x"}
        self.job.save()
        variables = self._inventory()["all"]["hosts"]["web01"]
        self.assertEqual(variables["ansible_password"], "x")
        self.assertEqual(variables["ansible_host"], "10.0.0.1")


class JobDetailRenderTests(TestCase):
    """The status block belongs in one place on the page."""

    def setUp(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))
        self.job = Job.objects.create(
            playbook_name="p", playbook_yaml="---", status=Job.SUCCESSFUL
        )

    def test_a_finished_job_shows_its_status_once(self):
        response = self.client.get(reverse("job_detail", args=[self.job.pk]))
        body = response.content.decode()
        self.assertEqual(body.count('id="job-status"'), 1)
        # Out of band is for a poll response; on the page it would draw a
        # second status block inside the log.
        self.assertNotIn("hx-swap-oob", body)

    def test_a_poll_that_finds_the_job_finished_swaps_the_status(self):
        response = self.client.get(reverse("job_events", args=[self.job.pk]))
        self.assertContains(response, "hx-swap-oob")

    def test_a_running_job_keeps_polling(self):
        self.job.status = Job.RUNNING
        self.job.save(update_fields=["status"])
        response = self.client.get(reverse("job_detail", args=[self.job.pk]))
        self.assertContains(response, 'id="poller"')


class RunDirectoryTests(TestCase):
    """The scratch directory holds secrets in clear text; it must not linger."""

    def test_nothing_is_left_on_disk_after_a_run(self):
        from inventory.models import Credential

        credential = Credential.objects.create(
            name="pw", kind=Credential.KIND_PASSWORD, username="deploy"
        )
        credential.secret = "hunter2"
        credential.save()
        host = Host.objects.create(
            name="localhost", credential=credential, variables={"ansible_connection": "local"}
        )
        job = Job.objects.create(
            playbook_name="p",
            playbook_yaml="- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.ping:\n",
        )
        job.target_hosts.add(host)
        with tempfile.TemporaryDirectory() as data_dir, self.settings(LOONA_DATA_DIR=data_dir):
            status = executor.run_job(job.pk)
            self.assertEqual(status, Job.SUCCESSFUL)
            self.assertEqual(list(Path(data_dir).iterdir()), [])


class DeadRunnerTests(TestCase):
    """A run whose process died must not show as running forever."""

    def setUp(self):
        import subprocess
        import sys

        finished = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"],
                                  capture_output=True, text=True)
        self.dead_pid = finished.stdout.strip()
        self.here = executor.socket.gethostname()

    def running(self, runner, private_data_dir=""):
        return Job.objects.create(
            playbook_name="p", playbook_yaml="---", status=Job.RUNNING,
            runner=runner, private_data_dir=private_data_dir,
        )

    def test_a_job_whose_process_is_gone_is_closed_with_an_explanation(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "job_1"
            (run_dir / "keys").mkdir(parents=True)
            (run_dir / "keys" / "host_1").write_text("PRIVATE")
            job = self.running(f"{self.here}:{self.dead_pid}", str(run_dir))
            job.connection_override = {"ansible_password": "typed-in"}
            job.save()

            self.assertEqual(executor.reap_dead_jobs(), 1)
            self.assertFalse(run_dir.exists())
        job.refresh_from_db()
        self.assertEqual(job.status, Job.ERROR)
        self.assertIn("check the hosts", job.error_message)
        self.assertEqual(job.connection_override, {})

    def test_a_live_process_is_left_alone(self):
        job = self.running(executor.runner_id())
        self.assertEqual(executor.reap_dead_jobs(), 0)
        job.refresh_from_db()
        self.assertEqual(job.status, Job.RUNNING)

    def test_a_runner_on_another_machine_is_not_second_guessed(self):
        job = self.running(f"some-other-host:{self.dead_pid}")
        self.assertEqual(executor.reap_dead_jobs(), 0)

    def test_a_newer_process_with_the_same_pid_does_not_pass_for_the_runner(self):
        # A restarted worker container hands out the same pids again.
        mine = executor.runner_id()
        host, pid, started = executor._runner_parts(mine)
        self.assertEqual((host, pid), (self.here, str(os.getpid())))
        job = self.running(f"{host}:{pid}:{int(started) - 1}")
        self.assertEqual(executor.reap_dead_jobs(), 1)
        job.refresh_from_db()
        self.assertEqual(job.status, Job.ERROR)

    def test_a_replaced_worker_is_spoken_for_by_the_ones_still_answering(self):
        gone = self.running("old-container:8:100")
        busy = self.running("other-worker:8:100")
        with patch.object(executor, "_answering_workers", return_value={"other-worker"}):
            self.assertEqual(executor.reap_dead_jobs(), 0)
            self.assertEqual(executor.reap_dead_jobs(ask_workers=True), 1)
        gone.refresh_from_db()
        busy.refresh_from_db()
        self.assertEqual((gone.status, busy.status), (Job.ERROR, Job.RUNNING))
        # No answer about who is alive is no verdict at all.
        with patch.object(executor, "_answering_workers", return_value=None):
            self.assertEqual(executor.reap_dead_jobs(ask_workers=True), 0)

    def test_opening_the_job_closes_it(self):
        self.client.force_login(get_user_model().objects.create_superuser("admin", password="x"))
        job = self.running(f"{self.here}:{self.dead_pid}")
        response = self.client.get(reverse("job_detail", args=[job.pk]))
        self.assertContains(response, "check the hosts")
        self.assertNotContains(response, 'id="poller"')


class LeftoverProcessTests(TestCase):
    """What a killed worker's ansible-playbook started must not outlive it."""

    def test_the_whole_process_group_is_stopped(self):
        import subprocess
        import sys
        import time

        run_dir = "/nonexistent/loona-test/job_7"
        # Stands in for ansible-playbook: a session leader with the job's
        # inventory on its command line, and a child of its own.
        leader = subprocess.Popen(
            [sys.executable, "-c",
             "import subprocess, sys, time; "
             "c = subprocess.Popen(['sleep', '60']); print(c.pid, flush=True); time.sleep(60)",
             "-i", f"{run_dir}/inventory"],
            start_new_session=True, stdout=subprocess.PIPE, text=True,
        )
        child = int(leader.stdout.readline())
        bystander = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)", f"{run_dir}2/inventory"],
            start_new_session=True,
        )
        for process in (bystander, leader):
            self.addCleanup(_stop, process)

        self.assertEqual(executor._kill_leftovers(Path(run_dir)), 1)
        leader.wait(timeout=5)
        for _ in range(50):
            if _process_state(child) in ("gone", "Z"):
                break
            time.sleep(0.1)
        self.assertIn(_process_state(child), ("gone", "Z"))
        # job_72 is not job_7.
        self.assertIsNone(bystander.poll())


def _process_state(pid) -> str:
    """The process's state letter, or "gone" - it may vanish between any two reads."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2]
    except (FileNotFoundError, ProcessLookupError, IndexError):
        return "gone"


def _stop(process):
    try:
        process.kill()
        process.wait(timeout=5)
    except (OSError, ValueError):
        pass


class SingleRunTests(TestCase):
    """A job runs once, however many times its task is delivered."""

    def test_a_second_delivery_does_not_run_the_playbook_again(self):
        job = Job.objects.create(playbook_name="p", playbook_yaml="---")
        job.target_hosts.add(Host.objects.create(name="h", variables={"ansible_connection": "local"}))
        # The first delivery claimed it and is (say) still running.
        Job.objects.filter(pk=job.pk).update(status=Job.RUNNING, runner="elsewhere:1")
        with patch.object(executor.ansible_runner, "run") as run:
            status = executor.run_job(job.pk)
        run.assert_not_called()
        self.assertEqual(status, Job.RUNNING)

    def test_a_job_claimed_by_a_process_that_died_before_starting_is_closed(self):
        import subprocess
        import sys

        dead = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"],
                              capture_output=True, text=True).stdout.strip()
        job = Job.objects.create(playbook_name="p", playbook_yaml="---", status=Job.PENDING,
                                 runner=f"{executor.socket.gethostname()}:{dead}")
        self.assertEqual(executor.reap_dead_jobs(), 1)
        job.refresh_from_db()
        self.assertEqual(job.status, Job.ERROR)

    def test_an_unclaimed_pending_job_is_left_for_its_worker(self):
        job = Job.objects.create(playbook_name="p", playbook_yaml="---", status=Job.PENDING)
        self.assertEqual(executor.reap_dead_jobs(), 0)


class LongNameTests(TestCase):
    def test_a_composed_name_too_long_for_the_column_is_trimmed_not_refused(self):
        job = Job.objects.create(playbook_name="x" * 400, playbook_yaml="")
        job.refresh_from_db()
        self.assertEqual(len(job.playbook_name), 255)

