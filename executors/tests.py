# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
import base64
import io
import json
import tarfile
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import LiveServerTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from inventory.models import Host, HostFacts, HostGroup
from runs import executor as runs_executor
from runs.models import Job, JobEvent

from . import agent, remote, routing
from .models import Agent, Executor

PLAYBOOK = "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.ping:\n"


def make_job(*hosts, yaml=PLAYBOOK, **fields):
    job = Job.objects.create(playbook_name="p", playbook_yaml=yaml, **fields)
    job.target_hosts.add(*hosts)
    return job


def local_host(name, *groups):
    host = Host.objects.create(name=name, variables={"ansible_connection": "local"})
    host.groups.add(*groups)
    return host


class RoutingTests(TestCase):
    def setUp(self):
        self.dmz = Executor.objects.create(name="DMZ")
        self.plant = Executor.objects.create(name="Plant")

    def test_no_executor_means_loona_itself(self):
        group = HostGroup.objects.create(name="web")
        self.assertIsNone(routing.executor_for_host(local_host("a", group)))

    def test_inherited_from_a_group_above(self):
        top = HostGroup.objects.create(name="dmz", executor=self.dmz)
        web = HostGroup.objects.create(name="web")
        web.parents.add(top)
        self.assertEqual(routing.executor_for_host(local_host("a", web)), self.dmz)
        self.assertEqual(routing.executor_for_group(web), self.dmz)

    def test_the_nearest_group_wins(self):
        top = HostGroup.objects.create(name="dmz", executor=self.dmz)
        legacy = HostGroup.objects.create(name="legacy", executor=self.plant)
        legacy.parents.add(top)
        self.assertEqual(routing.executor_for_host(local_host("a", legacy)), self.plant)

    def test_two_executors_at_the_same_distance_is_a_conflict(self):
        one = HostGroup.objects.create(name="one", executor=self.dmz)
        two = HostGroup.objects.create(name="two", executor=self.plant)
        with self.assertRaisesMessage(routing.Conflict, "different executors"):
            routing.executor_for_host(local_host("a", one, two))

    def test_hosts_behind_different_executors_cannot_share_a_run(self):
        dmz = HostGroup.objects.create(name="dmz", executor=self.dmz)
        here = HostGroup.objects.create(name="here")
        hosts = [local_host("a", dmz), local_host("b", here)]
        with self.assertRaisesMessage(routing.Conflict, "b via Loona itself; a via DMZ"):
            routing.executor_for_hosts(hosts)


class HandOffTests(TestCase):
    def setUp(self):
        self.executor = Executor.objects.create(name="DMZ")
        self.token = self.executor.issue_token()
        self.group = HostGroup.objects.create(name="dmz", executor=self.executor)
        self.host = local_host("far", self.group)
        self.data = tempfile.TemporaryDirectory()
        self.addCleanup(self.data.cleanup)

    def run_job(self, job):
        with self.settings(LOONA_DATA_DIR=self.data.name):
            return runs_executor.run_job(job.pk)

    def post(self, path, body=None, token=None, protocol="1"):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token or self.token}"}
        if protocol:
            headers["HTTP_X_LOONA_EXECUTOR_PROTOCOL"] = protocol
        return self.client.post(f"/api/executor/v1/{path}", json.dumps({"agent": "a1", **(body or {})}),
                                content_type="application/json", **headers)

    def test_a_run_on_a_remote_host_is_packed_and_left_waiting(self):
        job = make_job(self.host)
        with patch.object(runs_executor.ansible_runner, "run") as run:
            self.assertEqual(self.run_job(job), Job.PENDING)
        run.assert_not_called()
        job.refresh_from_db()
        self.assertEqual(job.executor, self.executor)
        self.assertEqual(job.runner, "executor/%d" % self.executor.pk)
        self.assertTrue(job.waiting_for_executor)
        self.assertTrue(job.bundle_encrypted)
        self.assertNotIn(b"ping", job.bundle_encrypted.encode())  # encrypted, not just packed
        self.assertEqual(list(Path(self.data.name).iterdir()), [])
        self.assertTrue(job.events.filter(event="loona_executor").exists())

    def test_mixed_targets_are_refused(self):
        here = local_host("near", HostGroup.objects.create(name="here"))
        job = make_job(self.host, here)
        self.assertEqual(self.run_job(job), Job.ERROR)
        job.refresh_from_db()
        self.assertIn("reached from different places", job.error_message)

    def test_the_bundle_carries_the_run(self):
        job = make_job(self.host, extra_vars={"colour": "blue"})
        self.run_job(job)
        response = self.post("claim/")
        self.assertEqual(response.status_code, 200)
        bundle = base64.b64decode(response.json()["bundle"])
        with tarfile.open(fileobj=io.BytesIO(bundle)) as tar:
            names = tar.getnames()
            spec = json.load(tar.extractfile("./loona.json"))
        self.assertIn("./inventory/hosts.yml", names)
        self.assertIn("./project/" + spec["playbook"], names)
        self.assertIn("./env/extra_vars.yml", names)
        self.assertIn("extra_vars.yml", spec["cmdline"])
        self.assertEqual(spec["job"], job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, Job.RUNNING)
        self.assertEqual(job.runner, f"executor/{self.executor.pk}/a1")
        self.assertEqual(job.bundle_encrypted, "")  # gone the moment it was taken
        self.assertEqual(self.post("claim/").status_code, 204)  # and taken once
        self.assertTrue(Agent.objects.filter(executor=self.executor, name="a1").exists())

    def test_wrong_token_and_other_protocol_are_refused(self):
        self.assertEqual(self.post("claim/", token="lxe_nope").status_code, 401)
        self.assertEqual(self.post("claim/", protocol="").status_code, 426)
        self.assertEqual(self.post("claim/", protocol="2").status_code, 426)

    def test_another_executors_agent_gets_nothing(self):
        self.run_job(make_job(self.host))
        other = Executor.objects.create(name="Other")
        self.assertEqual(self.post("claim/", token=other.issue_token()).status_code, 204)

    def test_a_disabled_executor_gets_nothing(self):
        self.run_job(make_job(self.host))
        Executor.objects.filter(pk=self.executor.pk).update(enabled=False)
        self.assertEqual(self.post("claim/").status_code, 204)

    def test_events_and_finish(self):
        job = make_job(self.host)
        self.run_job(job)
        self.post("claim/")
        event = {"event": "runner_on_ok", "counter": 3, "uuid": "u-1", "stdout": "ok: [far]",
                 "event_data": {"host": "far", "task": "ping", "res": {"changed": False}}}
        self.assertEqual(self.post(f"jobs/{job.pk}/events/", {"events": [event]}).json(), {"cancel": False})
        # Sent again after a lost answer: stored once.
        self.post(f"jobs/{job.pk}/events/", {"events": [event]})
        self.assertEqual(job.events.filter(uuid="u-1").count(), 1)
        stats = {"ok": {"far": 1}}
        response = self.post(f"jobs/{job.pk}/finish/", {"status": "successful", "rc": 0, "stats": stats})
        self.assertEqual(response.json(), {"status": "successful"})
        job.refresh_from_db()
        self.assertEqual(job.status, Job.SUCCESSFUL)
        self.assertEqual(job.stats, stats)
        # Over: the agent hears so.
        self.assertEqual(self.post(f"jobs/{job.pk}/events/", {"events": []}).status_code, 409)

    def test_another_agent_cannot_report_on_a_run(self):
        job = make_job(self.host)
        self.run_job(job)
        self.post("claim/")
        response = self.client.post(
            f"/api/executor/v1/jobs/{job.pk}/finish/", json.dumps({"agent": "a2", "status": "failed"}),
            content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {self.token}",
            HTTP_X_LOONA_EXECUTOR_PROTOCOL="1")
        self.assertEqual(response.status_code, 409)

    def test_cancel_reaches_the_agent(self):
        from runs import services

        job = make_job(self.host)
        self.run_job(job)
        self.post("claim/")
        admin = get_user_model().objects.create_superuser("root", password="x")
        services.cancel(job, admin)
        self.assertEqual(self.post(f"jobs/{job.pk}/events/", {"events": []}).json(), {"cancel": True})
        self.post(f"jobs/{job.pk}/finish/", {"status": "failed"})
        job.refresh_from_db()
        self.assertEqual(job.status, Job.CANCELED)

    def test_cancelling_a_waiting_run_closes_it_and_drops_the_bundle(self):
        from runs import services

        job = make_job(self.host)
        self.run_job(job)
        services.cancel(job, get_user_model().objects.create_superuser("root", password="x"))
        job.refresh_from_db()
        self.assertEqual(job.status, Job.CANCELED)
        self.assertEqual(job.bundle_encrypted, "")
        self.assertEqual(self.post("claim/").status_code, 204)

    def test_a_silent_agent_loses_the_run(self):
        job = make_job(self.host)
        self.run_job(job)
        self.post("claim/")
        Job.objects.filter(pk=job.pk).update(heartbeat_at=timezone.now() - timedelta(minutes=10))
        self.assertEqual(runs_executor.reap_dead_jobs(), 1)
        job.refresh_from_db()
        self.assertEqual(job.status, Job.ERROR)
        self.assertIn("stopped reporting", job.error_message)

    def test_a_waiting_run_is_not_reaped(self):
        job = make_job(self.host)
        self.run_job(job)
        self.assertEqual(runs_executor.reap_dead_jobs(ask_workers=True), 0)
        job.refresh_from_db()
        self.assertEqual(job.status, Job.PENDING)

    def test_deleting_the_executor_closes_waiting_runs(self):
        admin = get_user_model().objects.create_superuser("root", password="x")
        self.client.force_login(admin)
        job = make_job(self.host)
        self.run_job(job)
        self.client.post(reverse("executor_delete", args=[self.executor.pk]))
        job.refresh_from_db()
        self.assertEqual(job.status, Job.ERROR)
        self.assertEqual(job.bundle_encrypted, "")
        self.group.refresh_from_db()
        self.assertIsNone(self.group.executor)

    def test_host_keys_met_on_the_far_side_are_pinned(self):
        host = Host.objects.create(name="ssh-far", address="10.9.9.9")
        host.groups.add(self.group)
        job = make_job(host)
        Job.objects.filter(pk=job.pk).update(
            status=Job.RUNNING, executor=self.executor, runner=f"executor/{self.executor.pk}/a1",
            resolved_hosts=["ssh-far"], heartbeat_at=timezone.now())
        self.post(f"jobs/{job.pk}/finish/", {
            "status": "successful", "known_hosts": "10.9.9.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK\n"})
        host.refresh_from_db()
        self.assertEqual(host.ssh_host_keys, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK")


class AgentPieceTests(TestCase):
    def test_protocol_versions_agree(self):
        self.assertEqual(agent.PROTOCOL, remote.PROTOCOL)

    def test_tofu_trusts_the_agents_ca(self):
        """tofu talks to Loona's state backend itself: LOONA_CA_FILE must reach it."""
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / "corp-ca.pem"
            ca.write_text("-----BEGIN CERTIFICATE-----\ncorp\n-----END CERTIFICATE-----\n")
            client = agent.Client.__new__(agent.Client)
            client.ca_file, client.root = str(ca), "https://loona.example.com"
            seen = {}

            def step(config, env, name, args, ok, reporter, counter):
                seen.update(env)
                return 0

            with patch.object(agent, "_tofu_step", step), patch.dict("os.environ", clear=False) as environ:
                environ.pop("SSL_CERT_FILE", None)
                agent.run_tofu(client, Path(tmp), Path(tmp), {"config": ".", "steps": [["init", [], [0]]]},
                               reporter=type("R", (), {"should_stop": lambda self: False})(), outcome={})
            bundle = Path(seen["SSL_CERT_FILE"]).read_text()
            self.assertIn("corp", bundle)
            self.assertGreater(bundle.count("BEGIN CERTIFICATE"), 1)  # the public roots stay

    def test_unpack_points_paths_at_the_new_place(self):
        with tempfile.TemporaryDirectory() as old, tempfile.TemporaryDirectory() as new:
            source = Path(old) / "job_7"
            (source / "env").mkdir(parents=True)
            (source / "inventory").mkdir()
            (source / "env" / "envvars").write_text(f"ANSIBLE_SSH_ARGS: -o UserKnownHostsFile={source}/known_hosts\n")
            (source / "inventory" / "hosts.yml").write_text(f"key: {source}/keys/a\n")
            bundle = remote.pack(source, {"base": str(source), "cmdline": f"-e @{source}/env/x.yml"})
            target = Path(new) / "job_7"
            spec = agent.unpack(bundle, target)
            self.assertEqual(spec["cmdline"], f"-e @{target}/env/x.yml")
            self.assertIn(f"{target}/known_hosts", (target / "env" / "envvars").read_text())
            self.assertIn(f"{target}/keys/a", (target / "inventory" / "hosts.yml").read_text())
            self.assertFalse((target / "loona.json").exists())

    def test_a_bundle_cannot_write_outside_its_directory(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            data = b"x"
            info = tarfile.TarInfo("../escaped")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(tarfile.TarError):
                agent.unpack(buffer.getvalue(), Path(root) / "job_1")
            self.assertFalse((Path(root) / "escaped").exists())

    def test_galaxy_installs_travel_with_the_run(self):
        with tempfile.TemporaryDirectory() as cache, tempfile.TemporaryDirectory() as jobs:
            installed = Path(cache) / "abc" / "roles" / "nginx"
            installed.mkdir(parents=True)
            (installed / "README").write_text("role")
            run = Path(jobs) / "job_1"
            (run / "env").mkdir(parents=True)
            (run / "env" / "envvars").write_text(
                f"ANSIBLE_ROLES_PATH: {run}/project/roles:{Path(cache) / 'abc' / 'roles'}\n")
            with self.settings(LOONA_GALAXY_CACHE=cache):
                remote._vendor_galaxy(run)
            self.assertTrue((run / "galaxy" / "1" / "nginx" / "README").exists())
            self.assertIn(f"{run}/galaxy/1", (run / "env" / "envvars").read_text())
            self.assertNotIn(cache, (run / "env" / "envvars").read_text())

    def test_plain_http_is_refused_away_from_localhost(self):
        with self.assertRaises(SystemExit):
            agent.Client("http://loona.example.com", "lxe_x", "a", 1)
        agent.Client("http://loona.example.com", "lxe_x", "a", 1, allow_http=True)
        agent.Client("http://localhost:8000", "lxe_x", "a", 1)

    def test_an_oversized_result_is_cut_down(self):
        event = {"event": "runner_on_ok", "stdout": "x" * 500_000,
                 "event_data": {"host": "h", "res": {"changed": True, "stdout": "y" * 500_000}}}
        small = agent._shrink(event)
        self.assertLess(len(json.dumps(small)), agent.MAX_EVENT_BYTES)
        self.assertTrue(small["event_data"]["res"]["changed"])


class AdministrationTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser("root", password="x")
        self.client.force_login(self.admin)

    def test_create_shows_the_token_once_and_assigns_groups(self):
        group = HostGroup.objects.create(name="dmz")
        response = self.client.post(reverse("executor_create"), {
            "name": "DMZ", "description": "", "enabled": "on", "groups": [group.pk]}, follow=True)
        executor = Executor.objects.get(name="DMZ")
        token = response.context["token"]
        self.assertTrue(token.startswith("lxe_"))
        self.assertContains(response, token)
        self.assertEqual(Executor.for_token(token), executor)
        group.refresh_from_db()
        self.assertEqual(group.executor, executor)
        again = self.client.get(reverse("executor_detail", args=[executor.pk]))
        self.assertNotContains(again, token)

    def test_a_new_token_replaces_the_old_one(self):
        executor = Executor.objects.create(name="DMZ")
        old = executor.issue_token()
        self.client.post(reverse("executor_token", args=[executor.pk]))
        self.assertIsNone(Executor.for_token(old))

    def test_unticking_a_group_hands_it_back_to_loona(self):
        executor = Executor.objects.create(name="DMZ")
        group = HostGroup.objects.create(name="dmz", executor=executor)
        self.client.post(reverse("executor_detail", args=[executor.pk]),
                         {"name": "DMZ", "description": "", "enabled": "on"})
        group.refresh_from_db()
        self.assertIsNone(group.executor)

    def test_superusers_only(self):
        user = get_user_model().objects.create_user("op", password="x")
        self.client.force_login(user)
        self.assertEqual(self.client.get(reverse("executor_list")).status_code, 403)

    def test_pages_render(self):
        executor = Executor.objects.create(name="DMZ")
        group = HostGroup.objects.create(name="dmz", executor=executor)
        host = local_host("far", group)
        Agent.objects.create(executor=executor, name="a1")
        self.assertContains(self.client.get(reverse("executor_list")), "1 online")
        self.assertContains(self.client.get(reverse("executor_detail", args=[executor.pk])), "loona:latest executor")
        self.assertContains(self.client.get(reverse("group_detail", args=[group.pk])), "executor <b>DMZ</b>")
        self.assertContains(self.client.get(reverse("host_detail", args=[host.pk])), "executor <b>DMZ</b>")

    def test_the_connection_check_does_not_pretend_from_here(self):
        executor = Executor.objects.create(name="DMZ")
        host = local_host("far", HostGroup.objects.create(name="dmz", executor=executor))
        response = self.client.post(reverse("host_probe"), {"host": host.pk, "address": "10.0.0.1",
                                                            "port": 22, "username": "root"})
        self.assertContains(response, "reached through executor DMZ")


class LiveAgentTests(LiveServerTestCase):
    """The real agent, over real HTTP, running a real ansible-playbook."""

    def test_a_run_goes_out_and_comes_back(self):
        executor = Executor.objects.create(name="DMZ")
        token = executor.issue_token()
        host = local_host("far", HostGroup.objects.create(name="dmz", executor=executor))
        job = make_job(host, yaml=(
            "- hosts: all\n  gather_facts: false\n  tasks:\n"
            "    - ansible.builtin.setup:\n        gather_subset: [min]\n"
            "    - ansible.builtin.debug:\n        msg: 'the password is {{ db_password }}'\n"
        ))
        job.secret_vars = {"db_password": "s3cret-and-long"}
        job.save()
        with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory() as far:
            with self.settings(LOONA_DATA_DIR=data):
                self.assertEqual(runs_executor.run_job(job.pk), Job.PENDING)
            client = agent.Client(self.live_server_url, token, "far-agent", 1)
            status, answer = client.post("claim/", {})
            self.assertEqual(status, 200)
            agent.carry_out(client, Path(far), answer["job"], base64.b64decode(answer["bundle"]))
            self.assertEqual(list(Path(far).iterdir()), [])
        job.refresh_from_db()
        self.assertEqual(job.status, Job.SUCCESSFUL, job.error_message)
        log = "\n".join(JobEvent.objects.filter(job=job).values_list("stdout", flat=True))
        self.assertIn("the password is ********", log)
        self.assertNotIn("s3cret-and-long", log)
        self.assertEqual(job.stats["ok"], {"far": 2})
        self.assertTrue(HostFacts.objects.filter(host=host).exists())
        self.assertEqual(job.secret_vars, {})


class TofuHandOffTests(HandOffTests.__base__):
    """OpenTofu runs for a project whose group is behind an executor."""

    def setUp(self):
        from infra.models import TofuFile, TofuProject

        self.executor = Executor.objects.create(name="DMZ")
        self.token = self.executor.issue_token()
        group = HostGroup.objects.create(name="dmz", executor=self.executor,
                                         approval_policy=HostGroup.APPROVAL_NONE)
        self.project = TofuProject.objects.create(name="dmz-cloud", host_group=group)
        TofuFile.objects.create(project=self.project, path="main.tf", content='output "x" { value = 1 }\n')
        self.user = get_user_model().objects.create_superuser("root", password="x")
        self.data = tempfile.TemporaryDirectory()
        self.addCleanup(self.data.cleanup)

    post = HandOffTests.post

    def test_a_plan_is_packed_for_the_agent_and_its_result_taken_in(self):
        from infra.services import start_plan

        job = start_plan(self.project, self.user)
        with self.settings(LOONA_DATA_DIR=self.data.name):
            self.assertEqual(runs_executor.run_job(job.pk), Job.PENDING)
        response = self.post("claim/")
        bundle = base64.b64decode(response.json()["bundle"])
        with tarfile.open(fileobj=io.BytesIO(bundle)) as tar:
            spec = json.load(tar.extractfile("./loona.json"))
            self.assertIn(f"./{spec['config']}/main.tf", tar.getnames())
        self.assertEqual(spec["kind"], "tofu")
        self.assertEqual([step[0] for step in spec["steps"]], ["init", "plan"])
        self.assertTrue(spec["env"]["TF_HTTP_ADDRESS"].startswith("{LOONA_URL}/infra/state/"))
        self.assertNotIn("PATH", spec["env"])  # the agent's own

        shown = {"resource_changes": [{"address": "terraform_data.a", "change": {"actions": ["create"],
                                                                               "after": {"input": 1}}}]}
        self.post(f"jobs/{job.pk}/finish/", {"status": "successful", "rc": 0, "tofu": {
            "plan_rc": 2, "show": shown, "plan_file": base64.b64encode(b"PLAN").decode()}})
        job.refresh_from_db()
        self.assertEqual(job.status, Job.SUCCESSFUL, job.error_message)
        self.assertEqual(job.tofu_plan_file, b"PLAN")
        self.assertEqual((job.stats["tofu"]["add"], job.stats["tofu"]["has_changes"]), (1, True))

    def test_a_bad_result_is_an_error_not_a_crash(self):
        from infra.services import start_plan
        from runs import plans

        plan = start_plan(self.project, self.user)
        Job.objects.filter(pk=plan.pk).update(status=Job.SUCCESSFUL, stats={"tofu": {"has_changes": True}})
        plan.refresh_from_db()
        from infra.runner import _digest

        plan.tofu_plan_file = b"PLAN"
        plan.tofu_files = {"main.tf": 'output "x" { value = 1 }\n'}
        plan.tofu_revision = _digest(plan.tofu_files)
        plan.save()
        job = plans.apply(plan, self.user)
        with self.settings(LOONA_DATA_DIR=self.data.name):
            runs_executor.run_job(job.pk)
        self.post("claim/")
        self.post(f"jobs/{job.pk}/finish/", {"status": "successful", "tofu": {"outputs": "nonsense"}})
        job.refresh_from_db()
        self.assertEqual(job.status, Job.ERROR)
        self.assertIn("could not be taken in", job.error_message)


@__import__("unittest").skipUnless(__import__("shutil").which("tofu"), "tofu is not installed here")
class LiveTofuAgentTests(LiveServerTestCase):
    """The real agent runs real OpenTofu; the state goes to Loona over the agent's own way in."""

    def test_plan_and_apply_through_the_agent(self):
        from infra.models import TofuFile, TofuProject, TofuVariable
        from infra.services import start_plan
        from runs import plans

        executor = Executor.objects.create(name="DMZ")
        token = executor.issue_token()
        user = get_user_model().objects.create_superuser("root", password="x")
        group = HostGroup.objects.create(name="dmz", executor=executor, approval_policy=HostGroup.APPROVAL_NONE)
        project = TofuProject.objects.create(name="dmz-cloud", host_group=group)
        TofuFile.objects.create(project=project, path="main.tf", content=(
            'variable "secret" {\n  type = string\n  sensitive = true\n}\n'
            'resource "terraform_data" "a" {\n  input = "hello"\n}\n'
            'output "note" {\n  value = terraform_data.a.output\n}\n'))
        secret = TofuVariable(project=project, name="secret", sensitive=True)
        secret.value = "hunter2-long"
        secret.save()

        def through_the_agent(job):
            with tempfile.TemporaryDirectory() as data, self.settings(LOONA_DATA_DIR=data):
                self.assertEqual(runs_executor.run_job(job.pk), Job.PENDING)
            client = agent.Client(self.live_server_url, token, "far", 1)
            status, answer = client.post("claim/", {})
            self.assertEqual(status, 200)
            with tempfile.TemporaryDirectory() as far:
                agent.carry_out(client, Path(far), answer["job"], base64.b64decode(answer["bundle"]))
                self.assertEqual([p.name for p in Path(far).iterdir()], ["tofu-plugins"])
            job.refresh_from_db()
            self.assertEqual(job.status, Job.SUCCESSFUL, job.error_message)
            return job

        plan = through_the_agent(start_plan(project, user))
        self.assertEqual(plan.stats["tofu"]["add"], 1)
        applied = through_the_agent(plans.apply(plan, user))
        self.assertEqual(applied.stats["tofu"]["outputs"], {"note": "hello"})
        self.assertIn("hello", project.current_state.data)
        log = "\n".join(JobEvent.objects.filter(job=applied).values_list("stdout", flat=True))
        self.assertIn("Apply complete", log)
        self.assertNotIn("hunter2-long", log)
