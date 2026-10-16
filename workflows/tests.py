# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Workflows: the walk through the graph, the rules on the way, the pages."""
import json
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from access.models import GroupGrant, Role
from api.models import ApiToken, Trigger
from infra.models import TofuProject
from inventory.models import Host, HostGroup
from notifications.models import WORKFLOW_FAILED, WORKFLOW_MESSAGE, Channel, Delivery
from playbooks.models import Playbook
from runs import executor
from runs import services as run_services
from runs.models import Job

from . import engine
from .forms import StepForm
from .models import Edge, Node, Run, Step, Workflow

User = get_user_model()


class WorkflowTestCase(TestCase):
    def setUp(self):
        self.lab = HostGroup.objects.create(name="lab", approval_policy=HostGroup.APPROVAL_NONE)
        self.prod = HostGroup.objects.create(name="prod", approval_policy=HostGroup.APPROVAL_CHANGES)
        for name, group in (("web1", self.lab), ("db1", self.prod)):
            Host.objects.create(name=name).groups.add(group)
        self.ops = Group.objects.create(name="ops")
        self.admins = Group.objects.create(name="admins")
        for group in (self.lab, self.prod):
            GroupGrant.objects.create(team=self.ops, host_group=group, role=Role.OPERATOR)
            GroupGrant.objects.create(team=self.admins, host_group=group, role=Role.ADMIN)
        self.alice = User.objects.create_user("alice", password="Alice-pass-123")
        self.alice.groups.add(self.ops)
        self.boss = User.objects.create_user("boss", password="Boss-pass-123")
        self.boss.groups.add(self.admins)
        self.playbook = Playbook.objects.create(name="ping")
        self.workflow = Workflow.objects.create(name="deploy", host_group=self.lab)
        self.channel = Channel.objects.create(name="ops-chat", kind=Channel.WEBHOOK,
                                              events=[WORKFLOW_FAILED, WORKFLOW_MESSAGE])
        self.dispatched = []
        for target in ("runs.services.dispatch", "runs.executor.dispatch"):
            patcher = patch(target, side_effect=self.dispatched.append)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch("notifications.dispatch._queue")
        patcher.start()
        self.addCleanup(patcher.stop)

    def step(self, name, kind=Step.PLAYBOOK, after=(), **fields):
        if kind == Step.PLAYBOOK:
            fields.setdefault("playbook", self.playbook)
            fields.setdefault("host_group", self.lab)
        if kind == Step.MESSAGE:
            fields.setdefault("message", "{workflow} #{run}: {step}, failed: {failed_steps}")
        step = Step.objects.create(workflow=self.workflow, name=name, kind=kind, **fields)
        for parent, condition in after:
            Edge.objects.create(workflow=self.workflow, parent=parent, child=step, condition=condition)
        return step

    def start(self, user=None):
        with self.captureOnCommitCallbacks(execute=True):
            return engine.start(self.workflow, user or self.alice)

    def nodes(self, run):
        return {n.step.name: n for n in run.nodes.select_related("step", "job")}

    def finish(self, job, ok=True, **fields):
        job.refresh_from_db()
        job.status = Job.SUCCESSFUL if ok else Job.FAILED
        for key, value in fields.items():
            setattr(job, key, value)
        job.save()
        with self.captureOnCommitCallbacks(execute=True):
            engine.on_job_finished(job)

    def status(self, run):
        return {name: node.status for name, node in self.nodes(run).items()}


class WalkTests(WorkflowTestCase):
    def test_success_and_failure_branches(self):
        build = self.step("build")
        self.step("tell", Step.MESSAGE, after=[(build, Edge.SUCCESS)])
        self.step("cry", Step.MESSAGE, after=[(build, Edge.FAILURE)])
        run = self.start()
        node = self.nodes(run)["build"]
        self.assertEqual(node.status, Node.RUNNING)
        self.assertEqual((node.job.workflow_node, node.job.playbook_name), (node, "deploy: build"))
        self.assertIn("step build of", self.client_page(node.job))
        self.finish(node.job)
        run.refresh_from_db()
        self.assertEqual(self.status(run), {"build": "successful", "tell": "successful", "cry": "skipped"})
        self.assertEqual(run.status, Run.SUCCESSFUL)
        message = Delivery.objects.get(event=WORKFLOW_MESSAGE)
        self.assertEqual(message.text, f"deploy #{run.pk}: tell, failed: none")

    def client_page(self, job):
        self.client.force_login(self.alice)
        return self.client.get(job.get_absolute_url()).content.decode()

    def test_a_handled_failure_is_not_a_failed_run_but_an_unhandled_one_is(self):
        build = self.step("build")
        self.step("cry", Step.MESSAGE, after=[(build, Edge.FAILURE)])
        run = self.start()
        self.finish(self.nodes(run)["build"].job, ok=False)
        run.refresh_from_db()
        self.assertEqual((run.status, self.status(run)["cry"]), (Run.SUCCESSFUL, "successful"))
        self.assertIn("failed: build", Delivery.objects.get(event=WORKFLOW_MESSAGE).text)

        Edge.objects.all().delete()
        run = self.start()
        self.finish(self.nodes(run)["build"].job, ok=False)
        run.refresh_from_db()
        self.assertEqual(run.status, Run.FAILED)
        self.assertEqual(self.status(run)["cry"], "successful")  # no arrow: a second start step
        self.assertTrue(Delivery.objects.filter(event=WORKFLOW_FAILED, subject__contains=f"#{run.pk}").exists())

    def test_branches_run_side_by_side_and_join(self):
        first = self.step("first")
        left = self.step("left", after=[(first, Edge.SUCCESS)])
        right = self.step("right", after=[(first, Edge.SUCCESS)])
        self.step("join", Step.MESSAGE, after=[(left, Edge.SUCCESS), (right, Edge.ALWAYS)])
        run = self.start()
        self.finish(self.nodes(run)["first"].job)
        self.assertEqual(self.status(run)["left"], "running")
        self.assertEqual(self.status(run)["right"], "running")
        self.finish(self.nodes(run)["left"].job)
        self.assertEqual(self.status(run)["join"], "pending")  # right is not done
        self.finish(self.nodes(run)["right"].job, ok=False)
        run.refresh_from_db()
        # right failed, but "always" handles that, and left's success fired too.
        self.assertEqual(self.status(run)["join"], "successful")
        self.assertEqual(run.status, Run.SUCCESSFUL)

    def test_skips_cascade(self):
        first = self.step("first")
        second = self.step("second", after=[(first, Edge.FAILURE)])
        self.step("third", after=[(second, Edge.ALWAYS)])
        run = self.start()
        self.finish(self.nodes(run)["first"].job)
        run.refresh_from_db()
        self.assertEqual(self.status(run), {"first": "successful", "second": "skipped", "third": "skipped"})
        self.assertEqual(run.status, Run.SUCCESSFUL)

    def test_a_group_that_wants_approval_gets_a_preview(self):
        self.step("migrate", host_group=self.prod)
        run = self.start()
        node = self.nodes(run)["migrate"]
        self.assertTrue(node.job.is_plan)
        self.assertIn("Started as a preview", node.note)
        self.finish(node.job, resolved_hosts=["db1"])
        node.refresh_from_db()
        self.assertEqual(node.status, Node.WAITING)
        _, applied = run_services.decide(node.job, self.boss, approve=True)
        node.refresh_from_db()
        self.assertEqual((node.status, node.job, applied.workflow_node), (Node.RUNNING, applied, node))
        self.finish(applied)
        run.refresh_from_db()
        self.assertEqual(run.status, Run.SUCCESSFUL)

    def test_a_rejected_preview_fails_the_step(self):
        self.step("migrate", host_group=self.prod)
        run = self.start()
        node = self.nodes(run)["migrate"]
        self.finish(node.job, resolved_hosts=["db1"])
        with self.captureOnCommitCallbacks(execute=True):
            run_services.decide(node.job, self.boss, approve=False, comment="not today")
        node.refresh_from_db()
        run.refresh_from_db()
        self.assertEqual((node.status, run.status), (Node.FAILED, Run.FAILED))
        self.assertIn("not today", node.note)

    def test_approval_steps(self):
        gate = self.step("gate", Step.APPROVAL, message="Ship it?")
        self.step("ship", after=[(gate, Edge.SUCCESS)])
        run = self.start()
        node = self.nodes(run)["gate"]
        self.assertEqual((node.status, node.note), (Node.WAITING, "Ship it?"))
        with self.assertRaises(engine.Refused):
            engine.decide(node, self.alice, True)  # started it
        engine.decide(node, self.boss, True, "go")
        self.assertEqual(self.status(run)["ship"], "running")
        self.assertEqual(self.nodes(run)["gate"].decided_by, self.boss)

    def test_tofu_waits_for_new_machines(self):
        project = TofuProject.objects.create(name="cloud", host_group=self.lab)
        self.step("infra", Step.TOFU, tofu_project=project)
        run = self.start()
        plan = self.nodes(run)["infra"].job
        self.assertEqual((plan.kind, plan.workflow_node_id), (Job.KIND_TOFU_PLAN, self.nodes(run)["infra"].pk))
        self.finish(plan, stats={"tofu": {"add": 1, "change": 0, "destroy": 0, "has_changes": True}},
                    tofu_plan_encrypted="x")
        apply_job = self.nodes(run)["infra"].job
        self.assertEqual(apply_job.kind, Job.KIND_TOFU_APPLY)
        vm = Host.objects.create(name="vm1", tofu_project=project)
        self.finish(apply_job, stats={"tofu": {"hosts": {"created": ["vm1"]}}})
        self.assertEqual(self.status(run)["infra"], "settling")
        vm.bootstrapped_at = timezone.now()
        vm.save()
        engine.on_job_finished(Job.objects.create(playbook_name="x", playbook_yaml=""))
        self.assertEqual(self.status(run)["infra"], "successful")

    def test_tofu_outputs_reach_the_steps_after_it(self):
        project = TofuProject.objects.create(name="cloud", host_group=self.lab)
        infra = self.step("infra", Step.TOFU, tofu_project=project)
        self.step("configure", after=[(infra, Edge.SUCCESS)], extra_vars={"region": "eu"})
        self.step("tell", Step.MESSAGE, after=[(infra, Edge.SUCCESS)], message="LB at {tofu[lb]}")
        run = self.start()
        plan = self.nodes(run)["infra"].job
        self.finish(plan, stats={"tofu": {"add": 1, "change": 0, "destroy": 0, "has_changes": True}},
                    tofu_plan_encrypted="x")
        apply_job = self.nodes(run)["infra"].job
        engine.keep_outputs(apply_job, {
            "lb": {"value": "10.0.0.5", "sensitive": False},
            "ports": {"value": [80, 443], "sensitive": False},
            "db_password": {"value": "Very-secret-1", "sensitive": True},
        })
        node = self.nodes(run)["infra"]
        self.assertNotIn("Very-secret-1", json.dumps(node.outputs) + node.secret_outputs_encrypted)
        with patch("notifications.dispatch.emit") as emit:
            self.finish(apply_job)
        job = self.nodes(run)["configure"].job
        self.assertEqual(job.extra_vars, {"tofu_outputs": {"lb": "10.0.0.5", "ports": [80, 443]}, "region": "eu"})
        self.assertEqual(job.secret_vars, {"tofu_secret_outputs": {"db_password": "Very-secret-1"}})
        self.assertEqual(emit.call_args.args[2], "LB at 10.0.0.5")
        # Gone from the workflow once the run is over.
        self.finish(job)
        run.refresh_from_db()
        self.assertEqual(run.status, Run.SUCCESSFUL)
        self.assertEqual(self.nodes(run)["infra"].secret_outputs_encrypted, "")

    def test_tofu_outputs_reach_the_steps_after_a_plan_with_nothing_to_change(self):
        from infra import runner

        project = TofuProject.objects.create(name="cloud", host_group=self.lab)
        infra = self.step("infra", Step.TOFU, tofu_project=project)
        self.step("configure", after=[(infra, Edge.SUCCESS)])
        run = self.start()
        plan = self.nodes(run)["infra"].job
        # What `tofu show -json` says of a plan on an unchanged project.
        runner.planned(plan, {"planned_values": {"outputs": {
            "lb": {"value": "10.0.0.5", "sensitive": False},
            "db_password": {"value": "Very-secret-1", "sensitive": True},
        }}}, b"plan", has_changes=False)
        self.finish(plan, stats=plan.stats)
        self.assertEqual(self.status(run)["infra"], "successful")
        job = self.nodes(run)["configure"].job
        self.assertEqual(job.extra_vars, {"tofu_outputs": {"lb": "10.0.0.5"}})
        self.assertEqual(job.secret_vars, {"tofu_secret_outputs": {"db_password": "Very-secret-1"}})

    def test_cancel(self):
        first = self.step("first")
        self.step("second", after=[(first, Edge.ALWAYS)])
        run = self.start()
        job = self.nodes(run)["first"].job
        engine.cancel(run, self.alice)
        run.refresh_from_db()
        job.refresh_from_db()
        self.assertEqual((run.status, job.canceled), (Run.CANCELED, True))
        self.assertEqual(set(self.status(run).values()), {"canceled"})
        self.finish(job, ok=False)  # a late word changes nothing
        self.assertEqual(set(self.status(run).values()), {"canceled"})

    def test_rights(self):
        self.step("migrate", host_group=self.prod)
        viewer = User.objects.create_user("vic")
        team = Group.objects.create(name="viewers")
        viewer.groups.add(team)
        GroupGrant.objects.create(team=team, host_group=self.lab, role=Role.OPERATOR)
        with self.assertRaises(engine.Refused) as caught:
            engine.start(self.workflow, viewer)
        self.assertIn("Operator on prod (step migrate)", str(caught.exception))
        empty = Workflow.objects.create(name="empty", host_group=self.lab)
        with self.assertRaises(engine.Refused):
            engine.start(empty, self.alice)


class EditorTests(WorkflowTestCase):
    def test_steps_and_cycles(self):
        a = self.step("a")
        b = self.step("b", after=[(a, Edge.SUCCESS)])
        form = StepForm({"name": "a", "kind": "playbook", "playbook": self.playbook.pk,
                         "host_group": self.lab.pk, f"after_{b.pk}": "success"},
                        instance=a, user=self.boss, workflow=self.workflow)
        self.assertFalse(form.is_valid())
        self.assertIn("circle", str(form.errors))
        form = StepForm({"name": "c", "kind": "message"}, user=self.boss, workflow=self.workflow)
        self.assertFalse(form.is_valid())
        self.assertIn("message", form.errors)

    def test_message_takes_only_known_placeholders(self):
        for text in ("{started_by.__class__}", "{started_by[x]}", "{run!r}", "{step:>99}", "{tofu}", "{nope}"):
            form = StepForm({"name": "m", "kind": "message", "message": text}, user=self.boss, workflow=self.workflow)
            self.assertFalse(form.is_valid(), text)
            self.assertIn("message", form.errors)
        form = StepForm({"name": "m", "kind": "message", "message": '{run} {tofu[lb]} {"json": 1}'},
                        user=self.boss, workflow=self.workflow)
        self.assertTrue(form.is_valid(), form.errors)

    def test_message_never_walks_objects(self):
        text = "{started_by.__class__.__init__.__globals__[settings].SECRET_KEY} {tofu[lb].x} {started_by}"
        self.assertEqual(engine.fill(text, {"started_by": "alice"}, {"lb": "1"}),
                         "{started_by.__class__.__init__.__globals__[settings].SECRET_KEY} {tofu[lb].x} alice")
        self.step("tell", Step.MESSAGE, message="{started_by.__class__.__init__.__globals__[settings].SECRET_KEY}")
        with patch("notifications.dispatch.emit") as emit:
            self.start()
        self.assertNotIn(settings.SECRET_KEY, emit.call_args.args[2])

    def test_pages(self):
        self.client.force_login(self.boss)
        response = self.client.post("/workflows/new/", {"name": "release", "host_group": self.lab.pk,
                                                       "extra_vars": "version: 2"})
        workflow = Workflow.objects.get(name="release")
        self.assertRedirects(response, workflow.get_absolute_url(), fetch_redirect_response=False)
        self.client.post(f"/workflows/{workflow.pk}/steps/new/", {
            "name": "deploy", "kind": "playbook", "playbook": self.playbook.pk, "host_group": self.lab.pk})
        first = workflow.steps.get()
        page = self.client.get(f"/workflows/{workflow.pk}/steps/new/")
        self.assertContains(page, f'name="after_{first.pk}"')
        self.client.post(f"/workflows/{workflow.pk}/steps/new/", {
            "name": "notify", "kind": "message", "message": "done", f"after_{first.pk}": "always"})
        self.assertEqual(Edge.objects.get(workflow=workflow).condition, Edge.ALWAYS)
        page = self.client.get(workflow.get_absolute_url())
        self.assertContains(page, "<svg")
        self.assertContains(page, "wf-line always")

        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(f"/workflows/{workflow.pk}/edit/").status_code, 403)
        response = self.client.post(f"/workflows/{workflow.pk}/run/", {"extra_vars": "only_here: 1"})
        run = Run.objects.get(workflow=workflow)
        self.assertRedirects(response, run.get_absolute_url(), fetch_redirect_response=False)
        self.assertEqual(run.extra_vars, {"version": 2, "only_here": 1})
        self.assertEqual(self.nodes(run)["deploy"].job.extra_vars, {"version": 2, "only_here": 1})
        self.assertContains(self.client.get(run.get_absolute_url()), "Running")
        self.assertContains(self.client.get("/workflows/"), "release")

        outsider = User.objects.create_user("eve")
        self.client.force_login(outsider)
        self.assertEqual(self.client.get(workflow.get_absolute_url()).status_code, 404)
        self.assertEqual(self.client.get(run.get_absolute_url()).status_code, 403)


class ApiTests(WorkflowTestCase):
    def test_run_and_decide(self):
        self.step("gate", Step.APPROVAL)
        api = APIClient()
        _, raw = ApiToken.issue(self.alice, "t")
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        self.assertEqual(api.get("/api/v1/workflows/").json()["results"][0]["steps"][0]["kind"], "approval")
        response = api.post(f"/api/v1/workflows/{self.workflow.pk}/run/", {}, format="json")
        self.assertEqual(response.status_code, 201, response.content)
        run = response.json()
        node = run["nodes"][0]
        self.assertEqual(node["status"], "waiting")
        url = f"/api/v1/workflow-runs/{run['id']}/decide/"
        self.assertEqual(api.post(url, {"node": node["id"], "approve": True}, format="json").status_code, 403)
        _, boss_raw = ApiToken.issue(self.boss, "t")
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {boss_raw}")
        done = api.post(url, {"node": node["id"], "approve": True}, format="json").json()
        self.assertEqual(done["status"], "successful")

    def test_a_trigger_starts_a_workflow(self):
        self.step("tell", Step.MESSAGE)
        trigger = Trigger(name="on push", action=Trigger.WORKFLOW, workflow=self.workflow, run_as=self.alice)
        secret = trigger.new_secret()
        trigger.save()
        api = APIClient()
        response = api.post(f"/api/v1/triggers/{trigger.pk}/fire/", {}, format="json",
                            HTTP_X_LOONA_TRIGGER_TOKEN=secret)
        self.assertEqual(response.status_code, 201, response.content)
        run = Run.objects.get()
        self.assertEqual(response.json()["workflow_run"], run.pk)
        trigger.refresh_from_db()
        self.assertEqual(trigger.last_run, run)


class LiveTests(WorkflowTestCase):
    """Real ansible-playbook runs on this machine, steps in order."""

    def test_a_failure_branch_with_real_runs(self):
        local = HostGroup.objects.create(name="local", approval_policy=HostGroup.APPROVAL_NONE)
        Host.objects.create(name="here", variables={"ansible_connection": "local"}).groups.add(local)
        GroupGrant.objects.create(team=self.ops, host_group=local, role=Role.OPERATOR)
        fine = Playbook.objects.create(name="fine", mode=Playbook.MODE_TEXT,
                                       text_content="- hosts: all\n  gather_facts: false\n  tasks:\n"
                                                   "    - ansible.builtin.debug: {msg: ok}\n")
        broken = Playbook.objects.create(name="broken", mode=Playbook.MODE_TEXT,
                                         text_content="- hosts: all\n  gather_facts: false\n  tasks:\n"
                                                     "    - ansible.builtin.fail: {msg: smoke test failed}\n")
        deploy = self.step("deploy", playbook=fine, host_group=local)
        smoke = self.step("smoke test", playbook=broken, host_group=local, after=[(deploy, Edge.SUCCESS)])
        self.step("roll back", playbook=fine, host_group=local, after=[(smoke, Edge.FAILURE)])
        self.step("celebrate", Step.MESSAGE, after=[(smoke, Edge.SUCCESS)])
        run = self.start()
        while self.dispatched:
            job = self.dispatched.pop(0)
            with self.captureOnCommitCallbacks(execute=True):
                executor.run_job(job.pk)
        run.refresh_from_db()
        self.assertEqual(self.status(run), {"deploy": "successful", "smoke test": "failed",
                                            "roll back": "successful", "celebrate": "skipped"})
        self.assertEqual(run.status, Run.SUCCESSFUL)
        smoke_job = self.nodes(run)["smoke test"].job
        self.assertTrue(smoke_job.events.filter(stdout__contains="smoke test failed").exists())


class SecretOutputsLiveTests(TestCase):
    """Sensitive outputs reach a real playbook as a structure, untemplated and masked."""

    def test_structured_secret_vars(self):
        import tempfile

        from runs.models import JobEvent

        host = Host.objects.create(name="localhost", variables={"ansible_connection": "local"})
        job = Job.objects.create(playbook_name="p", playbook_yaml=(
            "- hosts: all\n  gather_facts: false\n  tasks:\n"
            "    - ansible.builtin.debug:\n        msg: 'pw={{ tofu_secret_outputs.db_password }}'\n"
            "    - ansible.builtin.debug:\n        msg: 'raw={{ tofu_secret_outputs.tricky }}'\n"
            "    - ansible.builtin.assert:\n        that: tofu_secret_outputs.nodes | length == 2\n"))
        job.target_hosts.add(host)
        job.secret_vars = {"tofu_secret_outputs": {"db_password": "Very-secret-1", "tricky": "{{ 7 * 7 }}",
                                                   "nodes": ["a", "b"]}}
        job.save()
        with tempfile.TemporaryDirectory() as data, self.settings(LOONA_DATA_DIR=data):
            self.assertEqual(executor.run_job(job.pk), Job.SUCCESSFUL)
        log = "\n".join(JobEvent.objects.filter(job=job).values_list("stdout", flat=True))
        self.assertIn("pw=********", log)
        self.assertNotIn("Very-secret-1", log)
        self.assertIn("raw=********", log)
        self.assertNotIn("raw=49", log)  # not templated
