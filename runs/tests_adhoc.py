# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Ad-hoc commands: who may type what, and that it runs like any other run."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from rest_framework.test import APIClient

from access.models import Approval, GroupGrant, Role
from administration import system
from administration.forms import GeneralForm
from api.models import ApiToken
from inventory.models import Host, HostGroup

from . import adhoc, plans, services
from .executor import _record_event, run_job
from .models import Job

User = get_user_model()


class ArgumentTests(TestCase):
    def test_free_form_and_key_value(self):
        self.assertEqual(adhoc.parse_args("shell", " df -h / "), "df -h /")
        self.assertEqual(adhoc.parse_args("ansible.builtin.service", 'name=nginx state="re started"'),
                         {"name": "nginx", "state": "re started"})
        self.assertEqual(adhoc.parse_args("file", "{path: /tmp/x, state: absent}"),
                         {"path": "/tmp/x", "state": "absent"})
        self.assertEqual(adhoc.parse_args("ping", ""), {})
        self.assertEqual(adhoc.parse_args("debug", "msg={{ a | default('x y') }} verbosity=1"),
                         {"msg": "{{ a | default('x y') }}", "verbosity": "1"})
        for module, text in (("shell", ""), ("service", "nginx"), ("file", "{bad"), ("file", "{}x: [")):
            with self.assertRaises(ValueError, msg=text):
                adhoc.parse_args(module, text)

    def test_only_superusers_get_templating(self):
        literal = adhoc.playbook("shell", "echo {{ lookup('pipe', 'id') }}", become=True, templated=False)
        self.assertIn("ansible.builtin.shell: !unsafe", literal)
        self.assertIn("name: !unsafe", literal)
        self.assertIn("become: true", literal)
        kv = adhoc.playbook("service", "name={{ x }} state=started", become=False, templated=False)
        self.assertIn("name: !unsafe '{{ x }}'", kv)
        self.assertNotIn("!unsafe", adhoc.playbook("shell", "echo {{ x }}", become=False, templated=True))

    def test_output_reads_like_ansible(self):
        text = adhoc.output("runner_on_ok", "web1", {"changed": True, "rc": 0, "stdout": "hello\n", "stderr": ""})
        self.assertEqual(text, "web1 | CHANGED | rc=0 >>\nhello")
        text = adhoc.output("runner_on_failed", "web1", {"rc": 2, "stdout": "", "stderr": "no such file"})
        self.assertEqual(text, "web1 | FAILED | rc=2 >>\nno such file")
        text = adhoc.output("runner_on_ok", "web1", {"changed": False, "ping": "pong", "invocation": {}})
        self.assertEqual(text, 'web1 | SUCCESS => {\n  "changed": false,\n  "ping": "pong"\n}')
        self.assertIn("UNREACHABLE", adhoc.output("runner_on_unreachable", "web1", {"msg": "timed out"}))
        self.assertIsNone(adhoc.output("runner_on_skipped", "web1", {}))


class ModuleRuleTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("dev")
        self.root = User.objects.create_superuser("root")

    def test_the_allowed_list_and_controller_modules(self):
        self.assertIsNone(adhoc.why_not_module("shell", self.user))
        self.assertIsNone(adhoc.why_not_module("ansible.builtin.shell", self.user))
        self.assertIn("not among", adhoc.why_not_module("community.general.nmcli", self.user))
        self.assertIn("not among", adhoc.why_not_module("copy", self.root))
        self.assertIn("Not a module", adhoc.why_not_module("shell; rm", self.user))
        row = system.get()
        row.adhoc_modules += "\ncopy"
        row.save()
        system.invalidate()
        self.assertIn("superuser", adhoc.why_not_module("copy", self.user))
        self.assertIsNone(adhoc.why_not_module("copy", self.root))

    def test_settings_form_checks_names(self):
        data = {"language": "en", "session_hours": 12, "local_login": "all", "mfa_policy": "optional", "default_approval_policy": "destroy",
                "job_retention_days": 0, "max_job_events": 5000, "bootstrap_wait_seconds": 300,
                "adhoc_modules": "shell\nshell\nping"}
        form = GeneralForm(data, instance=system.get())
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["adhoc_modules"], "shell\nping")
        form = GeneralForm({**data, "adhoc_modules": "shell\nrm -rf"}, instance=system.get())
        self.assertFalse(form.is_valid())


class AdhocTestCase(TestCase):
    def setUp(self):
        self.lab = HostGroup.objects.create(name="lab", approval_policy=HostGroup.APPROVAL_NONE)
        self.prod = HostGroup.objects.create(name="prod", approval_policy=HostGroup.APPROVAL_CHANGES)
        self.web = Host.objects.create(name="web1")
        self.web.groups.add(self.lab)
        self.db = Host.objects.create(name="db1")
        self.db.groups.add(self.prod)
        self.team = Group.objects.create(name="devs")
        self.user = User.objects.create_user("dev", password="Dev-pass-123")
        self.user.groups.add(self.team)
        self.grant = GroupGrant.objects.create(team=self.team, host_group=self.lab, role=Role.OPERATOR)
        self.client.force_login(self.user)

    def post(self, action="run", **fields):
        data = {"target_hosts": [self.web.pk], "adhoc_module": "shell", "adhoc_args": "uptime",
                "forks": 5, "verbosity": 0, "action": action, **fields}
        return self.client.post("/runs/command/", data)


@patch("runs.services.dispatch")
class ViewTests(AdhocTestCase):
    def test_an_operator_may_not_type_commands(self, dispatch):
        self.assertEqual(self.client.get("/runs/command/").status_code, 403)
        self.assertEqual(self.post().status_code, 403)
        self.assertFalse(Job.objects.exists())

    def test_an_admin_runs_one_on_their_hosts_only(self, dispatch):
        self.grant.role = Role.ADMIN
        self.grant.save()
        page = self.client.get(f"/runs/command/?host={self.web.pk}")
        self.assertContains(page, '<option value="shell">')
        self.assertNotContains(page, "db1")
        self.assertEqual(self.post(target_hosts=[self.db.pk]).status_code, 200)
        self.assertFalse(Job.objects.exists())
        response = self.post(adhoc_become="on")
        job = Job.objects.get()
        self.assertRedirects(response, job.get_absolute_url(), fetch_redirect_response=False)
        self.assertEqual((job.kind, job.playbook_name, job.check_mode), (Job.KIND_ADHOC, "shell: uptime", False))
        self.assertIn("become: true", job.playbook_yaml)
        dispatch.assert_called_once()
        job.status = Job.SUCCESSFUL
        job.save()
        page = self.client.get(job.get_absolute_url())
        self.assertContains(page, "Run again")
        self.assertContains(self.client.get(f"/runs/command/?relaunch={job.pk}"), "uptime")
        # And it is in the host's history.
        self.assertContains(self.client.get(f"/inventory/hosts/{self.web.pk}/"), "shell: uptime")

    def test_bad_input_is_explained(self, dispatch):
        self.grant.role = Role.ADMIN
        self.grant.save()
        self.assertContains(self.post(adhoc_module="copy", adhoc_args="src=/etc/passwd dest=/tmp"), "not among")
        self.assertContains(self.post(adhoc_module="service", adhoc_args="nginx"), "key=value")
        self.assertContains(self.post(limit="web1,@/etc/passwd"), "@file")
        self.assertFalse(Job.objects.exists())

    def test_the_approval_rules_hold(self, dispatch):
        GroupGrant.objects.create(team=self.team, host_group=self.prod, role=Role.ADMIN)
        self.grant.role = Role.ADMIN
        self.grant.save()
        self.assertContains(self.post(target_hosts=[self.db.pk]), "second person")
        self.assertFalse(Job.objects.exists())
        self.post(action="plan", target_hosts=[self.db.pk])
        plan = Job.objects.get()
        self.assertTrue(plan.check_mode and plan.is_plan)
        plan.status = Job.SUCCESSFUL
        plan.resolved_hosts = ["db1"]
        plan.save()
        with self.assertRaises(plans.CannotApply):
            services.apply(plan, self.user)
        # Another admin of prod approves - and the command applies as typed.
        other = User.objects.create_user("ops")
        other.groups.add(self.team)
        approval, job = services.decide(plan, other, approve=True)
        self.assertEqual(approval.decision, Approval.APPROVED)
        self.assertEqual((job.kind, job.adhoc_args, job.check_mode), (Job.KIND_ADHOC, "uptime", False))
        self.assertEqual(job.playbook_yaml, plan.playbook_yaml)

    def test_applying_a_preview_takes_an_admin(self, dispatch):
        self.grant.role = Role.ADMIN
        self.grant.save()
        self.post(action="plan")
        plan = Job.objects.get()
        plan.status = Job.SUCCESSFUL
        plan.save()
        operator = User.objects.create_user("op")
        operators = Group.objects.create(name="ops")
        operator.groups.add(operators)
        GroupGrant.objects.create(team=operators, host_group=self.lab, role=Role.OPERATOR)
        from django.core.exceptions import PermissionDenied

        with self.assertRaises(PermissionDenied):
            services.apply(plan, operator)
        self.assertEqual(services.apply(plan, self.user).kind, Job.KIND_ADHOC)


class ApiTests(AdhocTestCase):
    def setUp(self):
        super().setUp()
        self.api = APIClient()
        _, raw = ApiToken.issue(self.user, "t")
        self.api.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")

    @patch("runs.services.dispatch")
    def test_adhoc_over_the_api(self, dispatch):
        body = {"module": "service", "args": "name=nginx state=restarted", "hosts": ["web1"], "become": True}
        self.assertEqual(self.api.post("/api/v1/adhoc/", body, format="json").status_code, 403)
        self.grant.role = Role.ADMIN
        self.grant.save()
        response = self.api.post("/api/v1/adhoc/", body, format="json")
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()["adhoc_module"], "service")
        self.assertEqual(self.api.post("/api/v1/adhoc/", {**body, "hosts": ["db1"]}, format="json").status_code, 400)
        self.assertEqual(self.api.post("/api/v1/adhoc/", {**body, "args": "nginx"}, format="json").status_code, 400)


class OutputTests(TestCase):
    def test_the_log_shows_what_the_command_printed(self):
        job = Job.objects.create(kind=Job.KIND_ADHOC, playbook_name="shell: id", playbook_yaml="-")
        event = {"event": "runner_on_ok", "counter": 1, "stdout": "changed: [web1]",
                 "event_data": {"host": "web1", "task": "shell: id",
                                "res": {"changed": True, "rc": 0, "stdout": "pw=s3cret-value", "stderr": ""}}}
        from core.masking import Masker

        _record_event(job.pk, event, {"stored": 0, "adhoc": True, "mask": Masker(["s3cret-value"])})
        self.assertEqual(job.events.get().stdout, "web1 | CHANGED | rc=0 >>\npw=********")


class LiveTests(TestCase):
    """Real ansible-playbook runs on this machine."""

    def setUp(self):
        self.group = HostGroup.objects.create(name="here", approval_policy=HostGroup.APPROVAL_NONE)
        self.host = Host.objects.create(name="here1", variables={"ansible_connection": "local"})
        self.host.groups.add(self.group)

    def run_as(self, user, args):
        form = adhoc.AdhocForm({"target_hosts": [self.host.pk], "adhoc_module": "shell", "adhoc_args": args,
                                "forks": 1, "verbosity": 0}, user=user)
        self.assertTrue(form.is_valid(), form.errors)
        with patch("runs.services.dispatch"):
            job = services.launch_adhoc(form, user, preview=False)
        self.assertEqual(run_job(job.pk), Job.SUCCESSFUL)
        return "\n".join(job.events.values_list("stdout", flat=True))

    def test_templating_only_for_superusers(self):
        admin = User.objects.create_user("admin1")
        team = Group.objects.create(name="t")
        admin.groups.add(team)
        GroupGrant.objects.create(team=team, host_group=self.group, role=Role.ADMIN)
        log = self.run_as(admin, "echo 'got-{{ 6 * 7 }}'")
        self.assertIn("here1 | CHANGED | rc=0 >>\ngot-{{ 6 * 7 }}", log)
        log = self.run_as(User.objects.create_superuser("root"), "echo 'got-{{ 6 * 7 }}'")
        self.assertIn("got-42", log)
