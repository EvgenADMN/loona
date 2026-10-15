# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Launch templates and their surveys."""
import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase, override_settings
from django.urls import reverse

from access.models import GroupGrant, Role
from core.masking import MASK
from inventory.models import Host, HostGroup
from playbooks.models import Playbook

from . import executor, services, surveys
from .models import Job, LaunchTemplate

QUESTIONS = [
    {"variable": "app_version", "label": "Version", "type": "choice", "choices": ["1.4", "1.5"],
     "default": "1.5", "required": True},
    {"variable": "replicas", "label": "Replicas", "type": "integer", "min": 1, "max": 5, "default": 2},
    {"variable": "services", "label": "Services", "type": "multichoice", "choices": ["web", "worker"]},
    {"variable": "dry", "label": "Dry", "type": "boolean"},
    {"variable": "db_password", "label": "DB password", "type": "password", "required": True,
     "default": "never-kept"},
]


class SpecTests(TestCase):
    def test_a_good_survey_is_normalised(self):
        spec = surveys.clean_spec(QUESTIONS, unrestricted=False)
        self.assertEqual(spec[1]["default"], 2)
        self.assertNotIn("default", spec[4])  # a password default would be a secret in the clear

    def test_mistakes_are_all_listed(self):
        bad = [
            {"variable": "1x", "type": "text"},
            {"variable": "a", "type": "text"}, {"variable": "a", "type": "text"},
            {"variable": "ansible_user", "type": "text"},
            {"variable": "c", "type": "choice", "choices": []},
            {"variable": "d", "type": "integer", "min": 5, "max": 1},
            {"variable": "e", "type": "choice", "choices": ["x"], "default": "y"},
            {"variable": "f", "type": "colour"},
        ]
        with self.assertRaises(forms.ValidationError) as caught:
            surveys.clean_spec(bad, unrestricted=False)
        text = " ".join(caught.exception.messages)
        for words in ("letters, digits", "asked twice", "only a superuser", "list the choices",
                      "min is above max", "default does not fit", "unknown type"):
            self.assertIn(words, text)

    def test_a_superuser_may_ask_for_connection_settings(self):
        surveys.clean_spec([{"variable": "ansible_become_password", "type": "password"}], unrestricted=True)

    def test_answers_are_typed_and_passwords_kept_apart(self):
        spec = surveys.clean_spec(QUESTIONS, unrestricted=False)
        form = surveys.SurveyForm(spec, {"q_app_version": "1.4", "q_replicas": "3", "q_services": ["web"],
                                         "q_dry": "on", "q_db_password": "pa55"})
        self.assertTrue(form.is_valid(), form.errors)
        plain, secret = form.answers()
        self.assertEqual(plain, {"app_version": "1.4", "replicas": 3, "services": ["web"], "dry": True})
        self.assertEqual(secret, {"db_password": "pa55"})

    def test_answers_are_checked(self):
        spec = surveys.clean_spec(QUESTIONS, unrestricted=False)
        form = surveys.SurveyForm(spec, {"q_app_version": "9.9", "q_replicas": "7"})
        self.assertFalse(form.is_valid())
        self.assertEqual(set(form.errors), {"q_app_version", "q_replicas", "q_db_password"})


class Base(TestCase):
    def setUp(self):
        User = get_user_model()
        self.group = HostGroup.objects.create(name="web", approval_policy=HostGroup.APPROVAL_NONE)
        self.host = Host.objects.create(name="localhost", variables={"ansible_connection": "local"})
        self.host.groups.add(self.group)
        self.playbook = Playbook.objects.create(name="Deploy", mode=Playbook.MODE_TEXT,
                                                text_content="- hosts: all\n  gather_facts: false\n  tasks: []\n")
        self.template = LaunchTemplate.objects.create(
            name="Deploy web", playbook=self.playbook, host_group=self.group,
            extra_vars={"app_version": "1.0", "env": "prod"}, limit="localhost",
            survey=surveys.clean_spec(QUESTIONS, unrestricted=False),
        )
        team = Group.objects.create(name="ops")
        GroupGrant.objects.create(team=team, host_group=self.group, role=Role.OPERATOR)
        self.op = User.objects.create_user("op", password="pw")
        self.op.groups.add(team)
        self.answers = {"q_app_version": "1.4", "q_replicas": "3", "q_db_password": "pa55-word"}


@patch("runs.services.dispatch")
class LaunchPageTests(Base):
    def test_a_launch_merges_answers_over_fixed_vars_and_keeps_the_password_out(self, dispatch):
        self.client.force_login(self.op)
        response = self.client.post(reverse("template_launch", args=[self.template.pk]),
                                    {**self.answers, "action": "plan"})
        job = Job.objects.get()
        self.assertRedirects(response, job.get_absolute_url(), fetch_redirect_response=False)
        self.assertTrue(job.is_plan)
        self.assertEqual(job.extra_vars, {"app_version": "1.4", "env": "prod", "replicas": 3, "dry": False})
        self.assertEqual(job.secret_vars, {"db_password": "pa55-word"})
        self.assertNotIn("pa55-word", job.secret_vars_encrypted + json.dumps(job.extra_vars))
        self.assertEqual((job.launch_template, job.playbook_name, job.limit), (self.template, "Deploy web", "localhost"))

    def test_the_limit_is_the_templates_unless_it_asks(self, dispatch):
        self.client.force_login(self.op)
        self.client.post(reverse("template_launch", args=[self.template.pk]), {**self.answers, "limit": "other"})
        self.assertEqual(Job.objects.get().limit, "localhost")
        self.template.ask_limit = True
        self.template.save()
        self.client.post(reverse("template_launch", args=[self.template.pk]), {**self.answers, "limit": "other"})
        self.assertEqual(Job.objects.latest("pk").limit, "other")

    def test_a_viewer_sees_but_cannot_launch(self, dispatch):
        viewer = get_user_model().objects.create_user("v", password="pw")
        team = Group.objects.create(name="viewers")
        GroupGrant.objects.create(team=team, host_group=self.group, role=Role.VIEWER)
        viewer.groups.add(team)
        self.client.force_login(viewer)
        self.assertContains(self.client.get(reverse("template_launch", args=[self.template.pk])), "not run it")
        self.assertEqual(self.client.post(reverse("template_launch", args=[self.template.pk]), self.answers).status_code, 403)
        self.assertFalse(Job.objects.exists())

    def test_missing_answers_are_asked_again(self, dispatch):
        self.client.force_login(self.op)
        response = self.client.post(reverse("template_launch", args=[self.template.pk]), {"q_app_version": "1.4"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Job.objects.exists())

    def test_the_editor_saves_a_survey_and_refuses_a_bad_one(self, dispatch):
        self.op.user_permissions.add(Permission.objects.get(codename="change_playbook"))
        self.client.force_login(self.op)
        data = {"name": "T2", "description": "", "playbook": self.playbook.pk, "host_group": self.group.pk,
                "limit": "", "tags": "", "skip_tags": "", "extra_vars": "",
                "survey": json.dumps([{"variable": "v", "label": "V", "type": "text"}])}
        self.assertEqual(self.client.post(reverse("template_create"), data).status_code, 302)
        self.assertEqual(LaunchTemplate.objects.get(name="T2").survey[0]["variable"], "v")
        data["name"] = "T3"
        data["survey"] = json.dumps([{"variable": "ansible_host", "type": "text"}])
        self.assertContains(self.client.post(reverse("template_create"), data), "only a superuser")
        for url in (reverse("template_list"), reverse("template_create"),
                    reverse("template_update", args=[self.template.pk])):
            self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_editing_needs_the_playbook_permission(self, dispatch):
        self.client.force_login(self.op)
        self.assertEqual(self.client.get(reverse("template_create")).status_code, 403)

    def test_api_launch(self, dispatch):
        from api.models import ApiToken

        token = ApiToken.issue(self.op, "t")[1]
        url = reverse("api-template-launch", args=[self.template.pk])
        auth = {"HTTP_AUTHORIZATION": f"Bearer {token}", "content_type": "application/json"}
        bad = self.client.post(url, {"answers": {"app_version": "9"}}, **auth)
        self.assertEqual(bad.status_code, 400)
        self.assertIn("app_version", bad.json())
        unknown = self.client.post(url, {"answers": {"app_version": "1.4", "db_password": "x" * 5, "nope": 1}}, **auth)
        self.assertEqual(unknown.status_code, 400)
        ok = self.client.post(url, {"answers": {"app_version": "1.4", "db_password": "pa55-word"}}, **auth)
        self.assertEqual(ok.status_code, 201, ok.content)
        self.assertEqual(ok.json()["launch_template"], self.template.pk)
        listed = self.client.get(reverse("api-template-list"), HTTP_AUTHORIZATION=f"Bearer {token}")
        self.assertIn("db_password", listed.content.decode())
        self.assertNotIn("pa55-word", listed.content.decode())


@override_settings()
class RealRunTests(Base):
    def setUp(self):
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        override = override_settings(LOONA_DATA_DIR=str(self.tmp / "jobs"))
        override.enable()
        self.addCleanup(override.disable)
        self.out = self.tmp / "out"
        self.playbook.text_content = (
            "- hosts: all\n  gather_facts: false\n  tasks:\n"
            f"    - copy: {{content: '{{{{ db_password }}}} {{{{ app_version }}}}', dest: '{self.out}'}}\n"
            "    - debug: {var: db_password}\n"
        )
        self.playbook.save()

    def launch(self, preview, password="{{ pa55 }}-word"):
        form = surveys.SurveyForm(self.template.survey, {**self.answers, "q_db_password": password})
        self.assertTrue(form.is_valid(), form.errors)
        with patch("runs.services.dispatch"):
            return services.launch_template(self.template, self.op, form, "", preview=preview)

    def log(self, job):
        return "\n".join(e.stdout for e in job.events.all())

    def test_run_now_gets_the_password_masks_it_and_forgets_it(self):
        job = self.launch(preview=False)
        self.assertEqual(executor.run_job(job.pk), Job.SUCCESSFUL, self.log(job))
        job.refresh_from_db()
        self.assertEqual(self.out.read_text(), "{{ pa55 }}-word 1.4")
        self.assertNotIn("pa55", self.log(job))
        self.assertIn(MASK, self.log(job))
        self.assertEqual(job.secret_vars_encrypted, "")

    def test_a_preview_hands_the_password_to_its_apply(self):
        self.out.write_text("before")
        plan = self.launch(preview=True)
        self.assertEqual(executor.run_job(plan.pk), Job.SUCCESSFUL, self.log(plan))
        plan.refresh_from_db()
        self.assertTrue(plan.can_be_applied)
        self.assertNotEqual(plan.secret_vars_encrypted, "")
        with patch("runs.services.dispatch"):
            job = services.apply(plan, self.op)
        plan.refresh_from_db()
        self.assertEqual(plan.secret_vars_encrypted, "")
        self.assertEqual(executor.run_job(job.pk), Job.SUCCESSFUL, self.log(job))
        job.refresh_from_db()
        self.assertEqual(self.out.read_text(), "{{ pa55 }}-word 1.4")
        self.assertEqual(job.secret_vars_encrypted, "")
