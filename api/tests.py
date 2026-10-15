# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The API allows exactly what the UI allows."""
import hashlib
import hmac
import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from access.models import GroupGrant, Role
from infra.models import TofuProject
from inventory.models import Credential, Host, HostGroup
from playbooks.models import Playbook
from runs.models import Job

from .models import ApiToken, Trigger, hash_token

User = get_user_model()


class ApiTestCase(TestCase):
    def setUp(self):
        self.lab = HostGroup.objects.create(name="lab", approval_policy=HostGroup.APPROVAL_NONE)
        self.prod = HostGroup.objects.create(name="prod")
        self.web1 = Host.objects.create(name="web1")
        self.web1.groups.add(self.lab)
        self.db1 = Host.objects.create(name="db1")
        self.db1.groups.add(self.prod)
        self.team = Group.objects.create(name="devs")
        self.user = User.objects.create_user("dev", password="Dev-pass-123")
        self.user.groups.add(self.team)
        self.playbook = Playbook.objects.create(name="ping")
        self.api = APIClient()

    def role(self, group, role):
        GroupGrant.objects.update_or_create(team=self.team, host_group=group, defaults={"role": role})

    def login(self, user=None):
        token, raw = ApiToken.issue(user or self.user, "test")
        self.api.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        return token, raw


class TokenTests(ApiTestCase):
    def test_a_token_acts_as_its_owner_and_only_its_hash_is_kept(self):
        token, raw = self.login()
        self.assertEqual(self.api.get("/api/v1/me/").json()["username"], "dev")
        self.assertEqual(token.token_hash, hash_token(raw))
        self.assertNotIn(raw, str(ApiToken.objects.values_list()))
        token.refresh_from_db()
        self.assertIsNotNone(token.last_used_at)

    def test_revoked_expired_and_locked_out_tokens_stop_working(self):
        token, _ = self.login()
        token.revoked_at = timezone.now()
        token.save()
        self.assertEqual(self.api.get("/api/v1/me/").status_code, 401)
        token, _ = self.login()
        token.expires_at = timezone.now() - timedelta(minutes=1)
        token.save()
        self.assertEqual(self.api.get("/api/v1/me/").status_code, 401)
        self.login()
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(self.api.get("/api/v1/me/").status_code, 401)

    def test_nothing_without_a_token(self):
        self.assertIn(self.api.get("/api/v1/hosts/").status_code, (401, 403))

    def test_the_documentation_is_not_for_strangers(self):
        self.assertIn(self.api.get("/api/schema/").status_code, (401, 403))
        page = self.client.get("/api/docs/")
        self.assertEqual(page.status_code, 302)
        self.assertIn(reverse("login"), page["Location"])

    def test_the_documentation_is_served_locally(self):
        self.login()
        self.assertEqual(self.api.get("/api/schema/").status_code, 200)
        self.client.force_login(self.user)
        page = self.client.get("/api/docs/")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn("cdn.jsdelivr", page.content.decode())


class InventoryTests(ApiTestCase):
    def test_hosts_follow_roles(self):
        self.role(self.lab, Role.VIEWER)
        self.login()
        names = [h["name"] for h in self.api.get("/api/v1/hosts/").json()["results"]]
        self.assertEqual(names, ["web1"])
        self.assertEqual(self.api.get(f"/api/v1/hosts/{self.db1.pk}/").status_code, 404)

    def test_create_and_patch_with_the_forms_rules(self):
        self.role(self.lab, Role.ADMIN)
        self.login()
        refused = self.api.post("/api/v1/hosts/", {"name": "new1", "groups": ["prod"]}, format="json")
        self.assertEqual(refused.status_code, 400)
        made = self.api.post("/api/v1/hosts/", {"name": "new1", "address": "10.0.0.9", "groups": ["lab"],
                                                "variables": {"role": "web"}}, format="json")
        self.assertEqual(made.status_code, 201, made.json())
        host = Host.objects.get(name="new1")
        patched = self.api.patch(f"/api/v1/hosts/{host.pk}/", {"description": "edited"}, format="json")
        self.assertEqual(patched.status_code, 200, patched.json())
        host.refresh_from_db()
        self.assertEqual((host.address, host.description, host.variables),
                         ("10.0.0.9", "edited", {"role": "web"}))
        self.assertEqual(list(host.groups.values_list("name", flat=True)), ["lab"])

    def test_a_credential_not_shared_with_the_team_is_refused(self):
        self.role(self.lab, Role.ADMIN)
        Credential.objects.create(name="root-pw", kind=Credential.KIND_PASSWORD)
        self.login()
        response = self.api.patch(f"/api/v1/hosts/{self.web1.pk}/", {"credential": "root-pw"}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_a_viewer_cannot_delete(self):
        self.role(self.lab, Role.VIEWER)
        self.login()
        self.assertEqual(self.api.delete(f"/api/v1/hosts/{self.web1.pk}/").status_code, 403)


@patch("runs.services.dispatch")
class LaunchTests(ApiTestCase):
    def test_a_preview_by_default(self, dispatch):
        self.role(self.lab, Role.OPERATOR)
        self.login()
        response = self.api.post(f"/api/v1/playbooks/{self.playbook.pk}/launch/", {"groups": ["lab"]}, format="json")
        self.assertEqual(response.status_code, 201, response.json())
        job = Job.objects.get()
        self.assertTrue(job.check_mode and job.is_plan)
        self.assertEqual(job.created_by, self.user)

    def test_the_uis_rules_hold(self, dispatch):
        self.role(self.lab, Role.OPERATOR)
        self.login()
        url = f"/api/v1/playbooks/{self.playbook.pk}/launch/"
        self.assertEqual(self.api.post(url, {"groups": ["prod"]}, format="json").status_code, 400)
        self.assertEqual(self.api.post(url, {"groups": ["lab"], "extra_vars": {"ansible_host": "6.6.6.6"}},
                                       format="json").status_code, 400)
        HostGroup.objects.filter(pk=self.lab.pk).update(approval_policy=HostGroup.APPROVAL_CHANGES)
        refused = self.api.post(url, {"groups": ["lab"], "preview": False}, format="json")
        self.assertEqual(refused.status_code, 409)
        self.assertIn("preview", refused.json()["detail"])
        dispatch.assert_not_called()


class JobTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        HostGroup.objects.filter(pk=self.lab.pk).update(approval_policy=HostGroup.APPROVAL_DESTROY)
        self.project = TofuProject.objects.create(name="lab", host_group=self.lab)
        self.plan = Job.objects.create(
            kind=Job.KIND_TOFU_PLAN, tofu_project=self.project, playbook_name="lab: plan",
            status=Job.SUCCESSFUL, created_by=self.user,
            stats={"tofu": {"has_changes": True, "add": 0, "change": 0, "destroy": 1}},
        )
        self.plan.target_groups.set([self.lab])

    def test_jobs_and_their_log_follow_roles(self):
        other = Job.objects.create(playbook_name="elsewhere", status=Job.SUCCESSFUL)
        other.target_hosts.add(self.db1)
        self.role(self.lab, Role.VIEWER)
        self.login()
        ids = [j["id"] for j in self.api.get("/api/v1/jobs/").json()["results"]]
        self.assertEqual(ids, [self.plan.pk])
        self.assertEqual(self.api.get(f"/api/v1/jobs/{self.plan.pk}/").json()["opentofu"]["destroy"], 1)
        self.assertEqual(self.api.get(f"/api/v1/jobs/{other.pk}/events/").status_code, 404)

    @patch("runs.services.dispatch")
    def test_approval_through_the_api_follows_the_two_person_rule(self, dispatch):
        self.role(self.lab, Role.ADMIN)
        self.login()
        self.assertEqual(self.api.post(f"/api/v1/jobs/{self.plan.pk}/apply/").status_code, 409)
        self.assertEqual(self.api.post(f"/api/v1/jobs/{self.plan.pk}/approve/").status_code, 409)
        colleague = User.objects.create_user("colleague")
        colleague.groups.add(self.team)
        self.login(colleague)
        response = self.api.post(f"/api/v1/jobs/{self.plan.pk}/approve/", {"comment": "ok"}, format="json")
        self.assertEqual(response.status_code, 201, response.json())
        self.assertEqual(response.json()["plan"], self.plan.pk)

    @patch("runs.executor.dispatch")
    def test_a_destroy_plan_needs_an_admin(self, dispatch):
        self.role(self.lab, Role.OPERATOR)
        self.login()
        url = f"/api/v1/opentofu/{self.project.pk}/plan/"
        self.assertEqual(self.api.post(url, {"destroy": True}, format="json").status_code, 403)
        self.assertEqual(self.api.post(url, {}, format="json").status_code, 201)


@patch("runs.executor.dispatch")
class TriggerTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.role(self.lab, Role.OPERATOR)
        self.project = TofuProject.objects.create(name="lab", host_group=self.lab)
        self.trigger = Trigger(name="on push", action=Trigger.PLAN, tofu_project=self.project,
                               branch="main", run_as=self.user)
        self.secret = self.trigger.new_secret()
        self.trigger.save()
        self.url = f"/api/v1/triggers/{self.trigger.pk}/fire/"

    def fire(self, body=None, **headers):
        return self.api.post(self.url, data=json.dumps(body or {}), content_type="application/json", **headers)

    def test_the_secret_starts_a_plan_as_the_owner(self, dispatch):
        response = self.fire(HTTP_X_LOONA_TRIGGER_TOKEN=self.secret)
        self.assertEqual(response.status_code, 201, response.json())
        job = Job.objects.get(pk=response.json()["job"])
        self.assertEqual((job.kind, job.created_by), (Job.KIND_TOFU_PLAN, self.user))

    def test_a_wrong_or_missing_secret_is_refused(self, dispatch):
        self.assertEqual(self.fire(HTTP_X_LOONA_TRIGGER_TOKEN="guess").status_code, 403)
        self.assertEqual(self.fire().status_code, 403)
        dispatch.assert_not_called()

    def test_github_signature_and_the_branch_filter(self, dispatch):
        def github(body):
            raw = json.dumps(body).encode()
            signature = "sha256=" + hmac.new(self.secret.encode(), raw, hashlib.sha256).hexdigest()
            return self.api.post(self.url, data=raw, content_type="application/json",
                                 HTTP_X_HUB_SIGNATURE_256=signature)

        skipped = github({"ref": "refs/heads/feature"})
        self.assertEqual(skipped.status_code, 202)
        self.assertIn("skipped", skipped.json())
        self.assertEqual(github({"ref": "refs/heads/main"}).status_code, 201)
        # Tampered with after signing:
        raw = json.dumps({"ref": "refs/heads/main"}).encode()
        signature = "sha256=" + hmac.new(self.secret.encode(), raw, hashlib.sha256).hexdigest()
        bad = self.api.post(self.url, data=raw + b" ", content_type="application/json",
                            HTTP_X_HUB_SIGNATURE_256=signature)
        self.assertEqual(bad.status_code, 403)

    def test_a_signed_delivery_fires_once(self, dispatch):
        raw = json.dumps({"ref": "refs/heads/main", "after": "abc"}).encode()
        signature = "sha256=" + hmac.new(self.secret.encode(), raw, hashlib.sha256).hexdigest()

        def send(delivery):
            return self.api.post(self.url, data=raw, content_type="application/json",
                                 HTTP_X_HUB_SIGNATURE_256=signature, HTTP_X_GITHUB_DELIVERY=delivery)

        self.assertEqual(send("d-1").status_code, 201)
        Job.objects.update(status=Job.SUCCESSFUL)  # the first run is over
        # The same signed body again, under any delivery id: refused.
        self.assertEqual(send("d-2").status_code, 409)
        self.assertEqual(dispatch.call_count, 1)

    def test_gitlab_token_header(self, dispatch):
        response = self.fire({"ref": "refs/heads/main"}, HTTP_X_GITLAB_TOKEN=self.secret)
        self.assertEqual(response.status_code, 201)

    def test_it_stops_when_its_owner_loses_the_right(self, dispatch):
        GroupGrant.objects.filter(team=self.team).update(role=Role.VIEWER)
        self.assertEqual(self.fire(HTTP_X_LOONA_TRIGGER_TOKEN=self.secret).status_code, 403)

    def test_runs_do_not_pile_up(self, dispatch):
        first = self.fire(HTTP_X_LOONA_TRIGGER_TOKEN=self.secret)
        second = self.fire(HTTP_X_LOONA_TRIGGER_TOKEN=self.secret)
        self.assertEqual((first.status_code, second.status_code), (201, 202))
        self.assertEqual(Job.objects.count(), 1)


class PageTests(ApiTestCase):
    def test_a_token_is_shown_once(self):
        self.client.force_login(self.user)
        page = self.client.post("/account/tokens/", {"name": "ci", "lifetime": 30})
        raw = page.context["fresh"]
        self.assertTrue(raw.startswith("loona_"))
        self.assertContains(page, raw)
        self.assertNotContains(self.client.get("/account/tokens/"), raw)

    def test_a_trigger_is_made_as_its_creator(self):
        self.role(self.lab, Role.OPERATOR)
        project = TofuProject.objects.create(name="lab", host_group=self.lab)
        self.client.force_login(self.user)
        page = self.client.post("/account/triggers/", {"name": "t", "action": "plan", "tofu_project": project.pk,
                                                       "branch": "main"})
        trigger = Trigger.objects.get()
        self.assertEqual(trigger.run_as, self.user)
        self.assertContains(page, page.context["fresh"]["secret"])
