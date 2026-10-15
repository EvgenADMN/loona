# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""HashiCorp Vault references: the client, who may refer to what, and runs."""
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse

from access.models import GroupGrant, Role
from administration import system
from administration.models import SystemSettings
from core.masking import MASK
from inventory.models import Host, HostGroup
from runs import executor
from runs.models import Job

from . import hashicorp, resolve
from .models import Secret

TOKEN = "s.loona-test-token"


class FakeVault:
    """Just enough of Vault's HTTP API: KV v1 and v2, AppRole, lookup-self."""

    def __init__(self):
        self.kv = {
            "secret/data/app": {"data": {"password": "kv2-pa55", "port": 5432}, "metadata": {"version": 3}},
            "kv1/app": {"password": "kv1-pa55"},
        }
        self.requests = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _answer(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                fake.requests.append(("GET", self.path, dict(self.headers)))
                if self.headers.get("X-Vault-Token") != TOKEN:
                    return self._answer(403, {"errors": ["permission denied"]})
                path = self.path.removeprefix("/v1/")
                if path == "auth/token/lookup-self":
                    return self._answer(200, {"data": {"policies": ["loona-read"], "ttl": 3600}})
                if path in fake.kv:
                    return self._answer(200, {"data": fake.kv[path]})
                return self._answer(404, {"errors": []})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.requests.append(("POST", self.path, body))
                if self.path == "/v1/auth/approle/login" and body == {"role_id": "r", "secret_id": "s"}:
                    return self._answer(200, {"auth": {"client_token": TOKEN}})
                return self._answer(400, {"errors": ["invalid role or secret ID"]})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.address = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def reads(self):
        return [path for method, path, _ in self.requests if method == "GET" and "lookup" not in path]


class VaultTestCase(TestCase):
    def setUp(self):
        self.vault = FakeVault()
        self.addCleanup(self.vault.stop)

    def configure(self, **fields):
        row = system.get()
        row.hcv_address = self.vault.address
        row.hcv_token = TOKEN
        for name, value in fields.items():
            setattr(row, name, value)
        row.save()
        system.invalidate()
        return row


class ClientTests(VaultTestCase):
    def vault_client(self, **conf):
        return hashicorp.Client(hashicorp.Conf(address=self.vault.address, token=TOKEN, **conf))

    def test_kv2_is_unwrapped_and_kv1_read_as_is(self):
        client = self.vault_client()
        self.assertEqual(client.get("secret/data/app#password"), "kv2-pa55")
        self.assertEqual(client.get("kv1/app#password"), "kv1-pa55")

    def test_a_non_string_comes_back_as_json(self):
        self.assertEqual(self.vault_client().get("secret/data/app#port"), "5432")

    def test_one_read_per_path(self):
        client = self.vault_client()
        client.get("secret/data/app#password")
        client.get("secret/data/app#port")
        self.assertEqual(self.vault.reads(), ["/v1/secret/data/app"])

    def test_missing_key_path_and_token_are_explained(self):
        with self.assertRaisesMessage(hashicorp.VaultError, "has no key 'nope'"):
            self.vault_client().get("secret/data/app#nope")
        with self.assertRaisesMessage(hashicorp.VaultError, "404"):
            self.vault_client().get("secret/data/gone#x")
        bad = hashicorp.Client(hashicorp.Conf(address=self.vault.address, token="wrong"))
        with self.assertRaisesMessage(hashicorp.VaultError, "permission denied"):
            bad.get("secret/data/app#password")

    def test_approle_signs_in_once(self):
        client = hashicorp.Client(hashicorp.Conf(address=self.vault.address, auth="approle", role_id="r", secret_id="s"))
        client.get("secret/data/app#password")
        client.get("kv1/app#password")
        self.assertEqual(sum(1 for m, *_ in self.vault.requests if m == "POST"), 1)

    def test_namespace_is_sent(self):
        self.vault_client(namespace="team-a").get("kv1/app#password")
        self.assertEqual(self.vault.requests[-1][2].get("X-Vault-Namespace"), "team-a")

    def test_unreachable(self):
        client = hashicorp.Client(hashicorp.Conf(address="http://127.0.0.1:9", token=TOKEN, timeout=2))
        with self.assertRaisesMessage(hashicorp.VaultError, "Could not reach Vault"):
            client.get("kv1/app#password")


class ParseAndAllowTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(hashicorp.parse("/secret/data/app/#pw"), ("secret/data/app", "pw"))
        for bad in ("secret/data/app", "a/../b#k", "a//b#k", "a b#k", "#k"):
            with self.assertRaises(hashicorp.VaultError, msg=bad):
                hashicorp.parse(bad)

    def test_allowed(self):
        prefixes = "secret/data/loona/{group}/\nsecret/data/apps/{project_id}\n\nsecret/data/shared"
        self.assertTrue(hashicorp.allowed("secret/data/loona/dev/db#pw", prefixes, group="dev"))
        self.assertTrue(hashicorp.allowed("secret/data/shared#pw", prefixes))
        self.assertTrue(hashicorp.allowed("secret/data/apps/7/x#k", prefixes, project_id="7"))
        self.assertFalse(hashicorp.allowed("secret/data/loona/prod/db#pw", prefixes, group="dev"))
        self.assertFalse(hashicorp.allowed("secret/data/loona/devx/db#pw", prefixes, group="dev"))
        self.assertFalse(hashicorp.allowed("secret/data/sharedx#pw", prefixes))
        # An unfilled placeholder matches nothing rather than everything.
        self.assertFalse(hashicorp.allowed("secret/data/loona/x#pw", prefixes))
        self.assertFalse(hashicorp.allowed("secret/data/apps/7/x#k", prefixes, group="dev"))


class ResolveTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.configure()
        self.group = HostGroup.objects.create(name="web")
        self.host = Host.objects.create(name="h")
        self.host.groups.add(self.group)

    def vault_secret(self, name, ref, **scope):
        return Secret.objects.create(name=name, vault_ref=ref, **scope)

    def test_a_reference_is_read_at_run_time(self):
        self.vault_secret("db_password", "secret/data/app#password", host_group=self.group)
        delivery = resolve.for_run([self.host])
        self.assertEqual(delivery.per_host["h"], {"db_password": "kv2-pa55"})
        self.assertIn("kv2-pa55", delivery.values)

    def test_a_shadowed_reference_is_not_read(self):
        from playbooks.models import Project

        project = Project.objects.create(name="p")
        self.vault_secret("db_password", "secret/data/app#password")
        stored = Secret(name="db_password", project=project)
        stored.value = "stored-here"
        stored.save()
        delivery = resolve.for_run([self.host], project)
        self.assertEqual(delivery.per_host["h"], {"db_password": "stored-here"})
        self.assertEqual(delivery.common, {"db_password": "stored-here"})
        self.assertEqual(self.vault.reads(), [])

    def test_a_broken_reference_elsewhere_does_not_matter(self):
        self.vault_secret("x", "secret/data/gone#x", host_group=HostGroup.objects.create(name="other"))
        self.assertEqual(resolve.for_run([self.host]).per_host, {})

    def test_a_broken_reference_that_applies_stops_the_run(self):
        self.vault_secret("x", "secret/data/gone#x", host_group=self.group)
        with self.assertRaisesMessage(ValueError, "could not be read from Vault"):
            resolve.for_run([self.host])

    def test_without_vault_set_up(self):
        row = system.get()
        row.hcv_address = ""
        row.save()
        system.invalidate()
        self.vault_secret("x", "secret/data/app#password")
        with self.assertRaisesMessage(ValueError, "not set up"):
            resolve.for_run([self.host])


@override_settings()
class RunTests(VaultTestCase):
    def test_a_run_gets_the_value_and_the_log_does_not(self):
        self.configure()
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        group = HostGroup.objects.create(name="local")
        host = Host.objects.create(name="localhost", variables={"ansible_connection": "local"})
        host.groups.add(group)
        Secret.objects.create(name="db_password", vault_ref="secret/data/app#password", host_group=group)
        out = tmp / "out"
        job = Job.objects.create(
            playbook_name="p",
            playbook_yaml="- hosts: all\n  gather_facts: false\n  tasks:\n"
            f"    - copy: {{content: '{{{{ db_password }}}}', dest: '{out}'}}\n"
            "    - debug: {var: db_password}\n",
        )
        job.target_groups.add(group)
        with self.settings(LOONA_DATA_DIR=str(tmp / "jobs")):
            status = executor.run_job(job.pk)
        log = "\n".join(e.stdout for e in job.events.all())
        self.assertEqual(status, Job.SUCCESSFUL, log)
        self.assertEqual(out.read_text(), "kv2-pa55")
        self.assertNotIn("kv2-pa55", log)
        self.assertIn(MASK, log)


class FormTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        self.configure(hcv_allowed_paths="secret/data/loona/{group}")
        self.dev = HostGroup.objects.create(name="dev")
        team = Group.objects.create(name="devs")
        GroupGrant.objects.create(team=team, host_group=self.dev, role=Role.ADMIN)
        self.user = get_user_model().objects.create_user("dev", password="pw")
        self.user.groups.add(team)
        self.client.login(username="dev", password="pw")

    def post(self, ref, **extra):
        return self.client.post(reverse("secret_create"), {
            "name": "db", "description": "", "scope": "group", "host_group": self.dev.pk, "project": "",
            "source": "vault", "vault_ref": ref, "value": "", **extra,
        })

    def test_a_reference_under_the_groups_prefix_is_accepted(self):
        self.assertEqual(self.post("secret/data/loona/dev/db#password").status_code, 302)
        secret = Secret.objects.get()
        self.assertEqual((secret.vault_ref, secret.value_encrypted), ("secret/data/loona/dev/db#password", ""))

    def test_anything_else_is_refused(self):
        response = self.post("secret/data/app#password")
        self.assertContains(response, "Not under a path you may refer to")
        self.assertFalse(Secret.objects.exists())

    def test_superusers_may_refer_anywhere(self):
        root = get_user_model().objects.create_superuser("root", password="pw")
        self.client.force_login(root)
        self.assertEqual(self.post("secret/data/app#password").status_code, 302)

    def test_switching_back_to_a_stored_value_needs_one(self):
        secret = Secret.objects.create(name="db", vault_ref="secret/data/loona/dev/db#pw", host_group=self.dev)
        data = {"name": "db", "description": "", "scope": "group", "host_group": self.dev.pk, "project": "",
                "source": "stored", "vault_ref": "", "value": ""}
        self.assertEqual(self.client.post(reverse("secret_update", args=[secret.pk]), data).status_code, 200)
        data["value"] = "now-stored"
        self.client.post(reverse("secret_update", args=[secret.pk]), data)
        secret.refresh_from_db()
        self.assertEqual((secret.vault_ref, secret.value), ("", "now-stored"))

    def test_no_vault_choice_while_vault_is_not_set_up(self):
        row = system.get()
        row.hcv_address = ""
        row.save()
        system.invalidate()
        self.assertNotContains(self.client.get(reverse("secret_create")), "HashiCorp Vault")


class AdminPageTests(VaultTestCase):
    def setUp(self):
        super().setUp()
        root = get_user_model().objects.create_superuser("root", password="pw")
        self.client.force_login(root)

    def data(self, **extra):
        return {"hcv_address": self.vault.address, "hcv_namespace": "", "hcv_auth": "token", "token": TOKEN,
                "hcv_approle_mount": "approle", "hcv_role_id": "", "secret_id": "", "hcv_verify_tls": "on",
                "hcv_ca_certificate": "", "hcv_timeout": 5, "hcv_allowed_paths": "", "test_ref": "", **extra}

    def test_test_connection_reads_without_showing_the_value(self):
        response = self.client.post(reverse("admin_vault"), self.data(test="1", test_ref="secret/data/app#password"))
        self.assertContains(response, "Signed in. Policies: loona-read")
        self.assertContains(response, "8 characters")
        self.assertNotContains(response, "kv2-pa55")
        self.assertFalse(SystemSettings.objects.filter(hcv_address=self.vault.address).exists())

    def test_saving_keeps_the_token_encrypted_and_out_of_the_audit_log(self):
        from administration.models import AuditEntry

        self.client.post(reverse("admin_vault"), self.data(save="1"))
        row = SystemSettings.objects.get(pk=1)
        self.assertEqual(row.hcv_token, TOKEN)
        self.assertNotIn(TOKEN, row.hcv_token_encrypted)
        self.assertNotIn(TOKEN, json.dumps(list(AuditEntry.objects.values_list("changes", flat=True))))


@unittest.skipUnless(os.getenv("LOONA_HCV_TEST_ADDR"), "set LOONA_HCV_TEST_ADDR and LOONA_HCV_TEST_TOKEN to run against a real Vault")
class LiveVaultTests(unittest.TestCase):
    """Against a real Vault, e.g. `docker run -e VAULT_DEV_ROOT_TOKEN_ID=root -p 8200:8200 hashicorp/vault`."""

    def setUp(self):
        self.address = os.environ["LOONA_HCV_TEST_ADDR"]
        self.token = os.environ["LOONA_HCV_TEST_TOKEN"]

    def call(self, method, path, body=None):
        request = urllib.request.Request(
            f"{self.address}/v1/{path}", method=method, data=json.dumps(body).encode() if body is not None else None,
            headers={"X-Vault-Token": self.token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=10) as answer:
            text = answer.read()
            return json.loads(text) if text else {}

    def test_kv2_with_a_token_and_with_approle(self):
        self.call("POST", "secret/data/loona-test", {"data": {"password": "live-pa55"}})
        client = hashicorp.Client(hashicorp.Conf(address=self.address, token=self.token))
        self.assertEqual(client.get("secret/data/loona-test#password"), "live-pa55")

        try:
            self.call("POST", "sys/auth/approle", {"type": "approle"})
        except urllib.error.HTTPError:
            pass  # already enabled
        self.call("PUT", "sys/policies/acl/loona-test",
                  {"policy": 'path "secret/data/loona-test" { capabilities = ["read"] }'})
        self.call("POST", "auth/approle/role/loona-test", {"token_policies": ["loona-test"]})
        role_id = self.call("GET", "auth/approle/role/loona-test/role-id")["data"]["role_id"]
        secret_id = self.call("POST", "auth/approle/role/loona-test/secret-id")["data"]["secret_id"]
        approle = hashicorp.Client(hashicorp.Conf(address=self.address, auth="approle",
                                                  role_id=role_id, secret_id=secret_id))
        self.assertEqual(approle.get("secret/data/loona-test#password"), "live-pa55")
        self.assertIn("loona-test", approle.whoami()["policies"])
        # The policy is the boundary: anything else is refused.
        self.call("POST", "secret/data/other", {"data": {"x": "y"}})
        with self.assertRaisesRegex(hashicorp.VaultError, "403"):
            approle.get("secret/data/other#x")
