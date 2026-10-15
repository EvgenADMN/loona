# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Secrets: who gets which value, that runs see them, and that logs do not."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse

from access.models import GroupGrant, Role
from core.masking import MASK, Masker
from inventory.models import Credential, Host, HostGroup
from playbooks.models import Playbook, Project, ProjectFile
from runs import executor
from runs.models import Job

from . import resolve
from .models import Secret

HAS_VAULT = shutil.which("ansible-vault") is not None


def secret(name, value, **scope):
    item = Secret(name=name, **scope)
    item.value = value
    item.save()
    return item


class MaskerTests(unittest.TestCase):
    def test_masks_the_value_and_its_json_form(self):
        mask = Masker(['pa"ss\\word'])
        self.assertEqual(mask('pw=pa"ss\\word'), f"pw={MASK}")
        self.assertEqual(mask('{"pw": "pa\\"ss\\\\word"}'), f'{{"pw": "{MASK}"}}')

    def test_short_values_are_left_alone(self):
        self.assertEqual(Masker(["abc"])("abc abc"), "abc abc")

    def test_lines_of_a_multi_line_secret_are_masked_one_by_one(self):
        mask = Masker(["-----BEGIN KEY-----\nAAAAB3NzaC1yc2EAAAA\n-----END KEY-----"])
        self.assertNotIn("AAAAB3NzaC1yc2EAAAA", mask("line: AAAAB3NzaC1yc2EAAAA"))

    def test_longer_values_win_over_their_own_prefixes(self):
        self.assertEqual(Masker(["secret", "secret-long"])("x secret-long"), f"x {MASK}")

    def test_deep_walks_structures(self):
        mask = Masker(["hunter22"])
        self.assertEqual(mask.deep({"a": ["x hunter22", 1]}), {"a": [f"x {MASK}", 1]})


class ResolveTests(TestCase):
    def setUp(self):
        self.top = HostGroup.objects.create(name="top")
        self.mid = HostGroup.objects.create(name="mid")
        self.mid.parents.add(self.top)
        self.other = HostGroup.objects.create(name="other")
        self.web = Host.objects.create(name="web")
        self.web.groups.add(self.mid)
        self.lone = Host.objects.create(name="lone")
        self.lone.groups.add(self.other)
        self.project = Project.objects.create(name="p")

    def test_precedence_global_then_groups_top_down_then_project(self):
        secret("a", "global")
        secret("a", "top", host_group=self.top)
        secret("b", "global")
        secret("b", "top", host_group=self.top)
        secret("b", "mid", host_group=self.mid)
        secret("c", "top", host_group=self.top)
        secret("c", "project", project=self.project)
        got = resolve.for_run([self.web, self.lone], self.project).per_host
        self.assertEqual(got["web"], {"a": "top", "b": "mid", "c": "project"})
        # Not in top or mid: only global and project.
        self.assertEqual(got["lone"], {"a": "global", "b": "global", "c": "project"})

    def test_another_projects_secrets_stay_out(self):
        secret("x", "theirs", project=Project.objects.create(name="q"))
        self.assertEqual(resolve.for_run([self.web], self.project).per_host, {})

    def test_used_lists_names_and_scopes_only(self):
        secret("db_password", "s3cret-value", host_group=self.top)
        delivery = resolve.for_run([self.web])
        self.assertEqual(delivery.used, ["db_password (group top)"])
        self.assertEqual(delivery.values, ["s3cret-value"])

    def test_values_are_dumped_unsafe(self):
        text = resolve.dump_inventory({"all": {"vars": {"a": resolve.Unsafe("{{ x }}"), "b": "plain"}}})
        self.assertIn("a: !unsafe '{{ x }}'", text)
        self.assertIn("b: plain", text)


@override_settings()
class RunTests(TestCase):
    """Real runs against localhost."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        override = override_settings(LOONA_DATA_DIR=str(self.tmp / "jobs"))
        override.enable()
        self.addCleanup(override.disable)
        self.group = HostGroup.objects.create(name="local")
        self.host = Host.objects.create(name="localhost", variables={"ansible_connection": "local"})
        self.host.groups.add(self.group)
        self.out = self.tmp / "out"

    def run_yaml(self, yaml, project=None, playbook=None):
        job = Job.objects.create(playbook_name="p", playbook_yaml=yaml, ansible_project=project, playbook=playbook)
        job.target_groups.add(self.group)
        status = executor.run_job(job.pk)
        job.refresh_from_db()
        return job, status

    def log(self, job):
        return "\n".join(e.stdout + e.task for e in job.events.all()) + job.error_message

    def test_a_secret_reaches_the_play_and_not_the_log(self):
        secret("db_password", "{{ not a template }} 0xDEADBEEF", host_group=self.group)
        job, status = self.run_yaml(
            "- hosts: all\n  gather_facts: false\n  tasks:\n"
            f"    - copy: {{content: '{{{{ db_password }}}}', dest: '{self.out}'}}\n"
            "    - name: show {{ db_password }}\n      debug: {var: db_password}\n"
        )
        self.assertEqual(status, Job.SUCCESSFUL, self.log(job))
        # As typed: the braces were not taken for a template.
        self.assertEqual(self.out.read_text(), "{{ not a template }} 0xDEADBEEF")
        self.assertNotIn("0xDEADBEEF", self.log(job))
        self.assertIn(MASK, self.log(job))
        self.assertEqual(job.secret_names, ["db_password (group local)"])
        self.assertNotIn("0xDEADBEEF", str(job.extra_vars) + str(job.stats))

    def test_a_secret_beats_a_plain_inventory_variable(self):
        self.host.variables = {"ansible_connection": "local", "token": "plain"}
        self.host.save()
        secret("token", "from-the-store")
        job, status = self.run_yaml(
            f"- hosts: all\n  gather_facts: false\n  tasks:\n    - copy: {{content: '{{{{ token }}}}', dest: '{self.out}'}}\n"
        )
        self.assertEqual(status, Job.SUCCESSFUL, self.log(job))
        self.assertEqual(self.out.read_text(), "from-the-store")

    def test_system_runs_get_no_secrets(self):
        secret("token", "from-the-store")
        job = Job.objects.create(playbook_name="p", kind=Job.KIND_KEY_VERIFY,
                                 playbook_yaml="- hosts: all\n  gather_facts: false\n  tasks: []\n")
        job.target_hosts.add(self.host)
        executor.run_job(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.secret_names, [])

    @unittest.skipUnless(HAS_VAULT, "ansible-vault is not installed here")
    def test_vault_encrypted_values_open_with_the_projects_password(self):
        password_file = self.tmp / "vault-pass"
        password_file.write_text("vault-pa55word\n")
        encrypted = subprocess.run(
            ["ansible-vault", "encrypt_string", "--vault-id", f"prod@{password_file}",
             "opened-by-vault", "--name", "greeting"],
            capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL,
        ).stdout
        credential = Credential(name="v", kind=Credential.KIND_VAULT, vault_id="prod")
        credential.secret = "vault-pa55word"
        credential.save()
        project = Project.objects.create(name="vaulted")
        project.vault_credentials.add(credential)
        ProjectFile.objects.create(project=project, path="vars/main.yml", content=encrypted)
        job, status = self.run_yaml(
            "- hosts: all\n  gather_facts: false\n  vars_files: [vars/main.yml]\n  tasks:\n"
            f"    - copy: {{content: '{{{{ greeting }}}}', dest: '{self.out}'}}\n",
            project=project,
        )
        self.assertEqual(status, Job.SUCCESSFUL, self.log(job))
        self.assertEqual(self.out.read_text(), "opened-by-vault")
        self.assertNotIn("vault-pa55word", self.log(job))
        self.assertEqual(list((self.tmp / "jobs").iterdir()), [])

    @unittest.skipUnless(HAS_VAULT, "ansible-vault is not installed here")
    def test_without_the_password_the_run_fails(self):
        password_file = self.tmp / "vault-pass"
        password_file.write_text("vault-pa55word\n")
        encrypted = subprocess.run(
            ["ansible-vault", "encrypt_string", "--vault-id", f"@{password_file}", "x", "--name", "greeting"],
            capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL,
        ).stdout
        playbook = Playbook.objects.create(name="v", mode=Playbook.MODE_TEXT)
        job, status = self.run_yaml(
            "- hosts: all\n  gather_facts: false\n  vars:\n" + "".join(f"    {l}\n" for l in encrypted.splitlines())
            + "  tasks:\n    - debug: {var: greeting}\n",
            playbook=playbook,
        )
        self.assertNotEqual(status, Job.SUCCESSFUL)
        credential = Credential(name="v", kind=Credential.KIND_VAULT)
        credential.secret = "vault-pa55word"
        credential.save()
        playbook.vault_credentials.add(credential)
        job, status = self.run_yaml(job.playbook_yaml, playbook=playbook)
        self.assertEqual(status, Job.SUCCESSFUL, self.log(job))


class PageTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.prod = HostGroup.objects.create(name="prod")
        self.dev = HostGroup.objects.create(name="dev")
        team = Group.objects.create(name="devs")
        GroupGrant.objects.create(team=team, host_group=self.dev, role=Role.ADMIN)
        GroupGrant.objects.create(team=team, host_group=self.prod, role=Role.VIEWER)
        self.user = User.objects.create_user("dev", password="pw")
        self.user.groups.add(team)
        self.client.login(username="dev", password="pw")

    def post(self, **data):
        base = {"name": "token", "description": "", "scope": "group", "host_group": self.dev.pk,
                "project": "", "value": "v4lue-here"}
        return self.client.post(reverse("secret_create"), {**base, **data})

    def test_a_group_admin_adds_a_secret_to_their_group(self):
        response = self.post()
        self.assertRedirects(response, reverse("secret_list"))
        stored = Secret.objects.get()
        self.assertEqual(stored.host_group, self.dev)
        self.assertEqual(stored.value, "v4lue-here")
        self.assertNotIn("v4lue-here", stored.value_encrypted)

    def test_not_to_a_group_they_only_view(self):
        response = self.post(host_group=self.prod.pk)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Secret.objects.exists())

    def test_nor_a_global_one(self):
        self.post(scope="global")
        self.assertFalse(Secret.objects.exists())

    def test_the_value_is_never_shown(self):
        item = secret("token", "v4lue-here", host_group=self.dev)
        for url in (reverse("secret_list"), reverse("secret_update", args=[item.pk]),
                    reverse("group_detail", args=[self.dev.pk])):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, "token")
            self.assertNotContains(response, "v4lue-here")

    def test_names_of_a_viewed_group_are_listed_but_not_editable(self):
        item = secret("prod_token", "x" * 8, host_group=self.prod)
        self.assertContains(self.client.get(reverse("secret_list")), "prod_token")
        self.assertEqual(self.client.get(reverse("secret_update", args=[item.pk])).status_code, 403)
        self.assertEqual(self.client.post(reverse("secret_delete", args=[item.pk])).status_code, 403)

    def test_an_unseen_group_stays_hidden(self):
        secret("other_token", "x" * 8, host_group=HostGroup.objects.create(name="hidden"))
        self.assertNotContains(self.client.get(reverse("secret_list")), "other_token")

    def test_an_empty_value_keeps_the_stored_one(self):
        item = secret("token", "v4lue-here", host_group=self.dev)
        self.client.post(reverse("secret_update", args=[item.pk]),
                         {"name": "token", "description": "d", "scope": "group", "host_group": self.dev.pk,
                          "project": "", "value": ""})
        item.refresh_from_db()
        self.assertEqual((item.description, item.value), ("d", "v4lue-here"))

    def test_one_name_per_group(self):
        secret("token", "x" * 8, host_group=self.dev)
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Secret.objects.count(), 1)


class ApiTests(TestCase):
    def setUp(self):
        from api.models import ApiToken

        self.root = get_user_model().objects.create_superuser("root")
        self.token = ApiToken.issue(self.root, "t")[1]
        self.group = HostGroup.objects.create(name="g")

    def call(self, method, url, data=None):
        return getattr(self.client, method)(url, data, content_type="application/json",
                                            HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def test_create_list_replace_delete_without_ever_returning_the_value(self):
        url = reverse("api-secret-list")
        created = self.call("post", url, {"name": "tok", "scope": "group", "group": "g", "value": "api-v4lue"})
        self.assertEqual(created.status_code, 201, created.content)
        self.assertEqual(created.json()["group"], "g")
        listed = self.call("get", url)
        self.assertNotIn("api-v4lue", listed.content.decode())
        detail = reverse("api-secret-detail", args=[created.json()["id"]])
        self.assertEqual(self.call("patch", detail, {"value": "new-v4lue"}).status_code, 200)
        self.assertEqual(Secret.objects.get().value, "new-v4lue")
        self.assertEqual(self.call("delete", detail).status_code, 204)
        self.assertFalse(Secret.objects.exists())


class VaultCredentialFormTests(TestCase):
    def test_a_login_in_use_cannot_become_a_vault_password(self):
        from inventory.forms import CredentialForm

        credential = Credential.objects.create(name="c", kind=Credential.KIND_PASSWORD)
        Host.objects.create(name="h", credential=credential)
        form = CredentialForm({"name": "c", "kind": "vault", "username": "root", "secret": "pw",
                               "become_method": "", "become_username": "root", "vault_id": "", "description": ""},
                              instance=credential)
        self.assertIn("kind", form.errors)

    def test_vault_passwords_are_not_offered_as_logins(self):
        from access import policy

        Credential.objects.create(name="v", kind=Credential.KIND_VAULT)
        root = get_user_model().objects.create_superuser("root")
        self.assertFalse(policy.for_user(root).credentials().exists())
