# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Where Loona keeps the people using it from reaching further than their role."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from core import gitsource
from infra.models import TofuProject
from inventory.models import HostGroup
from playbooks.models import Project

HAS_GIT = shutil.which("git") is not None


class RepositoryAddressTests(SimpleTestCase):
    def test_ordinary_addresses_pass(self):
        for url in ["https://git.example.com/infra/ansible.git", "http://gitlab.lan:8080/a/b.git",
                    "ssh://git@git.example.com:2222/infra/ansible.git", "git@git.example.com:infra/ansible.git",
                    "gitea:infra/ansible.git", "git://git.example.com/a.git", "ssh://[fd00::1]/a.git"]:
            self.assertEqual(gitsource.check_url(url), url)

    def test_transports_and_options_that_run_or_read_things_do_not(self):
        for url in ["ext::sh -c id", "ext::sh -c id% >&2", "fd::17", "file:///etc", "FILE:///etc", "/srv/repo",
                    "--upload-pack=id", "-u id", "ssh://-oProxyCommand=id/x", "ssh://git@-oProxyCommand=id/x",
                    "git@-oProxyCommand=id:x", "https:///x", "ext:://x"]:
            with self.assertRaises(ValidationError, msg=url):
                gitsource.check_url(url)

    def test_a_ref_is_never_an_option(self):
        self.assertEqual(gitsource.check_ref("release/1.0"), "release/1.0")
        for ref in ["--upload-pack=id", "-x", "main extra"]:
            with self.assertRaises(ValidationError, msg=ref):
                gitsource.check_ref(ref)

    def test_checkout_refuses_before_git_runs(self):
        with patch("core.gitsource.subprocess.run") as run, tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(gitsource.GitError):
                gitsource.checkout("ext::sh -c id", Path(tmp) / "repo", {})
            with self.assertRaises(gitsource.GitError):
                gitsource.ls_remote("https://git.example.com/a.git", "--upload-pack=id", {})
        run.assert_not_called()

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_git_itself_is_held_to_the_list(self):
        """Even past the form, git refuses: ext:: and file:// are not allowed."""
        with tempfile.TemporaryDirectory() as tmp:
            env = gitsource.environment(None, Path(tmp))
            self.assertEqual(env["GIT_ALLOW_PROTOCOL"], gitsource.PROTOCOLS)
            for url in ("ext::false", f"file://{tmp}"):
                done = subprocess.run(["git", "ls-remote", "--", url], env=env, capture_output=True, text=True)
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("not allowed", done.stderr)


class RepositoryFormTests(TestCase):
    def setUp(self):
        self.editor = get_user_model().objects.create_user("editor", password="x")
        self.editor.user_permissions.add(Permission.objects.get(codename="change_playbook"))
        self.client.force_login(self.editor)

    def test_an_ansible_project_refuses_a_command_for_an_address(self):
        response = self.client.post(reverse("project_create"), {
            "name": "p", "description": "", "source": Project.SOURCE_GIT, "git_url": "ext::sh -c id",
            "git_ref": "main", "git_path": ""})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Project.objects.exists())

    def test_checking_a_bad_address_already_stored_runs_nothing(self):
        project = Project.objects.create(name="old", source=Project.SOURCE_GIT, git_url="ext::sh -c id")
        with patch("subprocess.run") as run:
            self.client.post(reverse("project_check", args=[project.pk]))
        run.assert_not_called()

    def test_an_opentofu_project_refuses_one_too(self):
        project = TofuProject(name="t", host_group=HostGroup.objects.create(name="g"),
                              source=TofuProject.SOURCE_GIT, git_url="file:///etc", git_ref="main")
        with self.assertRaises(ValidationError) as caught:
            project.full_clean()
        self.assertIn("git_url", caught.exception.message_dict)


class HeaderTests(TestCase):
    def test_pages_say_what_may_run(self):
        response = self.client.get(reverse("login"))
        policy = response["Content-Security-Policy"]
        self.assertIn("script-src 'self' 'unsafe-eval'", policy)
        self.assertNotIn("'unsafe-inline'", policy.split("script-src")[1].split(";")[0])
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertIn("camera=()", response["Permissions-Policy"])

    def test_no_template_carries_inline_script(self):
        import re

        from django.conf import settings

        inline = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>|\son[a-z]+=\"|javascript:", re.IGNORECASE)
        found = [str(path) for path in Path(settings.BASE_DIR, "templates").rglob("*.html")
                 if inline.search(path.read_text())]
        self.assertEqual(found, [])


class GroupAdminBoundaryTests(TestCase):
    """An Admin of one group runs nothing on the Loona server and takes no
    other team's login anywhere."""

    def setUp(self):
        from django.contrib.auth.models import Group

        from access.models import GroupGrant, Role
        from inventory.models import Credential, Host

        self.group = HostGroup.objects.create(name="team-a")
        team = Group.objects.create(name="a")
        GroupGrant.objects.create(team=team, host_group=self.group, role=Role.ADMIN)
        self.admin = get_user_model().objects.create_user("lead")
        self.admin.groups.add(team)
        self.client.force_login(self.admin)
        self.root_login = Credential.objects.create(name="prod-root", kind=Credential.KIND_PASSWORD,
                                                    username="root")
        self.root_login.secret = "not-for-team-a"
        self.root_login.save()
        self.host = Host.objects.create(name="web1", address="10.0.0.5", credential=self.root_login,
                                        variables={"ansible_python_interpreter": "/usr/bin/python3"})
        self.host.groups.add(self.group)

    def edit_host(self, **changes):
        data = {"name": "web1", "address": "10.0.0.5", "port": 22, "credential": self.root_login.pk,
                "groups": [self.group.pk], "enabled": "on", "description": "",
                "variables": "ansible_python_interpreter: /usr/bin/python3", **changes}
        response = self.client.post(reverse("host_update", args=[self.host.pk]), data)
        self.host.refresh_from_db()
        return response

    def test_an_unshared_login_does_not_move_with_the_host(self):
        response = self.edit_host(address="203.0.113.66")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.host.address, "10.0.0.5")
        # Dropping the credential is how it moves.
        self.edit_host(address="203.0.113.66", credential="")
        self.assertEqual((self.host.address, self.host.credential_id), ("203.0.113.66", None))

    def test_the_pinned_key_of_such_a_host_stays(self):
        self.host.ssh_host_keys = "10.0.0.5 ssh-ed25519 AAAA"
        self.host.save()
        self.client.post(reverse("host_forget_host_key", args=[self.host.pk]))
        self.host.refresh_from_db()
        self.assertTrue(self.host.ssh_host_keys)

    def test_the_connection_check_does_not_take_it_elsewhere(self):
        with patch("inventory.probe.check_connection") as check:
            page = self.client.post(reverse("host_probe"), {"host": self.host.pk, "address": "203.0.113.66"})
        check.assert_not_called()
        self.assertContains(page, "not shared with you")

    def test_variables_take_no_ansible_names_and_no_templates(self):
        for text in ("ansible_ssh_common_args: -o Compression=yes", "ansible_host: 203.0.113.66",
                     "release: '{{ 1 + 1 }}'", "nested: {deep: ['{%- if x %}']}"):
            response = self.edit_host(variables="ansible_python_interpreter: /usr/bin/python3\n" + text)
            self.assertEqual(response.status_code, 200, text)
            self.assertEqual(set(self.host.variables), {"ansible_python_interpreter"}, text)
        # What a superuser set stays; plain values are fine.
        self.edit_host(variables="ansible_python_interpreter: /usr/bin/python3\nrelease: 42")
        self.assertEqual(self.host.variables["release"], 42)

    def test_group_variables_too(self):
        response = self.client.post(reverse("group_update", args=[self.group.pk]), {
            "name": "team-a", "description": "", "variables": "ansible_port: 2222"})
        self.assertEqual(response.status_code, 200)
        self.group.refresh_from_db()
        self.assertEqual(self.group.variables, {})

    def test_secrets_named_after_ansible_variables_are_passwords_only(self):
        from secretstore.forms import SecretForm

        for name, ok in (("ansible_ssh_common_args", False), ("ansible_host", False),
                         ("ansible_become_password", True), ("db_password", True)):
            form = SecretForm({"name": name, "description": "", "scope": "group", "host_group": self.group.pk,
                               "value": "x"}, user=self.admin)
            self.assertEqual(form.is_valid(), ok, (name, form.errors))

    def test_login_names_for_keys(self):
        from inventory.forms import KeyProvisionForm

        self.assertFalse(KeyProvisionForm({"username": "{{ 1 + 1 }}", "password": "x"}, host=self.host).is_valid())
        self.assertTrue(KeyProvisionForm({"username": "deploy", "password": "x"}, host=self.host).is_valid())

    def test_logins_and_addresses_reach_ansible_as_data(self):
        from inventory.services import host_vars
        from secretstore.resolve import Unsafe, dump_inventory

        with tempfile.TemporaryDirectory() as tmp:
            variables = host_vars(self.host, Path(tmp))
        self.assertIsInstance(variables["ansible_host"], Unsafe)
        self.assertIsInstance(variables["ansible_user"], Unsafe)
        self.assertIn("ansible_user: !unsafe", dump_inventory(variables))


class AdhocModuleTests(TestCase):
    def test_collection_names_count_as_their_module(self):
        from runs import adhoc

        user = get_user_model().objects.create_user("lead")
        with patch("runs.adhoc.allowed_modules", return_value=["ansible.posix.synchronize", "include_tasks"]):
            self.assertIn("superuser", adhoc.why_not_module("ansible.posix.synchronize", user))
            self.assertIn("superuser", adhoc.why_not_module("include_tasks", user))


class ProcessHardeningTests(SimpleTestCase):
    def test_the_keys_are_not_left_for_children(self):
        import os

        from core import hardening

        for name in hardening.SECRET_VARIABLES:
            self.assertNotIn(name, os.environ)
        done = subprocess.run(["env"], capture_output=True, text=True)
        for name in hardening.SECRET_VARIABLES:
            self.assertNotIn(name + "=", done.stdout)

    @unittest.skipUnless(Path("/proc/self/status").exists(), "Linux only")
    def test_this_process_cannot_be_read_by_its_neighbours(self):
        import ctypes

        libc = ctypes.CDLL(None)
        self.assertEqual(libc.prctl(3, 0, 0, 0, 0), 0)  # PR_GET_DUMPABLE: 0 = not dumpable


class AlpineTemplateTests(SimpleTestCase):
    def test_template_values_inside_javascript_are_escaped(self):
        import re

        from django.conf import settings

        # x-data="{ kind: '{{ form.kind.value }}' }": HTML escaping does not
        # protect a JavaScript string.
        attribute = re.compile(r'''(?:\sx-[a-z:.-]+|\s@[a-z.:-]+|\s:[a-z-]+|\shx-(?:vals|on[a-z:-]*))=(?:"([^"]*)"|'([^']*)')''')
        found = []
        for path in Path(settings.BASE_DIR, "templates").rglob("*.html"):
            for value in ("".join(pair) for pair in attribute.findall(path.read_text())):
                for expression in re.findall(r"\{\{(.*?)\}\}", value):
                    if "escapejs" not in expression and not expression.strip().startswith(("csrf_token",)):
                        found.append(f"{path.name}: {expression.strip()}")
        self.assertEqual(found, [])
