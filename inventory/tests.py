# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import yaml
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from core.crypto import decrypt, encrypt
from runs.models import Job, JobEvent

from . import probe, provisioning
from .models import Credential, Host, HostGroup, HostKey
from .services import apply_connection_override, build_inventory, resolve_targets


class CredentialSecretTests(TestCase):
    def test_secret_is_not_stored_in_clear_text(self):
        credential = Credential.objects.create(name="deploy", username="deploy")
        credential.secret = "super-secret-key"
        credential.save()

        stored = Credential.objects.get(pk=credential.pk)
        self.assertNotIn("super-secret-key", stored.secret_encrypted)
        self.assertEqual(stored.secret, "super-secret-key")

    def test_encrypt_round_trip(self):
        self.assertEqual(decrypt(encrypt("hello")), "hello")
        self.assertEqual(decrypt(""), "")


class CredentialSharingTests(TestCase):
    def test_the_form_saves_the_teams_a_credential_is_shared_with(self):
        from django.contrib.auth.models import Group

        self.client.force_login(get_user_model().objects.create_superuser("root"))
        team = Group.objects.create(name="web-admins")
        self.client.post(reverse("credential_create"), {
            "name": "deploy", "kind": "password", "username": "ops", "secret": "pw",
            "become_method": "", "become_username": "root", "teams": [team.pk],
        })
        self.assertEqual(list(Credential.objects.get(name="deploy").teams.all()), [team])


class GroupNestingTests(TestCase):
    def setUp(self):
        self.web = HostGroup.objects.create(name="web")
        self.prod = HostGroup.objects.create(name="prod")
        self.web.parents.add(self.prod)
        self.host = Host.objects.create(name="web01", address="10.0.0.1")
        self.host.groups.add(self.web)

    def test_parent_group_includes_child_hosts(self):
        self.assertEqual([h.name for h in self.prod.all_hosts()], ["web01"])

    def test_cycles_do_not_hang(self):
        self.prod.parents.add(self.web)
        self.assertEqual(len(self.prod.all_hosts()), 1)

    def test_disabled_hosts_are_not_targeted(self):
        self.host.enabled = False
        self.host.save()
        self.assertEqual(resolve_targets(groups=[self.prod]), [])

    def test_the_form_refuses_a_circle_and_names_ansible_cannot_use(self):
        self.client.force_login(get_user_model().objects.create_superuser("root"))
        edit = reverse("group_update", args=[self.prod.pk])
        response = self.client.post(edit, {"name": "prod", "parents": [self.web.pk], "variables": "",
                                           "approval_policy": "destroy"})
        self.assertContains(response, "cannot be its parent as well")
        self.assertFalse(self.prod.parents.exists())
        for name in ("two words", "web,db", "all"):
            self.client.post(reverse("group_create"), {"name": name, "variables": "", "approval_policy": "destroy"})
            self.client.post(reverse("host_create"), {"name": name, "address": "10.0.0.2", "port": 22,
                                                      "enabled": "on", "variables": ""})
        self.assertFalse(HostGroup.objects.exclude(name__in=["web", "prod"]).exists())
        self.assertEqual(list(Host.objects.exclude(name="web01").values_list("name", flat=True)), ["all"])


class InventoryBuildTests(TestCase):
    def test_inventory_carries_connection_vars(self):
        credential = Credential.objects.create(
            name="root-pw", kind=Credential.KIND_PASSWORD, username="root"
        )
        credential.secret = "hunter2"
        credential.save()

        group = HostGroup.objects.create(name="db", variables={"pg_version": 16})
        host = Host.objects.create(
            name="db01", address="10.0.0.9", port=2222, credential=credential
        )
        host.groups.add(group)

        with tempfile.TemporaryDirectory() as tmp:
            inventory = build_inventory([host], [group], Path(tmp))

        host_vars = inventory["all"]["hosts"]["db01"]
        self.assertEqual(host_vars["ansible_host"], "10.0.0.9")
        self.assertEqual(host_vars["ansible_port"], 2222)
        self.assertEqual(host_vars["ansible_user"], "root")
        self.assertEqual(host_vars["ansible_password"], "hunter2")
        self.assertEqual(inventory["all"]["children"]["db"]["vars"], {"pg_version": 16})

    def test_a_host_brings_all_its_groups_however_the_run_was_aimed(self):
        prod = HostGroup.objects.create(name="prod", variables={"env": "production", "tier": "any"})
        web = HostGroup.objects.create(name="web", variables={"tier": "web"})
        web.parents.add(prod)
        HostGroup.objects.create(name="elsewhere", variables={"env": "lab"})
        host = Host.objects.create(name="web01", address="10.0.0.1")
        host.groups.add(web)

        with tempfile.TemporaryDirectory() as tmp:
            aimed_at_parent = build_inventory([host], [prod], Path(tmp))["all"]["children"]
            aimed_at_host = build_inventory([host], [], Path(tmp))["all"]["children"]

        self.assertEqual(aimed_at_parent, aimed_at_host)
        self.assertEqual(set(aimed_at_host), {"prod", "web"})
        # Nested as in Loona, so Ansible lets web's "tier" beat prod's.
        self.assertEqual(aimed_at_host["prod"], {"hosts": {}, "children": {"web": {}},
                                                 "vars": {"env": "production", "tier": "any"}})
        self.assertEqual(aimed_at_host["web"], {"hosts": {"web01": {}}, "vars": {"tier": "web"}})

    def test_private_key_is_written_with_owner_only_permissions(self):
        credential = Credential.objects.create(name="key", username="ops")
        credential.secret = "-----BEGIN OPENSSH PRIVATE KEY-----"
        credential.save()
        host = Host.objects.create(name="app01", credential=credential)

        with tempfile.TemporaryDirectory() as tmp:
            inventory = build_inventory([host], [], Path(tmp))
            key_path = Path(inventory["all"]["hosts"]["app01"]["ansible_ssh_private_key_file"])
            self.assertTrue(key_path.exists())
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)

    def test_host_variables_win_over_credential_defaults(self):
        credential = Credential.objects.create(name="c", username="root")
        host = Host.objects.create(
            name="h", credential=credential, variables={"ansible_user": "override"}
        )
        with tempfile.TemporaryDirectory() as tmp:
            inventory = build_inventory([host], [], Path(tmp))
        self.assertEqual(inventory["all"]["hosts"]["h"]["ansible_user"], "override")


class KeyGenerationTests(TestCase):
    def test_fingerprint_matches_openssh(self):
        from .keys import fingerprint, generate_keypair

        private_text, public_text = generate_keypair("loona-web01-1")
        with tempfile.TemporaryDirectory() as tmp:
            pub_path = Path(tmp) / "k.pub"
            pub_path.write_text(public_text + "\n")
            reported = subprocess.run(
                ["ssh-keygen", "-lf", str(pub_path)], capture_output=True, text=True
            ).stdout
        self.assertIn(fingerprint(public_text), reported)
        self.assertTrue(private_text.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"))

    def test_each_host_gets_its_own_key(self):
        one = provisioning.ensure_keypair(Host.objects.create(name="a"), "root")
        two = provisioning.ensure_keypair(Host.objects.create(name="b"), "root")
        self.assertNotEqual(one.public_key, two.public_key)

    def test_private_half_is_not_stored_in_clear_text(self):
        key = provisioning.ensure_keypair(Host.objects.create(name="a"), "root")
        stored = HostKey.objects.get(pk=key.pk)
        self.assertNotIn("PRIVATE KEY", stored.private_key_encrypted)
        self.assertIn("PRIVATE KEY", stored.private_key)

    def test_an_installed_key_is_never_regenerated(self):
        host = Host.objects.create(name="a")
        key = provisioning.ensure_keypair(host, "root")
        key.installed_at = timezone.now()
        key.save()
        again = provisioning.ensure_keypair(host, "deploy")
        self.assertEqual(again.public_key, key.public_key)
        self.assertEqual(again.username, "root")

    def test_an_uninstalled_key_follows_a_corrected_login(self):
        host = Host.objects.create(name="a")
        provisioning.ensure_keypair(host, "rooot")
        host.refresh_from_db()
        self.assertEqual(provisioning.ensure_keypair(host, "root").username, "root")


class ManagedKeyInventoryTests(TestCase):
    def setUp(self):
        self.credential = Credential.objects.create(
            name="shared", kind=Credential.KIND_PASSWORD, username="root"
        )
        self.credential.secret = "hunter2"
        self.credential.become_method = "sudo"
        self.credential.save()
        self.host = Host.objects.create(name="web01", credential=self.credential)
        self.key = provisioning.ensure_keypair(self.host, "deploy")

    def _vars(self, tmp):
        self.host.refresh_from_db()
        return build_inventory([self.host], [], Path(tmp))["all"]["hosts"]["web01"]

    def test_an_active_key_replaces_the_shared_password(self):
        self.key.status = HostKey.ACTIVE
        self.key.save()
        with tempfile.TemporaryDirectory() as tmp:
            variables = self._vars(tmp)
            self.assertNotIn("ansible_password", variables)
            self.assertEqual(variables["ansible_user"], "deploy")
            key_path = Path(variables["ansible_ssh_private_key_file"])
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            self.assertIn("PRIVATE KEY", key_path.read_text())

    def test_escalation_still_comes_from_the_credential(self):
        self.key.status = HostKey.ACTIVE
        self.key.save()
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._vars(tmp)["ansible_become_method"], "sudo")

    def test_a_key_that_is_not_installed_yet_is_not_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            variables = self._vars(tmp)
        self.assertEqual(variables["ansible_password"], "hunter2")
        self.assertNotIn("ansible_ssh_private_key_file", variables)

    def test_a_failed_key_falls_back_to_the_credential(self):
        self.key.status = HostKey.FAILED
        self.key.installed_at = timezone.now()
        self.key.save()
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._vars(tmp)["ansible_password"], "hunter2")

    def test_one_off_credentials_replace_every_auth_variable(self):
        self.key.status = HostKey.ACTIVE
        self.key.save()
        with tempfile.TemporaryDirectory() as tmp:
            variables = apply_connection_override(
                self._vars(tmp), provisioning.password_override("root", "typed-in")
            )
        self.assertEqual(variables["ansible_user"], "root")
        self.assertEqual(variables["ansible_password"], "typed-in")
        self.assertNotIn("ansible_ssh_private_key_file", variables)
        self.assertNotIn("ansible_become_method", variables)
        # Everything that is not about authentication survives.
        self.assertEqual(variables["ansible_port"], 22)


class KeyLifecycleTests(TestCase):
    """The state machine the executor drives once one of Loona's runs ends."""

    def setUp(self):
        self.host = Host.objects.create(name="web01")
        self.key = provisioning.ensure_keypair(self.host, "root")
        self.dispatched = []
        patcher = mock.patch(
            "runs.executor.dispatch", side_effect=self.dispatched.append
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _finish(self, job, status):
        job.status = status
        job.save(update_fields=["status"])
        provisioning.on_job_finished(job)
        self.key.refresh_from_db()

    def test_pushing_a_working_key_again_keeps_it_usable_for_that_run(self):
        self.key.status = HostKey.ACTIVE
        self.key.installed_at = timezone.now()
        self.key.save()
        provisioning.start_key_install(self.host, self.key)
        self.key.refresh_from_db()
        # No login was typed, so the key is what the run gets in with.
        self.assertTrue(self.key.is_usable)
        provisioning.start_key_install(
            self.host, self.key, override=provisioning.password_override("root", "typed-in")
        )
        self.key.refresh_from_db()
        self.assertEqual(self.key.status, HostKey.PENDING)

    def test_a_successful_push_is_verified_before_being_trusted(self):
        job = provisioning.start_key_install(self.host, self.key)
        self._finish(job, Job.SUCCESSFUL)
        self.assertEqual(self.key.status, HostKey.VERIFYING)
        self.assertIsNotNone(self.key.installed_at)
        self.assertEqual(self.dispatched[-1].kind, Job.KIND_KEY_VERIFY)

    def test_verification_promotes_the_key(self):
        install = provisioning.start_key_install(self.host, self.key)
        self._finish(install, Job.SUCCESSFUL)
        self._finish(self.dispatched[-1], Job.SUCCESSFUL)
        self.assertEqual(self.key.status, HostKey.ACTIVE)
        self.assertIsNotNone(self.key.verified_at)

    def test_a_key_that_cannot_be_used_does_not_become_active(self):
        install = provisioning.start_key_install(self.host, self.key)
        self._finish(install, Job.SUCCESSFUL)
        self._finish(self.dispatched[-1], Job.FAILED)
        self.assertEqual(self.key.status, HostKey.FAILED)
        self.assertIn("could not log in", self.key.error_message)

    def test_a_failed_push_leaves_the_key_uninstalled(self):
        job = provisioning.start_key_install(self.host, self.key)
        self._finish(job, Job.FAILED)
        self.assertEqual(self.key.status, HostKey.FAILED)
        self.assertIsNone(self.key.installed_at)

    def test_revocation_removes_loonas_copy_and_then_the_host(self):
        self.key.installed_at = timezone.now()
        self.key.status = HostKey.ACTIVE
        self.key.save()
        job = provisioning.start_key_revoke(self.host, self.key, delete_host=True)
        job.status = Job.SUCCESSFUL
        job.save(update_fields=["status"])
        provisioning.on_job_finished(job)
        self.assertFalse(HostKey.objects.filter(pk=self.key.pk).exists())
        self.assertFalse(Host.objects.filter(pk=self.host.pk).exists())

    def test_a_failed_revocation_keeps_the_host(self):
        self.key.installed_at = timezone.now()
        self.key.save()
        job = provisioning.start_key_revoke(self.host, self.key, delete_host=True)
        self._finish(job, Job.FAILED)
        self.assertEqual(self.key.status, HostKey.REVOKE_FAILED)
        self.assertTrue(Host.objects.filter(pk=self.host.pk).exists())

    def test_revoking_without_deleting_keeps_the_host(self):
        self.key.installed_at = timezone.now()
        self.key.save()
        job = provisioning.start_key_revoke(self.host, self.key)
        job.status = Job.SUCCESSFUL
        job.save(update_fields=["status"])
        provisioning.on_job_finished(job)
        self.assertFalse(HostKey.objects.filter(pk=self.key.pk).exists())
        self.assertTrue(Host.objects.filter(pk=self.host.pk).exists())


class _PlaybookLoader(yaml.SafeLoader):
    """Reads what Loona writes: !unsafe strings come back as plain strings."""


_PlaybookLoader.add_constructor("!unsafe", lambda loader, node: loader.construct_scalar(node))


def load_playbook(text):
    return yaml.load(text, Loader=_PlaybookLoader)


class GeneratedPlaybookTests(TestCase):
    def setUp(self):
        self.host = Host.objects.create(name="web01")
        self.key = provisioning.ensure_keypair(self.host, "deploy")

    def test_what_was_typed_in_stays_text(self):
        text = provisioning.key_install_playbook(self.host, self.key)
        self.assertIn("user: !unsafe 'deploy'", text)
        with self.assertRaises(ValueError):
            provisioning.ensure_keypair(self.host, "{{ 1 + 1 }}")

    def test_install_adds_the_key_without_touching_the_others(self):
        play = load_playbook(provisioning.key_install_playbook(self.host, self.key))[0]
        args = play["tasks"][0]["ansible.builtin.authorized_key"]
        self.assertEqual(args["state"], "present")
        self.assertEqual(args["user"], "deploy")
        self.assertFalse(args["exclusive"])
        self.assertEqual(args["key"], self.key.public_key)

    def test_revoke_removes_exactly_loonas_key(self):
        play = load_playbook(provisioning.key_revoke_playbook(self.host, self.key))[0]
        args = play["tasks"][0]["ansible.builtin.authorized_key"]
        self.assertEqual(args["state"], "absent")
        self.assertEqual(args["key"], self.key.public_key)
        self.assertFalse(args["exclusive"])


class HostDeletionTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))
        self.host = Host.objects.create(name="web01")
        self.key = provisioning.ensure_keypair(self.host, "root")
        self.key.installed_at = timezone.now()
        self.key.status = HostKey.ACTIVE
        self.key.save()
        self.dispatched = []
        patcher = mock.patch(
            "runs.executor.dispatch", side_effect=self.dispatched.append
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_deleting_with_revocation_waits_for_the_key_to_come_off(self):
        response = self.client.post(
            reverse("host_delete", args=[self.host.pk]), {"revoke_key": "1"}
        )
        self.assertTrue(Host.objects.filter(pk=self.host.pk).exists())
        job = self.dispatched[-1]
        self.assertEqual(job.kind, Job.KIND_KEY_REVOKE)
        self.assertTrue(job.delete_host_on_success)
        self.assertRedirects(response, job.get_absolute_url())
        self.key.refresh_from_db()
        self.assertEqual(self.key.status, HostKey.REVOKING)

    def test_deleting_without_revocation_is_immediate(self):
        self.client.post(reverse("host_delete", args=[self.host.pk]))
        self.assertFalse(Host.objects.filter(pk=self.host.pk).exists())
        self.assertEqual(self.dispatched, [])

    def test_the_confirmation_offers_revocation(self):
        response = self.client.get(reverse("host_delete", args=[self.host.pk]))
        self.assertContains(response, "revoke_key")
        self.assertContains(response, self.key.fingerprint)


class KeyProvisioningViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))
        self.host = Host.objects.create(name="web01")
        self.dispatched = []
        patcher = mock.patch(
            "runs.executor.dispatch", side_effect=self.dispatched.append
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_creating_a_host_saves_it_and_stays_out_of_the_way(self):
        response = self.client.post(
            reverse("host_create"),
            {"name": "web02", "port": 22, "enabled": "on", "variables": ""},
        )
        host = Host.objects.get(name="web02")
        self.assertRedirects(response, reverse("host_detail", args=[host.pk]))

    def test_pushing_a_key_uses_the_typed_password_and_stores_nothing(self):
        self.client.post(
            reverse("host_key_provision", args=[self.host.pk]),
            {"username": "root", "password": "typed-in"},
        )
        job = self.dispatched[-1]
        self.assertEqual(job.kind, Job.KIND_KEY_INSTALL)
        self.assertEqual(job.connection_override["ansible_password"], "typed-in")
        self.assertNotIn("typed-in", job.connection_override_encrypted)
        self.assertTrue(HostKey.objects.filter(host=self.host).exists())

    def test_a_password_is_required_when_there_is_no_other_way_in(self):
        response = self.client.post(
            reverse("host_key_provision", args=[self.host.pk]),
            {"username": "root", "password": ""},
        )
        self.assertContains(response, "no saved credential")
        self.assertEqual(self.dispatched, [])

    def test_pushing_a_key_answers_in_place_rather_than_redirecting(self):
        response = self.client.post(
            reverse("host_key_provision", args=[self.host.pk]),
            {"username": "root", "password": "typed-in"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="key-panel"')
        # A run is in flight, so the panel polls itself instead of offering the form.
        self.assertContains(response, reverse("host_key_status", args=[self.host.pk]))

    def test_discarding_a_keypair_that_never_reached_the_server(self):
        provisioning.ensure_keypair(self.host, "root")
        self.client.post(reverse("host_key_revoke", args=[self.host.pk]))
        self.assertFalse(HostKey.objects.filter(host=self.host).exists())
        self.assertEqual(self.dispatched, [])


class KeyPageRenderTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))
        self.host = Host.objects.create(name="web01")
        self.key = provisioning.ensure_keypair(self.host, "deploy")
        self.key.status = HostKey.ACTIVE
        self.key.installed_at = timezone.now()
        self.key.verified_at = timezone.now()
        self.key.save()

    def test_the_key_page_shows_the_fingerprint_and_the_way_out(self):
        response = self.client.get(reverse("host_key", args=[self.host.pk]))
        self.assertContains(response, self.key.fingerprint)
        self.assertContains(response, "Remove key from server")

    def test_the_host_pages_link_to_the_key(self):
        for name in ("host_detail", "host_list"):
            args = [self.host.pk] if name == "host_detail" else []
            response = self.client.get(reverse(name, args=args))
            self.assertContains(response, reverse("host_key", args=[self.host.pk]))


class ConnectionProbeTests(TestCase):
    """The check runs in the request and answers into the page, saving nothing."""

    def setUp(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))
        self.seen = []
        patcher = mock.patch.object(
            probe,
            "check_connection",
            side_effect=self._capture,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _capture(self, build_variables, label="", **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            self.seen.append({"label": label, "variables": build_variables(Path(tmp))})
        return probe.ProbeResult("ok", "Logged in.")

    def test_an_unsaved_host_can_be_checked_before_it_exists(self):
        response = self.client.post(
            reverse("host_probe"),
            {"name": "web09", "address": "10.0.0.9", "port": "2222",
             "username": "root", "password": "typed-in"},
        )
        self.assertContains(response, "Logged in.")
        variables = self.seen[-1]["variables"]
        self.assertEqual(variables["ansible_host"], "10.0.0.9")
        self.assertEqual(variables["ansible_port"], 2222)
        self.assertEqual(variables["ansible_password"], "typed-in")
        # Checking is not creating.
        self.assertFalse(Host.objects.exists())
        self.assertFalse(Job.objects.exists())

    def test_a_saved_host_is_checked_with_the_key_it_already_has(self):
        host = Host.objects.create(name="web01", address="10.0.0.1")
        key = provisioning.ensure_keypair(host, "deploy")
        key.status = HostKey.ACTIVE
        key.save()
        self.client.post(reverse("host_probe"), {"host": host.pk})
        variables = self.seen[-1]["variables"]
        self.assertEqual(variables["ansible_user"], "deploy")
        self.assertIn("ansible_ssh_private_key_file", variables)

    def test_an_edited_address_is_checked_before_it_is_saved(self):
        credential = Credential.objects.create(
            name="c", kind=Credential.KIND_PASSWORD, username="root"
        )
        credential.secret = "stored"
        credential.save()
        host = Host.objects.create(name="web01", address="10.0.0.1", credential=credential)
        self.client.post(
            reverse("host_probe"), {"host": host.pk, "address": "10.0.0.99", "port": "2200"}
        )
        variables = self.seen[-1]["variables"]
        self.assertEqual(variables["ansible_host"], "10.0.0.99")
        self.assertEqual(variables["ansible_port"], 2200)
        self.assertEqual(variables["ansible_password"], "stored")
        # The edit is only a probe; the stored host is untouched.
        host.refresh_from_db()
        self.assertEqual(host.address, "10.0.0.1")

    def test_nothing_to_log_in_with_is_said_rather_than_timed_out(self):
        host = Host.objects.create(name="web01", address="10.0.0.1")
        response = self.client.post(reverse("host_probe"), {"host": host.pk})
        self.assertContains(response, "no way to log in")
        self.assertEqual(self.seen, [])

    def test_an_empty_form_asks_for_an_address(self):
        response = self.client.post(reverse("host_probe"), {})
        self.assertContains(response, "Fill in the name or address")
        self.assertEqual(self.seen, [])


class KeyPanelPollingTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))
        self.host = Host.objects.create(name="web01")
        patcher = mock.patch("runs.executor.dispatch")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_panel_polls_while_a_run_is_in_flight_and_stops_after(self):
        self.client.post(
            reverse("host_key_provision", args=[self.host.pk]),
            {"username": "root", "password": "typed-in"},
        )
        url = reverse("host_key_status", args=[self.host.pk])
        self.assertContains(self.client.get(url), "hx-trigger")

        job = Job.objects.get(kind=Job.KIND_KEY_INSTALL)
        job.status = Job.FAILED
        job.save(update_fields=["status"])
        response = self.client.get(url)
        self.assertNotContains(response, "hx-trigger")
        # With nothing running, the panel offers the form again.
        self.assertContains(response, "Check connection")


class FailureReportingTests(TestCase):
    """A failed key run has to say why, not just that it failed."""

    def setUp(self):
        self.host = Host.objects.create(name="web01")
        self.key = provisioning.ensure_keypair(self.host, "root")
        patcher = mock.patch("runs.executor.dispatch")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.job = provisioning.start_key_install(self.host, self.key)

    def _fail_with(self, event, stdout, failed=False):
        JobEvent.objects.create(job=self.job, event=event, stdout=stdout, failed=failed)
        self.job.status = Job.FAILED
        self.job.save(update_fields=["status"])
        provisioning.on_job_finished(self.job)
        self.key.refresh_from_db()

    def test_an_unreachable_host_reports_the_ssh_error(self):
        # ansible-runner leaves "failed" unset on an unreachable host.
        self._fail_with(
            "runner_on_unreachable",
            'fatal: [web01]: UNREACHABLE! => {"changed": false, "msg": "Failed to '
            'connect to the host via ssh: ssh: connect to host 10.0.0.1 port 22: '
            'Connection refused", "unreachable": true}',
        )
        self.assertIn("Connection refused", self.key.error_message)
        self.assertNotIn("unreachable\": true", self.key.error_message)

    def test_a_failed_task_reports_its_message(self):
        self._fail_with(
            "runner_on_failed",
            'fatal: [web01]: FAILED! => {"changed": false, "msg": "Permission denied"}',
            failed=True,
        )
        self.assertEqual(self.key.error_message, "Permission denied")

    def test_output_that_is_not_json_is_still_shown(self):
        self._fail_with("runner_on_failed", "something went wrong", failed=True)
        self.assertEqual(self.key.error_message, "something went wrong")


class KeyRunsRefreshTests(TestCase):
    def test_the_runs_list_rides_along_with_the_panel(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))
        host = Host.objects.create(name="web01")
        with mock.patch("runs.executor.dispatch"):
            response = self.client.post(
                reverse("host_key_provision", args=[host.pk]),
                {"username": "root", "password": "typed-in"},
            )
        self.assertContains(response, 'id="key-runs"')
        self.assertContains(response, "hx-swap-oob")
        self.assertContains(response, "Key install")


class HostListRenderTests(TestCase):
    def test_the_count_reflects_every_host_not_just_this_page(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))
        Host.objects.create(name="web01")
        Host.objects.create(name="web02")
        response = self.client.get(reverse("host_list"))
        self.assertContains(response, "2 managed machines")
