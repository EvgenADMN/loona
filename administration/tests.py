# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from ldap3 import MOCK_SYNC

from access import ldap as loona_ldap
from access.models import DirectoryAccount, DirectoryGroup
from access.tests_ldap import ALICE, GROUPS, PEOPLE, SERVICE, build_directory
from inventory.models import HostGroup
from runs.housekeeping import forget_old_runs
from runs.models import Job

from . import system
from .models import AuditEntry, SystemSettings

User = get_user_model()


class AdminTestCase(TestCase):
    def setUp(self):
        self.root = User.objects.create_superuser("root", password="Root-pass-123")
        self.client.force_login(self.root)

    def settings_row(self):
        system.invalidate()
        return system.get()


class AccessTests(AdminTestCase):
    def test_only_superusers_get_in(self):
        someone = User.objects.create_user("dev", password="Dev-pass-123", is_staff=True)
        self.client.force_login(someone)
        for name in ("admin_overview", "admin_general", "admin_ldap", "admin_directory",
                     "admin_users", "admin_user_create", "admin_audit"):
            self.assertEqual(self.client.get(reverse(name)).status_code, 403, name)
        self.assertNotContains(self.client.get(reverse("dashboard")), "Administration")

    def test_the_overview_reports_the_system(self):
        with self.settings(LOONA_RUNNER_MODE="thread"):
            page = self.client.get(reverse("admin_overview"))
        self.assertContains(page, "PostgreSQL")
        self.assertContains(page, "thread mode")


class GeneralSettingsTests(AdminTestCase):
    def general(self, stale=False, **changes):
        row = self.settings_row()
        if stale:
            # Another process changes the row after this one took its copy.
            SystemSettings.objects.filter(pk=1).update(**stale)
        data = {f: getattr(row, f) for f in (
            "instance_name", "public_url", "language", "session_hours", "local_login", "mfa_policy",
            "default_approval_policy",
            "job_retention_days", "max_job_events", "bootstrap_wait_seconds")}
        data["module_docs"] = "on" if row.module_docs else ""
        data.update(changes)
        return self.client.post(reverse("admin_general"), data)

    def test_the_instance_name_shows_in_the_header_and_the_change_is_audited(self):
        self.general(instance_name="Production")
        self.assertContains(self.client.get(reverse("dashboard")), '<span class="instance">Production</span>')
        entry = AuditEntry.objects.get()
        self.assertEqual(entry.changes["instance_name"], ["", "Production"])
        self.assertEqual(entry.user, self.root)

    def test_saving_one_section_keeps_what_another_process_just_saved(self):
        # This process holds a copy from before; another web process then
        # saves Vault settings.  Saving General here must not undo them.
        with patch.object(system, "TTL", 60.0):
            self.general(stale={"hcv_address": "https://vault.example.com"}, instance_name="Production")
        row = SystemSettings.objects.get(pk=1)
        self.assertEqual((row.instance_name, row.hcv_address), ("Production", "https://vault.example.com"))

    def test_a_refused_form_leaves_the_shared_copy_alone(self):
        with patch.object(system, "TTL", 60.0):
            self.general(public_url="https://typed.example.com", session_hours=-1)
            self.assertEqual(system.get().public_url, SystemSettings.objects.get(pk=1).public_url)

    def test_a_sign_in_lasts_as_long_as_configured(self):
        self.general(session_hours=3)
        self.client.logout()
        self.client.post(reverse("login"), {"username": "root", "password": "Root-pass-123"})
        self.assertEqual(self.client.session.get_expiry_age(), 3 * 3600)

    def test_local_sign_in_can_be_kept_for_superusers(self):
        User.objects.create_user("dev", password="Dev-pass-123")
        self.general(local_login="superusers")
        self.assertIsNone(authenticate(username="dev", password="Dev-pass-123"))
        self.assertIsNotNone(authenticate(username="root", password="Root-pass-123"))

    def test_new_groups_start_with_the_default_approval_rule(self):
        self.general(default_approval_policy="changes")
        self.client.post(reverse("group_create"), {"name": "fresh", "description": "", "parents": [],
                                                   "variables": "", "approval_policy": "changes"})
        self.assertEqual(HostGroup.objects.get(name="fresh").approval_policy, "changes")
        page = self.client.get(reverse("group_create"))
        self.assertContains(page, '<option value="changes" selected>')

    def test_bad_values_are_refused(self):
        response = self.general(session_hours=0, bootstrap_wait_seconds=1)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(AuditEntry.objects.exists())

    def test_old_runs_are_forgotten_after_the_retention_period(self):
        self.general(job_retention_days=30)
        old = Job.objects.create(playbook_name="old", status=Job.SUCCESSFUL,
                                 finished_at=timezone.now() - timedelta(days=31))
        recent = Job.objects.create(playbook_name="recent", status=Job.SUCCESSFUL,
                                    finished_at=timezone.now() - timedelta(days=2))
        running = Job.objects.create(playbook_name="running", status=Job.RUNNING)
        self.assertEqual(forget_old_runs(), 1)
        self.assertEqual(set(Job.objects.all()), {recent, running})
        self.assertFalse(Job.objects.filter(pk=old.pk).exists())


class LdapSettingsTests(AdminTestCase):
    def setUp(self):
        super().setUp()
        self.server, self.conn = build_directory()
        server = self.server

        class InMemory(loona_ldap.Directory):
            def __init__(self, conf):
                super().__init__(conf, server=server, strategy=MOCK_SYNC)

        patcher = patch.object(loona_ldap.LdapBackend, "directory_factory", InMemory)
        patcher.start()
        self.addCleanup(patcher.stop)

    def data(self, **changes):
        row = self.settings_row()
        from .forms import LDAP_FIELDS

        data = {f: getattr(row, f) for f in LDAP_FIELDS}
        data.update({
            "ldap_enabled": "on", "ldap_server_uri": "ldap://directory.test",
            "ldap_bind_dn": SERVICE, "bind_password": "service-pw",
            "ldap_user_base": PEOPLE, "ldap_group_base": GROUPS,
            "ldap_start_tls": "", "ldap_verify_tls": "on",
        })
        data.update(changes)
        return {k: ("" if v is False else "on" if v is True else v) for k, v in data.items()}

    def test_saving_turns_ldap_on_and_the_password_stays_secret(self):
        self.client.post(reverse("admin_ldap"), {**self.data(), "save": "1"})
        row = self.settings_row()
        self.assertTrue(row.ldap_enabled)
        self.assertEqual(row.ldap_bind_password, "service-pw")
        self.assertNotIn("service-pw", row.ldap_bind_password_encrypted)
        entry = AuditEntry.objects.get()
        self.assertNotIn("service-pw", str(entry.changes))
        self.assertEqual(system.ldap_conf()["SOURCE"], "administration")
        # And people sign in through it.
        self.assertEqual(authenticate(username="alice", password="alice-pw").username, "alice")

    def test_test_connection_shows_groups_and_teams_before_saving(self):
        Group.objects.create(name="devs")
        response = self.client.post(reverse("admin_ldap"), {**self.data(test_username="alice"), "test": "1"})
        self.assertContains(response, "Works")
        self.assertContains(response, f"Found {ALICE}")
        self.assertContains(response, "→ devs")
        self.assertContains(response, "eng (created at first sign-in)")
        self.assertFalse(self.settings_row().ldap_enabled, "a test must not save")

    def test_a_wrong_service_password_is_reported(self):
        response = self.client.post(reverse("admin_ldap"), {**self.data(bind_password="nope"), "test": "1"})
        self.assertContains(response, "Failed")

    def test_the_stored_password_is_kept_when_the_field_is_left_empty(self):
        self.client.post(reverse("admin_ldap"), {**self.data(), "save": "1"})
        self.client.post(reverse("admin_ldap"), {**self.data(bind_password=""), "save": "1"})
        self.assertEqual(self.settings_row().ldap_bind_password, "service-pw")

    def test_enabling_needs_a_server(self):
        response = self.client.post(reverse("admin_ldap"), {**self.data(ldap_server_uri=""), "save": "1"})
        self.assertContains(response, "Needed to sign anyone in")
        self.assertFalse(self.settings_row().ldap_enabled)


class DirectoryMappingTests(AdminTestCase):
    def test_map_ahead_change_and_forget(self):
        ops = Group.objects.create(name="ops")
        self.client.post(reverse("admin_directory"), {"dn": "cn=ops,ou=groups,dc=x", "name": "", "team": ops.pk})
        link = DirectoryGroup.objects.get()
        self.assertEqual((link.name, link.team), ("ops", ops))
        platform = Group.objects.create(name="platform")
        self.client.post(reverse("admin_directory_update", args=[link.pk]), {"team": platform.pk})
        link.refresh_from_db()
        self.assertEqual(link.team, platform)
        self.client.post(reverse("admin_directory_update", args=[link.pk]), {"delete": "1"})
        self.assertFalse(DirectoryGroup.objects.exists())
        self.assertEqual(AuditEntry.objects.count(), 3)


class UserTests(AdminTestCase):
    def edit(self, person, **changes):
        data = {"first_name": person.first_name, "last_name": person.last_name, "email": person.email,
                "is_active": "on" if person.is_active else "", "is_superuser": "on" if person.is_superuser else "",
                "teams": [], "new_password": ""}
        data.update(changes)
        return self.client.post(reverse("admin_user_edit", args=[person.pk]), data)

    def test_create_a_local_user_in_teams(self):
        ops = Group.objects.create(name="ops")
        self.client.post(reverse("admin_user_create"), {
            "username": "dana", "first_name": "", "last_name": "", "email": "",
            "password": "Dana-pass-123", "teams": [ops.pk]})
        dana = User.objects.get(username="dana")
        self.assertTrue(dana.check_password("Dana-pass-123"))
        self.assertEqual(list(dana.groups.all()), [ops])
        self.assertNotIn("Dana-pass-123", str(AuditEntry.objects.get().changes))

    def test_you_cannot_lock_yourself_out_or_drop_your_own_superuser(self):
        self.assertContains(self.edit(self.root, is_active=""), "lock yourself out")
        self.assertContains(self.edit(self.root, is_superuser=""), "your own superuser")
        self.root.refresh_from_db()
        self.assertTrue(self.root.is_active and self.root.is_superuser)

    def test_another_superuser_can_be_demoted_but_not_yourself(self):
        # Reaching this form takes being an active superuser, so demoting
        # someone else never leaves Loona without one; demoting yourself could.
        other = User.objects.create_superuser("other", password="Other-pass-123")
        self.edit(other, is_superuser="")
        other.refresh_from_db()
        self.assertFalse(other.is_superuser)
        self.assertContains(self.edit(self.root, is_superuser=""), "your own superuser")

    def test_directory_teams_survive_an_edit(self):
        alice = User.objects.create_user("alice")
        ldap_team = Group.objects.create(name="devs")
        local_team = Group.objects.create(name="oncall")
        alice.groups.add(ldap_team)
        DirectoryAccount.objects.create(user=alice, dn=ALICE, granted_team_ids=[ldap_team.pk])
        self.edit(alice, teams=[local_team.pk], first_name="Mallory")
        alice.refresh_from_db()
        self.assertEqual(set(alice.groups.all()), {ldap_team, local_team})
        self.assertEqual(alice.first_name, "", "the directory owns the name")
