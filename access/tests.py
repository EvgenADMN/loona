# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase
from django.urls import reverse

from inventory.models import Credential, Host, HostGroup
from playbooks.models import Playbook, PlaybookTask
from runs.models import Job

from . import policy
from .models import GroupGrant, Role


class AccessTestCase(TestCase):
    """Two teams, each with its own corner of the inventory.

        prod ── prod-web ── web1
          └──── prod-db  ── db1
        staging ────────── stage1
        (no group) ─────── stray
    """

    def setUp(self):
        User = get_user_model()
        self.prod = HostGroup.objects.create(name="prod")
        self.web = HostGroup.objects.create(name="prod-web")
        self.db = HostGroup.objects.create(name="prod-db")
        self.web.parents.add(self.prod)
        self.db.parents.add(self.prod)
        self.staging = HostGroup.objects.create(name="staging")

        self.web1 = Host.objects.create(name="web1")
        self.web1.groups.add(self.web)
        self.db1 = Host.objects.create(name="db1")
        self.db1.groups.add(self.db)
        self.stage1 = Host.objects.create(name="stage1")
        self.stage1.groups.add(self.staging)
        self.stray = Host.objects.create(name="stray")

        self.ops = Group.objects.create(name="ops")
        self.devs = Group.objects.create(name="devs")
        self.user = User.objects.create_user("dev", password="x")
        self.user.groups.add(self.devs)
        self.client.force_login(self.user)

        self.playbook = Playbook.objects.create(name="Ping")
        PlaybookTask.objects.create(playbook=self.playbook, module="ansible.builtin.ping")

    def grant(self, group, role, team=None):
        GroupGrant.objects.create(team=team or self.devs, host_group=group, role=role)

    def allow(self, codename):
        self.devs.permissions.add(Permission.objects.get(codename=codename))

    def access(self):
        # A fresh user object, so nothing cached on the old one leaks through.
        return policy.for_user(get_user_model().objects.get(pk=self.user.pk))


class PolicyTests(AccessTestCase):
    def test_a_grant_covers_every_group_nested_under_it(self):
        self.grant(self.prod, Role.VIEWER)
        access = self.access()
        self.assertEqual(set(access.hosts()), {self.web1, self.db1})
        self.assertEqual(access.role_for_group(self.db), Role.VIEWER)

    def test_the_strongest_grant_wins(self):
        self.grant(self.prod, Role.VIEWER)
        self.grant(self.web, Role.ADMIN)
        access = self.access()
        self.assertEqual(access.role_for_host(self.web1), Role.ADMIN)
        self.assertEqual(access.role_for_host(self.db1), Role.VIEWER)

    def test_other_teams_grants_do_not_count(self):
        self.grant(self.prod, Role.ADMIN, team=self.ops)
        self.assertEqual(list(self.access().hosts()), [])

    def test_a_host_in_no_group_is_for_superusers_only(self):
        self.grant(self.prod, Role.ADMIN)
        self.assertNotIn(self.stray, self.access().hosts())
        root = get_user_model().objects.create_superuser("root", password="x")
        self.assertIn(self.stray, policy.for_user(root).hosts())

    def test_a_job_is_only_as_visible_as_its_least_visible_target(self):
        self.grant(self.prod, Role.VIEWER)
        mine = Job.objects.create(playbook_name="p", playbook_yaml="")
        mine.target_hosts.add(self.web1)
        mixed = Job.objects.create(playbook_name="p", playbook_yaml="")
        mixed.target_hosts.add(self.web1, self.stage1)
        by_group = Job.objects.create(playbook_name="p", playbook_yaml="")
        by_group.target_groups.add(self.prod)
        untargeted = Job.objects.create(playbook_name="p", playbook_yaml="")
        self.assertEqual(set(self.access().jobs()), {mine, by_group})
        self.assertNotIn(untargeted, self.access().jobs())


class HostViewTests(AccessTestCase):
    def test_a_host_you_cannot_see_is_not_found(self):
        response = self.client.get(reverse("host_detail", args=[self.stage1.pk]))
        self.assertEqual(response.status_code, 404)

    def test_a_viewer_sees_the_host_but_cannot_edit_it(self):
        self.grant(self.prod, Role.VIEWER)
        self.assertEqual(
            self.client.get(reverse("host_detail", args=[self.web1.pk])).status_code, 200
        )
        for name in ("host_update", "host_delete", "host_key"):
            response = self.client.get(reverse(name, args=[self.web1.pk]))
            self.assertEqual(response.status_code, 403, name)

    def test_the_host_list_only_shows_your_hosts(self):
        self.grant(self.staging, Role.VIEWER)
        response = self.client.get(reverse("host_list"))
        self.assertContains(response, "stage1")
        self.assertNotContains(response, "web1")
        self.assertNotContains(response, "Add host")

    def _host_data(self, **overrides):
        data = {"name": "new1", "address": "", "port": 22, "credential": "",
                "groups": [], "enabled": "on", "description": "", "variables": ""}
        data.update(overrides)
        return data

    def test_a_new_host_must_land_in_a_group_you_administer(self):
        self.grant(self.web, Role.ADMIN)
        response = self.client.post(reverse("host_create"), self._host_data())
        self.assertContains(response, "at least one group you administer")
        response = self.client.post(
            reverse("host_create"), self._host_data(groups=[self.staging.pk])
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Host.objects.filter(name="new1").exists())
        response = self.client.post(
            reverse("host_create"), self._host_data(groups=[self.web.pk])
        )
        self.assertEqual(response.status_code, 302)

    def test_editing_keeps_memberships_you_cannot_manage(self):
        self.grant(self.web, Role.ADMIN)
        self.web1.groups.add(self.staging)
        response = self.client.post(
            reverse("host_update", args=[self.web1.pk]),
            self._host_data(name="web1", groups=[self.web.pk]),
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(set(self.web1.groups.all()), {self.web, self.staging})

    def test_only_credentials_shared_with_your_team_can_be_attached(self):
        self.grant(self.web, Role.ADMIN)
        secret = Credential.objects.create(name="root-pw", kind=Credential.KIND_PASSWORD)
        response = self.client.post(
            reverse("host_update", args=[self.web1.pk]),
            self._host_data(name="web1", groups=[self.web.pk], credential=secret.pk),
        )
        self.assertEqual(response.status_code, 200)
        self.web1.refresh_from_db()
        self.assertIsNone(self.web1.credential)

        secret.teams.add(self.devs)
        response = self.client.post(
            reverse("host_update", args=[self.web1.pk]),
            self._host_data(name="web1", groups=[self.web.pk], credential=secret.pk),
        )
        self.assertEqual(response.status_code, 302)

    def test_a_probe_cannot_borrow_a_credential_you_were_not_given(self):
        self.grant(self.web, Role.ADMIN)
        secret = Credential.objects.create(name="root-pw", kind=Credential.KIND_PASSWORD)
        with patch("inventory.views.probe.check_connection") as check:
            self.client.post(
                reverse("host_probe"), {"address": "10.0.0.9", "credential": secret.pk}
            )
        check.assert_not_called()

    def test_a_probe_needs_admin_somewhere(self):
        self.grant(self.web, Role.OPERATOR)
        response = self.client.post(reverse("host_probe"), {"address": "10.0.0.9"})
        self.assertEqual(response.status_code, 403)


class GroupViewTests(AccessTestCase):
    def _group_data(self, **overrides):
        data = {"name": "new", "description": "", "parents": [], "variables": ""}
        data.update(overrides)
        return data

    def test_a_new_group_must_nest_under_one_you_administer(self):
        self.grant(self.prod, Role.ADMIN)
        response = self.client.post(reverse("group_create"), self._group_data())
        self.assertContains(response, "Nest the new group")
        response = self.client.post(
            reverse("group_create"), self._group_data(parents=[self.prod.pk])
        )
        self.assertEqual(response.status_code, 302)

    def test_you_cannot_hang_a_group_under_one_you_do_not_administer(self):
        # Moving your group under someone else's would hand them your hosts,
        # and theirs to you if it went the other way.
        self.grant(self.web, Role.ADMIN)
        self.grant(self.staging, Role.VIEWER)
        response = self.client.post(
            reverse("group_update", args=[self.web.pk]),
            self._group_data(name="prod-web", parents=[self.staging.pk]),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(self.web.parents.all()), {self.prod})

    def test_saving_a_group_keeps_parents_you_cannot_manage(self):
        self.grant(self.web, Role.ADMIN)
        response = self.client.post(
            reverse("group_update", args=[self.web.pk]),
            self._group_data(name="prod-web", description="edited"),
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(set(self.web.parents.all()), {self.prod})

    def test_a_viewer_cannot_delete_the_group(self):
        self.grant(self.prod, Role.VIEWER)
        response = self.client.post(reverse("group_delete", args=[self.prod.pk]))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(HostGroup.objects.filter(pk=self.prod.pk).exists())


class LaunchTests(AccessTestCase):
    def _post(self, **overrides):
        data = {"target_groups": [], "target_hosts": [], "limit": "", "extra_vars": "",
                "tags": "", "skip_tags": "", "forks": 5, "verbosity": 0}
        data.update(overrides)
        return self.client.post(reverse("job_launch", args=[self.playbook.pk]), data)

    def test_a_viewer_cannot_launch(self):
        self.grant(self.prod, Role.VIEWER)
        self.assertEqual(self._post(target_groups=[self.prod.pk]).status_code, 403)

    @patch("runs.services.dispatch")
    def test_an_operator_launches_on_their_own_hosts(self, dispatch):
        self.grant(self.prod, Role.OPERATOR)
        response = self._post(target_groups=[self.prod.pk])
        self.assertEqual(response.status_code, 302)
        dispatch.assert_called_once()

    @patch("runs.services.dispatch")
    def test_an_operator_cannot_reach_past_their_hosts(self, dispatch):
        self.grant(self.prod, Role.OPERATOR)
        self._post(target_hosts=[self.web1.pk, self.stage1.pk])
        self._post(target_groups=[self.staging.pk])
        dispatch.assert_not_called()
        self.assertEqual(Job.objects.count(), 0)

    @patch("runs.services.dispatch")
    def test_extra_vars_cannot_redirect_the_connection(self, dispatch):
        self.grant(self.prod, Role.OPERATOR)
        response = self._post(
            target_groups=[self.prod.pk], extra_vars="ansible_host: 203.0.113.9"
        )
        self.assertContains(response, "ansible_host")
        dispatch.assert_not_called()
        self._post(target_groups=[self.prod.pk], extra_vars="release: 42")
        dispatch.assert_called_once()

    @patch("runs.services.dispatch")
    def test_no_ansible_variable_gets_past_an_operator(self, dispatch):
        # These run commands on the Loona server, not on the host.
        self.grant(self.prod, Role.OPERATOR)
        for name in ("ansible_scp_extra_args", "ansible_sftp_extra_args", "ansible_shell_executable",
                     "ansible_python_interpreter", "ANSIBLE_SSH_COMMON_ARGS"):
            response = self._post(target_groups=[self.prod.pk], extra_vars=f"{name}: -o ProxyCommand=x")
            self.assertContains(response, name)
        dispatch.assert_not_called()

    def test_a_viewer_cannot_cancel_a_run(self):
        self.grant(self.prod, Role.VIEWER)
        job = Job.objects.create(playbook_name="p", playbook_yaml="", status=Job.RUNNING)
        job.target_hosts.add(self.web1)
        response = self.client.post(reverse("job_cancel", args=[job.pk]))
        self.assertEqual(response.status_code, 403)
        job.refresh_from_db()
        self.assertFalse(job.canceled)


class GlobalPermissionTests(AccessTestCase):
    def test_editing_playbooks_takes_the_django_permission(self):
        url = reverse("playbook_settings", args=[self.playbook.pk])
        self.assertEqual(self.client.get(url).status_code, 403)
        self.allow("change_playbook")
        self.assertEqual(self.client.get(url).status_code, 200)

    def test_anyone_signed_in_can_read_a_playbook(self):
        response = self.client.get(reverse("playbook_detail", args=[self.playbook.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Add task")
        self.assertNotContains(response, "Run playbook")

    def test_credentials_take_the_django_permission(self):
        self.assertEqual(self.client.get(reverse("credential_list")).status_code, 403)
        self.allow("change_credential")
        self.assertEqual(self.client.get(reverse("credential_list")).status_code, 200)
