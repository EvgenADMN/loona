# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase
from django.urls import reverse

from inventory.models import HostGroup

from .models import DirectoryAccount, DirectoryGroup, GroupGrant, Role


class TeamPagesTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.root = User.objects.create_superuser("root", password="x")
        self.client.force_login(self.root)
        self.team = Group.objects.create(name="ops")
        self.web = HostGroup.objects.create(name="web")
        self.local = User.objects.create_user("local")
        self.ldap_user = User.objects.create_user("alice")
        DirectoryAccount.objects.create(
            user=self.ldap_user, dn="uid=alice,dc=x", granted_team_ids=[self.team.pk]
        )
        self.ldap_user.groups.add(self.team)
        self.link = DirectoryGroup.objects.create(dn="cn=ops,dc=x", name="ops", team=self.team)

    def url(self, name, *args):
        return reverse(name, args=[self.team.pk, *args])

    def test_the_team_page_shows_roles_members_and_ldap_groups(self):
        GroupGrant.objects.create(team=self.team, host_group=self.web, role=Role.ADMIN)
        response = self.client.get(self.url("team_detail"))
        self.assertContains(response, "web")
        self.assertContains(response, "Admin")
        self.assertContains(response, "alice")
        self.assertContains(response, "cn=ops,dc=x")

    def test_granting_a_group_twice_changes_the_role(self):
        self.client.post(self.url("team_grant_add"), {"host_group": self.web.pk, "role": Role.VIEWER})
        self.client.post(self.url("team_grant_add"), {"host_group": self.web.pk, "role": Role.OPERATOR})
        self.assertEqual(GroupGrant.objects.get(team=self.team).role, Role.OPERATOR)

    def test_removing_a_role(self):
        grant = GroupGrant.objects.create(team=self.team, host_group=self.web, role=Role.ADMIN)
        self.client.post(self.url("team_grant_remove", grant.pk))
        self.assertFalse(GroupGrant.objects.exists())

    def test_a_local_member_can_be_added_and_removed(self):
        self.client.post(self.url("team_member_add"), {"user": self.local.pk})
        self.assertIn(self.team, self.local.groups.all())
        self.client.post(self.url("team_member_remove", self.local.pk))
        self.assertNotIn(self.team, self.local.groups.all())

    def test_an_ldap_member_is_not_removed_by_hand(self):
        # The next sign-in would quietly put them back.
        response = self.client.post(self.url("team_member_remove", self.ldap_user.pk), follow=True)
        self.assertContains(response, "through LDAP")
        self.assertIn(self.team, self.ldap_user.groups.all())

    def test_ldap_accounts_are_not_offered_for_an_ldap_fed_team(self):
        other = get_user_model().objects.create_user("bob")
        DirectoryAccount.objects.create(user=other, dn="uid=bob,dc=x")
        response = self.client.post(self.url("team_member_add"), {"user": other.pk})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.team, other.groups.all())

    def test_linking_and_unlinking_a_directory_group(self):
        devs = Group.objects.create(name="devs")
        self.client.post(
            reverse("team_directory_link", args=[devs.pk]), {"directory_group": self.link.pk}
        )
        self.link.refresh_from_db()
        self.assertEqual(self.link.team, devs)
        self.client.post(reverse("team_directory_unlink", args=[devs.pk, self.link.pk]))
        self.link.refresh_from_db()
        self.assertIsNone(self.link.team)

    def test_deleting_a_team_keeps_the_directory_group_known(self):
        self.client.post(self.url("team_delete"))
        self.assertFalse(Group.objects.filter(pk=self.team.pk).exists())
        self.link.refresh_from_db()
        self.assertIsNone(self.link.team)


class TeamPermissionTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("dev")
        self.client.force_login(self.user)
        self.team = Group.objects.create(name="ops")

    def test_the_pages_need_the_change_group_permission(self):
        for url in (reverse("team_list"), reverse("team_detail", args=[self.team.pk])):
            self.assertEqual(self.client.get(url).status_code, 403)
        grant_url = reverse("team_grant_add", args=[self.team.pk])
        web = HostGroup.objects.create(name="web")
        self.client.post(grant_url, {"host_group": web.pk, "role": Role.ADMIN})
        self.assertFalse(GroupGrant.objects.exists())

    def test_superusers_find_teams_under_administration_not_in_the_header(self):
        root = get_user_model().objects.create_superuser("root")
        self.client.force_login(root)
        header = self.client.get(reverse("dashboard")).content.decode().split('<main')[0]
        self.assertNotIn('href="/access/teams/"', header)
        self.assertNotIn('href="/inventory/credentials/"', header)
        self.assertContains(self.client.get(reverse("credential_list")), 'class="admin-nav"')
        page = self.client.get(reverse("team_list"))
        self.assertContains(page, 'class="admin-nav"')

    def test_with_the_permission_the_nav_shows_teams(self):
        self.assertNotContains(self.client.get(reverse("dashboard")), "Teams")
        self.user.user_permissions.add(Permission.objects.get(codename="change_group"))
        self.client.force_login(get_user_model().objects.get(pk=self.user.pk))
        self.assertContains(self.client.get(reverse("dashboard")), "Teams")
        self.assertEqual(self.client.get(reverse("team_list")).status_code, 200)
