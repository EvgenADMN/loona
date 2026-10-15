# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Sign-in against a real directory server.

Skipped unless LOONA_LDAP_TEST_URI points at a server holding the tree these
tests expect (dc=example,dc=org; alice, bob and carol in ou=people, their groups
in ou=groups, cn=admin with password admin-pw):

    LOONA_LDAP_TEST_URI=ldap://localhost:3389 python manage.py test access.tests_ldap_live
"""
import os
import unittest

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse

from inventory.models import Host, HostGroup

from .models import DirectoryGroup, GroupGrant, Role

URI = os.getenv("LOONA_LDAP_TEST_URI", "")
BASE = "dc=example,dc=org"

LIVE = {
    **settings.LOONA_LDAP,
    "SERVER_URI": URI,
    "BIND_DN": f"cn=admin,{BASE}",
    "BIND_PASSWORD": "admin-pw",
    "USER_BASE": f"ou=people,{BASE}",
    "GROUP_BASE": f"ou=groups,{BASE}",
    "SUPERUSER_GROUP": f"cn=loona-admins,ou=groups,{BASE}",
}


@unittest.skipUnless(URI, "set LOONA_LDAP_TEST_URI to run against a real server")
@override_settings(LOONA_LDAP=LIVE)
class LiveDirectoryTests(TestCase):
    def log_in(self, username, password):
        return self.client.post(
            reverse("login"), {"username": username, "password": password}
        )

    def teams(self, username):
        user = get_user_model().objects.get(username=username)
        return set(user.groups.values_list("name", flat=True))

    def test_nested_groups_become_teams(self):
        self.assertEqual(self.log_in("alice", "alice-pw").status_code, 302)
        self.assertEqual(self.teams("alice"), {"devs", "eng"})

    def test_unique_member_and_posix_groups_count_too(self):
        self.assertEqual(self.log_in("bob", "bob-pw").status_code, 302)
        self.assertEqual(self.teams("bob"), {"backend", "eng", "legacy"})

    def test_the_admin_group_makes_a_superuser(self):
        self.log_in("carol", "carol-pw")
        carol = get_user_model().objects.get(username="carol")
        self.assertTrue(carol.is_superuser and carol.is_staff)

    def test_a_wrong_password_stays_on_the_login_page(self):
        response = self.log_in("alice", "nope")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_a_role_on_the_mapped_team_reaches_the_hosts(self):
        # The whole chain: nested directory group -> team -> role -> host.
        web = HostGroup.objects.create(name="web")
        Host.objects.create(name="web1").groups.add(web)
        eng = Group.objects.create(name="eng")
        GroupGrant.objects.create(team=eng, host_group=web, role=Role.OPERATOR)

        self.log_in("alice", "alice-pw")
        self.assertEqual(DirectoryGroup.objects.get(name="eng").team, eng)
        response = self.client.get(reverse("host_list"))
        self.assertContains(response, "web1")
