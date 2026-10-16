# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""LDAP sign-in against ldap3's in-memory directory.

The tree used throughout:

    dc=example,dc=org
      ou=people   alice, bob, admin (the service account)
      ou=groups   devs     <- alice
                  backend  <- bob             (groupOfUniqueNames)
                  eng      <- devs, backend   (nested)
                  root     <- alice
                  legacy   <- memberUid bob   (posixGroup)
"""
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import Group
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse
from ldap3 import MODIFY_DELETE, MOCK_SYNC, NONE, Connection, Server

from ldap3.core.exceptions import LDAPSocketOpenError

from . import ldap as loona_ldap
from . import middleware
from .models import DirectoryAccount, DirectoryGroup, GroupGrant, Role, dn_key

BASE = "dc=example,dc=org"
PEOPLE = f"ou=people,{BASE}"
GROUPS = f"ou=groups,{BASE}"
ALICE = f"uid=alice,{PEOPLE}"
BOB = f"uid=bob,{PEOPLE}"
SERVICE = f"cn=admin,{BASE}"

CONF = {
    **settings.LOONA_LDAP,
    "SERVER_URI": "ldap://directory.test",
    "BIND_DN": SERVICE,
    "BIND_PASSWORD": "service-pw",
    "USER_BASE": PEOPLE,
    "GROUP_BASE": GROUPS,
}


def build_directory():
    server = Server("directory.test", get_info=NONE)
    conn = Connection(server, user=SERVICE, password="service-pw", client_strategy=MOCK_SYNC)
    add = conn.strategy.add_entry
    add(SERVICE, {"objectClass": ["person"], "cn": "admin", "userPassword": "service-pw"})
    add(ALICE, {"objectClass": ["inetOrgPerson"], "uid": "alice", "userPassword": "alice-pw",
                "mail": "alice@example.org", "givenName": "Alice", "sn": "Liddell"})
    add(BOB, {"objectClass": ["inetOrgPerson"], "uid": "bob", "userPassword": "bob-pw"})
    add(f"cn=devs,{GROUPS}", {"objectClass": ["groupOfNames"], "cn": "devs", "member": [ALICE]})
    add(f"cn=backend,{GROUPS}", {"objectClass": ["groupOfUniqueNames"], "cn": "backend",
                                 "uniqueMember": [BOB]})
    add(f"cn=eng,{GROUPS}", {"objectClass": ["groupOfNames"], "cn": "eng",
                             "member": [f"cn=devs,{GROUPS}", f"cn=backend,{GROUPS}"]})
    add(f"cn=root,{GROUPS}", {"objectClass": ["groupOfNames"], "cn": "root", "member": [ALICE]})
    add(f"cn=legacy,{GROUPS}", {"objectClass": ["posixGroup"], "cn": "legacy",
                                "memberUid": ["bob"]})
    return server, conn


class LdapTestCase(TestCase):
    def setUp(self):
        self.server, self.conn = build_directory()
        server = self.server

        class InMemory(loona_ldap.Directory):
            def __init__(self, conf):
                super().__init__(conf, server=server, strategy=MOCK_SYNC)

        original = loona_ldap.LdapBackend.directory_factory
        loona_ldap.LdapBackend.directory_factory = InMemory
        self.addCleanup(setattr, loona_ldap.LdapBackend, "directory_factory", original)

    def sign_in(self, username, password, **conf):
        with override_settings(LOONA_LDAP={**CONF, **conf}):
            return authenticate(username=username, password=password)

    def remove_member(self, group_dn, member_dn):
        self.conn.bind()
        self.conn.modify(group_dn, {"member": [(MODIFY_DELETE, [member_dn])]})
        assert self.conn.result["result"] == 0, self.conn.result

    def teams(self, user):
        return set(user.groups.values_list("name", flat=True))


class SignInTests(LdapTestCase):
    def test_a_directory_user_signs_in_and_gets_a_local_account(self):
        user = self.sign_in("alice", "alice-pw")
        self.assertEqual(user.username, "alice")
        self.assertEqual(user.email, "alice@example.org")
        self.assertEqual(user.get_full_name(), "Alice Liddell")
        self.assertFalse(user.has_usable_password())
        self.assertEqual(user.directory_account.dn, ALICE)

    def test_a_wrong_password_is_refused(self):
        self.assertIsNone(self.sign_in("alice", "wrong"))
        self.assertFalse(get_user_model().objects.filter(username="alice").exists())

    def test_an_empty_password_never_reaches_the_server(self):
        # Many servers treat it as an anonymous bind and say yes.
        self.assertIsNone(self.sign_in("alice", ""))

    def test_filter_characters_in_the_login_are_escaped(self):
        self.assertIsNone(self.sign_in("*", "alice-pw"))
        self.assertIsNone(self.sign_in("alice)(uid=*", "alice-pw"))

    def test_ldap_is_off_without_a_server(self):
        self.assertIsNone(self.sign_in("alice", "alice-pw", SERVER_URI=""))

    def test_a_local_account_with_the_same_name_is_not_taken_over(self):
        get_user_model().objects.create_superuser("alice", password="local-pw")
        self.assertIsNone(self.sign_in("alice", "alice-pw"))
        # The local password still works through the ordinary backend.
        self.assertIsNotNone(self.sign_in("alice", "local-pw"))

    def test_a_user_disabled_in_loona_stays_out(self):
        user = self.sign_in("alice", "alice-pw")
        user.is_active = False
        user.save()
        self.assertIsNone(self.sign_in("alice", "alice-pw"))

    def test_the_required_group_gates_sign_in(self):
        conf = {"REQUIRE_GROUP": f"cn=root,{GROUPS}"}
        self.assertIsNotNone(self.sign_in("alice", "alice-pw", **conf))
        self.assertIsNone(self.sign_in("bob", "bob-pw", **conf))


class GroupMappingTests(LdapTestCase):
    def test_every_group_becomes_a_team_nested_ones_included(self):
        alice = self.sign_in("alice", "alice-pw")
        self.assertEqual(self.teams(alice), {"devs", "eng", "root"})
        bob = self.sign_in("bob", "bob-pw")
        self.assertEqual(self.teams(bob), {"backend", "eng", "legacy"})

    def test_a_team_set_up_before_ldap_keeps_its_roles(self):
        from inventory.models import HostGroup

        devs = Group.objects.create(name="devs")
        GroupGrant.objects.create(
            team=devs, host_group=HostGroup.objects.create(name="web"), role=Role.OPERATOR
        )
        alice = self.sign_in("alice", "alice-pw")
        self.assertIn(devs, alice.groups.all())
        self.assertEqual(DirectoryGroup.objects.get(name="devs").team, devs)

    def test_a_remapped_group_moves_its_members_to_the_new_team(self):
        self.sign_in("alice", "alice-pw")
        platform = Group.objects.create(name="platform")
        DirectoryGroup.objects.filter(name="devs").update(team=platform)
        alice = self.sign_in("alice", "alice-pw")
        self.assertIn("platform", self.teams(alice))
        self.assertNotIn("devs", self.teams(alice))

    def test_leaving_a_directory_group_leaves_the_team(self):
        self.sign_in("alice", "alice-pw")
        self.remove_member(f"cn=root,{GROUPS}", ALICE)
        alice = self.sign_in("alice", "alice-pw")
        self.assertNotIn("root", self.teams(alice))

    def test_local_teams_are_left_alone(self):
        alice = self.sign_in("alice", "alice-pw")
        oncall = Group.objects.create(name="oncall")
        alice.groups.add(oncall)
        alice = self.sign_in("alice", "alice-pw")
        self.assertIn("oncall", self.teams(alice))

    def test_mapped_mode_only_honours_groups_an_admin_linked(self):
        alice = self.sign_in("alice", "alice-pw", MIRROR_GROUPS="mapped")
        self.assertEqual(self.teams(alice), set())
        # The groups are recorded, waiting for someone to map them.
        self.assertTrue(DirectoryGroup.objects.filter(name="devs", team=None).exists())
        DirectoryGroup.objects.filter(name="devs").update(
            team=Group.objects.create(name="developers")
        )
        alice = self.sign_in("alice", "alice-pw", MIRROR_GROUPS="mapped")
        self.assertEqual(self.teams(alice), {"developers"})

    def test_a_group_can_be_mapped_before_anyone_from_it_signs_in(self):
        team = Group.objects.create(name="developers")
        DirectoryGroup.objects.create(dn=f"CN=devs, OU=groups, DC=example, DC=org", team=team)
        alice = self.sign_in("alice", "alice-pw", MIRROR_GROUPS="mapped")
        self.assertEqual(self.teams(alice), {"developers"})

    def test_the_superuser_flag_follows_the_directory(self):
        conf = {"SUPERUSER_GROUP": f"cn=root,{GROUPS}"}
        alice = self.sign_in("alice", "alice-pw", **conf)
        self.assertTrue(alice.is_superuser and alice.is_staff)
        self.remove_member(f"cn=root,{GROUPS}", ALICE)
        alice = self.sign_in("alice", "alice-pw", **conf)
        self.assertFalse(alice.is_superuser or alice.is_staff)

    def test_the_directory_owns_accounts_only_it_created(self):
        self.sign_in("alice", "alice-pw")
        self.assertEqual(DirectoryAccount.objects.count(), 1)


@override_settings(LOONA_LDAP=CONF)
class SessionRecheckTests(LdapTestCase):
    """A signed-in directory user follows the directory, not their old sign-in."""

    def setUp(self):
        super().setUp()
        response = self.client.post(reverse("login"), {"username": "alice", "password": "alice-pw"})
        self.assertEqual(response.status_code, 302)

    def time_passes(self):
        session = self.client.session
        session[middleware.SESSION_KEY] = 0
        session.save()

    def test_a_group_change_applies_without_signing_in_again(self):
        self.remove_member(f"cn=root,{GROUPS}", ALICE)
        self.client.get(reverse("dashboard"))
        self.assertIn("root", self.teams(get_user_model().objects.get(username="alice")))
        self.time_passes()
        self.client.get(reverse("dashboard"))
        self.assertNotIn("root", self.teams(get_user_model().objects.get(username="alice")))

    def test_a_user_removed_from_the_directory_is_signed_out(self):
        self.conn.bind()
        self.conn.delete(ALICE)
        self.time_passes()
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, reverse("login"), fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_leaving_the_required_group_signs_out(self):
        with override_settings(LOONA_LDAP={**CONF, "REQUIRE_GROUP": f"cn=root,{GROUPS}"}):
            self.remove_member(f"cn=root,{GROUPS}", ALICE)
            self.time_passes()
            response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_the_directory_being_down_does_not_sign_anyone_out(self):
        class Unreachable:
            def __init__(self, conf):
                pass

            def lookup(self, username):
                raise LDAPSocketOpenError("connection refused")

        self.time_passes()
        with patch.object(loona_ldap.LdapBackend, "directory_factory", Unreachable):
            response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_local_accounts_are_never_checked(self):
        get_user_model().objects.create_superuser("root", password="x")
        self.client.force_login(get_user_model().objects.get(username="root"))
        self.time_passes()
        with patch.object(loona_ldap.LdapBackend, "directory_factory") as factory:
            self.client.get(reverse("dashboard"))
        factory.assert_not_called()


class DnKeyTests(TestCase):
    def test_case_and_spacing_do_not_matter(self):
        self.assertEqual(dn_key("CN=Ops, OU=Groups,DC=Example"), "cn=ops,ou=groups,dc=example")

    def test_an_escaped_comma_stays_part_of_the_name(self):
        self.assertEqual(dn_key("cn=Doe\\, John,ou=people"), "cn=doe\\, john,ou=people")
        self.assertNotEqual(dn_key("cn=Doe\\, John,ou=people"), dn_key("cn=Doe\\,John,ou=people"))



@override_settings(LOONA_LDAP=CONF)
class TokenRecheckTests(LdapTestCase):
    """An API token is only as good as its owner's standing in the directory."""

    def test_a_token_dies_with_the_directory_account(self):
        from datetime import timedelta

        from django.utils import timezone
        from rest_framework.test import APIClient

        from api.models import ApiToken

        alice = authenticate(username="alice", password="alice-pw")
        _, raw = ApiToken.issue(alice, "ci")
        api = APIClient()
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        self.assertEqual(api.get("/api/v1/me/").status_code, 200)

        self.conn.bind()
        self.conn.delete(ALICE)
        # Within the re-check interval the token still works; after it, not.
        self.assertEqual(api.get("/api/v1/me/").status_code, 200)
        DirectoryAccount.objects.filter(user=alice).update(synced_at=timezone.now() - timedelta(hours=1))
        self.assertEqual(api.get("/api/v1/me/").status_code, 401)

    def test_the_first_request_after_a_demotion_is_already_demoted(self):
        from datetime import timedelta

        from django.utils import timezone
        from rest_framework.test import APIClient

        from api.models import ApiToken

        conf = {**CONF, "SUPERUSER_GROUP": f"cn=root,{GROUPS}"}
        with override_settings(LOONA_LDAP=conf):
            alice = authenticate(username="alice", password="alice-pw")
            self.assertTrue(alice.is_superuser)
            _, raw = ApiToken.issue(alice, "ci")
            api = APIClient()
            api.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
            self.remove_member(f"cn=root,{GROUPS}", ALICE)
            DirectoryAccount.objects.filter(user=alice).update(synced_at=timezone.now() - timedelta(hours=1))
            response = api.get("/api/v1/me/")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["superuser"])

    def test_a_trigger_stops_with_its_owners_directory_account(self):
        from datetime import timedelta

        from django.utils import timezone

        from api.models import Trigger
        from playbooks.models import Playbook

        alice = authenticate(username="alice", password="alice-pw")
        trigger = Trigger(name="ci", action=Trigger.PREVIEW, playbook=Playbook.objects.create(name="p"),
                          run_as=alice)
        secret = trigger.new_secret()
        trigger.save()
        self.conn.bind()
        self.conn.delete(ALICE)
        DirectoryAccount.objects.filter(user=alice).update(synced_at=timezone.now() - timedelta(hours=1))
        response = self.client.post(f"/api/v1/triggers/{trigger.pk}/fire/",
                                    HTTP_X_LOONA_TRIGGER_TOKEN=secret)
        self.assertEqual(response.status_code, 403)
        self.assertIn("owner", response.json()["detail"])

    def test_a_disabled_active_directory_account_is_out(self):
        from ldap3 import MODIFY_REPLACE

        from django.utils import timezone
        from datetime import timedelta

        alice = authenticate(username="alice", password="alice-pw")
        self.conn.bind()
        self.conn.modify(ALICE, {"userAccountControl": [(MODIFY_REPLACE, ["514"])]})
        self.assertIsNone(authenticate(username="alice", password="alice-pw"))
        DirectoryAccount.objects.filter(user=alice).update(synced_at=timezone.now() - timedelta(hours=1))
        self.assertFalse(middleware.directory_still_allows(alice))
        self.conn.modify(ALICE, {"userAccountControl": [(MODIFY_REPLACE, ["512"])]})
        self.assertIsNotNone(authenticate(username="alice", password="alice-pw"))
