# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Sign-in against LDAP or Active Directory, with groups mapped onto teams.

The flow on every sign-in:

1. Search for the user with the service account (or anonymously).
2. Bind as the user's DN with the typed password - that is the password check.
3. Collect the groups the user is in, following nested groups upwards.
4. Update the local user: name and mail, superuser/staff flags, and team
   membership - see :func:`sync_user`.

Built on ldap3 because it is pure Python: python-ldap needs a compiler and
the OpenLDAP headers, which is a poor first impression for an install.
"""
from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass, field

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group
from django.db import transaction
from ldap3 import NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars

from administration import system

from .models import DirectoryAccount, DirectoryGroup, dn_key

log = logging.getLogger("loona.ldap")

# How far up nested groups are followed.  Deep enough for any sane tree, and
# a hard stop for a directory with a membership loop.
MAX_NESTING = 10

MEMBER_ATTRS = ("member", "uniqueMember")


@dataclass
class DirectoryUser:
    dn: str
    username: str
    email: str = ""
    first_name: str = ""
    last_name: str = ""
    # dn_key -> (dn, display name)
    groups: dict[str, tuple[str, str]] = field(default_factory=dict)

    def in_group(self, dn: str) -> bool:
        return bool(dn) and dn_key(dn) in self.groups


class Directory:
    """One conversation with the directory server."""

    def __init__(self, conf: dict, server=None, strategy=None):
        self.conf = conf
        self.server = server or self._server()
        # Tests pass ldap3's MOCK_SYNC here to talk to an in-memory directory.
        self.strategy = strategy

    def _server(self):
        conf = self.conf
        tls = Tls(
            validate=ssl.CERT_REQUIRED if conf["VERIFY_TLS"] else ssl.CERT_NONE,
            ca_certs_file=conf.get("CA_FILE") or None,
            ca_certs_data=conf.get("CA_DATA") or None,
        )
        return Server(
            conf["SERVER_URI"], connect_timeout=conf["TIMEOUT"], tls=tls, get_info=NONE
        )

    def _connect(self, user=None, password=None) -> Connection:
        kwargs = {"receive_timeout": self.conf["TIMEOUT"], "raise_exceptions": False}
        if self.strategy:
            kwargs["client_strategy"] = self.strategy
        conn = Connection(self.server, user=user, password=password, **kwargs)
        conn.open()
        if self.conf["START_TLS"]:
            conn.start_tls()
        return conn

    def authenticate(self, username: str, password: str) -> DirectoryUser | None:
        return self._look_up(username, password=password)

    def lookup(self, username: str) -> DirectoryUser | None:
        """The user as the directory has them now, without a password check.

        For re-checking a signed-in session: None means the entry is gone.
        """
        return self._look_up(username, password=None)

    def _look_up(self, username, password):
        conf = self.conf
        service = self._connect(conf["BIND_DN"] or None, conf["BIND_PASSWORD"] or None)
        try:
            if not service.bind():
                # Not "no such user": the directory could not be asked at all.
                raise LDAPBindError(f"LDAP service bind failed: {service.result}")
            found = self._find_user(service, username)
            if found is None:
                return None
            if password is not None and not self._password_ok(found.dn, password):
                return None
            found.groups = self._groups_of(service, found)
            return found
        finally:
            service.unbind()

    def _find_user(self, conn, username) -> DirectoryUser | None:
        conf = self.conf
        query = conf["USER_FILTER"].format(username=escape_filter_chars(username))
        attrs = [
            a
            for a in (
                conf["USERNAME_ATTR"],
                conf["EMAIL_ATTR"],
                conf["FIRST_NAME_ATTR"],
                conf["LAST_NAME_ATTR"],
            )
            if a
        ]
        conn.search(conf["USER_BASE"], query, SUBTREE, attributes=attrs, size_limit=2)
        entries = conn.entries
        if len(entries) != 1:
            # None means no such user; two means the filter is ambiguous, and
            # guessing which one is meant is how the wrong person gets in.
            if entries:
                log.warning("LDAP filter %s matched more than one entry", query)
            return None
        entry = entries[0]
        return DirectoryUser(
            dn=entry.entry_dn,
            username=_first(entry, conf["USERNAME_ATTR"]) or username,
            email=_first(entry, conf["EMAIL_ATTR"]),
            first_name=_first(entry, conf["FIRST_NAME_ATTR"]),
            last_name=_first(entry, conf["LAST_NAME_ATTR"]),
        )

    def _password_ok(self, dn, password) -> bool:
        conn = self._connect(dn, password)
        try:
            return bool(conn.bind())
        finally:
            conn.unbind()

    def _groups_of(self, conn, user: DirectoryUser) -> dict[str, tuple[str, str]]:
        conf = self.conf
        if not conf["GROUP_BASE"]:
            return {}
        name_attr = conf["GROUP_NAME_ATTR"]

        # Direct membership: by DN for groupOfNames and AD, by login for posixGroup.
        terms = [f"({a}={escape_filter_chars(user.dn)})" for a in MEMBER_ATTRS]
        terms.append(f"(memberUid={escape_filter_chars(user.username)})")
        found: dict[str, tuple[str, str]] = {}
        frontier = self._search_groups(conn, terms, name_attr, found)

        # Then whatever those groups are themselves members of.
        for _ in range(MAX_NESTING):
            if not frontier:
                break
            terms = [
                f"({a}={escape_filter_chars(dn)})" for dn in frontier for a in MEMBER_ATTRS
            ]
            frontier = self._search_groups(conn, terms, name_attr, found)
        return found

    def _search_groups(self, conn, terms, name_attr, found) -> list[str]:
        """Add matching groups to ``found``; return the DNs that are new."""
        query = f"(&{self.conf['GROUP_FILTER']}(|{''.join(terms)}))"
        conn.search(self.conf["GROUP_BASE"], query, SUBTREE, attributes=[name_attr])
        new = []
        for entry in conn.entries:
            key = dn_key(entry.entry_dn)
            if key not in found:
                found[key] = (entry.entry_dn, _first(entry, name_attr) or entry.entry_dn)
                new.append(entry.entry_dn)
        return new


def _first(entry, attr) -> str:
    if not attr or attr not in entry.entry_attributes:
        return ""
    values = entry[attr].values
    return str(values[0]) if values else ""


# -- the local side -----------------------------------------------------------


@transaction.atomic
def sync_user(found: DirectoryUser, conf: dict):
    """Create or update the local user for a directory sign-in.

    Returns None when the sign-in must be refused on Loona's side.
    """
    User = get_user_model()
    if conf["REQUIRE_GROUP"] and not found.in_group(conf["REQUIRE_GROUP"]):
        log.info("LDAP user %s is not in the required group", found.username)
        return None

    user = User.objects.filter(username=found.username).first()
    if user is None:
        user = User(username=found.username)
        user.set_unusable_password()
    elif not DirectoryAccount.objects.filter(user=user).exists():
        log.warning(
            "LDAP user %s matches a local account; refusing to take it over",
            found.username,
        )
        return None

    user.email = found.email[:254]
    user.first_name = found.first_name[:150]
    user.last_name = found.last_name[:150]
    if conf["SUPERUSER_GROUP"]:
        user.is_superuser = found.in_group(conf["SUPERUSER_GROUP"])
    if conf["SUPERUSER_GROUP"] or conf["STAFF_GROUP"]:
        user.is_staff = user.is_superuser or found.in_group(conf["STAFF_GROUP"])
    user.save()
    account, _ = DirectoryAccount.objects.update_or_create(
        user=user, defaults={"dn": found.dn}
    )
    _sync_teams(user, account, found, mirror=conf["MIRROR_GROUPS"] != "mapped")
    return user


def _sync_teams(user, account, found: DirectoryUser, mirror: bool):
    wanted = set()
    for key, (dn, name) in found.groups.items():
        link = DirectoryGroup.objects.filter(dn_key=key).first()
        if link is None:
            link = DirectoryGroup(dn=dn, name=name[:255])
            if mirror:
                link.team = _team_for(name, dn)
        elif link.name != name[:255]:
            link.name = name[:255]
        link.save()
        if link.team_id:
            wanted.add(link.team_id)

    # Teams the directory owns: those any directory group points at, plus
    # whatever it granted this user last time.  Local teams are left alone -
    # they are managed by hand, in Loona.
    owned = set(
        DirectoryGroup.objects.exclude(team=None).values_list("team_id", flat=True)
    ) | set(account.granted_team_ids)
    current = set(user.groups.filter(pk__in=owned).values_list("pk", flat=True))
    if current - wanted:
        user.groups.remove(*(current - wanted))
    if wanted - current:
        user.groups.add(*(wanted - current))
    account.granted_team_ids = sorted(wanted)
    account.save(update_fields=["granted_team_ids", "synced_at"])


def _team_for(name: str, dn: str) -> Group:
    """The team a newly seen directory group lands in.

    A team of the same name that no directory group owns yet is adopted, so
    teams set up by hand before LDAP was switched on carry their roles over.
    Two directory groups with one name (cn=admins in two OUs) do not share a
    team by accident: the second gets its DN in the name.
    """
    team = Group.objects.filter(name=name[:150]).first()
    if team is None:
        return Group.objects.create(name=name[:150])
    if not team.directory_groups.exists():
        return team
    return Group.objects.get_or_create(name=f"{name} ({dn})"[:150])[0]


class LdapBackend(ModelBackend):
    """Authenticates against the directory; permissions work as for any user."""

    # Tests swap in an in-memory directory here.
    directory_factory = Directory

    def authenticate(self, request, username=None, password=None, **kwargs):
        conf = system.ldap_conf()
        # An empty password would be an anonymous bind, which most servers
        # accept - and which proves nothing.
        if not conf["SERVER_URI"] or not username or not password:
            return None
        try:
            found = self.directory_factory(conf).authenticate(username, password)
        except LDAPException:
            log.exception("LDAP sign-in for %s failed", username)
            return None
        if found is None:
            return None
        user = sync_user(found, conf)
        return user if user is not None and self.user_can_authenticate(user) else None
