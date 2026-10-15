# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""What OIDC and SAML sign-ins have in common: the Loona user behind them.

The provider is matched by its subject identifier, never by username alone:
an identity provider that lets people pick a username must not be a way
into the break-glass admin account.  Groups become teams exactly as LDAP
groups do (access.ldap), recorded in "Directory groups" as
``oidc:<group>`` / ``saml:<group>``.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.translation import gettext as _

from access.ldap import _sync_teams
from access.models import DirectoryAccount, dn_key

from .models import SsoIdentity

log = logging.getLogger("loona.sso")
USERNAME = re.compile(r"^[\w.@+-]{1,150}$")


class Refused(Exception):
    """A sign-in Loona will not accept; the message is for the person."""


@dataclass
class Claims:
    protocol: str
    issuer: str
    subject: str
    username: str
    email: str = ""
    first_name: str = ""
    last_name: str = ""
    groups: list[str] = field(default_factory=list)


@dataclass
class _Found:
    """The shape access.ldap._sync_teams expects."""

    groups: dict


def conf():
    from administration import system

    return system.get()


def as_list(value) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v)]
    return [str(value)]


def group_names(values) -> list[str]:
    # Keycloak sends "/devops" for a top-level group, "/a/b" for a nested one.
    return sorted({v.strip().lstrip("/") for v in as_list(values) if v.strip().lstrip("/")})


def _may_take_over(user) -> bool:
    """Only an account nobody can sign in to by other means: no superuser, no
    password of its own, no one-time codes.  Whoever controls a username at
    the provider must not inherit more than that."""
    from .models import TotpDevice

    return (not user.is_superuser and not user.has_usable_password()
            and not TotpDevice.objects.filter(user=user).exists())


@transaction.atomic
def user_for(claims: Claims):
    row = conf()
    if not claims.subject:
        raise Refused(_("The identity provider did not say who you are."))
    if not USERNAME.match(claims.username or ""):
        raise Refused(_("The identity provider sent no usable username (%(name)r).") % {"name": claims.username})
    if row.sso_require_group and row.sso_require_group not in claims.groups:
        log.info("SSO user %s is not in %s", claims.username, row.sso_require_group)
        raise Refused(_("Your account is not in the group that may use Loona."))

    User = get_user_model()
    identity = SsoIdentity.objects.select_related("user").filter(
        protocol=claims.protocol, issuer=claims.issuer, subject=claims.subject).first()
    if identity is not None:
        user = identity.user
    else:
        user = User.objects.filter(username=claims.username).first()
        if user is not None:
            taken = SsoIdentity.objects.filter(user=user).exists()
            if not taken and row.sso_link_existing and not _may_take_over(user):
                log.warning("SSO user %s matches a superuser or an account with its own password or "
                            "codes; never taken over", claims.username)
                raise Refused(_("An account named %(name)s already exists in Loona and signs in on its "
                                "own; single sign-on does not take such accounts over.") % {"name": claims.username})
            if taken or not row.sso_link_existing:
                log.warning("SSO user %s matches an existing account; refusing to take it over",
                            claims.username)
                raise Refused(_("An account named %(name)s already exists in Loona. An administrator "
                                "has to let single sign-on take it over.") % {"name": claims.username})
            # Became an SSO account: the directory no longer speaks for it.
            DirectoryAccount.objects.filter(user=user).delete()
        else:
            user = User(username=claims.username)
            user.set_unusable_password()
            user.save()
        identity = SsoIdentity.objects.create(user=user, protocol=claims.protocol,
                                              issuer=claims.issuer, subject=claims.subject)
    if not user.is_active:
        raise Refused(_("This account is locked in Loona."))

    user.email = (claims.email or user.email)[:254]
    user.first_name = (claims.first_name or user.first_name)[:150]
    user.last_name = (claims.last_name or user.last_name)[:150]
    if row.sso_superuser_group:
        user.is_superuser = user.is_staff = row.sso_superuser_group in claims.groups
    user.save()
    groups = {dn_key(f"{claims.protocol}:{name}"): (f"{claims.protocol}:{name}", name)
              for name in claims.groups}
    _sync_teams(user, identity, _Found(groups=groups), mirror=row.sso_mirror_groups != "mapped")
    return user
