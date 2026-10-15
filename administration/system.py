# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The one place Loona reads its runtime settings from.

Every process - web, worker, scheduler - reads the SystemSettings row
through here and keeps it for a few seconds, so a change made in the UI
reaches all of them without a restart.
"""
from __future__ import annotations

import time

from django.conf import settings

# Seconds a process trusts its copy. The test runner sets 0.
TTL = 5.0
_cache: dict = {"at": 0.0, "row": None}


def get():
    from .models import SystemSettings

    now = time.monotonic()
    row = _cache["row"]
    if row is not None and now - _cache["at"] < TTL:
        return row
    row = SystemSettings.objects.filter(pk=1).first() or _first_row()
    _cache.update(at=now, row=row)
    return row


def invalidate():
    _cache.update(at=0.0, row=None)


def for_editing():
    """A fresh copy of the row for a settings form - never the cached one.

    The cached copy may be seconds old in this process, and a form writes
    every field of the row back, so saving it could undo a change just made
    through another process.  A form also writes what was typed into its
    instance before validating, which must not leak into the shared copy.
    """
    from .models import SystemSettings

    return SystemSettings.objects.filter(pk=1).first() or _first_row()


def _first_row():
    """Start from what the environment said, so upgrading changes nothing."""
    from .models import SystemSettings

    env = settings.LOONA_LDAP
    row = SystemSettings(
        pk=1,
        max_job_events=settings.LOONA_MAX_JOB_EVENTS,
        ldap_server_uri=env["SERVER_URI"],
        ldap_start_tls=env["START_TLS"],
        ldap_verify_tls=env["VERIFY_TLS"],
        ldap_timeout=env["TIMEOUT"],
        ldap_bind_dn=env["BIND_DN"],
        ldap_user_base=env["USER_BASE"],
        ldap_user_filter=env["USER_FILTER"],
        ldap_username_attr=env["USERNAME_ATTR"],
        ldap_email_attr=env["EMAIL_ATTR"],
        ldap_first_name_attr=env["FIRST_NAME_ATTR"],
        ldap_last_name_attr=env["LAST_NAME_ATTR"],
        ldap_group_base=env["GROUP_BASE"],
        ldap_group_filter=env["GROUP_FILTER"],
        ldap_group_name_attr=env["GROUP_NAME_ATTR"],
        ldap_mirror_groups=env["MIRROR_GROUPS"],
        ldap_require_group=env["REQUIRE_GROUP"],
        ldap_superuser_group=env["SUPERUSER_GROUP"],
        ldap_staff_group=env["STAFF_GROUP"],
        ldap_recheck_minutes=env["RECHECK_MINUTES"],
    )
    row.ldap_bind_password = env["BIND_PASSWORD"]
    row.save()
    return row


def ldap_conf() -> dict:
    """LDAP settings in the shape access.ldap expects.

    Once LDAP is switched on in Administration those settings rule; until
    then whatever the environment configures keeps working as before.
    """
    row = get()
    if not row.ldap_enabled:
        return {**settings.LOONA_LDAP, "CA_DATA": "", "SOURCE": "environment"}
    return {
        "SOURCE": "administration",
        "SERVER_URI": row.ldap_server_uri,
        "START_TLS": row.ldap_start_tls,
        "VERIFY_TLS": row.ldap_verify_tls,
        "CA_FILE": "",
        "CA_DATA": row.ldap_ca_certificate,
        "TIMEOUT": row.ldap_timeout,
        "BIND_DN": row.ldap_bind_dn,
        "BIND_PASSWORD": row.ldap_bind_password,
        "USER_BASE": row.ldap_user_base,
        "USER_FILTER": row.ldap_user_filter,
        "USERNAME_ATTR": row.ldap_username_attr,
        "EMAIL_ATTR": row.ldap_email_attr,
        "FIRST_NAME_ATTR": row.ldap_first_name_attr,
        "LAST_NAME_ATTR": row.ldap_last_name_attr,
        "GROUP_BASE": row.ldap_group_base,
        "GROUP_FILTER": row.ldap_group_filter,
        "GROUP_NAME_ATTR": row.ldap_group_name_attr,
        "MIRROR_GROUPS": row.ldap_mirror_groups,
        "REQUIRE_GROUP": row.ldap_require_group,
        "SUPERUSER_GROUP": row.ldap_superuser_group,
        "STAFF_GROUP": row.ldap_staff_group,
        "RECHECK_MINUTES": row.ldap_recheck_minutes,
    }
