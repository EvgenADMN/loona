# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Keep Loona's own keys away from the programs its runs start.

Ansible, ansible-galaxy and OpenTofu run as children of a Loona process and
execute code written by people Loona trusts less than its operator.  Two
things stand between that code and the master keys:

* The keys leave the environment as soon as the settings have read them, so
  no child inherits them (ansible-runner hands its children a copy of it).
* The process is marked non-dumpable: another process of the same user can
  then read neither its memory nor /proc/<pid>/environ, where the environment
  it started with is still kept.
"""
from __future__ import annotations

import ctypes
import os
import sys

# Variables that unlock something: the master keys, the database, the broker,
# the directory's service account, an executor's token.  (The first admin's
# password never reaches Loona's processes: the entrypoint passes it to
# createsuperuser alone.)
SECRET_VARIABLES = (
    "LOONA_SECRET_KEY",
    "LOONA_SECRET_STORE_KEY",
    "LOONA_DATABASE_URL",
    "LOONA_DB_PASSWORD",
    "LOONA_BROKER_URL",
    "LOONA_RESULT_BACKEND",
    "LOONA_LDAP_BIND_PASSWORD",
    "LOONA_REDIS_PASSWORD",
    "LOONA_EXECUTOR_TOKEN",
)
PR_SET_DUMPABLE = 4


def forget_secret_environment() -> None:
    for name in SECRET_VARIABLES:
        os.environ.pop(name, None)


def make_undumpable() -> bool:
    """True when the kernel took it (Linux); elsewhere there is nothing to do."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def harden() -> None:
    forget_secret_environment()
    make_undumpable()
