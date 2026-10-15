# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Local sign-in, subject to the policy set in Administration."""
from django.contrib.auth.backends import ModelBackend

from . import system


class LocalBackend(ModelBackend):
    """Loona's own accounts. With "superusers only" set, everyone else goes
    through the directory; the superuser stays as the way in when LDAP is down.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        user = super().authenticate(request, username=username, password=password, **kwargs)
        if user is None:
            return None
        if system.get().local_login == "superusers" and not user.is_superuser:
            return None
        return user
