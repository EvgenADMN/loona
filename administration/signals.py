# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from . import system


@receiver(user_logged_in)
def _session_length(sender, request, user, **kwargs):
    if request is not None and hasattr(request, "session"):
        request.session.set_expiry(system.get().session_hours * 3600)
