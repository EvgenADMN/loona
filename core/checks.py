# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""What manage.py check --deploy says about Loona's own settings."""
from django.conf import settings
from django.core.checks import Tags, Warning, register


@register(Tags.security, deploy=True)
def loona_deploy(app_configs, **kwargs):
    found = []
    if not settings.LOONA_SECRET_STORE_KEY:
        found.append(Warning(
            "LOONA_SECRET_STORE_KEY is empty: stored secrets are encrypted with a key derived from "
            "LOONA_SECRET_KEY, so whoever learns one has both.", id="loona.W001"))
    if settings.DATABASES["default"].get("PASSWORD") in settings.PLACEHOLDER_SECRETS | {"loona"}:
        found.append(Warning("The database password is still the example's.", id="loona.W002"))
    return found
