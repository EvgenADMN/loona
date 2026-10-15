# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.conf import settings

from .models import UserPreference
from .version import __version__


def loona(request):
    return {
        "LOONA_VERSION": __version__,
        "LOONA_RUNNER_MODE": settings.LOONA_RUNNER_MODE,
        # "" means no explicit choice: the page follows prefers-color-scheme.
        "LOONA_THEME": UserPreference.theme_for(getattr(request, "user", None)),
        # The person's own language choice ("" = the default) and the choices.
        "LOONA_LANGUAGE": UserPreference.language_for(getattr(request, "user", None)),
        "LOONA_LANGUAGES": settings.LANGUAGES,
    }
