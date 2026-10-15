# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.utils import translation

from . import system


class SystemLanguageMiddleware:
    """The interface in the person's own language, else the one chosen in
    Administration; the API in English."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        language = system.get().language
        if request.path.startswith("/api/"):
            # Scripts and their authors read the API: one language, always.
            language = "en"
        else:
            from core.models import UserPreference

            language = UserPreference.language_for(request.user) or language
        translation.activate(language)
        request.LANGUAGE_CODE = language
        response = self.get_response(request)
        response.headers.setdefault("Content-Language", language)
        return response
