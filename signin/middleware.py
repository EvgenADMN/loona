# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Required one-time codes reach sessions that were open before the rule."""
from django.shortcuts import redirect

from . import mfa

ALLOWED_PREFIXES = ("/account/security/", "/logout/", "/static/", "/api/", "/login/", "/language/", "/theme/")


class RequireCodesMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if (
            user is not None and user.is_authenticated
            and request.session.get(mfa.METHOD, "password") == "password"
            and not request.path.startswith(ALLOWED_PREFIXES)
            and mfa.required_for(user) and not mfa.has_codes(user)
        ):
            return redirect("account_security")
        return self.get_response(request)
