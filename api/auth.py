# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from datetime import timedelta

from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import TOKEN_PREFIX, ApiToken, hash_token


class TokenAuthentication(authentication.BaseAuthentication):
    """Authorization: Bearer loona_... - acts as the token's owner."""

    keyword = "Bearer"

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).decode(errors="replace")
        if not header.startswith(f"{self.keyword} {TOKEN_PREFIX}"):
            return None
        raw = header[len(self.keyword) + 1:].strip()
        token = ApiToken.objects.select_related("user").filter(token_hash=hash_token(raw)).first()
        if token is None or not token.is_live:
            raise exceptions.AuthenticationFailed("Unknown, expired or revoked token.")
        user = token.user
        if not user.is_active:
            raise exceptions.AuthenticationFailed("The token's owner cannot sign in.")
        from access.middleware import directory_still_allows

        if not directory_still_allows(user):
            raise exceptions.AuthenticationFailed("The directory no longer lets this user in.")
        # A write per request is waste; a minute's precision is plenty.
        now = timezone.now()
        if token.last_used_at is None or now - token.last_used_at > timedelta(minutes=1):
            ApiToken.objects.filter(pk=token.pk).update(last_used_at=now)
        return user, token

    def authenticate_header(self, request):
        return self.keyword
