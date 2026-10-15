# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class TokenScheme(OpenApiAuthenticationExtension):
    target_class = "api.auth.TokenAuthentication"
    name = "LoonaToken"

    def get_security_definition(self, auto_schema):
        return {"type": "http", "scheme": "bearer", "description": "A personal token: loona_..."}
