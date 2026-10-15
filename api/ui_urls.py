# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import ui

urlpatterns = [
    path("tokens/", ui.tokens, name="api_tokens"),
    path("tokens/<int:pk>/revoke/", ui.token_revoke, name="api_token_revoke"),
    path("triggers/", ui.triggers, name="api_triggers"),
    path("triggers/<int:pk>/delete/", ui.trigger_delete, name="api_trigger_delete"),
    path("triggers/<int:pk>/toggle/", ui.trigger_toggle, name="api_trigger_toggle"),
]
