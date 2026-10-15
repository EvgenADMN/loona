# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.apps import AppConfig


class SecretstoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "secretstore"
    verbose_name = "Secrets"
