# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib import admin

from .models import Secret


@admin.register(Secret)
class SecretAdmin(admin.ModelAdmin):
    list_display = ["name", "host_group", "project", "updated_at"]
    # The value is encrypted and edited in Loona only.
    exclude = ["value_encrypted"]
