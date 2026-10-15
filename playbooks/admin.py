# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib import admin

from .models import Playbook, PlaybookTask


class TaskInline(admin.TabularInline):
    model = PlaybookTask
    extra = 0
    fields = ("order", "name", "module", "enabled")
    ordering = ("order",)


@admin.register(Playbook)
class PlaybookAdmin(admin.ModelAdmin):
    list_display = ("name", "mode", "become", "gather_facts", "updated_at")
    list_filter = ("mode", "become")
    search_fields = ("name", "description")
    inlines = [TaskInline]


@admin.register(PlaybookTask)
class PlaybookTaskAdmin(admin.ModelAdmin):
    list_display = ("playbook", "order", "name", "module", "enabled")
    list_filter = ("module", "enabled")
    search_fields = ("name", "module")
