# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib import admin

from .models import Job, JobEvent


@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = ("id", "playbook_name", "status", "created_by", "created_at", "finished_at")
    list_filter = ("status", "check_mode")
    search_fields = ("playbook_name",)
    readonly_fields = ("playbook_yaml", "stats", "private_data_dir", "task_id")


@admin.register(JobEvent)
class JobEventAdmin(admin.ModelAdmin):
    list_display = ("job", "counter", "event", "host", "task")
    list_filter = ("event",)
    search_fields = ("host", "task", "stdout")
