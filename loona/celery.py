# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Celery entry point for Loona."""
import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "loona.settings")

app = Celery("loona")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
