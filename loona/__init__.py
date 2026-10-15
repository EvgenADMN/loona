# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from .celery import app as celery_app

__all__ = ("celery_app",)
