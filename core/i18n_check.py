# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Which form labels Django derives from field names - for core/i18n_labels.py."""
from __future__ import annotations

import importlib
import inspect

from django.forms import BaseForm
from django.forms.utils import pretty_name
from django.utils.functional import Promise

OWN_APPS = ("core", "inventory", "playbooks", "runs", "access", "infra", "administration",
            "notifications", "secretstore", "catalog", "workflows", "executors", "api")


def auto_labels() -> set[str]:
    found = set()
    for app in OWN_APPS:
        for module_name in ("forms", "views", "schedule_views", "template_views", "drift_views",
                            "project_views", "adhoc", "ui"):
            try:
                module = importlib.import_module(f"{app}.{module_name}")
            except ImportError:
                continue
            for _name, cls in inspect.getmembers(module, inspect.isclass):
                if not issubclass(cls, BaseForm) or cls.__module__ != module.__name__:
                    continue
                for field_name, field in cls.base_fields.items():
                    label = field.label
                    if label is None:
                        found.add(pretty_name(field_name))
                    elif isinstance(label, str) and not isinstance(label, Promise):
                        found.add(label)
    return {label for label in found if label.strip()}
