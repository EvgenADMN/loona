# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("theme/", views.theme_toggle, name="theme_toggle"),
    path("language/", views.language_set, name="language_set"),
]
