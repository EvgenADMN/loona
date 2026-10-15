# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import views

urlpatterns = [
    path("", views.secret_list, name="secret_list"),
    path("new/", views.secret_edit, name="secret_create"),
    path("<int:pk>/", views.secret_edit, name="secret_update"),
    path("<int:pk>/delete/", views.secret_delete, name="secret_delete"),
]
