# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import state, views

urlpatterns = [
    path("state/<int:project_pk>/", state.state, name="tofu_state"),
    path("", views.project_list, name="tofu_project_list"),
    path("new/", views.project_create, name="tofu_project_create"),
    path("<int:pk>/", views.project_detail, name="tofu_project_detail"),
    path("<int:pk>/edit/", views.project_update, name="tofu_project_update"),
    path("<int:pk>/delete/", views.project_delete, name="tofu_project_delete"),
    path("<int:pk>/plan/", views.project_plan, name="tofu_project_plan"),
    path("hosts/<int:host_pk>/bootstrap/", views.host_bootstrap_retry, name="tofu_host_bootstrap"),
    path("<int:pk>/files/new/", views.file_edit, name="tofu_file_create"),
    path("<int:pk>/files/<int:file_pk>/", views.file_edit, name="tofu_file_edit"),
    path("<int:pk>/files/<int:file_pk>/delete/", views.file_delete, name="tofu_file_delete"),
    path("<int:pk>/variables/new/", views.variable_edit, name="tofu_variable_create"),
    path("<int:pk>/variables/<int:variable_pk>/", views.variable_edit, name="tofu_variable_edit"),
    path("<int:pk>/variables/<int:variable_pk>/delete/", views.variable_delete, name="tofu_variable_delete"),
]
