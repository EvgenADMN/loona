# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import project_views, views

urlpatterns = [
    path("projects/", project_views.project_list, name="project_list"),
    path("projects/new/", project_views.project_edit, name="project_create"),
    path("projects/<int:pk>/", project_views.project_detail, name="project_detail"),
    path("projects/<int:pk>/edit/", project_views.project_edit, name="project_update"),
    path("projects/<int:pk>/delete/", project_views.project_delete, name="project_delete"),
    path("projects/<int:pk>/check/", project_views.project_check, name="project_check"),
    path("projects/<int:pk>/files/new/", project_views.file_edit, name="project_file_create"),
    path("projects/<int:pk>/files/<int:file_pk>/", project_views.file_edit, name="project_file_edit"),
    path("projects/<int:pk>/files/<int:file_pk>/delete/", project_views.file_delete, name="project_file_delete"),
    path("", views.playbook_list, name="playbook_list"),
    path("new/", views.playbook_create, name="playbook_create"),
    path("<int:pk>/", views.playbook_detail, name="playbook_detail"),
    path("<int:pk>/settings/", views.playbook_settings, name="playbook_settings"),
    path("<int:pk>/save-text/", views.playbook_save_text, name="playbook_save_text"),
    path("<int:pk>/delete/", views.playbook_delete, name="playbook_delete"),
    path("<int:pk>/duplicate/", views.playbook_duplicate, name="playbook_duplicate"),
    path("<int:pk>/switch-mode/", views.playbook_switch_mode, name="playbook_switch_mode"),
    path("<int:pk>/import/", views.playbook_import, name="playbook_import"),
    path("<int:pk>/export/", views.playbook_export, name="playbook_export"),
    path("<int:pk>/tasks/new/", views.task_create, name="task_create"),
    path("<int:pk>/tasks/fields/", views.task_fields, name="task_fields"),
    path("<int:pk>/modules/search/", views.module_search, name="module_search"),
    path("tasks/<int:pk>/edit/", views.task_update, name="task_update"),
    path("tasks/<int:pk>/delete/", views.task_delete, name="task_delete"),
    path("tasks/<int:pk>/toggle/", views.task_toggle, name="task_toggle"),
    path("tasks/<int:pk>/move/<str:direction>/", views.task_move, name="task_move"),
]
