# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import views

urlpatterns = [
    path("", views.workflow_list, name="workflow_list"),
    path("new/", views.workflow_edit, name="workflow_create"),
    path("<int:pk>/", views.workflow_detail, name="workflow_detail"),
    path("<int:pk>/edit/", views.workflow_edit, name="workflow_update"),
    path("<int:pk>/delete/", views.workflow_delete, name="workflow_delete"),
    path("<int:pk>/run/", views.workflow_start, name="workflow_start"),
    path("<int:pk>/steps/new/", views.step_edit, name="workflow_step_create"),
    path("<int:pk>/steps/<int:step_pk>/", views.step_edit, name="workflow_step_update"),
    path("<int:pk>/steps/<int:step_pk>/delete/", views.step_delete, name="workflow_step_delete"),
    path("runs/<int:pk>/", views.run_detail, name="workflow_run"),
    path("runs/<int:pk>/cancel/", views.run_cancel, name="workflow_run_cancel"),
    path("runs/<int:pk>/nodes/<int:node_pk>/decide/", views.node_decide, name="workflow_node_decide"),
]
