# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import protocol, views

urlpatterns = [
    path("", views.executor_list, name="executor_list"),
    path("new/", views.executor_create, name="executor_create"),
    path("<int:pk>/", views.executor_detail, name="executor_detail"),
    path("<int:pk>/token/", views.executor_token, name="executor_token"),
    path("<int:pk>/delete/", views.executor_delete, name="executor_delete"),
]

protocol_urlpatterns = [
    path("claim/", protocol.claim, name="executor_claim"),
    path("jobs/<int:job_id>/events/", protocol.events, name="executor_events"),
    path("jobs/<int:job_id>/finish/", protocol.finish, name="executor_finish"),
]
