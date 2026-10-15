# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import views

urlpatterns = [
    path("", views.overview, name="admin_notifications"),
    path("channels/new/", views.channel_edit, name="admin_channel_create"),
    path("channels/<int:pk>/", views.channel_edit, name="admin_channel_edit"),
    path("channels/<int:pk>/delete/", views.channel_delete, name="admin_channel_delete"),
    path("channels/<int:pk>/test/", views.channel_test, name="admin_channel_test"),
]
