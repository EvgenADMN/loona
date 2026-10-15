# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import views

urlpatterns = [
    path("teams/", views.team_list, name="team_list"),
    path("teams/new/", views.team_create, name="team_create"),
    path("teams/<int:pk>/", views.team_detail, name="team_detail"),
    path("teams/<int:pk>/rename/", views.team_rename, name="team_rename"),
    path("teams/<int:pk>/delete/", views.team_delete, name="team_delete"),
    path("teams/<int:pk>/members/add/", views.member_add, name="team_member_add"),
    path("teams/<int:pk>/members/<int:user_pk>/remove/", views.member_remove, name="team_member_remove"),
    path("teams/<int:pk>/grants/add/", views.grant_add, name="team_grant_add"),
    path("teams/<int:pk>/grants/<int:grant_pk>/remove/", views.grant_remove, name="team_grant_remove"),
    path("teams/<int:pk>/directory/link/", views.directory_link, name="team_directory_link"),
    path("teams/<int:pk>/directory/<int:link_pk>/unlink/", views.directory_unlink, name="team_directory_unlink"),
    path("groups/<int:group_pk>/windows/new/", views.window_add, name="window_add"),
    path("windows/<int:pk>/delete/", views.window_delete, name="window_delete"),
]
