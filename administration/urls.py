# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import views

urlpatterns = [
    path("", views.overview, name="admin_overview"),
    path("general/", views.general, name="admin_general"),
    path("general/modules/", views.refresh_modules, name="admin_refresh_modules"),
    path("ldap/", views.ldap, name="admin_ldap"),
    path("vault/", views.vault, name="admin_vault"),
    path("sso/", views.sso, name="admin_sso"),
    path("directory/", views.directory_groups, name="admin_directory"),
    path("directory/<int:pk>/", views.directory_group_update, name="admin_directory_update"),
    path("users/", views.users, name="admin_users"),
    path("users/new/", views.user_create, name="admin_user_create"),
    path("users/<int:pk>/", views.user_edit, name="admin_user_edit"),
    path("users/<int:pk>/codes/reset/", views.user_codes_reset, name="admin_user_codes_reset"),
    path("audit/", views.audit_log, name="admin_audit"),
]
