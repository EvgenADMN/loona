# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import views

urlpatterns = [
    path("hosts/", views.HostList.as_view(), name="host_list"),
    path("hosts/new/", views.HostCreate.as_view(), name="host_create"),
    path("hosts/<int:pk>/", views.HostDetail.as_view(), name="host_detail"),
    path("hosts/<int:pk>/edit/", views.HostUpdate.as_view(), name="host_update"),
    path("hosts/<int:pk>/history/", views.host_history, name="host_history"),
    path("hosts/<int:pk>/facts/", views.host_facts, name="host_facts"),
    path("hosts/<int:pk>/facts/gather/", views.host_gather_facts, name="host_gather_facts"),
    path("hosts/<int:pk>/delete/", views.HostDelete.as_view(), name="host_delete"),
    path("hosts/probe/", views.host_probe, name="host_probe"),
    path("hosts/<int:pk>/key/", views.host_key, name="host_key"),
    path("hosts/<int:pk>/key/status/", views.host_key_status, name="host_key_status"),
    path("hosts/<int:pk>/key/provision/", views.host_key_provision, name="host_key_provision"),
    path("hosts/<int:pk>/key/revoke/", views.host_key_revoke, name="host_key_revoke"),
    path("hosts/<int:pk>/key/forget/", views.host_key_forget, name="host_key_forget"),
    path("hosts/<int:pk>/host-key/forget/", views.host_forget_host_key, name="host_forget_host_key"),
    path("groups/", views.GroupList.as_view(), name="group_list"),
    path("groups/new/", views.GroupCreate.as_view(), name="group_create"),
    path("groups/<int:pk>/", views.GroupDetail.as_view(), name="group_detail"),
    path("groups/<int:pk>/gather-facts/", views.group_gather_facts, name="group_gather_facts"),
    path("groups/<int:pk>/edit/", views.GroupUpdate.as_view(), name="group_update"),
    path("groups/<int:pk>/delete/", views.GroupDelete.as_view(), name="group_delete"),
    path("credentials/", views.CredentialList.as_view(), name="credential_list"),
    path("credentials/new/", views.CredentialCreate.as_view(), name="credential_create"),
    path("credentials/<int:pk>/edit/", views.CredentialUpdate.as_view(), name="credential_update"),
    path("credentials/<int:pk>/delete/", views.CredentialDelete.as_view(), name="credential_delete"),
]
