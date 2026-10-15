# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import views

urlpatterns = [
    path("", views.catalog_home, name="catalog_home"),
    path("items/new/", views.item_edit, name="catalog_item_create"),
    path("items/<int:pk>/edit/", views.item_edit, name="catalog_item_update"),
    path("items/<int:pk>/delete/", views.item_delete, name="catalog_item_delete"),
    path("items/<int:pk>/request/", views.request_new, name="catalog_request_new"),
    path("requests/<int:pk>/", views.request_detail, name="catalog_request_detail"),
    path("requests/<int:pk>/<str:action>/", views.request_action, name="catalog_request_action"),
]
