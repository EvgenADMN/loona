# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from executors.urls import protocol_urlpatterns
from signin.views import admin_login

# Django admin signs in through Loona's own page, one-time codes included.
admin.site.login = admin_login

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("signin.urls")),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", include("core.urls")),
    path("inventory/", include("inventory.urls")),
    path("playbooks/", include("playbooks.urls")),
    path("runs/", include("runs.urls")),
    path("access/", include("access.urls")),
    path("infra/", include("infra.urls")),
    path("secrets/", include("secretstore.urls")),
    path("catalog/", include("catalog.urls")),
    path("workflows/", include("workflows.urls")),
    path("api/executor/v1/", include(protocol_urlpatterns)),
    path("api/", include("api.urls")),
    path("account/", include("api.ui_urls")),
    path("administration/notifications/", include("notifications.urls")),
    path("administration/executors/", include("executors.urls")),
    path("administration/", include("administration.urls")),
]
