# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib.auth.decorators import login_required
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerSplitView
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("hosts", views.HostViewSet, basename="api-host")
router.register("groups", views.HostGroupViewSet, basename="api-group")
router.register("playbooks", views.PlaybookViewSet, basename="api-playbook")
router.register("jobs", views.JobViewSet, basename="api-job")
router.register("opentofu", views.TofuProjectViewSet, basename="api-tofu")
router.register("drift", views.DriftCheckViewSet, basename="api-drift")
router.register("secrets", views.SecretViewSet, basename="api-secret")
router.register("schedules", views.ScheduleViewSet, basename="api-schedule")
router.register("templates", views.LaunchTemplateViewSet, basename="api-template")
router.register("workflows", views.WorkflowViewSet, basename="api-workflow")
router.register("workflow-runs", views.WorkflowRunViewSet, basename="api-workflow-run")
router.register("catalog/items", views.CatalogItemViewSet, basename="api-catalog-item")
router.register("catalog/requests", views.CatalogRequestViewSet, basename="api-catalog-request")

urlpatterns = [
    path("v1/me/", views.MeView.as_view(), name="api-me"),
    path("v1/adhoc/", views.AdhocView.as_view(), name="api-adhoc"),
    path("v1/triggers/<int:pk>/fire/", views.fire_trigger, name="api-trigger-fire"),
    path("v1/", include(router.urls)),
    path("schema/", SpectacularAPIView.as_view(), name="api-schema"),
    # The split view loads its start-up script from a URL: no inline script for the CSP to allow.
    path("docs/", login_required(SpectacularSwaggerSplitView.as_view(url_name="api-schema")), name="api-docs"),
]
