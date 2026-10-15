# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import drift_views, schedule_views, template_views, views

urlpatterns = [
    path("", views.job_list, name="job_list"),
    path("launch/<int:playbook_pk>/", views.job_launch, name="job_launch"),
    path("command/", views.adhoc_launch, name="adhoc_launch"),
    path("<int:pk>/", views.job_detail, name="job_detail"),
    path("<int:pk>/events/", views.job_events, name="job_events"),
    path("<int:pk>/cancel/", views.job_cancel, name="job_cancel"),
    path("<int:pk>/apply/", views.plan_apply, name="plan_apply"),
    path("<int:pk>/decide/", views.plan_decide, name="plan_decide"),
    path("drift/", drift_views.drift_list, name="drift_list"),
    path("drift/<int:pk>/run/", drift_views.drift_run, name="drift_run"),
    path("drift/<int:pk>/toggle/", drift_views.drift_toggle, name="drift_toggle"),
    path("drift/<int:pk>/delete/", drift_views.drift_delete, name="drift_delete"),
    path("drift/project/<int:project_pk>/", drift_views.drift_watch_project, name="drift_watch_project"),
    path("schedules/", schedule_views.schedule_list, name="schedule_list"),
    path("schedules/new/", schedule_views.schedule_edit, name="schedule_create"),
    path("schedules/<int:pk>/", schedule_views.schedule_edit, name="schedule_update"),
    path("schedules/<int:pk>/run/", schedule_views.schedule_run, name="schedule_run"),
    path("schedules/<int:pk>/toggle/", schedule_views.schedule_toggle, name="schedule_toggle"),
    path("schedules/<int:pk>/delete/", schedule_views.schedule_delete, name="schedule_delete"),
    path("templates/", template_views.template_list, name="template_list"),
    path("templates/new/", template_views.template_edit, name="template_create"),
    path("templates/<int:pk>/", template_views.template_launch, name="template_launch"),
    path("templates/<int:pk>/edit/", template_views.template_edit, name="template_update"),
    path("templates/<int:pk>/delete/", template_views.template_delete, name="template_delete"),
    path("<int:pk>/delete/", views.job_delete, name="job_delete"),
]
