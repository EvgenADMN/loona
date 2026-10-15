# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The API: the same rights and rules as the UI, through the same code paths."""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta

from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.translation import gettext as _
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from access import policy
from core.version import __version__
from infra.models import TofuProject
from inventory import facts
from inventory.forms import HostForm
from inventory.models import Credential, Host, HostFacts, HostGroup
from playbooks.models import Playbook
from runs import drift, plans, services
from runs.forms import JobLaunchForm
from runs.models import DriftCheck, Job, LaunchTemplate, Schedule
from runs.schedule_views import ScheduleForm, may_manage
from secretstore.forms import SecretForm
from secretstore.models import Secret

from . import serializers as s
from .models import Trigger


def _pick(queryset, values, what):
    """Objects by id or by name; unknown ones are an error, not silently skipped."""
    found, missing = [], []
    for value in values:
        value = str(value)
        match = queryset.filter(pk=int(value)) if value.isdigit() else queryset.filter(name=value)
        obj = match.first()
        (found.append(obj) if obj else missing.append(value))
    if missing:
        raise _Invalid({what: [f"Not found or not yours to use: {', '.join(missing)}"]})
    return found


class _Invalid(Exception):
    def __init__(self, errors):
        self.errors = errors


def _form_errors(form) -> dict:
    return {k.replace("__all__", "non_field_errors"): v for k, v in form.errors.items()}


def _refused(message, code=status.HTTP_409_CONFLICT):
    return Response({"detail": str(message)}, status=code)


class MeView(APIView):
    @extend_schema(summary="Who the token belongs to, and what they may do",
                   responses=OpenApiTypes.OBJECT)
    def get(self, request):
        access = policy.for_user(request.user)
        return Response({
            "username": request.user.get_username(),
            "superuser": request.user.is_superuser,
            "teams": list(request.user.groups.values_list("name", flat=True)),
            "can_run_playbooks": access.runs_playbooks,
            "can_edit_playbooks": access.edit_playbooks,
            "admin_of_groups": list(access.groups(policy.ADMIN).values_list("name", flat=True)),
            "loona_version": __version__,
        })


class HostViewSet(viewsets.ViewSet):
    serializer_class = s.HostSerializer
    queryset = Host.objects.none()  # for the schema: ids are integers

    def _visible(self, request):
        return (policy.for_user(request.user).hosts().prefetch_related("groups")
                .select_related("credential", "facts").defer("facts__facts"))

    @extend_schema(parameters=[
        OpenApiParameter("group", str, description="Host group name."),
        OpenApiParameter("q", str, description="The host list's search: words, os:ubuntu, ram>=8, "
                         "cpus>=4, ip:10.0., facts:none, ansible_<fact path>:value. Words are ANDed."),
    ])
    def list(self, request):
        hosts = self._visible(request)
        if request.query_params.get("group"):
            hosts = hosts.filter(groups__name=request.query_params["group"])
        if request.query_params.get("q"):
            search = facts.parse(request.query_params["q"])
            if search.errors:
                return Response({"q": search.errors}, status=status.HTTP_400_BAD_REQUEST)
            hosts = hosts.filter(search.filter)
        page = self.paginator.paginate_queryset(hosts.distinct().order_by("name"), request, view=self)
        return self.paginator.get_paginated_response(s.HostSerializer(page, many=True).data)

    @property
    def paginator(self):
        from rest_framework.settings import api_settings

        if not hasattr(self, "_paginator"):
            self._paginator = api_settings.DEFAULT_PAGINATION_CLASS()
        return self._paginator

    def retrieve(self, request, pk=None):
        return Response(s.HostSerializer(get_object_or_404(self._visible(request), pk=pk)).data)

    @extend_schema(request=s.HostWriteSerializer, responses=s.HostSerializer)
    def create(self, request):
        return self._save(request, Host())

    @extend_schema(request=s.HostWriteSerializer, responses=s.HostSerializer)
    def partial_update(self, request, pk=None):
        host = get_object_or_404(self._visible(request), pk=pk)
        policy.for_user(request.user).require_host(host, policy.ADMIN)
        return self._save(request, host)

    @extend_schema(responses=s.HostFactsSerializer, summary="Everything Ansible last reported about the host")
    @action(detail=True, methods=["get"], url_path="facts")
    def host_facts(self, request, pk=None):
        host = get_object_or_404(self._visible(request), pk=pk)
        found = get_object_or_404(HostFacts, host=host)
        return Response(s.HostFactsSerializer(found).data)

    @extend_schema(request=None, responses={201: s.JobSerializer}, summary="Gather facts from the host now")
    @action(detail=True, methods=["post"])
    def gather_facts(self, request, pk=None):
        host = get_object_or_404(self._visible(request), pk=pk)
        policy.for_user(request.user).require_host(host, policy.OPERATOR)
        if not host.enabled:
            return _refused(f"{host.name} is disabled.")
        return Response(s.JobSerializer(facts.start(request.user, hosts=[host])).data,
                        status=status.HTTP_201_CREATED)

    def destroy(self, request, pk=None):
        host = get_object_or_404(self._visible(request), pk=pk)
        policy.for_user(request.user).require_host(host, policy.ADMIN)
        host.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def _save(self, request, host):
        access = policy.for_user(request.user)
        if not host.pk and not access.manages_inventory:
            raise PermissionDenied
        body = s.HostWriteSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        data = body.validated_data
        # Start from what is there, so a PATCH only changes what it names.
        current = {
            "name": host.name, "address": host.address, "port": host.port or 22,
            "credential": host.credential_id or "", "enabled": host.enabled if host.pk else True,
            "description": host.description,
            "variables": json.dumps(host.variables or {}),
            "groups": list(host.groups.values_list("pk", flat=True)) if host.pk else [],
        }
        try:
            if "groups" in data:
                current["groups"] = [g.pk for g in _pick(access.groups(policy.ADMIN), data["groups"], "groups")]
            if "credential" in data:
                current["credential"] = (
                    _pick(access.credentials(), [data["credential"]], "credential")[0].pk
                    if data["credential"] else ""
                )
        except _Invalid as exc:
            return Response(exc.errors, status=status.HTTP_400_BAD_REQUEST)
        for key in ("name", "address", "port", "enabled", "description"):
            if key in data:
                current[key] = data[key]
        if "variables" in data:
            current["variables"] = json.dumps(data["variables"])
        if not current["enabled"]:
            current.pop("enabled")  # a checkbox: absent means off
        form = HostForm(current, instance=host, user=request.user)
        if not form.is_valid():
            return Response(_form_errors(form), status=status.HTTP_400_BAD_REQUEST)
        created = host.pk is None
        saved = form.save()
        return Response(s.HostSerializer(saved).data,
                        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class HostGroupViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = s.HostGroupSerializer

    def get_queryset(self):
        return policy.for_user(self.request.user).groups().prefetch_related("parents", "hosts", "maintenance_windows").order_by("name")

    @extend_schema(request=None, responses={201: s.JobSerializer},
                   summary="Gather facts from every enabled host of the group")
    @action(detail=True, methods=["post"])
    def gather_facts(self, request, pk=None):
        group = self.get_object()
        policy.for_user(request.user).require_group(group, policy.OPERATOR)
        if not any(h.enabled for h in group.all_hosts()):
            return _refused(f"{group.name} has no enabled hosts.")
        return Response(s.JobSerializer(facts.start(request.user, groups=[group])).data,
                        status=status.HTTP_201_CREATED)


class SecretViewSet(viewsets.ModelViewSet):
    """Names and scopes of the secrets you may see; values go in and never come out."""

    serializer_class = s.SecretSerializer
    http_method_names = ["get", "post", "patch", "delete"]

    def get_queryset(self):
        return policy.for_user(self.request.user).secrets().order_by("name", "pk")

    @extend_schema(request=s.SecretWriteSerializer, responses={201: s.SecretSerializer})
    def create(self, request):
        return self._save(request, Secret(created_by=request.user))

    @extend_schema(request=s.SecretWriteSerializer, responses=s.SecretSerializer)
    def partial_update(self, request, pk=None):
        secret = self.get_object()
        policy.for_user(request.user).require_secret(secret)
        return self._save(request, secret)

    def destroy(self, request, pk=None):
        secret = self.get_object()
        policy.for_user(request.user).require_secret(secret)
        secret.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def _save(self, request, secret):
        from playbooks.models import Project

        body = s.SecretWriteSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        data = body.validated_data
        access = policy.for_user(request.user)
        if not secret.pk and not access.manages_secrets:
            raise PermissionDenied
        # Start from what is there, so a PATCH only changes what it names.
        current = {
            "name": secret.name, "description": secret.description,
            "scope": secret.scope if secret.pk else "",
            "host_group": secret.host_group_id or "", "project": secret.project_id or "",
            "source": "vault" if secret.in_vault else "stored", "vault_ref": secret.vault_ref,
        }
        try:
            if data.get("group"):
                current["host_group"] = _pick(access.groups(policy.ADMIN), [data["group"]], "group")[0].pk
            if data.get("project"):
                projects = Project.objects.all() if access.edit_playbooks else Project.objects.none()
                current["project"] = _pick(projects, [data["project"]], "project")[0].pk
        except _Invalid as exc:
            return Response(exc.errors, status=status.HTTP_400_BAD_REQUEST)
        for key in ("name", "description", "scope", "value", "vault_ref"):
            if key in data:
                current[key] = data[key]
        if "vault_ref" in data:
            current["source"] = "vault" if data["vault_ref"] else "stored"
        form = SecretForm(current, instance=secret, user=request.user)
        if not form.is_valid():
            return Response(_form_errors(form), status=status.HTTP_400_BAD_REQUEST)
        created = secret.pk is None
        saved = form.save()
        return Response(s.SecretSerializer(saved).data,
                        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class ScheduleViewSet(viewsets.ModelViewSet):
    """Scheduled runs on the groups you can see. Saving one makes it run as you."""

    serializer_class = s.ScheduleSerializer
    http_method_names = ["get", "post", "patch", "delete"]

    def get_queryset(self):
        groups = policy.for_user(self.request.user).groups()
        return Schedule.objects.filter(host_group__in=groups).select_related(
            "playbook", "workflow", "host_group", "run_as").order_by("name", "pk")

    @extend_schema(request=s.ScheduleWriteSerializer, responses={201: s.ScheduleSerializer})
    def create(self, request):
        if not policy.for_user(request.user).runs_playbooks:
            raise PermissionDenied
        return self._save(request, Schedule(run_as=request.user))

    @extend_schema(request=s.ScheduleWriteSerializer, responses=s.ScheduleSerializer)
    def partial_update(self, request, pk=None):
        schedule = self.get_object()
        if not may_manage(request.user, schedule):
            raise PermissionDenied
        return self._save(request, schedule)

    def destroy(self, request, pk=None):
        schedule = self.get_object()
        if not may_manage(request.user, schedule):
            raise PermissionDenied
        schedule.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def _save(self, request, schedule):
        body = s.ScheduleWriteSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        data = body.validated_data
        access = policy.for_user(request.user)
        current = {
            "name": schedule.name, "playbook": schedule.playbook_id or "", "host_group": schedule.host_group_id or "",
            "workflow": schedule.workflow_id or "",
            "what": ScheduleForm.WORKFLOW if schedule.workflow_id else ScheduleForm.PLAYBOOK,
            "action": schedule.action, "cron": schedule.cron, "timezone": schedule.timezone,
            "limit": schedule.limit, "tags": schedule.tags, "skip_tags": schedule.skip_tags,
            "extra_vars": json.dumps(schedule.extra_vars or {}),
            **({"enabled": "on"} if schedule.enabled else {}),
        }
        try:
            if "playbook" in data:
                current["playbook"] = _pick(Playbook.objects.all(), [data["playbook"]], "playbook")[0].pk
                current["what"] = ScheduleForm.PLAYBOOK
            if "workflow" in data:
                from workflows.models import Workflow

                workflows = Workflow.objects.filter(host_group__in=access.groups(policy.OPERATOR))
                current["workflow"] = _pick(workflows, [data["workflow"]], "workflow")[0].pk
                current["what"] = ScheduleForm.WORKFLOW
            if "group" in data:
                current["host_group"] = _pick(access.groups(policy.OPERATOR), [data["group"]], "group")[0].pk
        except _Invalid as exc:
            return Response(exc.errors, status=status.HTTP_400_BAD_REQUEST)
        for key in ("name", "action", "cron", "timezone", "limit", "tags", "skip_tags"):
            if key in data:
                current[key] = data[key]
        if "extra_vars" in data:
            current["extra_vars"] = json.dumps(data["extra_vars"])
        if "enabled" in data:
            current.pop("enabled", None)
            if data["enabled"]:
                current["enabled"] = "on"
        form = ScheduleForm(current, instance=schedule, user=request.user)
        if not form.is_valid():
            return Response(_form_errors(form), status=status.HTTP_400_BAD_REQUEST)
        created = schedule.pk is None
        saved = form.save()
        return Response(s.ScheduleSerializer(saved).data,
                        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class LaunchTemplateViewSet(viewsets.ReadOnlyModelViewSet):
    """Launch templates on the groups you can see, with their survey questions."""

    serializer_class = s.LaunchTemplateSerializer

    def get_queryset(self):
        groups = policy.for_user(self.request.user).groups()
        return LaunchTemplate.objects.filter(host_group__in=groups).select_related(
            "playbook", "host_group").order_by("name")

    @extend_schema(request=s.TemplateLaunchSerializer, responses={201: s.JobSerializer},
                   summary="Launch a template with survey answers")
    @action(detail=True, methods=["post"])
    def launch(self, request, pk=None):
        from runs.surveys import SurveyForm

        template = self.get_object()
        body = s.TemplateLaunchSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        data = body.validated_data
        if policy.for_user(request.user).role_for_group(template.host_group) < policy.OPERATOR:
            raise PermissionDenied
        form = SurveyForm(template.survey, {f"q_{k}": v for k, v in data["answers"].items()})
        if not form.is_valid():
            return Response({k.removeprefix("q_"): v for k, v in form.errors.items()},
                            status=status.HTTP_400_BAD_REQUEST)
        unknown = sorted(set(data["answers"]) - {q["variable"] for q in template.survey})
        if unknown:
            return Response({"answers": [f"Not asked by this template: {', '.join(unknown)}"]},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            job = services.launch_template(template, request.user, form, data["limit"], preview=data["preview"])
        except services.Refused as exc:
            return _refused(exc)
        return Response(s.JobSerializer(job).data, status=status.HTTP_201_CREATED)


class PlaybookViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = s.PlaybookSerializer
    queryset = Playbook.objects.order_by("name")

    @extend_schema(request=s.LaunchSerializer, responses={201: s.JobSerializer},
                   summary="Preview (default) or run a playbook")
    @action(detail=True, methods=["post"])
    def launch(self, request, pk=None):
        playbook = self.get_object()
        body = s.LaunchSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        data = body.validated_data
        access = policy.for_user(request.user)
        if not access.runs_playbooks:
            raise PermissionDenied
        try:
            groups = _pick(access.groups(policy.OPERATOR), data["groups"], "groups")
            hosts = _pick(access.hosts(policy.OPERATOR), data["hosts"], "hosts")
        except _Invalid as exc:
            return Response(exc.errors, status=status.HTTP_400_BAD_REQUEST)
        form = JobLaunchForm({
            "target_groups": [g.pk for g in groups],
            "target_hosts": [h.pk for h in hosts],
            "limit": data["limit"],
            "extra_vars": json.dumps(data["extra_vars"]) if data["extra_vars"] else "",
            "tags": data["tags"],
            "skip_tags": data["skip_tags"],
            "forks": data["forks"],
            "verbosity": data["verbosity"],
            **({"diff_mode": "on"} if data["diff"] else {}),
        }, user=request.user)
        if not form.is_valid():
            return Response(_form_errors(form), status=status.HTTP_400_BAD_REQUEST)
        try:
            job = services.launch(form, playbook, request.user, preview=data["preview"])
        except services.Refused as exc:
            return _refused(exc)
        return Response(s.JobSerializer(job).data, status=status.HTTP_201_CREATED)


class CatalogItemViewSet(viewsets.ViewSet):
    """What you may request."""

    @extend_schema(responses=s.CatalogItemSerializer(many=True))
    def list(self, request):
        from catalog import services as catalog

        return Response(s.CatalogItemSerializer(catalog.requestable(request.user), many=True).data)

    @extend_schema(request=s.CatalogOrderSerializer, responses={201: s.CatalogRequestSerializer},
                   summary="Request one; it is planned at once")
    @action(detail=True, methods=["post"], url_path="request")
    def order(self, request, pk=None):
        from catalog import services as catalog
        from catalog.forms import RequestForm
        from catalog.models import CatalogItem

        item = get_object_or_404(CatalogItem, pk=pk)
        if not catalog.can_request(request.user, item):
            raise PermissionDenied
        body = s.CatalogOrderSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        data = {"name": body.validated_data["name"]}
        for question in item.fields or []:
            value = body.validated_data["values"].get(question["variable"])
            if value is None:
                continue
            if question["type"] == "boolean":
                if value:
                    data[f"q_{question['variable']}"] = "on"
            else:
                data[f"q_{question['variable']}"] = value
        form = RequestForm(item, data)
        if not form.is_valid():
            errors = {k.removeprefix("q_"): v for k, v in _form_errors(form).items()}
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)
        try:
            filed = catalog.submit(item, request.user, form.cleaned_data["name"], form.values())
        except catalog.Refused as exc:
            return _refused(exc)
        return Response(s.CatalogRequestSerializer(filed).data, status=status.HTTP_201_CREATED)


class CatalogRequestViewSet(viewsets.ReadOnlyModelViewSet):
    """Your requests, and those of the items you run."""

    serializer_class = s.CatalogRequestSerializer

    def get_queryset(self):
        from catalog import services as catalog

        return catalog.visible_requests(self.request.user).select_related("item", "requested_by").order_by("-pk")

    @extend_schema(request=None, responses=s.CatalogRequestSerializer, summary="Destroy the machine")
    @action(detail=True, methods=["post"])
    def retire(self, request, pk=None):
        from catalog import services as catalog

        found = self.get_object()
        try:
            catalog.retire(found, request.user)
        except catalog.Refused as exc:
            return _refused(exc)
        found.refresh_from_db()
        return Response(s.CatalogRequestSerializer(found).data)


class WorkflowViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = s.WorkflowSerializer

    def get_queryset(self):
        from workflows.models import Workflow

        groups = policy.for_user(self.request.user).groups()
        return Workflow.objects.filter(host_group__in=groups).select_related("host_group").order_by("name")

    @extend_schema(request=s.WorkflowStartSerializer, responses={201: s.WorkflowRunSerializer},
                   summary="Start a run (Operator on the workflow's group and every step's)")
    @action(detail=True, methods=["post"])
    def run(self, request, pk=None):
        from workflows import engine

        workflow = self.get_object()
        policy.for_user(request.user).require_group(workflow.host_group, policy.OPERATOR)
        body = s.WorkflowStartSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        try:
            started = engine.start(workflow, request.user, body.validated_data["extra_vars"])
        except engine.Refused as exc:
            return _refused(exc)
        return Response(s.WorkflowRunSerializer(started).data, status=status.HTTP_201_CREATED)


class WorkflowRunViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = s.WorkflowRunSerializer

    def get_queryset(self):
        from workflows.models import Run

        groups = policy.for_user(self.request.user).groups()
        return (Run.objects.filter(workflow__host_group__in=groups)
                .select_related("workflow", "created_by").prefetch_related("nodes__step").order_by("-pk"))

    @extend_schema(request=None, responses=s.WorkflowRunSerializer)
    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        from workflows import engine

        found = self.get_object()
        engine.cancel(found, request.user)
        found.refresh_from_db()
        return Response(s.WorkflowRunSerializer(found).data)

    @extend_schema(request=s.NodeDecisionSerializer, responses=s.WorkflowRunSerializer,
                   summary="Approve or reject a waiting approval step")
    @action(detail=True, methods=["post"])
    def decide(self, request, pk=None):
        from workflows import engine

        found = self.get_object()
        body = s.NodeDecisionSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        node = get_object_or_404(found.nodes.select_related("step", "run__workflow"), pk=body.validated_data["node"])
        try:
            engine.decide(node, request.user, body.validated_data["approve"], body.validated_data["comment"])
        except engine.Refused as exc:
            return _refused(exc, status.HTTP_403_FORBIDDEN)
        found.refresh_from_db()
        return Response(s.WorkflowRunSerializer(found).data)


class AdhocView(APIView):
    @extend_schema(request=s.AdhocSerializer, responses={201: s.JobSerializer},
                   summary="Run an ad-hoc command (Admin on every target)")
    def post(self, request):
        from runs.adhoc import AdhocForm

        body = s.AdhocSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        data = body.validated_data
        access = policy.for_user(request.user)
        if not access.manages_inventory:
            raise PermissionDenied
        try:
            groups = _pick(access.groups(policy.ADMIN), data["groups"], "groups")
            hosts = _pick(access.hosts(policy.ADMIN), data["hosts"], "hosts")
        except _Invalid as exc:
            return Response(exc.errors, status=status.HTTP_400_BAD_REQUEST)
        form = AdhocForm({
            "target_groups": [g.pk for g in groups], "target_hosts": [h.pk for h in hosts],
            "limit": data["limit"], "adhoc_module": data["module"], "adhoc_args": data["args"],
            "forks": data["forks"], "verbosity": data["verbosity"],
            **({"adhoc_become": "on"} if data["become"] else {}),
            **({"diff_mode": "on"} if data["diff"] else {}),
        }, user=request.user)
        if not form.is_valid():
            return Response(_form_errors(form), status=status.HTTP_400_BAD_REQUEST)
        try:
            job = services.launch_adhoc(form, request.user, preview=data["preview"])
        except services.Refused as exc:
            return _refused(exc)
        return Response(s.JobSerializer(job).data, status=status.HTTP_201_CREATED)


class JobViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = s.JobSerializer

    def get_queryset(self):
        jobs = policy.for_user(self.request.user).jobs().select_related("created_by").order_by("-pk")
        params = self.request.query_params
        if params.get("status"):
            jobs = jobs.filter(status=params["status"])
        if params.get("kind"):
            jobs = jobs.filter(kind=params["kind"])
        if params.get("playbook"):
            jobs = jobs.filter(playbook_id=params["playbook"])
        return jobs

    @extend_schema(responses=s.JobEventSerializer(many=True),
                   summary="Log lines after ?after=<event id>, up to 500")
    @action(detail=True, methods=["get"])
    def events(self, request, pk=None):
        job = self.get_object()
        after = int(request.query_params.get("after") or 0)
        events = job.events.filter(pk__gt=after).order_by("pk")[:500]
        return Response(s.JobEventSerializer(events, many=True).data)

    @extend_schema(request=None, responses={202: None})
    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        stopped = services.cancel(self.get_object(), request.user)
        return Response({"cancel_requested": stopped}, status=status.HTTP_202_ACCEPTED)

    @extend_schema(request=None, responses={201: s.JobSerializer}, summary="Apply a preview or plan")
    @action(detail=True, methods=["post"])
    def apply(self, request, pk=None):
        try:
            job = services.apply(self.get_object(), request.user)
        except plans.CannotApply as exc:
            return _refused(exc)
        return Response(s.JobSerializer(job).data, status=status.HTTP_201_CREATED)

    @extend_schema(request=s.CommentSerializer, responses={201: s.JobSerializer},
                   summary="Approve a plan (as someone other than its author) and apply it")
    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        return self._decide(request, approve=True)

    @extend_schema(request=s.CommentSerializer, responses={200: s.JobSerializer})
    @action(detail=True, methods=["post"])
    def reject(self, request, pk=None):
        return self._decide(request, approve=False)

    def _decide(self, request, approve):
        plan = self.get_object()
        body = s.CommentSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        try:
            _approval, job = services.decide(plan, request.user, approve, body.validated_data["comment"])
        except (services.Refused, plans.CannotApply) as exc:
            return _refused(exc)
        if job is None:
            return Response(s.JobSerializer(plan).data)
        return Response(s.JobSerializer(job).data, status=status.HTTP_201_CREATED)


class TofuProjectViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = s.TofuProjectSerializer

    def get_queryset(self):
        groups = policy.for_user(self.request.user).groups()
        return TofuProject.objects.filter(host_group__in=groups).select_related("host_group").order_by("name")

    @extend_schema(request=s.PlanRequestSerializer, responses={201: s.JobSerializer})
    @action(detail=True, methods=["post"])
    def plan(self, request, pk=None):
        from infra.services import start_plan
        from runs.executor import dispatch

        project = self.get_object()
        body = s.PlanRequestSerializer(data=request.data)
        body.is_valid(raise_exception=True)
        destroy = body.validated_data["destroy"]
        policy.for_user(request.user).require_group(
            project.host_group, policy.ADMIN if destroy else policy.OPERATOR
        )
        job = start_plan(project, request.user, destroy=destroy)
        dispatch(job)
        return Response(s.JobSerializer(job).data, status=status.HTTP_201_CREATED)


class DriftCheckViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = s.DriftCheckSerializer

    def get_queryset(self):
        groups = policy.for_user(self.request.user).groups()
        return (DriftCheck.objects.filter(host_group__in=groups)
                | DriftCheck.objects.filter(tofu_project__host_group__in=groups)).distinct().order_by("name")

    @extend_schema(request=None, responses={201: s.JobSerializer})
    @action(detail=True, methods=["post"])
    def run(self, request, pk=None):
        check = self.get_object()
        policy.for_user(request.user).require_group(check.scope_group, policy.OPERATOR)
        job = drift.start(check, user=request.user)
        if job is None:
            return _refused("A check is already running.")
        return Response(s.JobSerializer(job).data, status=status.HTTP_201_CREATED)


# -- triggers ------------------------------------------------------------------


@extend_schema(request=None, responses={201: OpenApiTypes.OBJECT, 202: OpenApiTypes.OBJECT},
               summary="Fire a trigger (from CI or a Git server's push webhook)",
               description="Authenticate with the trigger's secret: X-Loona-Trigger-Token, or "
                           "GitLab's X-Gitlab-Token, or GitHub's X-Hub-Signature-256.")
@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
def fire_trigger(request, pk):
    trigger = Trigger.objects.filter(pk=pk, enabled=True).select_related("run_as").first()
    # Unknown, disabled and wrongly signed all look alike from outside.
    if trigger is None or not _trigger_authentic(request, trigger.secret):
        return Response({"detail": "Unknown trigger or bad secret."}, status=status.HTTP_403_FORBIDDEN)
    if not _first_delivery(request, trigger):
        return Response({"detail": "This signed delivery was received before."},
                        status=status.HTTP_409_CONFLICT)
    ref = _pushed_ref(request)
    if trigger.branch and ref is not None and ref != f"refs/heads/{trigger.branch}":
        return Response({"skipped": f"push to {ref}, this trigger follows {trigger.branch}"},
                        status=status.HTTP_202_ACCEPTED)
    if trigger.action == Trigger.WORKFLOW:
        if trigger.last_run_id and not trigger.last_run.is_final:
            return Response({"skipped": "the previous run from this trigger is still going",
                             "workflow_run": trigger.last_run_id}, status=status.HTTP_202_ACCEPTED)
    elif trigger.last_job_id and not trigger.last_job.is_final:
        return Response({"skipped": "the previous run from this trigger is still going",
                         "job": trigger.last_job_id}, status=status.HTTP_202_ACCEPTED)
    user = trigger.run_as
    if not user.is_active:
        return Response({"detail": "The trigger's owner can no longer sign in."},
                        status=status.HTTP_403_FORBIDDEN)
    if trigger.action == Trigger.WORKFLOW:
        from workflows import engine

        try:
            run = engine.start(trigger.workflow, user)
        except engine.Refused as exc:
            return _refused(exc)
        Trigger.objects.filter(pk=trigger.pk).update(last_fired_at=timezone.now(), last_run=run)
        return Response({"workflow_run": run.pk, "status": run.status,
                         "web_url": s.WorkflowRunSerializer(run).data["web_url"]},
                        status=status.HTTP_201_CREATED)
    try:
        job = _fire(trigger, user)
    except PermissionDenied:
        return Response({"detail": f"{user} may no longer do this."}, status=status.HTTP_403_FORBIDDEN)
    except services.Refused as exc:
        return _refused(exc)
    Trigger.objects.filter(pk=trigger.pk).update(last_fired_at=timezone.now(), last_job=job)
    return Response({"job": job.pk, "status": job.status, "web_url": s.JobSerializer(job).data["web_url"]},
                    status=status.HTTP_201_CREATED)


def _trigger_authentic(request, secret) -> bool:
    given = request.headers.get("X-Loona-Trigger-Token") or request.headers.get("X-Gitlab-Token")
    if given:
        return hmac.compare_digest(given, secret)
    signature = request.headers.get("X-Hub-Signature-256", "")
    if signature.startswith("sha256="):
        expected = hmac.new(secret.encode(), request.body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature[7:], expected)
    return False


def _first_delivery(request, trigger) -> bool:
    """False for a signed body this trigger has already accepted."""
    from django.db import IntegrityError, transaction

    from .models import TriggerDelivery

    if request.headers.get("X-Loona-Trigger-Token") or request.headers.get("X-Gitlab-Token"):
        return True  # the secret itself is sent; there is no signature to replay
    digest = hashlib.sha256(request.body).hexdigest()
    TriggerDelivery.objects.filter(received_at__lt=timezone.now() - timedelta(days=400)).delete()
    try:
        with transaction.atomic():
            TriggerDelivery.objects.create(trigger=trigger, digest=digest)
    except IntegrityError:
        return False
    return True


def _pushed_ref(request):
    try:
        payload = json.loads(request.body or b"{}")
    except ValueError:
        return None
    return payload.get("ref") if isinstance(payload, dict) else None


def _fire(trigger, user) -> Job:
    from infra.services import start_plan
    from runs.executor import dispatch

    access = policy.for_user(user)
    if trigger.action == Trigger.PLAN:
        access.require_group(trigger.tofu_project.host_group, policy.OPERATOR)
        job = start_plan(trigger.tofu_project, user)
        job.playbook_name = f"{trigger.tofu_project.name}: plan (trigger {trigger.name})"
        job.save(update_fields=["playbook_name"])
        dispatch(job)
        return job
    access.require_group(trigger.host_group, policy.OPERATOR)
    form = JobLaunchForm({"target_groups": [trigger.host_group_id], "target_hosts": [],
                          "limit": "", "extra_vars": "", "tags": "", "skip_tags": "",
                          "forks": 5, "verbosity": 0}, user=user)
    if not form.is_valid():
        raise services.Refused(_('Cannot launch: %(as_text)s') % {"as_text": form.errors.as_text()})
    return services.launch(form, trigger.playbook, user, preview=trigger.action == Trigger.PREVIEW)
