# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Drift checks in the UI."""
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext_lazy as _

from access import policy
from core.forms import style
from infra.models import TofuProject
from playbooks.models import Playbook

from . import drift
from .models import DriftCheck


def _visible(user):
    groups = policy.for_user(user).groups()
    return DriftCheck.objects.filter(host_group__in=groups) | DriftCheck.objects.filter(
        tofu_project__host_group__in=groups
    )


def _check_for(request, pk, role):
    check = get_object_or_404(_visible(request.user).distinct(), pk=pk)
    policy.for_user(request.user).require_group(check.scope_group, role)
    return check


class DriftCheckForm(forms.ModelForm):
    class Meta:
        model = DriftCheck
        fields = ["name", "playbook", "host_group", "tofu_project", "interval_minutes"]
        labels = {"tofu_project": _("OpenTofu project"), "interval_minutes": _("How often")}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        access = policy.for_user(user)
        runnable = access.groups(policy.OPERATOR)
        self.fields["host_group"].queryset = runnable
        self.fields["tofu_project"].queryset = TofuProject.objects.filter(host_group__in=runnable)
        self.fields["playbook"].queryset = Playbook.objects.all()
        for name in ("playbook", "host_group", "tofu_project"):
            self.fields[name].required = False
        style(self)

    def clean(self):
        cleaned = super().clean()
        playbook, group, project = (cleaned.get(k) for k in ("playbook", "host_group", "tofu_project"))
        if project and (playbook or group):
            raise forms.ValidationError(_("Pick either an OpenTofu project, or a playbook and a group."))
        if not project and not (playbook and group):
            raise forms.ValidationError(_("Pick an OpenTofu project, or a playbook and a host group to run it on."))
        return cleaned


@login_required
def drift_list(request):
    access = policy.for_user(request.user)
    form = DriftCheckForm(request.POST or None, user=request.user)
    if request.method == "POST":
        if not access.runs_playbooks:
            raise PermissionDenied
        if form.is_valid():
            check = form.save(commit=False)
            check.created_by = request.user
            check.save()
            drift.start(check, user=request.user)
            messages.success(request, _('Watching %(name)s; the first check is running now.') % {"name": check.name})
            return redirect("drift_list")
    checks = _visible(request.user).distinct().select_related(
        "playbook", "host_group", "tofu_project", "last_job"
    )
    return render(
        request,
        "runs/drift_list.html",
        {"checks": checks, "form": form, "can_create": access.runs_playbooks},
    )


@login_required
@require_POST
def drift_run(request, pk):
    check = _check_for(request, pk, policy.OPERATOR)
    job = drift.start(check, user=request.user)
    if job is None:
        messages.info(request, _("A check is already running."))
        return redirect("drift_list")
    return redirect(job)


@login_required
@require_POST
def drift_toggle(request, pk):
    check = _check_for(request, pk, policy.OPERATOR)
    check.enabled = not check.enabled
    check.save(update_fields=["enabled"])
    return redirect("drift_list")


@login_required
@require_POST
def drift_delete(request, pk):
    check = _check_for(request, pk, policy.OPERATOR)
    check.delete()
    messages.success(request, _('Stopped watching %(name)s.') % {"name": check.name})
    return redirect("drift_list")


@login_required
@require_POST
def drift_watch_project(request, project_pk):
    """One click on a project page: check it for drift every day."""
    project = get_object_or_404(TofuProject, pk=project_pk)
    policy.for_user(request.user).require_group(project.host_group, policy.OPERATOR)
    check, created = DriftCheck.objects.get_or_create(
        tofu_project=project,
        defaults={"name": f"{project.name} (OpenTofu)", "created_by": request.user},
    )
    if created:
        drift.start(check, user=request.user)
    return redirect(project)
