# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""OpenTofu projects in the UI.

Every check is a role on the project's host group: Viewer to look, Operator
to plan and apply, Admin to plan a destroy.  Changing the configuration also
takes the global right to write OpenTofu code (access.policy.edit_tofu).
"""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _

from access import policy
from runs.executor import dispatch
from runs.models import Job

from .forms import FileForm, ProjectForm, VariableForm
from .models import TofuFile, TofuProject, TofuVariable
from .services import start_plan


def _projects(user):
    return TofuProject.objects.filter(
        host_group__in=policy.for_user(user).groups()
    ).select_related("host_group")


def _project_for(request, pk, role):
    project = get_object_or_404(_projects(request.user), pk=pk)
    policy.for_user(request.user).require_group(project.host_group, role)
    return project


def _code_for(request, pk):
    """A project whose configuration this user may write: Admin on its group
    and the right to write OpenTofu code (see access.policy.edit_tofu)."""
    project = _project_for(request, pk, policy.ADMIN)
    if not policy.for_user(request.user).edit_tofu:
        raise PermissionDenied
    return project


def _role(request, project):
    return policy.for_user(request.user).role_for_group(project.host_group)


@login_required
def project_list(request):
    return render(
        request,
        "infra/project_list.html",
        {"projects": _projects(request.user).prefetch_related("jobs")},
    )


@login_required
def project_create(request):
    access = policy.for_user(request.user)
    if not (access.manages_inventory and access.edit_tofu):
        raise PermissionDenied
    form = ProjectForm(request.POST or None, user=request.user)
    if request.method == "POST" and form.is_valid():
        project = form.save(commit=False)
        project.created_by = request.user
        project.save()
        if not project.is_git:
            # Something to start from, so the first plan has a file to read.
            TofuFile.objects.create(project=project, path="main.tf", content=STARTER)
        messages.success(request, _('Project %(project)s created.') % {"project": project})
        return redirect(project)
    return render(request, "infra/project_form.html", {"form": form})


STARTER = """# Your OpenTofu configuration. Loona keeps the state; no backend block needed.
#
# terraform {
#   required_providers {
#     proxmox = { source = "bpg/proxmox" }
#   }
# }
"""


@login_required
def project_update(request, pk):
    project = _code_for(request, pk)
    form = ProjectForm(request.POST or None, instance=project, user=request.user)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, _("Project saved."))
        return redirect(project)
    return render(request, "infra/project_form.html", {"form": form, "project": project})


@login_required
def project_delete(request, pk):
    project = _project_for(request, pk, policy.ADMIN)
    if request.method == "POST":
        if project.managed_resources:
            messages.error(
                request,
                _("This project still manages resources. Plan a destroy and apply it first, "
                "or they are left running with nothing tracking them."),
            )
            return redirect(project)
        name = project.name
        project.delete()
        messages.success(request, _('Project %(name)s deleted.') % {"name": name})
        return redirect("tofu_project_list")
    return render(request, "core/confirm_delete.html", {"object": project})


@login_required
def project_detail(request, pk):
    project = _project_for(request, pk, policy.VIEWER)
    role = _role(request, project)
    jobs = policy.for_user(request.user).jobs().filter(tofu_project=project)
    last_apply = jobs.filter(kind=Job.KIND_TOFU_APPLY, status=Job.SUCCESSFUL).first()
    return render(
        request,
        "infra/project_detail.html",
        {
            "project": project,
            "can_run": role >= policy.OPERATOR,
            "can_admin": role >= policy.ADMIN,
            "can_edit": role >= policy.ADMIN and policy.for_user(request.user).edit_tofu,
            "jobs": jobs.order_by("-pk")[:15],
            "state": project.current_state,
            "outputs": (last_apply.stats.get("tofu", {}).get("outputs") if last_apply else None),
            "files": project.files.all(),
            "variables": project.variables.all(),
            "hosts": project.hosts.select_related("managed_key").order_by("name"),
            "bootstrap_key": project.ensure_bootstrap_key() if role >= policy.OPERATOR else "",
            "drift": project.drift_checks.select_related("last_job").first(),
        },
    )


@login_required
@require_POST
def host_bootstrap_retry(request, host_pk):
    """Bring a machine up again: after a failed attempt, or after OpenTofu
    replaced it - the new one carries only the project's bootstrap key, so
    this is the one way back in.
    """
    from inventory.models import Host

    from . import bootstrap

    host = get_object_or_404(
        policy.for_user(request.user).hosts(policy.ADMIN).filter(tofu_project__isnull=False),
        pk=host_pk,
    )
    busy = {*Job.SYSTEM_KINDS, Job.KIND_BOOTSTRAP}
    if host.jobs.filter(kind__in=busy).exclude(status__in=Job.FINAL_STATUSES).exists():
        messages.info(request, _('%(name)s is being set up right now.') % {"name": host.name})
    else:
        bootstrap.begin(host, host.tofu_project, user=request.user)
        messages.info(request, _('Setting up %(name)s again.') % {"name": host.name})
    return redirect(host)


@login_required
@require_POST
def project_plan(request, pk):
    destroy = request.POST.get("destroy") == "1"
    project = _project_for(request, pk, policy.ADMIN if destroy else policy.OPERATOR)
    job = start_plan(project, request.user, destroy=destroy)
    dispatch(job)
    return redirect(job)


# -- files ---------------------------------------------------------------------


@login_required
def file_edit(request, pk, file_pk=None):
    project = _code_for(request, pk)
    instance = (
        get_object_or_404(TofuFile, pk=file_pk, project=project)
        if file_pk
        else TofuFile(project=project)
    )
    form = FileForm(request.POST or None, instance=instance)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, _('%(path)s saved.') % {"path": instance.path})
        return redirect(project)
    return render(
        request, "infra/file_form.html", {"form": form, "project": project, "file": instance}
    )


@login_required
@require_POST
def file_delete(request, pk, file_pk):
    project = _code_for(request, pk)
    get_object_or_404(TofuFile, pk=file_pk, project=project).delete()
    return redirect(project)


# -- variables -----------------------------------------------------------------


@login_required
def variable_edit(request, pk, variable_pk=None):
    project = _code_for(request, pk)
    instance = (
        get_object_or_404(TofuVariable, pk=variable_pk, project=project)
        if variable_pk
        else TofuVariable(project=project)
    )
    form = VariableForm(request.POST or None, instance=instance)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, _('Variable %(name)s saved.') % {"name": instance.name})
        return redirect(project)
    return render(
        request,
        "infra/variable_form.html",
        {"form": form, "project": project, "variable": instance},
    )


@login_required
@require_POST
def variable_delete(request, pk, variable_pk):
    project = _code_for(request, pk)
    get_object_or_404(TofuVariable, pk=variable_pk, project=project).delete()
    return redirect(project)
