# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Workflow pages: the list, the editor with its picture, and runs."""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db.models import ProtectedError
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _

from access import policy
from core.forms import VariablesField

from . import engine, graph
from .forms import StepForm, WorkflowForm
from .models import Node, Run, Workflow


def _visible(user):
    return Workflow.objects.filter(host_group__in=policy.for_user(user).groups())


def _workflow(request, pk, role):
    workflow = get_object_or_404(_visible(request.user).select_related("host_group"), pk=pk)
    policy.for_user(request.user).require_group(workflow.host_group, role)
    return workflow


@login_required
def workflow_list(request):
    access = policy.for_user(request.user)
    workflows = list(_visible(request.user).select_related("host_group"))
    for workflow in workflows:
        workflow.last_run = workflow.runs.first()
        workflow.can_run = access.role_for_group(workflow.host_group) >= policy.OPERATOR
    return render(request, "workflows/list.html", {"workflows": workflows,
                                                   "can_add": access.manages_inventory})


@login_required
def workflow_edit(request, pk=None):
    if pk:
        workflow = _workflow(request, pk, policy.ADMIN)
    else:
        if not policy.for_user(request.user).manages_inventory:
            raise PermissionDenied
        workflow = Workflow(created_by=request.user)
    form = WorkflowForm(request.POST or None, instance=workflow, user=request.user)
    if request.method == "POST" and form.is_valid():
        workflow = form.save()
        messages.success(request, _('%(name)s saved.') % {"name": workflow.name})
        return redirect(workflow)
    return render(request, "workflows/form.html", {"form": form, "workflow": workflow})


@login_required
@require_POST
def workflow_delete(request, pk):
    workflow = _workflow(request, pk, policy.ADMIN)
    if workflow.runs.filter(status=Run.RUNNING).exists():
        messages.error(request, _("A run of it is still going."))
        return redirect(workflow)
    workflow.delete()
    messages.success(request, _('%(name)s deleted.') % {"name": workflow.name})
    return redirect("workflow_list")


@login_required
def workflow_detail(request, pk):
    workflow = _workflow(request, pk, policy.VIEWER)
    access = policy.for_user(request.user)
    steps = list(workflow.steps.select_related("playbook", "host_group", "tofu_project"))
    edges = list(workflow.edges.all())
    names = {s.pk: s.name for s in steps}
    for step in steps:
        step.after = [(names[e.parent_id], e.get_condition_display()) for e in edges if e.child_id == step.pk]
    return render(request, "workflows/detail.html", {
        "workflow": workflow, "steps": steps,
        "graph": graph.layout(steps, edges),
        "runs": workflow.runs.select_related("created_by")[:20],
        "can_edit": access.role_for_group(workflow.host_group) >= policy.ADMIN,
        "can_run": access.role_for_group(workflow.host_group) >= policy.OPERATOR,
        "missing": engine.missing_rights(workflow, request.user),
    })


@login_required
def step_edit(request, pk, step_pk=None):
    workflow = _workflow(request, pk, policy.ADMIN)
    step = get_object_or_404(workflow.steps, pk=step_pk) if step_pk else None
    form = StepForm(request.POST or None, instance=step, user=request.user, workflow=workflow)
    if request.method == "POST" and form.is_valid():
        form.save()
        return redirect(workflow)
    return render(request, "workflows/step_form.html", {"form": form, "workflow": workflow, "step": step})


@login_required
@require_POST
def step_delete(request, pk, step_pk):
    workflow = _workflow(request, pk, policy.ADMIN)
    step = get_object_or_404(workflow.steps, pk=step_pk)
    if workflow.runs.filter(status=Run.RUNNING).exists():
        messages.error(request, _("A run is going; change the steps once it is over."))
        return redirect(workflow)
    try:
        step.delete()
    except ProtectedError:
        messages.error(request, _("That step is still referenced."))
    return redirect(workflow)


@login_required
@require_POST
def workflow_start(request, pk):
    workflow = _workflow(request, pk, policy.OPERATOR)
    field = VariablesField(required=False)
    try:
        extra = field.clean(request.POST.get("extra_vars", "")) or {}
    except Exception as exc:  # noqa: BLE001 - shown to the user
        messages.error(request, _('Variables: %(join)s') % {"join": ' '.join(getattr(exc, 'messages', [str(exc)]))})
        return redirect(workflow)
    try:
        run = engine.start(workflow, request.user, extra)
    except engine.Refused as exc:
        messages.error(request, str(exc))
        return redirect(workflow)
    return redirect(run)


def _run(request, pk, role=policy.VIEWER):
    run = get_object_or_404(Run.objects.select_related("workflow__host_group", "created_by"), pk=pk)
    access = policy.for_user(request.user)
    if run.workflow.host_group_id not in access.group_ids(policy.VIEWER) and not access.unrestricted:
        raise PermissionDenied
    access.require_group(run.workflow.host_group, role)
    return run


@login_required
def run_detail(request, pk):
    run = _run(request, pk)
    access = policy.for_user(request.user)
    nodes = list(run.nodes.select_related("step", "job", "decided_by"))
    for node in nodes:
        node.job_visible = node.job is not None and access.can_job(node.job)
        node.can_decide = engine.why_not_approver(node, request.user) is None
    steps = [n.step for n in nodes]
    return render(request, "workflows/run.html", {
        "run": run, "nodes": nodes,
        "graph": graph.layout(steps, run.workflow.edges.all(), {n.step_id: n for n in nodes}),
        "can_cancel": not run.is_final and access.role_for_group(run.workflow.host_group) >= policy.OPERATOR,
    })


@login_required
@require_POST
def run_cancel(request, pk):
    run = _run(request, pk, policy.OPERATOR)
    engine.cancel(run, request.user)
    return redirect(run)


@login_required
@require_POST
def node_decide(request, pk, node_pk):
    run = _run(request, pk)
    node = get_object_or_404(Node.objects.select_related("step", "run__workflow"), pk=node_pk, run=run)
    try:
        engine.decide(node, request.user, request.POST.get("decision") == "approve",
                      request.POST.get("comment", ""))
    except engine.Refused as exc:
        messages.error(request, str(exc))
    return redirect(run)
