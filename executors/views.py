# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Administration - Executors.  Superusers only: an executor decides where
the passwords and keys of every run on its groups end up."""
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _

from administration.views import audit, superuser_only
from runs.models import Job

from . import remote
from .forms import ExecutorForm
from .models import Executor

TOKEN_SESSION_KEY = "executor_fresh_token"


@superuser_only
def executor_list(request):
    executors = Executor.objects.prefetch_related("agents", "groups")
    rows = []
    for executor in executors:
        rows.append({
            "executor": executor,
            "online": executor.online_agents,
            "agents": list(executor.agents.all()),
            "waiting": Job.objects.filter(executor=executor, status=Job.PENDING,
                                          runner=executor.runner_waiting).count(),
            "running": Job.objects.filter(executor=executor, status=Job.RUNNING).count(),
        })
    return render(request, "executors/list.html", {"section": "executors", "rows": rows})


@superuser_only
def executor_create(request):
    form = ExecutorForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        executor = form.save()
        request.session[TOKEN_SESSION_KEY] = [executor.pk, executor.issue_token()]
        audit(request.user, "executors", f"Created executor {executor.name}", form)
        return redirect("executor_detail", executor.pk)
    return render(request, "executors/form.html", {"section": "executors", "form": form})


@superuser_only
def executor_detail(request, pk):
    executor = get_object_or_404(Executor, pk=pk)
    form = ExecutorForm(request.POST or None, instance=executor)
    if request.method == "POST" and form.is_valid():
        form.save()
        if form.changed_data:
            audit(request.user, "executors", f"Changed executor {executor.name}", form)
        messages.success(request, _('%(name)s saved.') % {"name": executor.name})
        return redirect("executor_detail", executor.pk)
    fresh = request.session.pop(TOKEN_SESSION_KEY, None)
    token = fresh[1] if fresh and fresh[0] == executor.pk else ""
    jobs = Job.objects.filter(executor=executor).order_by("-created_at")[:15]
    return render(request, "executors/detail.html", {
        "section": "executors",
        "executor": executor,
        "form": form,
        "token": token,
        "agents": executor.agents.all(),
        "jobs": jobs,
        "url": _public_url(request),
    })


def _public_url(request) -> str:
    return request.build_absolute_uri("/").rstrip("/")


@superuser_only
@require_POST
def executor_token(request, pk):
    executor = get_object_or_404(Executor, pk=pk)
    request.session[TOKEN_SESSION_KEY] = [executor.pk, executor.issue_token()]
    audit(request.user, "executors", f"New token for executor {executor.name}")
    messages.success(request, _("New token made; the old one no longer works. Restart the agents with it."))
    return redirect("executor_detail", executor.pk)


@superuser_only
@require_POST
def executor_delete(request, pk):
    executor = get_object_or_404(Executor, pk=pk)
    name = executor.name
    closed = remote.abandon_waiting(executor)
    executor.delete()
    audit(request.user, "executors", f"Deleted executor {name}")
    note = f" {closed} waiting run(s) were closed." if closed else ""
    messages.success(request, _('Executor %(name)s deleted; its groups run from Loona again.%(note)s') % {"name": name, "note": note})
    return redirect("executor_list")
