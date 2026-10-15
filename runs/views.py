# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _

from access import policy
from playbooks import yaml_io
from playbooks.models import Playbook

from . import plans, services
from .executor import reap_dead_jobs
from . import adhoc
from .forms import JobLaunchForm
from .models import Job


@login_required
def job_list(request):
    reap_dead_jobs()
    jobs = policy.for_user(request.user).jobs().select_related("playbook", "created_by")
    status = request.GET.get("status", "")
    if status:
        jobs = jobs.filter(status=status)
    query = request.GET.get("q", "").strip()
    if query:
        jobs = jobs.filter(Q(playbook_name__icontains=query))
    # Key management runs are kept out of the way by default: they are frequent,
    # short, and rarely what someone opens this page looking for.
    kind = request.GET.get("kind", "")
    if kind == "system":
        jobs = jobs.filter(kind__in=Job.SYSTEM_KINDS)
    elif kind != "all":
        jobs = jobs.exclude(kind__in=Job.SYSTEM_KINDS)
    return render(
        request,
        "runs/job_list.html",
        {
            "jobs": jobs[:200],
            "status": status,
            "q": query,
            "kind": kind,
            "statuses": Job.STATUS_CHOICES,
        },
    )


@login_required
def job_launch(request, playbook_pk):
    """Target selection and runtime options, then start the run."""
    playbook = get_object_or_404(Playbook, pk=playbook_pk)
    if not policy.for_user(request.user).runs_playbooks:
        raise PermissionDenied
    initial = _initial_from_previous(request, playbook)
    form = JobLaunchForm(request.POST or None, initial=initial, user=request.user)

    if request.method == "POST" and form.is_valid():
        try:
            job = services.launch(form, playbook, request.user,
                                  preview=request.POST.get("action") == "plan")
        except services.Refused as exc:
            form.add_error(None, str(exc))
        else:
            return redirect(job)

    return render(
        request,
        "runs/job_launch.html",
        {"form": form, "playbook": playbook, "preview": yaml_io.playbook_yaml(playbook)},
    )


@login_required
def adhoc_launch(request):
    """Type a command, pick the targets, preview or run it."""
    access = policy.for_user(request.user)
    if not access.manages_inventory:
        raise PermissionDenied
    form = adhoc.AdhocForm(request.POST or None, initial=_adhoc_initial(request), user=request.user)
    if request.method == "POST" and form.is_valid():
        try:
            job = services.launch_adhoc(form, request.user, preview=request.POST.get("action") == "plan")
        except services.Refused as exc:
            form.add_error(None, str(exc))
        else:
            return redirect(job)
    return render(request, "runs/adhoc_launch.html", {
        "form": form,
        "modules": [m for m in adhoc.allowed_modules()
                    if request.user.is_superuser or m not in adhoc.CONTROLLER_MODULES],
    })


def _adhoc_initial(request):
    """Targets from ?host= / ?group=, or everything from ?relaunch=."""
    access = policy.for_user(request.user)
    source_pk = request.GET.get("relaunch")
    if source_pk:
        source = access.jobs(policy.ADMIN).filter(pk=source_pk, kind=Job.KIND_ADHOC).first()
        if source:
            return {
                "target_groups": source.target_groups.all(), "target_hosts": source.target_hosts.all(),
                "limit": source.limit, "adhoc_module": source.adhoc_module, "adhoc_args": source.adhoc_args,
                "adhoc_become": source.adhoc_become, "diff_mode": source.diff_mode,
                "forks": source.forks, "verbosity": source.verbosity,
            }
    return {
        "target_hosts": access.hosts(policy.ADMIN).filter(pk__in=request.GET.getlist("host")),
        "target_groups": access.groups(policy.ADMIN).filter(pk__in=request.GET.getlist("group")),
        "adhoc_module": "shell",
    }


def _initial_from_previous(request, playbook):
    """Pre-fill the launch form from the job being relaunched, if any."""
    source_pk = request.GET.get("relaunch")
    if not source_pk:
        return {}
    source = (
        policy.for_user(request.user)
        .jobs(policy.OPERATOR)
        .filter(pk=source_pk, playbook=playbook)
        .first()
    )
    if not source:
        return {}
    return {
        "target_groups": source.target_groups.all(),
        "target_hosts": source.target_hosts.all(),
        "limit": source.limit,
        "extra_vars": source.extra_vars,
        "diff_mode": source.diff_mode,
        "tags": source.tags,
        "skip_tags": source.skip_tags,
        "forks": source.forks,
        "verbosity": source.verbosity,
    }


def _moved_on(job) -> bool:
    """Has the playbook, or the project files behind it, changed since this preview?"""
    playbook, project = job.playbook, job.ansible_project
    if playbook is None:
        return False
    from_git = project is not None and project.is_git
    # A file in Git is only read at run time; what is there now is not known
    # here, and applying uses the previewed commit whatever happened since.
    if not (from_git and playbook.mode == playbook.MODE_FILE):
        if yaml_io.playbook_yaml(playbook) != job.playbook_yaml:
            return True
    if project is not None and not from_git and job.project_revision:
        from . import projects

        return projects.digest({f.path: f.content for f in project.files.all()}) != job.project_revision
    return False


@login_required
def job_detail(request, pk):
    access = policy.for_user(request.user)
    job = get_object_or_404(access.jobs().select_related("playbook", "created_by"), pk=pk)
    if reap_dead_jobs(Job.objects.filter(pk=job.pk)):
        job.refresh_from_db()
    events = job.events.all()
    can_operate = access.can_job(job, policy.OPERATOR)
    plan_context = {}
    if job.is_tofu:
        role = access.role_for_group(job.tofu_project.host_group) if job.tofu_project else 0
        needed = policy.ADMIN if job.tofu_destroy else policy.OPERATOR
        plan_context = {
            "tofu": (job.stats or {}).get("tofu"),
            "can_apply": job.is_final and role >= needed and job.can_be_applied,
            "applied_as": job.applications.first(),
        }
    elif job.is_plan and job.is_final:
        plan_context = {
            "plan": plans.summarize(job),
            "can_apply": access.can_job(job, policy.ADMIN if job.is_adhoc else policy.OPERATOR)
            and job.can_be_applied,
            "applied_as": job.applications.first(),
            "playbook_moved_on": _moved_on(job),
        }
    if job.is_plan and job.is_final:
        from access import approvals

        needed = approvals.requirement(job)
        given = approvals.decision(job)
        plan_context["approval"] = {
            "needed": needed,
            "given": given,
            "i_can": approvals.why_not_approver(request.user, job) is None,
            "who": approvals.approvers(job) if needed and given is None else [],
        }
        if needed and (given is None or not given.approved):
            # Nobody applies it by the plain button; the approver's does.
            plan_context["can_apply"] = False
    return render(
        request,
        "runs/job_detail.html",
        {
            **plan_context,
            "job": job,
            "can_operate": can_operate,
            "events": events,
            "last_counter": events.last().pk if events else 0,
        },
    )


@login_required
def job_events(request, pk):
    """HTMX partial: events newer than ?after=, plus the next poller."""
    job = get_object_or_404(policy.for_user(request.user).jobs(), pk=pk)
    if reap_dead_jobs(Job.objects.filter(pk=job.pk)):
        job.refresh_from_db()
    after = int(request.GET.get("after") or 0)
    events = list(job.events.filter(pk__gt=after))
    last = events[-1].pk if events else after
    response = render(
        request,
        "runs/_job_events.html",
        {"job": job, "events": events, "last_counter": last, "polling": True},
    )
    if job.is_final:
        # The header buttons, the event count and a preview's summary all
        # change when a run ends; reload once rather than patch each in.
        response["HX-Refresh"] = "true"
    return response


@login_required
@require_POST
def plan_decide(request, pk):
    """Approve a plan and apply it at once, or reject it."""
    plan = get_object_or_404(policy.for_user(request.user).jobs(), pk=pk)
    approve = request.POST.get("decision") == "approve"
    try:
        _approval, job = services.decide(plan, request.user, approve, request.POST.get("comment", ""))
    except (services.Refused, plans.CannotApply) as exc:
        messages.error(request, str(exc))
        return redirect(plan)
    if job is None:
        messages.info(request, _("Plan rejected. It can no longer be applied."))
        return redirect(plan)
    return redirect(job)


@login_required
@require_POST
def plan_apply(request, pk):
    """Carry out a preview."""
    plan = get_object_or_404(policy.for_user(request.user).jobs(), pk=pk)
    try:
        job = services.apply(plan, request.user)
    except plans.CannotApply as exc:
        messages.error(request, str(exc))
        return redirect(plan)
    return redirect(job)


@login_required
@require_POST
def job_cancel(request, pk):
    """Ask the runner to stop; it checks this flag between tasks."""
    job = get_object_or_404(policy.for_user(request.user).jobs(), pk=pk)
    if services.cancel(job, request.user):
        messages.success(request, _("Cancellation requested."))
    else:
        messages.info(request, _("That job has already finished."))
    return redirect(job)


@login_required
@require_POST
def job_delete(request, pk):
    job = get_object_or_404(policy.for_user(request.user).jobs(), pk=pk)
    policy.for_user(request.user).require_job(job, policy.ADMIN)
    if not job.is_final:
        messages.error(request, _("Cancel the job before deleting it."))
        return redirect(job)
    job.delete()
    messages.success(request, _("Job deleted."))
    return redirect("job_list")
