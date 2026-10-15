# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""What Loona tells people about, and in what words.

Each function is called from the place the thing happens and hands a
ready-made message to dispatch.emit; none of them may raise.
"""
from __future__ import annotations

import logging

from django.urls import reverse

from . import dispatch
from .models import (
    APPROVAL_DECIDED,
    APPROVAL_NEEDED,
    BOOTSTRAP_FAILED,
    DRIFT_DETECTED,
    DRIFT_RESOLVED,
    HOST_KEY_CHANGED,
    RUN_FAILED,
)

log = logging.getLogger(__name__)


def _safely(func):
    def wrapped(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:  # noqa: BLE001
            log.exception("Notification hook %s failed", func.__name__)
            return None

    return wrapped


def _groups(job) -> set[int]:
    from access.approvals import affected_group_ids

    return affected_group_ids(job)


def _job_data(job) -> dict:
    return {
        "job": job.pk,
        "name": job.playbook_name,
        "kind": job.kind,
        "status": job.status,
        "hosts": job.resolved_hosts,
        "started_by": str(job.created_by or ""),
    }


def _who(job) -> str:
    return f"Started by {job.created_by}." if job.created_by else "Started by Loona."


@_safely
def job_finished(job):
    """Called by the executor for every run that ends."""
    from access import approvals
    from inventory.hostkeys import MISMATCH_MARKERS
    from runs.models import Job

    if job.drift_check_id:
        return  # drift has its own events
    path = reverse("job_detail", args=[job.pk])
    groups = _groups(job)

    if job.status in (Job.FAILED, Job.ERROR):
        mismatched = sorted(set(
            job.events.filter(failed=True)
            .filter(stdout__iregex="|".join(MISMATCH_MARKERS))
            .exclude(host="")
            .values_list("host", flat=True)
        ))
        for host in mismatched:
            dispatch.emit(
                HOST_KEY_CHANGED,
                f"SSH host key mismatch on {host}",
                f"{host} presented an SSH host key other than the one Loona pinned, so "
                f"run #{job.pk} ({job.playbook_name}) did not connect to it. Either the machine "
                "was rebuilt - then forget the pinned key on its host page - or something "
                "else answered at its address.",
                path, groups, {**_job_data(job), "host": host},
            )
        if job.is_system or job.kind == Job.KIND_BOOTSTRAP:
            return  # reported as bootstrap_failed where it matters
        failed = list(
            job.events.filter(event__in=("runner_on_failed", "runner_on_unreachable"))
            .exclude(host="")
            .values_list("host", "task")[:5]
        )
        details = "; ".join(f"{h}: {t}" if t else h for h, t in failed)
        reason = details or job.error_message or "see the log"
        dispatch.emit(
            RUN_FAILED,
            f"Run failed: #{job.pk} {job.playbook_name}",
            f"{job.playbook_name} ended as {job.get_status_display().lower()}.\n"
            f"{reason}\n{_who(job)}",
            path, groups, _job_data(job),
        )
        return

    if job.is_plan and job.status == Job.SUCCESSFUL and job.plan_has_changes:
        needed = approvals.requirement(job)
        if needed:
            who = ", ".join(u.get_username() for u in approvals.approvers(job)) or "nobody else - check the roles"
            dispatch.emit(
                APPROVAL_NEEDED,
                f"Waiting for approval: #{job.pk} {job.playbook_name}",
                f"{needed}\n{_summary(job)}{_who(job)}\nCan approve: {who}.",
                path, groups, _job_data(job),
            )


def _summary(job) -> str:
    tofu = (job.stats or {}).get("tofu")
    if tofu:
        return f"Plan: +{tofu.get('add', 0)} ~{tofu.get('change', 0)} -{tofu.get('destroy', 0)}.\n"
    return ""


@_safely
def decided(approval):
    job = approval.plan
    verdict = "approved and applied" if approval.approved else "rejected"
    comment = f'\nComment: "{approval.comment}"' if approval.comment else ""
    dispatch.emit(
        APPROVAL_DECIDED,
        f"Plan {verdict}: #{job.pk} {job.playbook_name}",
        f"{approval.decided_by} {verdict} #{job.pk}, made by {job.created_by or 'Loona'}.{comment}",
        reverse("job_detail", args=[job.pk]),
        _groups(job),
        {**_job_data(job), "decision": approval.decision, "decided_by": str(approval.decided_by)},
    )


@_safely
def drift_changed(check, before: str):
    from runs.models import DriftCheck

    group = check.scope_group
    groups = group.ancestor_ids() if group else set()
    path = reverse("job_detail", args=[check.last_job_id]) if check.last_job_id else reverse("drift_list")
    data = {"check": check.name, "status": check.status, "drifted": check.drifted}
    if check.status == DriftCheck.DRIFTED:
        dispatch.emit(
            DRIFT_DETECTED,
            f"Drift: {check.name}",
            f"{check.name} no longer matches what Loona would make it.\n"
            f"Changed: {', '.join(check.drifted[:20]) or '?'}.\n"
            "The check's preview shows the difference; applying it puts things back.",
            path, groups, data,
        )
    elif check.status == DriftCheck.ERROR:
        dispatch.emit(
            DRIFT_DETECTED,
            f"Drift check failed: {check.name}",
            f"{check.name} could not run, so drift there goes unnoticed until it can.",
            path, groups, data,
        )
    elif check.status == DriftCheck.IN_SYNC and before in (DriftCheck.DRIFTED, DriftCheck.ERROR):
        dispatch.emit(
            DRIFT_RESOLVED,
            f"In sync again: {check.name}",
            f"{check.name} matches again.",
            path, groups, data,
        )


@_safely
def bootstrap_failed(host, job=None):
    groups = set()
    for group in host.groups.all():
        groups |= group.ancestor_ids()
    dispatch.emit(
        BOOTSTRAP_FAILED,
        f"New machine not set up: {host.name}",
        f"{host.name} ({host.ansible_host}) was created by "
        f"{host.tofu_project.name if host.tofu_project else 'OpenTofu'}, but Loona could not "
        f"set it up: {host.bootstrap_error}\nRetry from the host page once it is reachable.",
        reverse("host_detail", args=[host.pk]),
        groups,
        {"host": host.name, "address": host.ansible_host, "job": getattr(job, "pk", None)},
    )
