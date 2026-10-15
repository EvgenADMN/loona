# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Running drift checks and reading what they found."""
from __future__ import annotations

import logging
from datetime import timedelta

from django.utils import timezone

from .models import DriftCheck, Job

log = logging.getLogger(__name__)


def start(check: DriftCheck, user=None) -> Job | None:
    """Start one preview for this check; None if one is still running."""
    from playbooks import yaml_io

    from .executor import dispatch

    if check.last_job_id and not check.last_job.is_final:
        return None
    if check.is_tofu:
        from infra.services import start_plan

        job = start_plan(check.tofu_project, user)
        job.drift_check = check
        job.playbook_name = f"{check.tofu_project.name}: drift check"
        job.save(update_fields=["drift_check", "playbook_name"])
    else:
        job = Job.objects.create(
            kind=Job.KIND_PLAYBOOK,
            playbook=check.playbook,
            ansible_project=check.playbook.project,
            playbook_name=f"{check.playbook.name}: drift check",
            playbook_yaml=yaml_io.playbook_yaml(check.playbook),
            check_mode=True,
            diff_mode=True,
            drift_check=check,
            created_by=user,
        )
        job.target_groups.set([check.host_group])
    check.last_job = job
    check.last_run_at = timezone.now()
    check.save(update_fields=["last_job", "last_run_at"])
    dispatch(job)
    return job


def due(now=None) -> list[DriftCheck]:
    now = now or timezone.now()
    return [
        check
        for check in DriftCheck.objects.filter(enabled=True).select_related("last_job")
        if check.last_run_at is None
        or now - check.last_run_at >= timedelta(minutes=check.interval_minutes)
    ]


def run_due() -> int:
    """Start the checks that are due. Returns how many started."""
    started = 0
    for check in due():
        try:
            if start(check):
                started += 1
        except Exception:  # noqa: BLE001 - one broken check must not stop the rest
            log.exception("Drift check %s could not start", check.pk)
    return started


def on_finished(job: Job):
    check = job.drift_check
    if check is None:
        return
    previous = list(check.drifted or [])
    if job.status != Job.SUCCESSFUL:
        status, drifted = DriftCheck.ERROR, []
    elif job.kind == Job.KIND_TOFU_PLAN:
        summary = (job.stats or {}).get("tofu", {})
        drifted = [r["address"] for r in summary.get("resources", [])]
        status = DriftCheck.DRIFTED if summary.get("has_changes") else DriftCheck.IN_SYNC
    else:
        drifted = [row["host"] for row in job.host_stats if row["changed"]]
        status = DriftCheck.DRIFTED if drifted else DriftCheck.IN_SYNC
    before = check.status
    if status != before:
        check.status_since = timezone.now()
        log.info("Drift check %s: %s -> %s", check, before, status)
    check.status = status
    check.drifted = drifted
    check.save(update_fields=["status", "status_since", "drifted"])
    # Tell people when something changes, not at every hourly check.
    if status != before or (status == DriftCheck.DRIFTED and drifted != previous):
        from notifications import events

        events.drift_changed(check, before)
