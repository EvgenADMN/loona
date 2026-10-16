# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Starting scheduled runs when they are due - from the scheduler's tick."""
from __future__ import annotations

import json
import logging
from datetime import timedelta

from django.core.exceptions import PermissionDenied
from django.utils import timezone

from .models import Schedule

log = logging.getLogger(__name__)

# A run missed by more than this - the scheduler was down - is skipped, not
# started late: a 03:00 job turning up at 11:00 surprises everyone.
GRACE = timedelta(minutes=30)


def run_due(now=None) -> int:
    """Start what is due. Returns how many runs started."""
    now = now or timezone.now()
    started = 0
    for schedule in Schedule.objects.filter(enabled=True).select_related("run_as", "playbook", "workflow", "host_group", "last_job", "last_workflow_run"):
        if schedule.next_run_at is None:
            Schedule.objects.filter(pk=schedule.pk).update(next_run_at=schedule.compute_next(now))
            continue
        if schedule.next_run_at > now:
            continue
        due_at = schedule.next_run_at
        following = schedule.compute_next(now)
        # Claim this occurrence, so two ticks never start it twice.
        if not Schedule.objects.filter(pk=schedule.pk, next_run_at=due_at).update(next_run_at=following):
            continue
        if now - due_at > GRACE:
            _note(schedule, f"Skipped {_local(schedule, due_at)}: the scheduler was not running then.")
            continue
        try:
            if fire(schedule, now):
                started += 1
        except Exception as exc:  # noqa: BLE001 - one broken schedule must not stop the rest
            log.exception("Schedule %s could not start", schedule.pk)
            _note(schedule, f"Could not start at {_local(schedule, due_at)}: {exc}")
    return started


def fire(schedule: Schedule, now=None):
    """Start one run of this schedule now, or say why not. Returns the job or None."""
    from access import policy
    from access.middleware import may_still_act

    from . import services
    from .forms import JobLaunchForm

    now = now or timezone.now()
    previous = schedule.last_started
    if previous is not None and not previous.is_final:
        _note(schedule, f"Skipped {_local(schedule, now)}: the previous run (#{previous.pk}) was still going.")
        return None
    user = schedule.run_as
    if not may_still_act(user):
        _note(schedule, f"Not started: {user} can no longer sign in.")
        return None
    access = policy.for_user(user)
    try:
        access.require_group(schedule.host_group, policy.OPERATOR)
    except PermissionDenied:
        _note(schedule, f"Not started: {user} may no longer run playbooks on {schedule.host_group}.")
        return None
    if schedule.workflow_id:
        return _fire_workflow(schedule, user, now)

    def launch_form():
        return JobLaunchForm({
            "target_groups": [schedule.host_group_id], "target_hosts": [], "limit": schedule.limit,
            "extra_vars": json.dumps(schedule.extra_vars) if schedule.extra_vars else "",
            "tags": schedule.tags, "skip_tags": schedule.skip_tags, "forks": 5, "verbosity": 0,
        }, user=user)

    form = launch_form()
    if not form.is_valid():
        _note(schedule, f"Not started: {form.errors.as_text()}")
        return None

    note = ""
    if schedule.action == Schedule.PREVIEW:
        job = services.launch(form, schedule.playbook, user, preview=True)
    else:
        try:
            job = services.launch(form, schedule.playbook, user, preview=False)
        except services.Refused as refusal:
            # Not allowed to just run right now: a preview someone can approve.
            form = launch_form()
            form.is_valid()
            job = services.launch(form, schedule.playbook, user, preview=True)
            note = f"Started as a preview at {_local(schedule, now)}; applying it needs approval. {refusal}"
    job.schedule = schedule
    job.playbook_name = f"{schedule.playbook.name} (schedule {schedule.name})"[:255]
    job.save(update_fields=["schedule", "playbook_name"])
    Schedule.objects.filter(pk=schedule.pk).update(last_run_at=now, last_job=job, last_note=note)
    return job


def _fire_workflow(schedule: Schedule, user, now):
    """A workflow's own steps turn into previews where the rules say so."""
    from workflows import engine

    try:
        run = engine.start(schedule.workflow, user, extra_vars=schedule.extra_vars or None)
    except engine.Refused as exc:
        _note(schedule, f"Not started: {exc}")
        return None
    run.schedule = schedule
    run.save(update_fields=["schedule"])
    Schedule.objects.filter(pk=schedule.pk).update(last_run_at=now, last_workflow_run=run, last_note="")
    return run


def _note(schedule, text):
    Schedule.objects.filter(pk=schedule.pk).update(last_note=text[:500])


def _local(schedule, moment) -> str:
    from zoneinfo import ZoneInfo

    return moment.astimezone(ZoneInfo(schedule.timezone)).strftime("%Y-%m-%d %H:%M %Z")
