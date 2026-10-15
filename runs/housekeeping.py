# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""What the scheduler does once a minute."""
from __future__ import annotations

import logging
from datetime import timedelta

from django.utils import timezone

from .models import Job

log = logging.getLogger(__name__)

DELETE_BATCH = 500


def tick() -> dict:
    from administration import system
    from administration.models import SystemSettings

    from . import drift, schedules
    from .executor import reap_dead_jobs

    from notifications.dispatch import retry_pending

    done = {
        "reaped": reap_dead_jobs(ask_workers=True),
        "deleted": forget_old_runs(),
        "checks": drift.run_due(),
        "scheduled": schedules.run_due(),
        "notifications": retry_pending(),
    }
    SystemSettings.objects.filter(pk=system.get().pk).update(last_tick_at=timezone.now())
    return done


def forget_old_runs() -> int:
    """Delete finished runs older than the retention set in Administration."""
    from administration import system

    days = system.get().job_retention_days
    if not days:
        return 0
    cutoff = timezone.now() - timedelta(days=days)
    old = Job.objects.filter(status__in=Job.FINAL_STATUSES, finished_at__lt=cutoff)
    deleted = 0
    while True:
        batch = list(old.values_list("pk", flat=True)[:DELETE_BATCH])
        if not batch:
            break
        deleted += Job.objects.filter(pk__in=batch).delete()[1].get("runs.Job", 0)
    if deleted:
        log.info("Deleted %s run(s) older than %s days", deleted, days)
    return deleted
