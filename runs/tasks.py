# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Celery entry points for job execution."""
from celery import shared_task
from celery.signals import worker_ready

from .executor import reap_dead_jobs, run_job


@shared_task(name="loona.run_job", bind=True)
def run_job_task(self, job_id: int) -> str:
    return run_job(job_id)


@worker_ready.connect
def _close_jobs_orphaned_by_the_last_worker(**kwargs):
    # A worker that was killed mid-run left its jobs marked running; the
    # processes behind them are gone now, so say so instead of spinning forever.
    reap_dead_jobs(ask_workers=True)


@shared_task(name="loona.tick")
def tick() -> dict:
    """Once a minute, from the scheduler; see runs.housekeeping."""
    from .housekeeping import tick as housekeeping_tick

    return housekeeping_tick()

