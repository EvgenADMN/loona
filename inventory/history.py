# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Everything that happened to one host, newest first.

Built from the runs the viewer may see: ones aimed at the host directly, and
ones that reached it through a group (found by its name in their events).
Each entry says what the run did to this host in particular, not to the run
as a whole.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from django.utils.translation import gettext as _

from access import policy


@dataclass
class Entry:
    job: object
    what: str
    ok: int = 0
    changed: int = 0
    failed: list = field(default_factory=list)
    unreachable: bool = False
    note: str = ""

    @property
    def status(self) -> str:
        if self.unreachable or self.failed:
            return "fail"
        if self.changed:
            return "warn"
        return "ok"


def timeline(host, user, limit: int = 50) -> list[Entry]:
    from runs.models import Job, JobEvent

    access = policy.for_user(user)
    ids = set(host.jobs.values_list("pk", flat=True))
    ids |= set(JobEvent.objects.filter(host=host.name).values_list("job_id", flat=True).distinct())
    jobs = list(
        access.jobs()
        .filter(pk__in=ids)
        .select_related("created_by", "drift_check", "plan__approval__decided_by")
        .order_by("-pk")[:limit]
    )
    entries = [_entry(job, host) for job in jobs]

    # Applies that created or changed the machine behind this host.
    if host.tofu_project_id:
        applies = (
            access.jobs()
            .filter(tofu_project_id=host.tofu_project_id, kind=Job.KIND_TOFU_APPLY)
            .select_related("created_by", "plan__approval__decided_by")
            .order_by("-pk")[:limit]
        )
        for job in applies:
            hosts = (job.stats or {}).get("tofu", {}).get("hosts", {})
            if host.name in hosts.get("created", []):
                entries.append(Entry(job, _("OpenTofu apply"), note=_("created this machine")))
            elif host.name in hosts.get("updated", []):
                entries.append(Entry(job, _("OpenTofu apply"), note=_("updated this machine's record")))
    entries.sort(key=lambda e: e.job.pk, reverse=True)
    return entries[:limit]


def _entry(job, host) -> Entry:
    from runs.models import Job

    if job.drift_check_id:
        what = _("Drift check")
    elif job.is_plan:
        what = _("Preview")
    elif job.plan_id:
        what = _("Apply")
    else:
        what = job.get_kind_display()
    entry = Entry(job, what)
    for row in job.host_stats:
        if row["host"] == host.name:
            entry.ok, entry.changed = row["ok"], row["changed"]
            entry.unreachable = bool(row["unreachable"])
    entry.failed = list(
        job.events.filter(host=host.name, event="runner_on_failed")
        .exclude(task="")
        .values_list("task", flat=True)[:3]
    )
    approval = getattr(job.plan, "approval", None) if job.plan_id else None
    if approval is not None:
        entry.note = _("approved by %(name)s") % {"name": approval.decided_by}
    if job.status in (Job.ERROR, Job.CANCELED) and not entry.failed:
        entry.note = job.get_status_display().lower()
    return entry
