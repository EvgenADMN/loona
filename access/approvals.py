# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The two-person rule: which applies need someone else to agree first.

A host group's ``approval_policy`` covers it and everything nested under it,
and the strictest policy among the groups a run touches decides:

* "destroy" - a plan that deletes or replaces anything needs approval.
  Only OpenTofu plans can say that ahead of time; a playbook cannot.
* "changes" - every preview needs approval before it is applied, and
  "Run now" is off: the change has to go through a preview someone saw.

Maintenance windows narrow this down in time: a group with windows (its own
or a parent's) takes changes inside them under the rules above, and outside
every one of them applying anything needs approval and "Run now" is off.

Approval is given by another person with the Admin role on every group the
plan touches - never by whoever made the plan - and it is given for that one
plan, so what gets applied is exactly what they looked at.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import gettext as _

from inventory.models import Host, HostGroup
from runs.models import Job

from . import policy
from .models import Approval, GroupGrant, MaintenanceWindow, Role

LEVELS = {
    HostGroup.APPROVAL_NONE: 0,
    HostGroup.APPROVAL_DESTROY: 1,
    HostGroup.APPROVAL_CHANGES: 2,
}


def _with_ancestors(group_ids) -> set[int]:
    found = set()
    for group in HostGroup.objects.filter(pk__in=group_ids):
        found |= group.ancestor_ids()
    return found


def affected_group_ids(job: Job) -> set[int]:
    direct = set(job.target_groups.values_list("pk", flat=True))
    hosts = Host.objects.filter(name__in=job.resolved_hosts) | job.target_hosts.all()
    direct |= set(Host.groups.through.objects.filter(host__in=hosts).values_list("hostgroup_id", flat=True))
    return _with_ancestors(direct)


def strictest(group_ids) -> tuple[int, HostGroup | None]:
    level, which = 0, None
    for group in HostGroup.objects.filter(pk__in=group_ids):
        if LEVELS.get(group.approval_policy, 0) > level:
            level, which = LEVELS[group.approval_policy], group
    return level, which


def destroys(job: Job) -> bool:
    if job.kind != Job.KIND_TOFU_PLAN:
        return False
    summary = (job.stats or {}).get("tofu", {})
    return job.tofu_destroy or bool(summary.get("destroy"))


def outside_window(group_ids, now=None) -> HostGroup | None:
    """A group among these that has maintenance windows and is outside all of them."""
    now = now or timezone.now()
    windows: dict[int, list[MaintenanceWindow]] = {}
    for window in MaintenanceWindow.objects.filter(host_group_id__in=group_ids).select_related("host_group"):
        windows.setdefault(window.host_group_id, []).append(window)
    for group_windows in sorted(windows.values(), key=lambda w: w[0].host_group.name):
        if not any(w.contains(now) for w in group_windows):
            return group_windows[0].host_group
    return None


def requirement(job: Job, now=None) -> str | None:
    """Why this plan needs approval, or None if it does not."""
    if not job.is_plan:
        return None
    groups = affected_group_ids(job)
    level, group = strictest(groups)
    if level >= LEVELS[HostGroup.APPROVAL_CHANGES]:
        return _("Every change to %(group)s needs a second person's approval.") % {"group": group.name}
    closed = outside_window(groups, now)
    if closed is not None:
        return _("%(group)s is outside its maintenance windows; a change now needs a second person's approval.") % {
            "group": closed.name}
    if level >= LEVELS[HostGroup.APPROVAL_DESTROY] and destroys(job):
        return _("This plan destroys resources in %(group)s, which needs a second person's approval.") % {
            "group": group.name}
    if job.catalog_request_id:
        from catalog.services import approval_reason

        return approval_reason(job)
    return None


def run_now_refusal(groups, hosts, now=None) -> str | None:
    """Why running without a preview is off for these targets, or None."""
    ids = {g.pk for g in groups}
    ids |= set(Host.groups.through.objects.filter(host__in=list(hosts)).values_list("hostgroup_id", flat=True))
    ids = _with_ancestors(ids)
    level, group = strictest(ids)
    if level >= LEVELS[HostGroup.APPROVAL_CHANGES]:
        return _("Changes to %(group)s go through a preview and a second person's "
                 "approval. Use Preview changes.") % {"group": group.name}
    closed = outside_window(ids, now)
    if closed is not None:
        return _("%(group)s is outside its maintenance windows. Preview the change; "
                 "a second person's approval lets it go ahead now.") % {"group": closed.name}
    return None


def decision(job: Job) -> Approval | None:
    return Approval.objects.filter(plan=job).first()


def why_not_approver(user, job: Job) -> str | None:
    """None if this user may decide on this plan; otherwise the reason."""
    if not job.is_plan or job.status != Job.SUCCESSFUL:
        return _("Only a finished preview can be approved.")
    if decision(job) is not None or job.applications.exists():
        return _("This preview has already been decided on.")
    if job.created_by_id == getattr(user, "pk", None):
        return _("You made this plan; someone else has to approve it.")
    if not policy.for_user(user).can_job(job, policy.ADMIN):
        return _("Approving takes the Admin role on everything the plan touches.")
    return None


def approvers(job: Job) -> list:
    """Who could approve this plan: other admins of what it touches."""
    User = get_user_model()
    groups = affected_group_ids(job)
    candidates = User.objects.filter(is_active=True).filter(
        is_superuser=True
    ) | User.objects.filter(
        is_active=True,
        groups__grants__role__gte=Role.ADMIN,
        groups__grants__host_group__in=groups,
    )
    return [u for u in candidates.distinct().order_by("username") if why_not_approver(u, job) is None]


def waiting_for(user, limit: int = 20) -> list:
    """Plans this user could approve right now, newest first."""
    plans = (
        policy.for_user(user)
        .jobs(policy.ADMIN)
        .filter(kind__in=(Job.KIND_TOFU_PLAN, Job.KIND_PLAYBOOK, Job.KIND_ADHOC), status=Job.SUCCESSFUL,
                approval__isnull=True, applications__isnull=True, drift_check__isnull=True)
        .exclude(created_by=user)
        .order_by("-pk")[: limit * 3]
    )
    found = []
    for job in plans:
        if job.is_plan and job.plan_has_changes and requirement(job):
            found.append(job)
        if len(found) >= limit:
            break
    return found
