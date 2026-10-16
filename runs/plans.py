# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Preview a run, then apply exactly what was previewed.

A plan is an ordinary playbook job run with --check --diff.  Applying it
starts a second job that:

* runs the plan's playbook snapshot, not whatever the playbook says now;
* is held to the hosts the plan actually reached (``resolved_hosts``);
* can happen once per plan, and only after a clean preview.

Check mode is a prediction, not a promise: commands and scripts do not run in
a preview, so the summary counts skipped tasks rather than pretending they
will not happen.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field

import yaml
from django.db import transaction
from django.utils.translation import gettext as _

from .models import Job

MAX_DIFF_LINES = 400


@dataclass
class Change:
    task: str
    blocks: list


@dataclass
class HostPlan:
    host: str
    changes: list = field(default_factory=list)
    unchanged: int = 0
    skipped: int = 0
    failed: list = field(default_factory=list)
    unreachable: bool = False


def summarize(job: Job) -> list[HostPlan]:
    """Per host: what would change (with diffs), what would not, what failed."""
    hosts: dict[str, HostPlan] = {name: HostPlan(name) for name in job.resolved_hosts}
    results = job.events.filter(
        event__in=(
            "runner_on_ok",
            "runner_on_failed",
            "runner_on_skipped",
            "runner_on_unreachable",
        )
    ).exclude(host="")
    for event in results:
        plan = hosts.setdefault(event.host, HostPlan(event.host))
        if event.event == "runner_on_unreachable":
            plan.unreachable = True
        elif event.event == "runner_on_failed" or event.failed:
            plan.failed.append(event.task)
        elif event.event == "runner_on_skipped":
            plan.skipped += 1
        elif event.changed:
            plan.changes.append(Change(event.task, render_diff(event.diff)))
        else:
            plan.unchanged += 1
    return sorted(hosts.values(), key=lambda p: p.host)


def render_diff(diff) -> list[dict]:
    """Ansible's diff payload as blocks of classified lines for the template.

    Each block is ``{"header": str, "lines": [(kind, text)]}`` where kind is
    one of add, del, hunk, ctx.
    """
    if not diff:
        return []
    items = diff if isinstance(diff, list) else [diff]
    blocks = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if "prepared" in item:
            lines = str(item["prepared"]).splitlines()
            blocks.append({"header": "", "lines": [("ctx", l) for l in lines[:MAX_DIFF_LINES]],
                           "truncated": len(lines) > MAX_DIFF_LINES})
            continue
        if "before" not in item and "after" not in item:
            continue
        before, after = _text(item.get("before")), _text(item.get("after"))
        header = item.get("after_header") or item.get("before_header") or ""
        raw = list(
            difflib.unified_diff(before.splitlines(), after.splitlines(), lineterm="", n=3)
        )[2:]  # the ---/+++ lines; the header says the same, better
        lines = [(_kind(line), line) for line in raw]
        if lines:
            blocks.append({"header": header, "lines": lines[:MAX_DIFF_LINES],
                           "truncated": len(lines) > MAX_DIFF_LINES})
    return blocks


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    # The file module describes attributes as a mapping: path, mode, owner...
    return yaml.safe_dump(value, sort_keys=True, allow_unicode=True)


def _kind(line: str) -> str:
    if line.startswith("@@"):
        return "hunk"
    if line.startswith("+"):
        return "add"
    if line.startswith("-"):
        return "del"
    return "ctx"


class CannotApply(Exception):
    pass


@transaction.atomic
def apply(plan: Job, user) -> Job:
    """Create the run that carries out a plan. Raises CannotApply if it may not.

    The caller dispatches it once this returns, i.e. after the commit.
    """
    # Locked, so two clicks on Apply cannot both find the plan unapplied.
    plan = Job.objects.select_for_update().get(pk=plan.pk)
    if not plan.is_plan:
        raise CannotApply(_("Only a preview can be applied."))
    existing = plan.applications.first()
    if existing is not None:
        raise CannotApply(_('This preview was already applied as #%(pk)s.') % {"pk": existing.pk})
    if plan.status != Job.SUCCESSFUL:
        raise CannotApply(
            _("The preview did not finish cleanly, so it says little about what "
            "applying would do. Fix the problem and preview again.")
        )
    if not plan.plan_has_changes:
        raise CannotApply(_("The plan found nothing to change."))
    # The two-person rule is enforced here, not just by hiding a button.
    from access import approvals

    given = approvals.decision(plan)
    if given is not None and not given.approved:
        raise CannotApply(_('%(decided_by)s rejected this plan.') % {"decided_by": given.decided_by})
    needed = approvals.requirement(plan)
    if needed and given is None:
        raise CannotApply(_('%(needed)s It has not been approved yet.') % {"needed": needed})
    if plan.kind == Job.KIND_TOFU_PLAN:
        return _apply_tofu(plan, user)
    job = Job.objects.create(
        kind=plan.kind,
        adhoc_module=plan.adhoc_module,
        adhoc_args=plan.adhoc_args,
        adhoc_become=plan.adhoc_become,
        plan=plan,
        playbook=plan.playbook,
        # The very project version the preview ran with; see runs.projects.
        ansible_project=plan.ansible_project,
        project_revision=plan.project_revision,
        playbook_file=plan.playbook_file,
        playbook_name=plan.playbook_name,
        playbook_yaml=plan.playbook_yaml,
        limit=plan.limit,
        extra_vars=plan.extra_vars,
        check_mode=False,
        diff_mode=True,
        verbosity=plan.verbosity,
        forks=plan.forks,
        tags=plan.tags,
        skip_tags=plan.skip_tags,
        launch_template=plan.launch_template,
        # Password answers travel to the apply and are then gone from the plan.
        secret_vars_encrypted=plan.secret_vars_encrypted,
        created_by=user,
    )
    plan.forget_secret_vars()
    job.target_hosts.set(plan.target_hosts.all())
    job.target_groups.set(plan.target_groups.all())
    _carry_on(plan, job)
    return job


def _carry_on(plan: Job, job: Job):
    """The workflow step a preview belongs to goes on with its apply."""
    if plan.workflow_node_id:
        from workflows.engine import on_apply_created

        on_apply_created(plan, job)


def _apply_tofu(plan: Job, user) -> Job:
    project = plan.tofu_project
    if project is None:
        raise CannotApply(_("The project this plan belongs to was deleted."))
    job = Job.objects.create(
        kind=Job.KIND_TOFU_APPLY,
        plan=plan,
        tofu_project=project,
        tofu_destroy=plan.tofu_destroy,
        tofu_revision=plan.tofu_revision,
        playbook_name=plan.playbook_name.replace(" plan", " apply"),
        playbook_yaml="",
        created_by=user,
    )
    job.target_groups.set(plan.target_groups.all())
    if plan.catalog_request_id:
        from catalog.services import on_apply_created

        on_apply_created(plan, job)
    _carry_on(plan, job)
    return job

