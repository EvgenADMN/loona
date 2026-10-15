# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Starting, applying, approving and cancelling runs - for the UI and the API.

Both front doors go through here, so a rule enforced once is enforced for
both: who may run what, when "Run now" is off, the two-person rule.
"""
from __future__ import annotations

from django.core.exceptions import PermissionDenied
from django.utils.translation import gettext as _

from access import approvals, policy
from access.models import Approval
from playbooks import yaml_io

from . import plans
from .executor import dispatch
from .models import Job


class Refused(Exception):
    """The request is understood but not allowed right now; str() says why."""


def launch(form, playbook, user, preview: bool, secret_vars=None, template=None) -> Job:
    """Start a playbook from a valid JobLaunchForm."""
    if not policy.for_user(user).runs_playbooks:
        raise PermissionDenied
    job = form.save(commit=False)
    if preview:
        # A check-mode run with diffs, applied later.
        job.check_mode = True
        job.diff_mode = True
    else:
        refusal = approvals.run_now_refusal(
            form.cleaned_data["target_groups"], form.cleaned_data["target_hosts"]
        )
        if refusal:
            raise Refused(refusal)
    job.playbook = playbook
    job.ansible_project = playbook.project
    job.playbook_name = playbook.name
    job.playbook_yaml = yaml_io.playbook_yaml(playbook)
    job.created_by = user
    job.secret_vars = secret_vars or {}
    job.launch_template = template
    job.save()
    form.save_m2m()
    dispatch(job)
    return job


def launch_adhoc(form, user, preview: bool) -> Job:
    """Start an ad-hoc command from a valid adhoc.AdhocForm."""
    from . import adhoc

    job = form.save(commit=False)
    if not preview:
        refusal = approvals.run_now_refusal(
            form.cleaned_data["target_groups"], form.cleaned_data["target_hosts"]
        )
        if refusal:
            raise Refused(refusal)
    job.check_mode = preview
    job.diff_mode = job.diff_mode or preview
    job.kind = Job.KIND_ADHOC
    job.playbook_name = adhoc.label(job.adhoc_module, job.adhoc_args)
    job.playbook_yaml = adhoc.playbook(job.adhoc_module, job.adhoc_args, job.adhoc_become,
                                       templated=user.is_superuser)
    job.created_by = user
    job.save()
    form.save_m2m()
    dispatch(job)
    return job


def launch_template(template, user, survey_form, limit: str, preview: bool) -> Job:
    """Start a launch template with a valid SurveyForm of answers."""
    import json

    from .forms import CONNECTION_VAR, JobLaunchForm

    access = policy.for_user(user)
    access.require_group(template.host_group, policy.OPERATOR)
    plain, secret = survey_form.answers()
    blocked = sorted(k for k in secret if CONNECTION_VAR.match(k))
    if blocked and not access.unrestricted:
        raise Refused(_('Only a superuser may set connection settings: %(join)s.') % {"join": ', '.join(blocked)})
    extra = {**(template.extra_vars or {}), **plain}
    form = JobLaunchForm({
        "target_groups": [template.host_group_id], "target_hosts": [],
        "limit": (limit if template.ask_limit else "") or template.limit,
        "extra_vars": json.dumps(extra) if extra else "",
        "tags": template.tags, "skip_tags": template.skip_tags, "forks": 5, "verbosity": 0,
    }, user=user)
    if not form.is_valid():
        raise Refused(" ".join(f"{k}: {' '.join(v)}" for k, v in form.errors.items()))
    job = launch(form, template.playbook, user, preview=preview, secret_vars=secret, template=template)
    job.playbook_name = f"{template.name}"[:255]
    job.save(update_fields=["playbook_name"])
    return job


def apply(plan: Job, user) -> Job:
    """Carry out a preview. Raises PermissionDenied or plans.CannotApply."""
    # Tearing infrastructure down is an Admin's call, and so is a typed-in
    # command; the rest an Operator's.
    needed = policy.ADMIN if plan.tofu_destroy or plan.is_adhoc else policy.OPERATOR
    policy.for_user(user).require_job(plan, needed)
    job = plans.apply(plan, user)
    dispatch(job)
    return job


def decide(plan: Job, user, approve: bool, comment: str = "") -> tuple[Approval, Job | None]:
    """Approve (and apply) or reject a plan. Raises Refused or plans.CannotApply."""
    from notifications import events

    reason = approvals.why_not_approver(user, plan)
    if reason:
        raise Refused(reason)
    approval = Approval.objects.create(
        plan=plan,
        decision=Approval.APPROVED if approve else Approval.REJECTED,
        decided_by=user,
        comment=(comment or "").strip()[:2000],
    )
    events.decided(approval)
    if not approve:
        if plan.catalog_request_id:
            from catalog.services import on_rejected

            on_rejected(plan, approval)
        if plan.workflow_node_id:
            from workflows.engine import on_rejected as step_rejected

            step_rejected(plan, approval)
        return approval, None
    job = plans.apply(plan, user)
    dispatch(job)
    return approval, job


def cancel(job: Job, user) -> bool:
    """Ask a run to stop. False if it had already finished."""
    policy.for_user(user).require_job(job, policy.OPERATOR)
    if job.is_final:
        return False
    job.canceled = True
    job.save(update_fields=["canceled"])
    if job.status == Job.PENDING:
        # Prepared for a remote executor and not yet taken: nobody else
        # would ever notice.  (A no-op for any other pending run.)
        from executors.remote import cancel_waiting

        cancel_waiting(job)
    return True
