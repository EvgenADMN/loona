# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Moving a workflow run along.

A step starts once every step with an arrow into it has finished and at
least one of those arrows fired (the step before succeeded and the arrow
says "on success", and so on).  When none fired the step is skipped, and so,
in turn, are the steps that waited on it alone.  Steps whose turn comes
together run side by side.

Every step that runs something does it as an ordinary run, with the rights
of whoever started the workflow at that moment and under the same rules:

* A playbook the group's rules do not let run right now (every change needs
  approval, a maintenance window is closed) becomes a preview, and the step
  waits until someone approves it - as a schedule does.
* An OpenTofu step plans, waits for approval where the rules want one, then
  applies.  Machines the apply created are brought up (infra.bootstrap)
  before the step counts as done, so the next step can reach them.

A run fails when a step fails and no arrow says what to do then.
"""
from __future__ import annotations

import json
import logging

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _

from access import policy
from runs.models import Job

from .models import Edge, Node, Run, Step, Workflow

log = logging.getLogger(__name__)

ACTIVE = {Node.RUNNING, Node.WAITING, Node.SETTLING}


class Refused(Exception):
    pass


# -- who may ---------------------------------------------------------------------


def missing_rights(workflow: Workflow, user) -> list[str]:
    """What this user lacks to run every step of the workflow."""
    access = policy.for_user(user)
    problems = []
    if access.role_for_group(workflow.host_group) < policy.OPERATOR:
        problems.append(f"Operator on {workflow.host_group}")
    for step in workflow.steps.select_related("host_group", "tofu_project__host_group"):
        if step.kind == Step.PLAYBOOK and access.role_for_group(step.host_group) < policy.OPERATOR:
            problems.append(f"Operator on {step.host_group} (step {step.name})")
        if step.kind == Step.TOFU and access.role_for_group(step.tofu_project.host_group) < policy.OPERATOR:
            problems.append(f"Operator on {step.tofu_project.host_group} (step {step.name})")
    return problems


def why_not_approver(node: Node, user) -> str | None:
    if node.step.kind != Step.APPROVAL or node.status != Node.WAITING:
        return "Nothing to approve here."
    if node.run.created_by_id == user.pk:
        return "You started this run; someone else has to approve it."
    if policy.for_user(user).role_for_group(node.run.workflow.host_group) < policy.ADMIN:
        return f"Approving takes the Admin role on {node.run.workflow.host_group}."
    return None


# -- starting and stopping --------------------------------------------------------------


def start(workflow: Workflow, user, extra_vars=None) -> Run:
    if not workflow.steps.exists():
        raise Refused(_("The workflow has no steps yet."))
    problems = missing_rights(workflow, user)
    if problems:
        raise Refused("Running this takes " + "; ".join(problems) + ".")
    run = Run.objects.create(workflow=workflow, created_by=user,
                             extra_vars={**(workflow.extra_vars or {}), **(extra_vars or {})})
    Node.objects.bulk_create(Node(run=run, step=step) for step in workflow.steps.all())
    advance(run)
    run.refresh_from_db()
    return run


def cancel(run: Run, user):
    policy.for_user(user).require_group(run.workflow.host_group, policy.OPERATOR)
    if run.is_final:
        return
    now = timezone.now()
    for node in run.nodes.exclude(status__in=Node.FINAL).select_related("job"):
        if node.job and not node.job.is_final:
            Job.objects.filter(pk=node.job_id).update(canceled=True)
        node.status, node.finished_at = Node.CANCELED, now
        node.note = node.note or f"Canceled by {user}."
        node.save(update_fields=["status", "finished_at", "note"])
    Run.objects.filter(pk=run.pk).update(status=Run.CANCELED, finished_at=now)


# -- the walk ---------------------------------------------------------------------------


def advance(run: Run):
    """Start or skip whatever is due; close the run when nothing is left."""
    while True:
        to_start = _claim(run.pk)
        if to_start is None:
            return
        if not to_start:
            break
        for node in to_start:
            try:
                _start_node(node)
            except Exception as exc:  # noqa: BLE001 - the step fails, not the engine
                log.exception("Workflow step %s could not start", node.pk)
                _finish_node(node, Node.FAILED, f"Could not start: {exc}", advance_after=False)
    _close(run.pk)


@transaction.atomic
def _claim(run_id) -> list[Node] | None:
    """Under the run's lock: skip what can no longer run, claim what can.
    None when the run is over."""
    run = Run.objects.select_for_update().get(pk=run_id)
    if run.is_final:
        return None
    nodes = {n.step_id: n for n in run.nodes.select_related("step", "job")}
    edges = list(Edge.objects.filter(workflow_id=run.workflow_id))
    incoming = {}
    for edge in edges:
        incoming.setdefault(edge.child_id, []).append(edge)
    claimed, changed = [], True
    while changed:
        changed = False
        for step_id, node in nodes.items():
            if node.status != Node.PENDING:
                continue
            parents = incoming.get(step_id, [])
            if any(not nodes[e.parent_id].is_final for e in parents):
                continue
            if parents and not any(e.fires(nodes[e.parent_id].status) for e in parents):
                node.status, node.finished_at = Node.SKIPPED, timezone.now()
                node.save(update_fields=["status", "finished_at"])
            else:
                node.status, node.started_at = Node.RUNNING, timezone.now()
                node.save(update_fields=["status", "started_at"])
                claimed.append(node)
            changed = True
    return claimed


@transaction.atomic
def _close(run_id):
    run = Run.objects.select_for_update().get(pk=run_id)
    if run.is_final or run.nodes.exclude(status__in=Node.FINAL).exists():
        return
    failed = [n for n in run.nodes.select_related("step") if n.status == Node.FAILED]
    handled = set(Edge.objects.filter(parent__in=[n.step for n in failed],
                                      condition__in=(Edge.FAILURE, Edge.ALWAYS)).values_list("parent_id", flat=True))
    unhandled = [n for n in failed if n.step_id not in handled]
    run.status = Run.FAILED if unhandled else Run.SUCCESSFUL
    run.finished_at = timezone.now()
    run.save(update_fields=["status", "finished_at"])
    # Nothing is left to hand them to.
    run.nodes.exclude(secret_outputs_encrypted="").update(secret_outputs_encrypted="")
    if unhandled:
        transaction.on_commit(lambda: _tell_failed(run, unhandled))


def _finish_node(node: Node, status: str, note: str = "", advance_after=True, decided_by=None):
    """Settle a node once; a second, late word on it is ignored."""
    updates = {"status": status, "finished_at": timezone.now()}
    if note:
        updates["note"] = note
    if decided_by is not None:
        updates["decided_by"] = decided_by
    done = Node.objects.filter(pk=node.pk).exclude(status__in=Node.FINAL).update(**updates)
    if done and advance_after:
        advance(node.run)
    return bool(done)


def _set(node: Node, **fields):
    Node.objects.filter(pk=node.pk).update(**fields)
    for key, value in fields.items():
        setattr(node, key, value)


# -- the steps ----------------------------------------------------------------------------


def _start_node(node: Node):
    step, run = node.step, node.run
    user = run.created_by
    if user is None or not user.is_active:
        return _finish_node(node, Node.FAILED, "Whoever started the run can no longer sign in.", advance_after=False)
    if step.kind == Step.MESSAGE:
        _send(node)
        return _finish_node(node, Node.SUCCESSFUL, advance_after=False)
    if step.kind == Step.APPROVAL:
        return _set(node, status=Node.WAITING, note=step.message)
    if step.kind == Step.PLAYBOOK:
        return _start_playbook(node, user)
    if step.kind == Step.TOFU:
        return _start_tofu(node, user)
    return _finish_node(node, Node.FAILED, f"Unknown step kind {step.kind}.", advance_after=False)


def _start_playbook(node: Node, user):
    from runs import services
    from runs.forms import JobLaunchForm

    step, run = node.step, node.run
    plain, secret = outputs_for(run)
    extra = {**(run.extra_vars or {}), **({OUTPUTS_VAR: plain} if plain else {}), **(step.extra_vars or {})}

    def form():
        built = JobLaunchForm({
            "target_groups": [step.host_group_id], "target_hosts": [], "limit": step.limit,
            "extra_vars": json.dumps(extra) if extra else "", "tags": "", "skip_tags": "",
            "forks": 5, "verbosity": 0,
        }, user=user)
        if not built.is_valid():
            raise Refused(" ".join(f"{k}: {' '.join(v)}" for k, v in built.errors.items()))
        return built

    secrets = {SECRET_OUTPUTS_VAR: secret} if secret else None
    note = ""
    try:
        try:
            job = services.launch(form(), step.playbook, user, preview=False, secret_vars=secrets)
        except services.Refused as refusal:
            job = services.launch(form(), step.playbook, user, preview=True, secret_vars=secrets)
            note = f"Started as a preview: {refusal}"
    except (Refused, PermissionDenied) as exc:
        return _finish_node(node, Node.FAILED, str(exc) or "Not allowed.", advance_after=False)
    _link(node, job, note)


def _start_tofu(node: Node, user):
    from infra.services import start_plan
    from runs.executor import dispatch

    project = node.step.tofu_project
    if policy.for_user(user).role_for_group(project.host_group) < policy.OPERATOR:
        return _finish_node(node, Node.FAILED, f"{user} may no longer run {project}.", advance_after=False)
    job = start_plan(project, user)
    job.workflow_node = node
    job.playbook_name = f"{node.run.workflow.name}: {node.step.name} (plan)"
    job.save(update_fields=["workflow_node", "playbook_name"])
    _set(node, job=job)
    dispatch(job)


OUTPUTS_VAR = "tofu_outputs"
SECRET_OUTPUTS_VAR = "tofu_secret_outputs"


def keep_outputs(job: Job, outputs: dict):
    """An OpenTofu step's apply read its outputs: keep them for the steps after it."""
    from core.crypto import encrypt

    if not job.workflow_node_id:
        return
    plain, secret = {}, {}
    for name, data in (outputs or {}).items():
        (secret if data.get("sensitive") else plain)[name] = data.get("value")
    Node.objects.filter(pk=job.workflow_node_id).update(
        outputs=plain, secret_outputs_encrypted=encrypt(json.dumps(secret)) if secret else "")


def outputs_for(run: Run) -> tuple[dict, dict]:
    """(plain, sensitive) outputs of the run's OpenTofu steps so far; a later
    step's output wins over an earlier one of the same name."""
    plain, secret = {}, {}
    done = run.nodes.filter(status=Node.SUCCESSFUL, step__kind=Step.TOFU).order_by("finished_at", "pk")
    for node in done:
        plain.update(node.outputs or {})
        secret.update(node.secret_outputs)
    return plain, secret


def _link(node: Node, job: Job, note=""):
    Job.objects.filter(pk=job.pk).update(
        workflow_node=node, playbook_name=f"{node.run.workflow.name}: {node.step.name}"[:255])
    _set(node, job=job, note=note)
    # A run that failed at once may have ended before it was linked.
    job.refresh_from_db()
    if job.is_final:
        on_job_finished(job)


def _send(node: Node):
    from notifications import dispatch
    from notifications.models import WORKFLOW_MESSAGE

    run = node.run
    failed = ", ".join(n.step.name for n in run.nodes.select_related("step") if n.status == Node.FAILED)
    values = {"workflow": run.workflow.name, "run": run.pk, "started_by": run.created_by or "",
              "failed_steps": failed or "none", "tofu": _Blank(outputs_for(run)[0])}
    text = node.step.message or "{workflow} reached {step}."
    try:
        text = text.format_map(_Blank({**values, "step": node.step.name}))
    except (ValueError, IndexError):
        pass  # braces that are not placeholders: sent as written
    channels = list(node.step.channels.all())
    dispatch.emit(WORKFLOW_MESSAGE, f"{run.workflow.name}: {node.step.name}", text,
                  reverse("workflow_run", args=[run.pk]), run.workflow.host_group.ancestor_ids(),
                  {"workflow": run.workflow.name, "run": run.pk, "step": node.step.name},
                  channels=channels or None)


class _Blank(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def _tell_failed(run, unhandled):
    from notifications import dispatch
    from notifications.models import WORKFLOW_FAILED

    names = ", ".join(n.step.name for n in unhandled)
    dispatch.emit(WORKFLOW_FAILED, f"Workflow failed: {run.workflow.name} #{run.pk}",
                  f"{run.workflow.name} stopped at: {names}. Started by {run.created_by or '?'}.",
                  reverse("workflow_run", args=[run.pk]), run.workflow.host_group.ancestor_ids(),
                  {"workflow": run.workflow.name, "run": run.pk, "failed": names})


# -- hooks from the run machinery ---------------------------------------------------------


def on_job_finished(job: Job):
    """Called for every run that ends: the step it carried out, and any step
    waiting for new hosts to be set up."""
    if job.workflow_node_id:
        node = Node.objects.select_related("run__workflow", "step").filter(pk=job.workflow_node_id).first()
        if node is not None and node.job_id == job.pk and not node.is_final:
            _job_done(node, job)
    _check_settling()


def _job_done(node: Node, job: Job):
    from access import approvals
    from runs import plans
    from runs.executor import dispatch

    if job.status != Job.SUCCESSFUL:
        word = job.get_status_display().lower()
        return _finish_node(node, Node.FAILED, job.error_message or f"Run #{job.pk} ended as {word}.")
    if job.is_plan:
        if not job.plan_has_changes:
            return _finish_node(node, Node.SUCCESSFUL, "Nothing to change.")
        needed = approvals.requirement(job)
        if needed:
            return _set(node, status=Node.WAITING, note=needed)
        try:
            applied = plans.apply(job, node.run.created_by)
        except plans.CannotApply as exc:
            return _finish_node(node, Node.FAILED, str(exc))
        dispatch(applied)
        return None
    if job.kind == Job.KIND_TOFU_APPLY:
        created = ((job.stats or {}).get("tofu") or {}).get("hosts", {}).get("created") or []
        if created:
            _set(node, status=Node.SETTLING, waiting_hosts=created,
                 note=f"Setting up {', '.join(created)}.")
            return _check_settling()
    return _finish_node(node, Node.SUCCESSFUL)


def _check_settling():
    from inventory.models import Host

    for node in Node.objects.filter(status=Node.SETTLING).select_related("run"):
        hosts = list(Host.objects.filter(name__in=node.waiting_hosts))
        if any(h.bootstrapped_at is None and not h.bootstrap_error for h in hosts):
            continue
        broken = [f"{h.name}: {h.bootstrap_error}" for h in hosts if h.bootstrap_error]
        if broken:
            _finish_node(node, Node.FAILED, "; ".join(broken))
        else:
            _finish_node(node, Node.SUCCESSFUL, f"Set up {', '.join(node.waiting_hosts)}.")


def on_apply_created(plan: Job, job: Job):
    """An approved (or automatically applied) preview of a step: the apply carries it on."""
    node = Node.objects.filter(pk=plan.workflow_node_id).first()
    if node is None or node.job_id != plan.pk or node.is_final:
        return
    Job.objects.filter(pk=job.pk).update(workflow_node=node)
    job.workflow_node = node
    _set(node, job=job, status=Node.RUNNING)


def on_rejected(plan: Job, approval):
    node = Node.objects.select_related("run").filter(pk=plan.workflow_node_id).first()
    if node is None or node.job_id != plan.pk:
        return
    reason = f"Rejected by {approval.decided_by}" + (f": {approval.comment}" if approval.comment else ".")
    _finish_node(node, Node.FAILED, reason, decided_by=approval.decided_by)


def decide(node: Node, user, approve: bool, comment: str = ""):
    """An approval step: go on, or stop here."""
    reason = why_not_approver(node, user)
    if reason:
        raise Refused(reason)
    verb = "Approved" if approve else "Rejected"
    note = f"{verb} by {user}" + (f": {comment.strip()}" if comment.strip() else ".")
    _finish_node(node, Node.SUCCESSFUL if approve else Node.FAILED, note[:2000], decided_by=user)


# -- checking a graph ---------------------------------------------------------------------


def has_cycle(pairs) -> bool:
    """Do these (parent, child) arrows go round in a circle?"""
    children = {}
    for parent, child in pairs:
        children.setdefault(parent, set()).add(child)
    state = {}

    def visit(step):
        if state.get(step) == 1:
            return True
        if state.get(step) == 2:
            return False
        state[step] = 1
        if any(visit(c) for c in children.get(step, ())):
            return True
        state[step] = 2
        return False

    return any(visit(s) for s in list(children))
