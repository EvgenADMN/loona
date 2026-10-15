# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Requests from the catalog, from the form to a running machine and back out.

A request goes:

    planning -> waiting (for approval) -> applying -> active
                                                  \\-> failed / rejected

and, retired, the same way again with ``retiring`` set, ending as retired.
Each step is an ordinary OpenTofu run of the item's project, tagged with
the request (Job.catalog_request):

* Every plan of the project gets ``var.loona_requests`` - one entry per
  machine that exists or is being created, so a plan made by hand never
  tears down what the catalog put up.  A request's own plan adds its entry
  (or, retiring, leaves it out).
* The plan is approved like any other (access.approvals); the requester is
  its author and so never approves it.
* After the apply the machine is in ``loona_hosts`` and becomes a host in
  the usual way (infra.lifecycle, infra.bootstrap).

The project's configuration declares::

    variable "loona_requests" {
      type = map(object({
        name   = string
        item   = string
        owner  = string
        values = map(string)
      }))
      default = {}
    }

Every answer arrives as a string: numbers as "4", yes/no as "true" or
"false", several choices as a JSON list.
"""
from __future__ import annotations

import json
import logging

from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils.translation import gettext as _

from access import policy
from inventory.models import Host
from runs.models import Job

from .models import CatalogItem, CatalogRequest

log = logging.getLogger(__name__)

VARIABLE = "loona_requests"


class Refused(Exception):
    pass


# -- who may do what ------------------------------------------------------------


def can_request(user, item: CatalogItem) -> bool:
    if not user.is_authenticated or not item.enabled:
        return False
    access = policy.for_user(user)
    if access.role_for_group(item.tofu_project.host_group) >= policy.OPERATOR:
        return True
    return item.teams.filter(pk__in=user.groups.values("pk")).exists()


def can_manage(user, item: CatalogItem) -> bool:
    return policy.for_user(user).role_for_group(item.tofu_project.host_group) >= policy.ADMIN


def requestable(user):
    return [item for item in CatalogItem.objects.filter(enabled=True).select_related("tofu_project__host_group")
            if can_request(user, item)]


def managed_items(user):
    access = policy.for_user(user)
    return CatalogItem.objects.filter(tofu_project__host_group__in=access.groups(policy.ADMIN))


def visible_requests(user):
    """Your own requests, and every request of the items you manage."""
    return CatalogRequest.objects.filter(requested_by=user) | CatalogRequest.objects.filter(
        item__in=managed_items(user)
    )


def require_owner_or_manager(user, request: CatalogRequest):
    if request.requested_by_id != user.pk and not can_manage(user, request.item):
        raise PermissionDenied


# -- what the project is told ---------------------------------------------------------


def as_string(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)


def entry(request: CatalogRequest) -> dict:
    return {
        "name": request.name,
        "item": request.item.name,
        "owner": request.requested_by.get_username() if request.requested_by else "",
        "values": {k: as_string(v) for k, v in (request.values or {}).items()},
    }


def requests_for(job: Job) -> dict | None:
    """var.loona_requests for a plan of this project; None if it has no catalog."""
    project = job.tofu_project
    if project is None or not project.catalog_items.exists():
        return None
    found = {}
    others = (CatalogRequest.objects.filter(item__tofu_project=project)
              .exclude(pk=job.catalog_request_id).select_related("item", "requested_by"))
    for request in others:
        if request.machine_exists:
            found[request.name] = entry(request)
    own = job.catalog_request
    if own is not None and not own.retiring:
        found[own.name] = entry(own)
    return dict(sorted(found.items()))


# -- moving a request along -------------------------------------------------------------


def name_taken(name: str) -> bool:
    if Host.objects.filter(name=name).exists():
        return True
    return any(r.is_open for r in CatalogRequest.objects.filter(name=name))


def open_count(user, item) -> int:
    return sum(1 for r in CatalogRequest.objects.filter(item=item, requested_by=user) if r.is_open)


@transaction.atomic
def submit(item: CatalogItem, user, name: str, values: dict) -> CatalogRequest:
    """File a request and plan it. Raises Refused."""
    if not can_request(user, item):
        raise PermissionDenied
    # One request at a time per item, so two cannot both squeeze under the quota.
    CatalogItem.objects.select_for_update().get(pk=item.pk)
    if item.max_per_user and open_count(user, item) >= item.max_per_user:
        raise Refused(_('You already have %(max_per_user)s of these; retire one first.') % {"max_per_user": item.max_per_user})
    if name_taken(name):
        raise Refused(_('The name %(name)s is taken.') % {"name": name})
    request = CatalogRequest.objects.create(item=item, requested_by=user, name=name, values=values)
    transaction.on_commit(lambda: _dispatch(start_plan(request, user)))
    return request


def start_plan(request: CatalogRequest, user) -> Job:
    """Plan the request's next step; the caller dispatches the job."""
    from infra.services import start_plan as tofu_plan

    job = tofu_plan(request.item.tofu_project, user)
    job.catalog_request = request
    job.playbook_name = f"Catalog: {'retire' if request.retiring else 'create'} {request.name}"
    job.save(update_fields=["catalog_request", "playbook_name"])
    request.status, request.job, request.error = CatalogRequest.PLANNING, job, ""
    request.save(update_fields=["status", "job", "error", "updated_at"])
    return job


def _dispatch(job):
    from runs.executor import dispatch

    dispatch(job)


def retire(request: CatalogRequest, user) -> Job:
    require_owner_or_manager(user, request)
    if request.status != CatalogRequest.ACTIVE:
        raise Refused(_("Only an active request can be retired."))
    request.retiring = True
    request.save(update_fields=["retiring"])
    job = start_plan(request, user)
    _dispatch(job)
    return job


def retry(request: CatalogRequest, user) -> Job:
    """Plan again: after a failure, or when the plan went stale."""
    require_owner_or_manager(user, request)
    if request.status not in (CatalogRequest.FAILED, CatalogRequest.WAITING):
        raise Refused(_("Only a failed or waiting request can be planned again."))
    if request.status == CatalogRequest.FAILED and not request.retiring and name_taken_by_other(request):
        raise Refused(_('The name %(name)s has been taken in the meantime.') % {"name": request.name})
    job = start_plan(request, user)
    _dispatch(job)
    return job


def name_taken_by_other(request) -> bool:
    if Host.objects.filter(name=request.name).exclude(tofu_project=request.item.tofu_project).exists():
        return True
    return any(r.is_open for r in CatalogRequest.objects.filter(name=request.name).exclude(pk=request.pk))


def withdraw(request: CatalogRequest, user):
    """Drop a request that has not been applied, or a retirement not yet applied."""
    require_owner_or_manager(user, request)
    if request.status not in (CatalogRequest.WAITING, CatalogRequest.FAILED):
        raise Refused(_("Only a request waiting for approval, or one that failed, can be withdrawn."))
    if request.retiring:
        request.retiring, request.status = False, CatalogRequest.ACTIVE
        request.error = ""
    else:
        request.status = CatalogRequest.REJECTED
        request.error = f"Withdrawn by {user.get_username()}."
    request.save(update_fields=["retiring", "status", "error", "updated_at"])


# -- hooks from the run machinery --------------------------------------------------------


def approval_reason(job: Job) -> str | None:
    """Why a request's plan needs approval beyond the group's own rules."""
    request = job.catalog_request
    if request is None:
        return None
    if request.item.approval_required:
        return f"Requests for {request.item.name} need an admin's approval."
    tofu = (job.stats or {}).get("tofu") or {}
    if not request.retiring and (tofu.get("destroy") or tofu.get("change")):
        return "This request's plan would also change or destroy other things, so an admin has to look at it."
    return None


def on_apply_created(plan: Job, job: Job):
    request = plan.catalog_request
    if request is None or request.job_id != plan.pk:
        return
    job.catalog_request = request
    job.save(update_fields=["catalog_request"])
    request.status, request.job = CatalogRequest.APPLYING, job
    request.save(update_fields=["status", "job", "updated_at"])


def on_rejected(plan: Job, approval):
    request = plan.catalog_request
    if request is None or request.job_id != plan.pk:
        return
    reason = f"Rejected by {approval.decided_by}" + (f": {approval.comment}" if approval.comment else ".")
    if request.retiring:
        request.retiring, request.status = False, CatalogRequest.ACTIVE
    else:
        request.status = CatalogRequest.REJECTED
    request.error = reason
    request.save(update_fields=["retiring", "status", "error", "updated_at"])


def on_job_finished(job: Job):
    """A request's plan or apply ended: move the request on."""
    request = job.catalog_request
    if request is None or request.job_id != job.pk:
        return  # an older run of a request that has moved on
    if job.kind == Job.KIND_TOFU_PLAN:
        _planned(request, job)
    elif job.kind == Job.KIND_TOFU_APPLY:
        _applied(request, job)


def _fail(request, message):
    request.status, request.error = CatalogRequest.FAILED, message
    request.save(update_fields=["status", "error", "updated_at"])


def _planned(request, job):
    from access import approvals
    from runs import plans

    if job.status != Job.SUCCESSFUL:
        return _fail(request, job.error_message or f"The plan (run #{job.pk}) did not finish; see its log.")
    if not job.plan_has_changes:
        existing = Host.objects.filter(tofu_project=request.item.tofu_project, name=request.name).first()
        if not request.retiring and existing is not None:
            # Already there - an earlier apply got further than it reported.
            return _applied(request, job)
        if request.retiring:
            request.status, request.host = CatalogRequest.RETIRED, None
            request.save(update_fields=["status", "host", "updated_at"])
            return None
        return _fail(request, f"The plan has nothing to create. Does {request.item.tofu_project.name} "
                              f"create a machine for each entry of var.{VARIABLE}?")
    if approvals.requirement(job):
        request.status = CatalogRequest.WAITING
        request.save(update_fields=["status", "updated_at"])
        return None
    try:
        apply_job = plans.apply(job, job.created_by)
    except plans.CannotApply as exc:
        return _fail(request, str(exc))
    _dispatch(apply_job)
    return None


def _applied(request, job):
    if job.status != Job.SUCCESSFUL:
        return _fail(request, job.error_message or f"Applying (run #{job.pk}) failed; see its log.")
    host = Host.objects.filter(tofu_project=request.item.tofu_project, name=request.name).first()
    if request.retiring:
        if host is not None:
            return _fail(request, f"The project still lists {request.name} in loona_hosts.")
        request.status, request.host = CatalogRequest.RETIRED, None
        request.save(update_fields=["status", "host", "updated_at"])
        return None
    if host is None:
        return _fail(request, f"Applied, but the project's loona_hosts output has no {request.name}.")
    request.status, request.host, request.address = CatalogRequest.ACTIVE, host, host.address
    request.error = ""
    request.save(update_fields=["status", "host", "address", "error", "updated_at"])
    return None


def extra_groups(project) -> dict:
    """Host name -> the group its catalog item puts it in, for infra.lifecycle."""
    found = {}
    for request in CatalogRequest.objects.filter(item__tofu_project=project).select_related("item__host_group"):
        if request.machine_exists or request.status == CatalogRequest.APPLYING:
            found[request.name] = request.item.host_group
    return found
