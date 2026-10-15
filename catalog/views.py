# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The catalog pages: what you may ask for, your requests, the items you run."""
import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _

from access import approvals, policy
from runs import surveys

from . import services
from .forms import ItemForm, RequestForm
from .models import CatalogItem, CatalogRequest


@login_required
def catalog_home(request):
    managed = list(services.managed_items(request.user).select_related("tofu_project", "host_group"))
    managed_ids = {i.pk for i in managed}
    return render(request, "catalog/home.html", {
        "items": services.requestable(request.user),
        "mine": CatalogRequest.objects.filter(requested_by=request.user).select_related("item")[:100],
        "managed": managed,
        "others": CatalogRequest.objects.filter(item_id__in=managed_ids).exclude(requested_by=request.user)
        .select_related("item", "requested_by")[:100],
        "can_add": policy.for_user(request.user).manages_inventory,
    })


@login_required
def item_edit(request, pk=None):
    item = get_object_or_404(CatalogItem, pk=pk) if pk else CatalogItem()
    if pk and not services.can_manage(request.user, item):
        raise PermissionDenied
    if not pk and not policy.for_user(request.user).manages_inventory:
        raise PermissionDenied
    form = ItemForm(request.POST or None, instance=item, user=request.user)
    if request.method == "POST" and form.is_valid():
        item = form.save()
        messages.success(request, _('%(name)s saved.') % {"name": item.name})
        return redirect("catalog_home")
    try:
        spec = json.loads(form["fields_spec"].value() or "[]")
    except ValueError:
        spec = []
    return render(request, "catalog/item_form.html", {
        "form": form, "item": item, "survey": spec if isinstance(spec, list) else [],
        "types": [(t, surveys.TYPE_LABELS[t]) for t in surveys.TYPES if t != "password"],
        "variable": services.VARIABLE,
    })


@login_required
@require_POST
def item_delete(request, pk):
    item = get_object_or_404(CatalogItem, pk=pk)
    if not services.can_manage(request.user, item):
        raise PermissionDenied
    if item.requests.exists():
        item.enabled = False
        item.save(update_fields=["enabled"])
        messages.info(request, _('%(name)s has requests, so it is switched off rather than deleted.') % {"name": item.name})
    else:
        item.delete()
        messages.success(request, _('%(name)s deleted.') % {"name": item.name})
    return redirect("catalog_home")


@login_required
def request_new(request, pk):
    item = get_object_or_404(CatalogItem, pk=pk)
    if not services.can_request(request.user, item):
        raise PermissionDenied
    form = RequestForm(item, request.POST or None)
    error = ""
    if request.method == "POST" and form.is_valid():
        try:
            filed = services.submit(item, request.user, form.cleaned_data["name"], form.values())
        except services.Refused as exc:
            error = str(exc)
        else:
            messages.success(request, _('Requested %(name)s. Loona is planning it now.') % {"name": filed.name})
            return redirect(filed)
    return render(request, "catalog/request_form.html", {"item": item, "form": form, "error": error})


@login_required
def request_detail(request, pk):
    found = get_object_or_404(services.visible_requests(request.user).select_related("item", "job", "host"), pk=pk)
    job = found.job
    plan = job.plan if job and job.plan_id else job
    access = policy.for_user(request.user)
    return render(request, "catalog/request_detail.html", {
        "req": found,
        "plan": plan,
        "tofu": (plan.stats or {}).get("tofu") if plan else None,
        "job_visible": job is not None and access.can_job(job),
        "can_act": found.requested_by_id == request.user.pk or services.can_manage(request.user, found.item),
        "can_approve": plan is not None and found.status == CatalogRequest.WAITING
        and approvals.why_not_approver(request.user, plan) is None,
        "host_visible": found.host_id is not None and access.hosts().filter(pk=found.host_id).exists(),
    })


@login_required
@require_POST
def request_action(request, pk, action):
    found = get_object_or_404(services.visible_requests(request.user), pk=pk)
    actions = {"retire": services.retire, "retry": services.retry, "withdraw": services.withdraw}
    if action not in actions:
        raise PermissionDenied
    try:
        actions[action](found, request.user)
    except services.Refused as exc:
        messages.error(request, str(exc))
    return redirect(found)
