# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Pages for secrets: the list of names, and adding, replacing, removing one."""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _

from access import policy

from .forms import SecretForm
from .models import Secret


@login_required
def secret_list(request):
    access = policy.for_user(request.user)
    secrets = list(access.secrets())
    return render(request, "secretstore/secret_list.html", {
        "secrets": secrets,
        "manageable": {s.pk for s in secrets if access.can_manage_secret(s)},
    })


@login_required
def secret_edit(request, pk=None):
    access = policy.for_user(request.user)
    if pk:
        secret = get_object_or_404(Secret, pk=pk)
        access.require_secret(secret)
    else:
        if not access.manages_secrets:
            raise PermissionDenied
        secret = Secret(created_by=request.user)
    initial = {}
    if not pk and request.GET.get("group"):
        initial = {"scope": Secret.GROUP, "host_group": request.GET["group"]}
    elif not pk and request.GET.get("project"):
        initial = {"scope": Secret.PROJECT, "project": request.GET["project"]}
    form = SecretForm(request.POST or None, instance=secret, user=request.user, initial=initial)
    if request.method == "POST" and form.is_valid():
        secret = form.save()
        messages.success(request, _('Secret %(name)s saved for %(scope_label)s.') % {"name": secret.name, "scope_label": secret.scope_label})
        return redirect(request.GET.get("next") if _safe(request.GET.get("next")) else "secret_list")
    return render(request, "secretstore/secret_form.html", {"form": form, "secret": secret})


@login_required
@require_POST
def secret_delete(request, pk):
    secret = get_object_or_404(Secret, pk=pk)
    policy.for_user(request.user).require_secret(secret)
    secret.delete()
    messages.success(request, _('Secret %(name)s (%(scope_label)s) deleted.') % {"name": secret.name, "scope_label": secret.scope_label})
    return redirect("secret_list")


def _safe(url) -> bool:
    return bool(url) and url.startswith("/") and not url.startswith("//")
