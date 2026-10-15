# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Pages for API tokens (everyone's own) and triggers."""
from datetime import timedelta

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.utils.translation import gettext_lazy as _

from access import policy
from core.forms import style
from infra.models import TofuProject
from playbooks.models import Playbook

from .models import ApiToken, Trigger


class TokenForm(forms.Form):
    name = forms.CharField(max_length=120, help_text=_('What will use it, e.g. "GitLab deploy pipeline".'))
    lifetime = forms.TypedChoiceField(
        coerce=int, initial=90, label=_("Valid for"),
        choices=[(30, _("30 days")), (90, _("90 days")), (365, _("A year")), (0, _("Until revoked"))],
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)


@login_required
def tokens(request):
    form = TokenForm(request.POST or None)
    fresh = None
    if request.method == "POST" and form.is_valid():
        days = form.cleaned_data["lifetime"]
        expires = timezone.now() + timedelta(days=days) if days else None
        token, fresh = ApiToken.issue(request.user, form.cleaned_data["name"], expires)
        form = TokenForm()
    return render(request, "api/tokens.html", {
        "form": form,
        "fresh": fresh,
        "tokens": request.user.api_tokens.filter(revoked_at__isnull=True),
        "docs": request.build_absolute_uri(reverse("api-docs")),
        "base": request.build_absolute_uri("/api/v1/"),
    })


@login_required
@require_POST
def token_revoke(request, pk):
    token = get_object_or_404(ApiToken, pk=pk, user=request.user)
    token.revoked_at = timezone.now()
    token.save(update_fields=["revoked_at"])
    messages.success(request, _('Token %(name)s revoked.') % {"name": token.name})
    return redirect("api_tokens")


class TriggerForm(forms.ModelForm):
    class Meta:
        model = Trigger
        fields = ["name", "action", "tofu_project", "playbook", "host_group", "workflow", "branch"]
        labels = {"tofu_project": _("OpenTofu project"), "host_group": _("On host group")}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        runnable = policy.for_user(user).groups(policy.OPERATOR)
        self.fields["host_group"].queryset = runnable
        self.fields["tofu_project"].queryset = TofuProject.objects.filter(host_group__in=runnable)
        self.fields["playbook"].queryset = Playbook.objects.order_by("name")
        from workflows.models import Workflow

        self.fields["workflow"].queryset = Workflow.objects.filter(host_group__in=runnable)
        self.fields["action"].choices = Trigger.ACTIONS
        if not self.instance.pk:
            self.fields["action"].initial = Trigger.PLAN
        style(self)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("action") == Trigger.WORKFLOW:
            if not cleaned.get("workflow"):
                self.add_error("workflow", _("Pick the workflow to start."))
            cleaned["playbook"] = cleaned["host_group"] = cleaned["tofu_project"] = None
            return cleaned
        cleaned["workflow"] = None
        if cleaned.get("action") == Trigger.PLAN:
            if not cleaned.get("tofu_project"):
                self.add_error("tofu_project", _("An OpenTofu plan needs a project."))
            cleaned["playbook"] = cleaned["host_group"] = None
        elif cleaned.get("action"):
            if not cleaned.get("playbook"):
                self.add_error("playbook", _("Needed for a playbook trigger."))
            if not cleaned.get("host_group"):
                self.add_error("host_group", _("Needed for a playbook trigger."))
            cleaned["tofu_project"] = None
        return cleaned


def _visible_triggers(user):
    groups = policy.for_user(user).groups()
    return (Trigger.objects.filter(host_group__in=groups)
            | Trigger.objects.filter(tofu_project__host_group__in=groups)
            | Trigger.objects.filter(workflow__host_group__in=groups)).distinct()


@login_required
def triggers(request):
    access = policy.for_user(request.user)
    form = TriggerForm(request.POST or None, user=request.user)
    fresh = None
    if request.method == "POST":
        if not access.runs_playbooks:
            raise PermissionDenied
        if form.is_valid():
            trigger = form.save(commit=False)
            trigger.run_as = request.user
            secret = trigger.new_secret()
            trigger.save()
            fresh = {"trigger": trigger, "secret": secret, "url": _fire_url(request, trigger)}
            form = TriggerForm(user=request.user)
    return render(request, "api/triggers.html", {
        "form": form,
        "fresh": fresh,
        "can_create": access.runs_playbooks,
        "triggers": [
            {"t": t, "url": _fire_url(request, t)}
            for t in _visible_triggers(request.user).select_related("run_as", "last_job", "tofu_project", "playbook", "host_group")
        ],
    })


def _fire_url(request, trigger):
    return request.build_absolute_uri(reverse("api-trigger-fire", args=[trigger.pk]))


def _trigger_for(request, pk):
    trigger = get_object_or_404(_visible_triggers(request.user), pk=pk)
    policy.for_user(request.user).require_group(trigger.scope_group, policy.OPERATOR)
    return trigger


@login_required
@require_POST
def trigger_delete(request, pk):
    trigger = _trigger_for(request, pk)
    trigger.delete()
    messages.success(request, _('Trigger %(name)s removed.') % {"name": trigger.name})
    return redirect("api_triggers")


@login_required
@require_POST
def trigger_toggle(request, pk):
    trigger = _trigger_for(request, pk)
    trigger.enabled = not trigger.enabled
    trigger.save(update_fields=["enabled"])
    return redirect("api_triggers")
