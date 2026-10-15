# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Launch templates: a playbook on a group, with a form for what may vary."""
import json

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext_lazy as _

from access import policy
from core.forms import VariablesField, style
from inventory.models import HostGroup
from playbooks.models import Playbook

from . import services, surveys
from .forms import CONNECTION_VAR
from .models import LaunchTemplate

EDIT = "playbooks.change_playbook"


def _visible(user):
    return LaunchTemplate.objects.filter(host_group__in=policy.for_user(user).groups())


class TemplateForm(forms.ModelForm):
    extra_vars = VariablesField(label=_("Fixed extra variables"))
    survey = forms.CharField(required=False, widget=forms.HiddenInput)

    class Meta:
        model = LaunchTemplate
        fields = ["name", "description", "playbook", "host_group", "limit", "ask_limit",
                  "tags", "skip_tags", "extra_vars"]
        widgets = {"description": forms.Textarea(attrs={"rows": 2})}
        labels = {"host_group": _("Runs on")}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.access = policy.for_user(user)
        groups = self.access.groups(policy.OPERATOR)
        if self.instance.pk:
            groups = groups | HostGroup.objects.filter(pk=self.instance.host_group_id)
        self.fields["host_group"].queryset = groups.distinct()
        self.fields["playbook"].queryset = Playbook.objects.all()
        self.fields["survey"].initial = json.dumps(self.instance.survey or [])
        style(self)

    def clean_extra_vars(self):
        extra = self.cleaned_data["extra_vars"]
        blocked = sorted(k for k in extra if CONNECTION_VAR.match(str(k)))
        if blocked and not self.access.unrestricted:
            raise forms.ValidationError(_('Only a superuser may set connection settings: %(join)s.') % {"join": ', '.join(blocked)})
        return extra

    def clean_survey(self):
        try:
            spec = json.loads(self.cleaned_data["survey"] or "[]")
        except ValueError as exc:
            raise forms.ValidationError(_("The survey could not be read.")) from exc
        return surveys.clean_spec(spec, self.access.unrestricted)

    def save(self, commit=True):
        template = super().save(commit=False)
        template.survey = self.cleaned_data["survey"]
        if commit:
            template.save()
        return template


@login_required
def template_list(request):
    access = policy.for_user(request.user)
    templates = list(_visible(request.user).select_related("playbook", "host_group"))
    operate = access.group_ids(policy.OPERATOR)
    for template in templates:
        template.launchable = template.host_group_id in operate
    return render(request, "runs/template_list.html", {"templates": templates})


@login_required
@permission_required(EDIT, raise_exception=True)
def template_edit(request, pk=None):
    template = get_object_or_404(_visible(request.user), pk=pk) if pk else LaunchTemplate(created_by=request.user)
    if pk and policy.for_user(request.user).role_for_group(template.host_group) < policy.OPERATOR:
        raise PermissionDenied
    initial = {"playbook": request.GET["playbook"]} if not pk and request.GET.get("playbook") else {}
    form = TemplateForm(request.POST or None, instance=template, user=request.user, initial=initial)
    if request.method == "POST" and form.is_valid():
        template = form.save()
        messages.success(request, _('Template %(name)s saved.') % {"name": template.name})
        return redirect(template)
    try:
        survey = json.loads(form["survey"].value() or "[]")
    except ValueError:
        survey = []
    return render(request, "runs/template_form.html", {
        "form": form, "template": template,
        "survey": survey if isinstance(survey, list) else [],
        "types": [(t, surveys.TYPE_LABELS[t]) for t in surveys.TYPES],
    })


@login_required
@permission_required(EDIT, raise_exception=True)
@require_POST
def template_delete(request, pk):
    template = get_object_or_404(_visible(request.user), pk=pk)
    policy.for_user(request.user).require_group(template.host_group, policy.OPERATOR)
    template.delete()
    messages.success(request, _('Template %(name)s deleted.') % {"name": template.name})
    return redirect("template_list")


@login_required
def template_launch(request, pk):
    template = get_object_or_404(_visible(request.user).select_related("playbook", "host_group"), pk=pk)
    access = policy.for_user(request.user)
    can_launch = access.role_for_group(template.host_group) >= policy.OPERATOR
    form = surveys.SurveyForm(template.survey, request.POST or None)
    limit = request.POST.get("limit", template.limit) if template.ask_limit else template.limit
    error = ""
    if request.method == "POST":
        if not can_launch:
            raise PermissionDenied
        if form.is_valid():
            try:
                job = services.launch_template(template, request.user, form, limit,
                                               preview=request.POST.get("action") != "run")
            except services.Refused as exc:
                error = str(exc)
            else:
                return redirect(job)
    return render(request, "runs/template_launch.html", {
        "template": template, "form": form, "limit": limit, "error": error, "can_launch": can_launch,
        "can_edit": access.edit_playbooks,
    })
