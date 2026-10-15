# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Scheduled runs in the UI."""
import json
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.utils.translation import gettext_lazy as _

from access import policy
from core.cron import Cron, CronError
from core.forms import VariablesField, style
from playbooks.models import Playbook
from workflows.models import Workflow

from . import schedules
from .forms import JobLaunchForm
from .models import Schedule


def _visible(user):
    return Schedule.objects.filter(host_group__in=policy.for_user(user).groups())


def may_manage(user, schedule) -> bool:
    """Its owner while they may still run on the group, or an Admin of the group."""
    role = policy.for_user(user).role_for_group(schedule.host_group)
    return role >= policy.ADMIN or (schedule.run_as_id == user.pk and role >= policy.OPERATOR)


class ScheduleForm(forms.ModelForm):
    PLAYBOOK, WORKFLOW = "playbook", "workflow"
    what = forms.ChoiceField(
        label=_("Starts"), choices=[(PLAYBOOK, _("A playbook")), (WORKFLOW, _("A workflow"))],
        initial=PLAYBOOK, widget=forms.RadioSelect, required=False,
    )
    extra_vars = VariablesField(label=_("Extra variables (-e)"))

    class Meta:
        model = Schedule
        fields = ["name", "playbook", "workflow", "host_group", "action", "cron", "timezone",
                  "limit", "tags", "skip_tags", "extra_vars", "enabled"]
        widgets = {"action": forms.RadioSelect,
                   "cron": forms.TextInput(attrs={"placeholder": _("0 3 * * mon-fri"), "class": "mono"}),
                   "timezone": forms.TextInput(attrs={"list": "timezones"})}
        labels = {"host_group": _("Run on")}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        groups = policy.for_user(user).groups(policy.OPERATOR)
        self.fields["host_group"].queryset = groups
        self.fields["playbook"].queryset = Playbook.objects.all()
        self.fields["workflow"].queryset = Workflow.objects.filter(host_group__in=groups)
        self.fields["workflow"].help_text = _("It runs on its own group, with your rights on every step's group.")
        for name in ("playbook", "host_group"):
            self.fields[name].required = False
        if self.instance.workflow_id:
            self.fields["what"].initial = self.WORKFLOW
        style(self)

    def clean_cron(self):
        try:
            Cron.parse(self.cleaned_data["cron"])
        except CronError as exc:
            raise forms.ValidationError(str(exc)) from exc
        return " ".join(self.cleaned_data["cron"].split())

    def clean_timezone(self):
        name = self.cleaned_data["timezone"].strip()
        try:
            ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise forms.ValidationError(_("Not a time zone name, e.g. Europe/Berlin or UTC.")) from exc
        return name

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("what") == self.WORKFLOW:
            cleaned["playbook"] = None
            if not cleaned.get("workflow"):
                self.add_error("workflow", _("Pick the workflow to start."))
                return cleaned
            # Its own group; limit, tags and preview-only belong to playbooks.
            cleaned["host_group"] = cleaned["workflow"].host_group
            cleaned.update(limit="", tags="", skip_tags="", action=Schedule.RUN)
            return cleaned
        cleaned["workflow"] = None
        if not cleaned.get("playbook"):
            self.add_error("playbook", _("Pick the playbook to run."))
        if not cleaned.get("host_group"):
            self.add_error("host_group", _("Pick the group to run it on."))
        if self.errors:
            return cleaned
        # The same checks a launch makes - extra vars that may not touch the
        # connection, a limit that parses - now rather than at 03:00.
        launch = JobLaunchForm({
            "target_groups": [cleaned["host_group"].pk], "target_hosts": [], "limit": cleaned.get("limit", ""),
            "extra_vars": json.dumps(cleaned.get("extra_vars") or {}) if cleaned.get("extra_vars") else "",
            "tags": cleaned.get("tags", ""), "skip_tags": cleaned.get("skip_tags", ""), "forks": 5, "verbosity": 0,
        }, user=self.user)
        if not launch.is_valid():
            for field, errors in launch.errors.items():
                target = field if field in self.fields else None
                for error in errors:
                    self.add_error(target, error)
        return cleaned

    def save(self, commit=True):
        schedule = super().save(commit=False)
        # Whoever saves it is whom it runs as: an Admin changing someone
        # else's schedule does not get to act under that person's name.
        schedule.run_as = self.user
        schedule.next_run_at = schedule.compute_next(timezone.now()) if schedule.enabled else None
        if commit:
            schedule.save()
        return schedule


@login_required
def schedule_list(request):
    access = policy.for_user(request.user)
    items = list(_visible(request.user).select_related("playbook", "workflow", "host_group", "run_as", "last_job", "last_workflow_run"))
    for item in items:
        item.manageable = may_manage(request.user, item)
    return render(request, "runs/schedule_list.html", {
        "schedules": items, "can_create": access.runs_playbooks,
    })


@login_required
def schedule_edit(request, pk=None):
    access = policy.for_user(request.user)
    if pk:
        schedule = get_object_or_404(_visible(request.user), pk=pk)
        if not may_manage(request.user, schedule):
            raise PermissionDenied
    else:
        if not access.runs_playbooks:
            raise PermissionDenied
        schedule = Schedule(run_as=request.user)
    initial = {}
    if not pk and request.GET.get("playbook"):
        initial["playbook"] = request.GET["playbook"]
    if not pk and request.GET.get("workflow"):
        initial.update(workflow=request.GET["workflow"], what=ScheduleForm.WORKFLOW)
    form = ScheduleForm(request.POST or None, instance=schedule, user=request.user, initial=initial)
    if request.method == "POST" and form.is_valid():
        schedule = form.save()
        when = _when(schedule)
        messages.success(request, _('Schedule %(name)s saved. %(when)s') % {"name": schedule.name, "when": when})
        return redirect("schedule_list")
    return render(request, "runs/schedule_form.html", {
        "form": form, "schedule": schedule, "timezones": sorted(available_timezones()),
    })


def _when(schedule) -> str:
    if not schedule.enabled:
        return "It is paused."
    if schedule.next_run_at is None:
        return "That time never comes."
    local = schedule.next_run_at.astimezone(ZoneInfo(schedule.timezone))
    return f"Next run {local:%a %Y-%m-%d %H:%M} {schedule.timezone}."


def _managed(request, pk):
    schedule = get_object_or_404(_visible(request.user), pk=pk)
    if not may_manage(request.user, schedule):
        raise PermissionDenied
    return schedule


@login_required
@require_POST
def schedule_toggle(request, pk):
    schedule = _managed(request, pk)
    schedule.enabled = not schedule.enabled
    schedule.next_run_at = schedule.compute_next() if schedule.enabled else None
    schedule.save(update_fields=["enabled", "next_run_at"])
    messages.success(request, f"{schedule.name}: {_when(schedule)}")
    return redirect("schedule_list")


@login_required
@require_POST
def schedule_run(request, pk):
    """Start it now, exactly as the scheduler would."""
    schedule = _managed(request, pk)
    if schedule.run_as_id != request.user.pk:
        # Started by hand, it runs as the one who pressed the button.
        schedule.run_as = request.user
        schedule.save(update_fields=["run_as"])
    job = schedules.fire(schedule)
    schedule.refresh_from_db()
    if job is None:
        messages.error(request, schedule.last_note or "Not started.")
        return redirect("schedule_list")
    if schedule.last_note:
        messages.warning(request, schedule.last_note)
    return redirect(job)


@login_required
@require_POST
def schedule_delete(request, pk):
    schedule = _managed(request, pk)
    schedule.delete()
    messages.success(request, _('Schedule %(name)s deleted.') % {"name": schedule.name})
    return redirect("schedule_list")
