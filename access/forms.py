# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils.translation import gettext_lazy as _

from core.forms import style
from inventory.models import HostGroup

from .models import WEEKDAYS, DirectoryGroup, MaintenanceWindow, Role


class TeamForm(forms.ModelForm):
    class Meta:
        model = Group
        fields = ["name"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)


class MemberForm(forms.Form):
    user = forms.ModelChoiceField(queryset=get_user_model().objects.none(), label=_("User"))

    def __init__(self, *args, team, **kwargs):
        super().__init__(*args, **kwargs)
        users = get_user_model().objects.filter(is_active=True).exclude(groups=team)
        if team.directory_groups.exists():
            # The directory rewrites this team's directory members at every
            # sign-in, so adding one here would not stick.
            users = users.filter(directory_account=None)
        self.fields["user"].queryset = users.order_by("username")
        style(self)


class GrantForm(forms.Form):
    host_group = forms.ModelChoiceField(
        queryset=HostGroup.objects.order_by("name"), label=_("Host group")
    )
    role = forms.TypedChoiceField(choices=Role.choices, coerce=int, initial=Role.VIEWER)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)


class DirectoryLinkForm(forms.Form):
    directory_group = forms.ModelChoiceField(
        queryset=DirectoryGroup.objects.none(), label=_("LDAP group")
    )

    def __init__(self, *args, team, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["directory_group"].queryset = DirectoryGroup.objects.exclude(team=team)
        style(self)


class MaintenanceWindowForm(forms.ModelForm):
    weekdays = forms.TypedMultipleChoiceField(
        choices=WEEKDAYS, coerce=int, widget=forms.CheckboxSelectMultiple, label=_("Days"),
        initial=[0, 1, 2, 3, 4, 5, 6],
    )

    class Meta:
        model = MaintenanceWindow
        fields = ["weekdays", "start", "end", "timezone", "description"]
        widgets = {"start": forms.TimeInput(attrs={"type": "time"}, format="%H:%M"),
                   "end": forms.TimeInput(attrs={"type": "time"}, format="%H:%M"),
                   "timezone": forms.TextInput(attrs={"list": "timezones"})}
        labels = {"start": _("From"), "end": _("Until")}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)

    def clean_timezone(self):
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

        name = self.cleaned_data["timezone"].strip()
        try:
            ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise forms.ValidationError(_("Not a time zone name, e.g. Europe/Berlin or UTC.")) from exc
        return name
