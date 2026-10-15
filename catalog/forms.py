# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
import json

from django import forms
from django.contrib.auth.models import Group
from django.utils.translation import gettext as _

from access import policy
from core.forms import style
from infra.models import TofuProject
from inventory.models import HostGroup, valid_name
from runs import surveys

from .models import CatalogItem
from .services import name_taken


class ItemForm(forms.ModelForm):
    fields_spec = forms.CharField(required=False, widget=forms.HiddenInput)

    class Meta:
        model = CatalogItem
        fields = ["name", "description", "tofu_project", "host_group", "teams",
                  "approval_required", "max_per_user", "enabled"]
        widgets = {"description": forms.Textarea(attrs={"rows": 3}),
                   "teams": forms.CheckboxSelectMultiple}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.access = policy.for_user(user)
        admin_groups = self.access.groups(policy.ADMIN)
        self.fields["tofu_project"].queryset = TofuProject.objects.filter(host_group__in=admin_groups)
        self.fields["host_group"].queryset = admin_groups
        self.fields["host_group"].required = False
        self.fields["host_group"].help_text = (
            _("Empty: the project's own group. Otherwise a group under it; roles there decide "
            "what requesters may do with their machines."))
        self.fields["teams"].queryset = Group.objects.order_by("name")
        self.fields["fields_spec"].initial = json.dumps(self.instance.fields or [])
        style(self)

    def clean_fields_spec(self):
        try:
            spec = json.loads(self.cleaned_data["fields_spec"] or "[]")
        except ValueError as exc:
            raise forms.ValidationError(_("The form could not be read.")) from exc
        cleaned = surveys.clean_spec(spec, unrestricted=True)
        if any(q["type"] == "password" for q in cleaned):
            # Every later plan of the project needs every answer again; a
            # password would have to be kept for the machine's whole life.
            raise forms.ValidationError(_("A catalog form cannot ask for a password; keep secrets "
                                        "in the project's variables."))
        if any(q["variable"] == "name" for q in cleaned):
            raise forms.ValidationError(_("name is asked anyway: it is the machine's name."))
        return cleaned

    def clean(self):
        cleaned = super().clean()
        project, group = cleaned.get("tofu_project"), cleaned.get("host_group")
        if project and group is None:
            cleaned["host_group"] = project.host_group
        elif project and group.pk not in project.host_group.descendant_ids():
            self.add_error("host_group", _('Pick %(name)s or a group under it.') % {"name": project.host_group.name})
        return cleaned

    def save(self, commit=True):
        item = super().save(commit=False)
        item.fields = self.cleaned_data["fields_spec"]
        item.host_group = self.cleaned_data["host_group"]
        if commit:
            item.save()
            self.save_m2m()
        return item


class RequestForm(surveys.SurveyForm):
    def __init__(self, item, *args, **kwargs):
        super().__init__(item.fields or [], *args, **kwargs)
        name = forms.CharField(
            label=_("Machine name"), max_length=60, validators=[valid_name],
            help_text=_("Becomes its host name in Loona. Letters, digits, dash, dot."),
        )
        name.widget.attrs["class"] = "input mono"
        self.fields = {"name": name, **self.fields}

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        if name_taken(name):
            raise forms.ValidationError(_('%(name)s is taken.') % {"name": name})
        return name

    def values(self) -> dict:
        plain, _secret = self.answers()
        return plain
