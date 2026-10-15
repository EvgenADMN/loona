# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
import re

from django import forms
from django.utils.translation import gettext_lazy as _

from access import policy
from core.forms import VariablesField, style

from .models import Job

# Extra vars beat every other variable source.  Ansible's own variables would
# let whoever launches a run redirect a host's saved login - and its password -
# elsewhere, or reach the Loona server itself through the options of a
# connection plugin.  All of them, not a list of the known-bad: that list is
# long and grows with every connection and become plugin.
CONNECTION_VAR = re.compile(r"^ansible_", re.IGNORECASE)


def check_limit(value: str) -> str:
    """Ansible reads "--limit @path" from a file on the Loona server; no."""
    value = (value or "").strip()
    if any(part.strip().lstrip("!&").startswith("@") for part in re.split(r"[,:]", value)):
        raise forms.ValidationError(_("A limit names hosts or groups; @file is not available here."))
    return value


class JobLaunchForm(forms.ModelForm):
    """Pick targets and runtime options, then start the playbook."""

    extra_vars = VariablesField(label=_("Extra variables (-e)"))

    class Meta:
        model = Job
        fields = [
            "target_groups",
            "target_hosts",
            "limit",
            "extra_vars",
            "diff_mode",
            "tags",
            "skip_tags",
            "forks",
            "verbosity",
        ]
        widgets = {
            "target_groups": forms.CheckboxSelectMultiple,
            "target_hosts": forms.CheckboxSelectMultiple,
            "limit": forms.TextInput(attrs={"placeholder": "web*:!web03"}),
            "tags": forms.TextInput(attrs={"placeholder": "deploy,config"}),
        }
        labels = {
            "limit": _("Limit pattern"),
            "diff_mode": _("Show diffs"),
        }

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.access = policy.for_user(user)
        self.fields["target_groups"].queryset = self.access.groups(
            policy.OPERATOR
        ).prefetch_related("hosts")
        self.fields["target_hosts"].queryset = self.access.hosts(policy.OPERATOR).filter(
            enabled=True
        )
        self.fields["verbosity"] = forms.TypedChoiceField(
            choices=[(0, _("Normal")), (1, "-v"), (2, _("-vv")), (3, _("-vvv")), (4, _("-vvvv"))],
            coerce=int,
            initial=0,
            label=_("Verbosity"),
        )
        style(self)

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("target_groups") and not cleaned.get("target_hosts"):
            raise forms.ValidationError(_("Select at least one host or host group."))
        return cleaned

    def clean_limit(self):
        return check_limit(self.cleaned_data["limit"])

    def clean_extra_vars(self):
        extra_vars = self.cleaned_data["extra_vars"]
        if self.access.unrestricted:
            return extra_vars
        blocked = sorted(k for k in extra_vars if CONNECTION_VAR.match(str(k)))
        if blocked:
            raise forms.ValidationError(
                _('Only a superuser may override connection settings: %(join)s. Set them on the host or its credential instead.') % {"join": ', '.join(blocked)}
            )
        return extra_vars
