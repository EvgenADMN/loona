# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django import forms
from django.utils.translation import gettext_lazy as _

from access import policy
from core.forms import TextFileField, style
from inventory.forms import check_git_credential_stays
from inventory.models import Credential, HostGroup

from .models import TofuFile, TofuProject, TofuVariable, normalise_path


class ProjectForm(forms.ModelForm):
    class Meta:
        model = TofuProject
        fields = [
            "name",
            "description",
            "host_group",
            "source",
            "git_url",
            "git_ref",
            "git_path",
            "git_credential",
            "bootstrap_user",
            "baseline_playbook",
        ]
        widgets = {
            "git_url": forms.TextInput(attrs={"placeholder": "git@git.example.com:infra/tofu.git"}),
            "source": forms.RadioSelect,
        }

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        access = policy.for_user(user)
        # A project can only be put where its creator is Admin, or they could
        # hand themselves infrastructure through a group they merely view.
        groups = access.groups(policy.ADMIN)
        if self.instance.pk:
            groups = groups | HostGroup.objects.filter(pk=self.instance.host_group_id)
        self.fields["host_group"].queryset = groups.distinct()
        credentials = access.credentials()
        if self.instance.git_credential_id:
            # Keep an existing choice selectable even if it is not ours to hand out.
            credentials = credentials | Credential.objects.filter(pk=self.instance.git_credential_id)
        self.fields["git_credential"].queryset = credentials.distinct()
        self.fields["git_credential"].required = False
        self.fields["baseline_playbook"].required = False
        self.access = access
        style(self)

    def clean(self):
        cleaned = super().clean()
        check_git_credential_stays(self, self.access)
        return cleaned


class FileForm(forms.ModelForm):
    content = TextFileField(
        widget=forms.Textarea(attrs={"rows": 28, "class": "code editor", "spellcheck": "false"})
    )

    class Meta:
        model = TofuFile
        fields = ["path", "content"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)

    def clean_path(self):
        path = normalise_path(self.cleaned_data["path"])
        clash = TofuFile.objects.filter(project=self.instance.project, path=path)
        if self.instance.pk:
            clash = clash.exclude(pk=self.instance.pk)
        if clash.exists():
            raise forms.ValidationError(_("The project already has a file with that path."))
        return path


class VariableForm(forms.ModelForm):
    value = TextFileField(
        strip=True,
        widget=forms.Textarea(attrs={"rows": 2, "class": "code", "spellcheck": "false"}),
    )

    class Meta:
        model = TofuVariable
        fields = ["kind", "name", "sensitive"]
        help_texts = {
            "name": _("An input variable's name as in the configuration, or an environment "
            "variable such as AWS_ACCESS_KEY_ID."),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            if self.instance.sensitive:
                self.fields["value"].help_text = _("Hidden. Leave empty to keep the stored value.")
            else:
                self.fields["value"].initial = self.instance.value
        style(self)

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        if not name.replace("_", "a").isalnum() or name[0].isdigit():
            raise forms.ValidationError(_("Letters, digits and underscores, not starting with a digit."))
        return name

    def clean(self):
        cleaned = super().clean()
        kind, name = cleaned.get("kind"), cleaned.get("name")
        if kind and name:
            clash = TofuVariable.objects.filter(project=self.instance.project, kind=kind, name=name)
            if self.instance.pk:
                clash = clash.exclude(pk=self.instance.pk)
            if clash.exists():
                self.add_error("name", _("The project already has this variable."))
        return cleaned

    def save(self, commit=True):
        variable = super().save(commit=False)
        value = self.cleaned_data.get("value") or ""
        keep = self.instance.pk and self.instance.sensitive and not value
        if not keep:
            variable.value = value
        if commit:
            variable.save()
        return variable
