# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django import forms
from django.utils.translation import gettext_lazy as _

from access import policy
from core.forms import TextFileField, style
from playbooks.models import Project

from .models import Secret


PASSWORD_VARS = {"ansible_password", "ansible_become_password"}
STORED = "stored"
VAULT = "vault"


class SecretForm(forms.ModelForm):
    scope = forms.ChoiceField(choices=Secret.SCOPES, widget=forms.RadioSelect, label=_("Given to"))
    source = forms.ChoiceField(
        choices=[(STORED, _("Stored in Loona")), (VAULT, _("Read from HashiCorp Vault"))],
        widget=forms.RadioSelect, label=_("Value"), initial=STORED,
    )
    value = TextFileField(
        label=_("Value"),
        widget=forms.Textarea(attrs={"rows": 4, "class": "code", "spellcheck": "false", "autocomplete": "off"}),
        help_text=_("Encrypted before it is stored and never shown again. Leave empty to keep the stored value."),
    )

    class Meta:
        model = Secret
        fields = ["name", "description", "host_group", "project", "vault_ref"]
        labels = {"host_group": _("Host group"), "project": _("Ansible project")}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        access = policy.for_user(user)
        scopes = []
        if access.manage_global_secrets:
            scopes.append(Secret.GLOBAL)
        if access.manages_inventory:
            scopes.append(Secret.GROUP)
        if access.edit_playbooks:
            scopes.append(Secret.PROJECT)
        self.fields["scope"].choices = [c for c in Secret.SCOPES if c[0] in scopes]
        self.fields["scope"].initial = self.instance.scope if self.instance.pk else (scopes or [""])[0]
        self.fields["host_group"].queryset = access.groups(policy.ADMIN)
        self.fields["project"].queryset = Project.objects.all() if access.edit_playbooks else Project.objects.none()
        self.fields["host_group"].required = self.fields["project"].required = False
        if not self.instance.pk or self.instance.in_vault:
            self.fields["value"].help_text = _("Encrypted before it is stored and never shown again.")
        self.fields["source"].initial = VAULT if self.instance.in_vault else STORED
        from administration import system

        if not system.get().hcv_address and not self.instance.in_vault:
            # Nothing to read from; the choice would only mislead.
            del self.fields["source"]
            del self.fields["vault_ref"]
        style(self)

    def clean_name(self):
        from inventory.forms import ANSIBLE_VAR

        name = self.cleaned_data["name"]
        # A secret reaches the hosts as a variable of that name; one of
        # Ansible's own would steer the connection, which is for superusers.
        # Passwords are what secrets are for, and they stay data.
        if (ANSIBLE_VAR.match(name) and name not in PASSWORD_VARS
                and not policy.for_user(self.user).unrestricted and name != self.instance.name):
            raise forms.ValidationError(_("Only a superuser may name a secret after one of Ansible's own "
                                          "variables, other than its passwords."))
        return name

    def clean(self):
        cleaned = super().clean()
        scope = cleaned.get("scope")
        if scope != Secret.GROUP:
            cleaned["host_group"] = None
        elif not cleaned.get("host_group"):
            self.add_error("host_group", _("Which group's hosts get it."))
        if scope != Secret.PROJECT:
            cleaned["project"] = None
        elif not cleaned.get("project"):
            self.add_error("project", _("Which project's runs get it."))
        if cleaned.get("source") == VAULT:
            cleaned["value"] = ""
            self._clean_vault_ref(cleaned)
        else:
            if "vault_ref" in self.fields:
                cleaned["vault_ref"] = ""
            if (not self.instance.pk or self.instance.in_vault) and not cleaned.get("value"):
                self.add_error("value", _("A secret needs a value."))
        return cleaned

    def _clean_vault_ref(self, cleaned):
        from administration import system

        from . import hashicorp

        ref = (cleaned.get("vault_ref") or "").strip()
        cleaned["vault_ref"] = ref
        try:
            hashicorp.parse(ref)
        except hashicorp.VaultError as exc:
            self.add_error("vault_ref", str(exc))
            return
        if self.user.is_superuser:
            return
        # Loona's own Vault identity does the reading, so without this anyone
        # who may add a secret could read whatever Loona may read.
        group, project = cleaned.get("host_group"), cleaned.get("project")
        if not hashicorp.allowed(ref, system.get().hcv_allowed_paths,
                                 group=group.name if group else "", project=project.name if project else "",
                                 group_id=str(group.pk) if group else "", project_id=str(project.pk) if project else ""):
            self.add_error("vault_ref", _("Not under a path you may refer to. See Administration - HashiCorp Vault for the allowed paths."))

    def save(self, commit=True):
        secret = super().save(commit=False)
        if secret.vault_ref:
            secret.value_encrypted = ""
        elif self.cleaned_data.get("value"):
            secret.value = self.cleaned_data["value"]
        if commit:
            secret.save()
        return secret
