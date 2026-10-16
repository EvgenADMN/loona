# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
import re

from django import forms
from django.utils.translation import gettext_lazy as _

from access import policy
from core.forms import TextFileField, VariablesField, style

from .models import RESERVED_GROUP_NAMES, Credential, Host, HostGroup

# Ansible's own variables steer how and where it connects, and a template is
# evaluated on the Loona server; both are for superusers.  Same rule as for
# extra vars (runs.forms.CONNECTION_VAR).
ANSIBLE_VAR = re.compile(r"^ansible_", re.IGNORECASE)
TEMPLATE_MARK = re.compile(r"\{\{|\{%|\{#")


def _templated(value) -> bool:
    if isinstance(value, str):
        return bool(TEMPLATE_MARK.search(value))
    if isinstance(value, dict):
        return any(_templated(k) or _templated(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_templated(v) for v in value)
    return False


def check_variables(new: dict, old: dict, access) -> dict:
    """Variables a non-superuser may save: what a superuser set stays as it
    is, but nothing new or changed may be Ansible's own or a template."""
    if access.unrestricted:
        return new
    changed = {k: v for k, v in new.items() if k not in old or old[k] != v}
    reserved = sorted(str(k) for k in changed if ANSIBLE_VAR.match(str(k)))
    templated = sorted(str(k) for k, v in changed.items()
                       if not ANSIBLE_VAR.match(str(k)) and (_templated(k) or _templated(v)))
    problems = []
    if reserved:
        problems.append(forms.ValidationError(
            _("Only a superuser may set Ansible's own variables: %(join)s.") % {"join": ", ".join(reserved)}))
    if templated:
        problems.append(forms.ValidationError(
            _("Only a superuser may use templates in variables: %(join)s.") % {"join": ", ".join(templated)}))
    if problems:
        raise forms.ValidationError(problems)
    return new


def may_use_credential(access, credential) -> bool:
    return credential is None or access.unrestricted or access.credentials().filter(pk=credential.pk).exists()


def check_git_credential_stays(form, access):
    """A Git login the user may not hand out stays with the repository it was
    set for: pointing the project elsewhere would send it to that server."""
    instance, cleaned = form.instance, form.cleaned_data
    credential = cleaned.get("git_credential")
    if not instance.pk or credential is None or credential.pk != instance.git_credential_id:
        return
    if cleaned.get("git_url", instance.git_url) != instance.git_url and not may_use_credential(access, credential):
        form.add_error("git_credential", _("This credential is not shared with you, so it cannot move to another "
                                           "repository. Choose one of yours or none."))


def _keep_unmanaged(selected, current, managed_ids):
    """The selection on screen plus links this user cannot see or change.

    A form only offers the groups its user administers, so anything outside
    them has to survive the save untouched rather than silently vanish.
    """
    kept = [group for group in current if group.pk not in managed_ids]
    return list(selected) + kept


class HostForm(forms.ModelForm):
    variables = VariablesField(label=_("Host variables"))

    class Meta:
        model = Host
        fields = [
            "name",
            "address",
            "port",
            "credential",
            "groups",
            "enabled",
            "description",
            "variables",
        ]
        widgets = {"groups": forms.CheckboxSelectMultiple}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.access = policy.for_user(user)
        self.fields["groups"].queryset = self.access.groups(policy.ADMIN)
        credentials = self.access.credentials()
        if self.instance.credential_id:
            # Keep an existing choice selectable even if it is not ours to hand out.
            credentials = credentials | Credential.objects.filter(pk=self.instance.credential_id)
        self.fields["credential"].queryset = credentials.distinct()
        style(self)

    def clean_variables(self):
        return check_variables(self.cleaned_data["variables"], self.instance.variables or {}, self.access)

    def clean(self):
        cleaned = super().clean()
        # Pointing a host somewhere else sends its login there.  Whoever may
        # not use the host's credential themselves may not do that with it.
        moved = self.moved()
        credential = cleaned.get("credential")
        if moved and credential and credential.pk == self.instance.credential_id \
                and not may_use_credential(self.access, credential):
            raise forms.ValidationError(_(
                "This host logs in with %(credential)s, which is not shared with you. "
                "Choose another credential to move it to a new address.") % {"credential": credential})
        return cleaned

    def moved(self) -> bool:
        """Whether the host now points at another machine. Without an address
        it is reached by its name, so a new name moves it too."""
        if not self.instance.pk:
            return False
        before = (self.initial.get("address") or self.initial.get("name"), self.initial.get("port"))
        cleaned = self.cleaned_data
        after = (cleaned.get("address") or cleaned.get("name"), cleaned.get("port"))
        return before != after

    def save(self, commit=True):
        host = super().save(commit=False)
        # A pinned SSH host key belongs to the machine at the old address; the
        # new one gets pinned at its first connection.
        if self.moved():
            host.ssh_host_keys = ""
            host.ssh_host_keys_pinned_at = None
        if commit:
            host.save()
            self.save_m2m()
        return host

    def clean_groups(self):
        groups = self.cleaned_data["groups"]
        if not self.access.unrestricted and not groups:
            raise forms.ValidationError(
                _("Put the host in at least one group you administer, "
                "or you will not be able to reach it afterwards.")
            )
        current = self.instance.groups.all() if self.instance.pk else []
        return _keep_unmanaged(groups, current, self.access.admin_groups)


class HostGroupForm(forms.ModelForm):
    variables = VariablesField(label=_("Group variables"))

    class Meta:
        model = HostGroup
        fields = ["name", "description", "parents", "variables", "approval_policy"]
        widgets = {"parents": forms.CheckboxSelectMultiple}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.access = policy.for_user(user)
        if not self.instance.pk and "approval_policy" in self.fields:
            from administration import system

            self.fields["approval_policy"].initial = system.get().default_approval_policy
        if not self.access.unrestricted:
            # A group's own admin relaxing its approval rule would make the
            # two-person rule a one-person rule.
            del self.fields["approval_policy"]
        parents = self.access.groups(policy.ADMIN)
        if self.instance.pk:
            # A group cannot be its own parent.
            parents = parents.exclude(pk=self.instance.pk)
        self.fields["parents"].queryset = parents
        style(self)

    def save(self, commit=True):
        group = super().save(commit=False)
        if not group.pk and "approval_policy" not in self.fields:
            from administration import system

            group.approval_policy = system.get().default_approval_policy
        if commit:
            group.save()
            self.save_m2m()
        return group

    def clean_variables(self):
        return check_variables(self.cleaned_data["variables"], self.instance.variables or {}, self.access)

    def clean_name(self):
        name = self.cleaned_data["name"]
        if name.lower() in RESERVED_GROUP_NAMES:
            raise forms.ValidationError(_('Ansible keeps the group %(name)s for itself.') % {"name": repr(name)})
        return name

    def clean_parents(self):
        parents = self.cleaned_data["parents"]
        if self.instance.pk:
            # Ansible refuses an inventory whose groups go round in a circle,
            # which would fail every run that touches them.
            below = self.instance.descendant_ids()
            loop = [g.name for g in parents if g.pk in below]
            if loop:
                raise forms.ValidationError(
                    _('%(join)s is already nested under this group; it cannot be its parent as well.') % {"join": ', '.join(loop)}
                )
            current = self.instance.parents.all()
        else:
            current = []
            # A new top-level group would be out of its creator's own reach.
            if not self.access.unrestricted and not parents:
                raise forms.ValidationError(
                    _("Nest the new group under one you administer.")
                )
        return _keep_unmanaged(parents, current, self.access.admin_groups)


class CredentialForm(forms.ModelForm):
    secret = TextFileField(
        label=_("Private key or password"),
        strip=True,
        widget=forms.Textarea(attrs={"rows": 6, "class": "code", "spellcheck": "false"}),
        help_text=_("Leave empty to keep the stored secret unchanged."),
    )
    become_secret = forms.CharField(
        label=_("Escalation password"),
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text=_("Leave empty to keep the stored password unchanged."),
    )

    class Meta:
        model = Credential
        fields = [
            "name",
            "kind",
            "username",
            "become_method",
            "become_username",
            "vault_id",
            "description",
            "teams",
        ]
        widgets = {"teams": forms.CheckboxSelectMultiple}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("kind") == Credential.KIND_VAULT:
            if not self.instance.secret_encrypted and not cleaned.get("secret"):
                self.add_error("secret", _("The Vault password itself."))
            if self.instance.pk and self.instance.hosts.exists():
                self.add_error("kind", _("Hosts log in with this credential; a Vault password cannot do that."))
            cleaned["become_method"] = ""
        else:
            cleaned["vault_id"] = ""
        vault_id = cleaned.get("vault_id") or ""
        if vault_id and not all(c.isalnum() or c in "-_." for c in vault_id):
            self.add_error("vault_id", _("Letters, digits, dash, underscore and dots."))
        return cleaned

    def save(self, commit=True):
        credential = super().save(commit=False)
        secret = self.cleaned_data.get("secret")
        become_secret = self.cleaned_data.get("become_secret")
        if secret:
            credential.secret = secret
        if become_secret:
            credential.become_secret = become_secret
        if commit:
            credential.save()
            # The teams it is shared with.
            self.save_m2m()
        return credential


class KeyProvisionForm(forms.Form):
    """The login used once, to hand Loona its own key.

    Nothing here is stored: the password lives encrypted on the job for as long
    as the run takes and is wiped when it ends.  After that the host is reached
    with the generated key instead.
    """

    username = forms.CharField(
        label=_("Login"),
        max_length=120,
        help_text=_("Loona logs in as this account and adds its key to that account's "
        "authorized_keys. Escalation for later playbooks still comes from the "
        "host's credential."),
    )
    password = forms.CharField(
        label=_("Password"),
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text=_("Used once and never stored. Leave empty to connect with the "
        "host's saved credential instead."),
    )

    def clean_username(self):
        from .provisioning import LOGIN

        username = self.cleaned_data["username"].strip()
        if not LOGIN.match(username):
            raise forms.ValidationError(_("Letters, digits, dot, dash and underscore, not starting with a digit."))
        return username

    def __init__(self, *args, host=None, **kwargs):
        self.host = host
        super().__init__(*args, **kwargs)
        style(self)

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("password") and self.host and not self.host.credential:
            key = getattr(self.host, "managed_key", None)
            if not (key and key.is_usable):
                raise forms.ValidationError(
                    _("This host has no saved credential and no working key yet, "
                    "so a password is needed to get in the first time.")
                )
        return cleaned


class ConnectionProbeForm(forms.Form):
    """Whatever the connection check can glean from the form on screen.

    Every field is optional because this runs against a host form that has not
    been saved - and may not even be valid yet. The point is to answer "will
    this address and login work" before anything is committed.
    """

    name = forms.CharField(required=False, max_length=120)
    address = forms.CharField(required=False, max_length=255)
    port = forms.IntegerField(required=False, min_value=1, max_value=65535)
    credential = forms.ModelChoiceField(
        queryset=Credential.objects.none(), required=False
    )
    username = forms.CharField(required=False, max_length=120)
    password = forms.CharField(required=False, strip=False)

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user is not None:
            self.fields["credential"].queryset = policy.for_user(user).credentials()

    def target_address(self) -> str:
        return (self.cleaned_data.get("address") or self.cleaned_data.get("name") or "").strip()
