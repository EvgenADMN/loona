# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django import forms
from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.models import Group
from django.utils.translation import gettext_lazy as _

from access.models import DirectoryGroup
from core.forms import style

from .models import SystemSettings

GENERAL_FIELDS = [
    "instance_name", "public_url", "language", "session_hours", "local_login", "mfa_policy",
    "default_approval_policy",
    "job_retention_days", "max_job_events", "bootstrap_wait_seconds", "module_docs", "adhoc_modules",
]
LDAP_FIELDS = [
    "ldap_enabled", "ldap_server_uri", "ldap_start_tls", "ldap_verify_tls", "ldap_ca_certificate",
    "ldap_timeout", "ldap_bind_dn", "ldap_user_base", "ldap_user_filter", "ldap_username_attr",
    "ldap_email_attr", "ldap_first_name_attr", "ldap_last_name_attr", "ldap_group_base",
    "ldap_group_filter", "ldap_group_name_attr", "ldap_mirror_groups", "ldap_require_group",
    "ldap_superuser_group", "ldap_staff_group", "ldap_recheck_minutes",
]
SSO_FIELDS = [
    "sso_protocol", "sso_label", "oidc_issuer", "oidc_client_id", "oidc_scopes", "saml_idp_metadata",
    "sso_username_attr", "sso_email_attr", "sso_first_name_attr", "sso_last_name_attr", "sso_groups_attr",
    "sso_mirror_groups", "sso_require_group", "sso_superuser_group", "sso_link_existing",
]
HCV_FIELDS = [
    "hcv_address", "hcv_namespace", "hcv_auth", "hcv_approle_mount", "hcv_role_id",
    "hcv_verify_tls", "hcv_ca_certificate", "hcv_timeout", "hcv_allowed_paths",
]


class GeneralForm(forms.ModelForm):
    class Meta:
        model = SystemSettings
        fields = GENERAL_FIELDS

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["session_hours"].min_value = 1
        self.fields["adhoc_modules"].widget = forms.Textarea(attrs={"rows": 6, "class": "code"})
        style(self)

    def clean_public_url(self):
        url = self.cleaned_data["public_url"].strip().rstrip("/")
        if url and not url.startswith(("http://", "https://")):
            raise forms.ValidationError(_("Starts with http:// or https://."))
        return url

    def clean_session_hours(self):
        hours = self.cleaned_data["session_hours"]
        if not 1 <= hours <= 24 * 90:
            raise forms.ValidationError(_("Between 1 hour and 90 days."))
        return hours

    def clean_adhoc_modules(self):
        from runs.adhoc import MODULE_RE

        names = self.cleaned_data["adhoc_modules"].split()
        bad = [n for n in names if not MODULE_RE.match(n)]
        if bad:
            raise forms.ValidationError(_('Not a module name: %(join)s.') % {"join": ', '.join(bad)})
        return "\n".join(dict.fromkeys(names))

    def clean_bootstrap_wait_seconds(self):
        seconds = self.cleaned_data["bootstrap_wait_seconds"]
        if not 10 <= seconds <= 3600:
            raise forms.ValidationError(_("Between 10 seconds and an hour."))
        return seconds


class LdapForm(forms.ModelForm):
    bind_password = forms.CharField(
        label=_("Service account password"),
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text=_("Leave empty to keep the stored password."),
    )
    test_username = forms.CharField(
        label=_("Try a user"),
        required=False,
        help_text=_("For Test connection: see which groups and teams this login would get."),
    )

    class Meta:
        model = SystemSettings
        fields = LDAP_FIELDS
        widgets = {"ldap_ca_certificate": forms.Textarea(attrs={"rows": 4, "class": "code"})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("ldap_enabled"):
            for name in ("ldap_server_uri", "ldap_user_base"):
                if not cleaned.get(name):
                    self.add_error(name, _("Needed to sign anyone in."))
        uri = cleaned.get("ldap_server_uri") or ""
        if uri and not uri.startswith(("ldap://", "ldaps://")):
            self.add_error("ldap_server_uri", _("Starts with ldap:// or ldaps://."))
        if "{username}" not in (cleaned.get("ldap_user_filter") or ""):
            self.add_error("ldap_user_filter", _("Must contain {username}."))
        return cleaned

    def save(self, commit=True):
        row = super().save(commit=False)
        if self.cleaned_data.get("bind_password"):
            row.ldap_bind_password = self.cleaned_data["bind_password"]
        if commit:
            row.save()
        return row

    def conf(self, stored_password: str) -> dict:
        """LDAP settings as typed, for testing before saving."""
        data = self.cleaned_data
        return {
            "SOURCE": "test",
            "SERVER_URI": data["ldap_server_uri"],
            "START_TLS": data["ldap_start_tls"],
            "VERIFY_TLS": data["ldap_verify_tls"],
            "CA_FILE": "",
            "CA_DATA": data["ldap_ca_certificate"],
            "TIMEOUT": data["ldap_timeout"],
            "BIND_DN": data["ldap_bind_dn"],
            "BIND_PASSWORD": data.get("bind_password") or stored_password,
            "USER_BASE": data["ldap_user_base"],
            "USER_FILTER": data["ldap_user_filter"],
            "USERNAME_ATTR": data["ldap_username_attr"],
            "EMAIL_ATTR": data["ldap_email_attr"],
            "FIRST_NAME_ATTR": data["ldap_first_name_attr"],
            "LAST_NAME_ATTR": data["ldap_last_name_attr"],
            "GROUP_BASE": data["ldap_group_base"],
            "GROUP_FILTER": data["ldap_group_filter"],
            "GROUP_NAME_ATTR": data["ldap_group_name_attr"],
            "MIRROR_GROUPS": data["ldap_mirror_groups"],
            "REQUIRE_GROUP": data["ldap_require_group"],
            "SUPERUSER_GROUP": data["ldap_superuser_group"],
            "STAFF_GROUP": data["ldap_staff_group"],
            "RECHECK_MINUTES": data["ldap_recheck_minutes"],
        }


class MappingForm(forms.ModelForm):
    """Point a directory group at a team - ahead of anyone signing in, too."""

    class Meta:
        model = DirectoryGroup
        fields = ["dn", "name", "team"]
        labels = {"dn": _("Group DN")}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["team"].queryset = Group.objects.order_by("name")
        self.fields["name"].required = False
        style(self)

    def clean(self):
        cleaned = super().clean()
        dn = cleaned.get("dn", "")
        if dn and not cleaned.get("name"):
            first = dn.split(",", 1)[0]
            cleaned["name"] = first.split("=", 1)[-1] if "=" in first else first
        return cleaned


class UserCreateForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, strip=False)
    teams = forms.ModelMultipleChoiceField(
        queryset=Group.objects.order_by("name"), required=False,
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = get_user_model()
        fields = ["username", "first_name", "last_name", "email", "is_superuser"]
        labels = {"is_superuser": _("Superuser - may do anything, including Administration")}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)

    def clean_password(self):
        password = self.cleaned_data["password"]
        password_validation.validate_password(password, self.instance)
        return password

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        user.is_staff = user.is_superuser
        user.save()
        user.groups.set(self.cleaned_data["teams"])
        return user


class UserEditForm(forms.ModelForm):
    teams = forms.ModelMultipleChoiceField(
        queryset=Group.objects.order_by("name"), required=False,
        widget=forms.CheckboxSelectMultiple,
        help_text=_("Teams the directory manages for this user are kept as they are."),
    )
    new_password = forms.CharField(
        label=_("New password"), widget=forms.PasswordInput, required=False, strip=False,
        help_text=_("Local accounts only. Leave empty to keep the current one."),
    )

    class Meta:
        model = get_user_model()
        fields = ["first_name", "last_name", "email", "is_active", "is_superuser"]
        labels = {"is_active": _("Can sign in"), "is_superuser": _("Superuser")}

    def __init__(self, *args, acting_user, directory_teams=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.acting_user = acting_user
        self.directory_teams = set(directory_teams)
        self.fields["teams"].initial = self.instance.groups.exclude(pk__in=self.directory_teams)
        self.fields["teams"].queryset = Group.objects.exclude(pk__in=self.directory_teams).order_by("name")
        if hasattr(self.instance, "directory_account"):
            # Name and mail come from the directory at every sign-in.
            for name in ("first_name", "last_name", "email", "new_password"):
                self.fields[name].disabled = True
        style(self)

    def clean(self):
        cleaned = super().clean()
        User = get_user_model()
        user = self.instance
        if user == self.acting_user and not cleaned.get("is_active", True):
            raise forms.ValidationError(_("You cannot lock yourself out."))
        losing_superuser = user.is_superuser and (
            not cleaned.get("is_superuser") or not cleaned.get("is_active")
        )
        if losing_superuser:
            if user == self.acting_user:
                raise forms.ValidationError(_("You cannot take your own superuser rights away."))
            others = User.objects.filter(is_superuser=True, is_active=True).exclude(pk=user.pk)
            if not others.exists():
                raise forms.ValidationError(_("This is the last active superuser; nobody could administer Loona."))
        password = cleaned.get("new_password")
        if password:
            password_validation.validate_password(password, user)
        return cleaned

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_staff = user.is_superuser
        if self.cleaned_data.get("new_password"):
            user.set_password(self.cleaned_data["new_password"])
        user.save()
        kept = user.groups.filter(pk__in=self.directory_teams)
        user.groups.set(list(kept) + list(self.cleaned_data["teams"]))
        return user


class VaultForm(forms.ModelForm):
    token = forms.CharField(
        label=_("Token"), required=False, widget=forms.PasswordInput(render_value=False),
        help_text=_("Leave empty to keep the stored token."),
    )
    secret_id = forms.CharField(
        label=_("Secret ID"), required=False, widget=forms.PasswordInput(render_value=False),
        help_text=_("Leave empty to keep the stored Secret ID."),
    )
    test_ref = forms.CharField(
        label=_("Try a reference"), required=False,
        help_text=_("For Test connection: path#key to read, e.g. secret/data/app#password. Only whether it worked is shown."),
    )

    class Meta:
        model = SystemSettings
        fields = HCV_FIELDS
        widgets = {
            "hcv_auth": forms.RadioSelect,
            "hcv_ca_certificate": forms.Textarea(attrs={"rows": 4, "class": "code"}),
            "hcv_allowed_paths": forms.Textarea(attrs={"rows": 3, "class": "code"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)

    def clean(self):
        cleaned = super().clean()
        address = cleaned.get("hcv_address") or ""
        if address and not address.startswith(("http://", "https://")):
            self.add_error("hcv_address", _("Starts with https:// (or http:// for a test server)."))
        cleaned["hcv_address"] = address.rstrip("/")
        if address and cleaned.get("hcv_auth") == "approle" and not cleaned.get("hcv_role_id"):
            self.add_error("hcv_role_id", _("AppRole needs a Role ID."))
        return cleaned

    def save(self, commit=True):
        row = super().save(commit=False)
        if self.cleaned_data.get("token"):
            row.hcv_token = self.cleaned_data["token"]
        if self.cleaned_data.get("secret_id"):
            row.hcv_secret_id = self.cleaned_data["secret_id"]
        if commit:
            row.save()
        return row

    def conf(self, row):
        """The settings as typed, for testing before saving."""
        from secretstore.hashicorp import Conf

        data = self.cleaned_data
        return Conf(
            address=data["hcv_address"], namespace=data["hcv_namespace"], auth=data["hcv_auth"],
            token=data.get("token") or (row.hcv_token if row.hcv_token_encrypted else ""),
            approle_mount=data["hcv_approle_mount"], role_id=data["hcv_role_id"],
            secret_id=data.get("secret_id") or (row.hcv_secret_id if row.hcv_secret_id_encrypted else ""),
            verify_tls=data["hcv_verify_tls"], ca_certificate=data["hcv_ca_certificate"],
            timeout=data["hcv_timeout"] or 10,
        )


class SsoForm(forms.ModelForm):
    client_secret = forms.CharField(
        label=_("Client secret"), required=False, widget=forms.PasswordInput(render_value=False),
        help_text=_("Leave empty to keep the stored secret."),
    )

    class Meta:
        model = SystemSettings
        fields = SSO_FIELDS
        widgets = {"saml_idp_metadata": forms.Textarea(attrs={"rows": 6, "class": "code"}),
                   "sso_protocol": forms.RadioSelect}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)

    def clean(self):
        cleaned = super().clean()
        protocol = cleaned.get("sso_protocol")
        if protocol == "oidc":
            for name in ("oidc_issuer", "oidc_client_id"):
                if not cleaned.get(name):
                    self.add_error(name, _("Needed to sign anyone in."))
            issuer = cleaned.get("oidc_issuer") or ""
            if issuer and not issuer.startswith(("https://", "http://")):
                self.add_error("oidc_issuer", _("Starts with https:// (or http:// for a test server)."))
            if "openid" not in (cleaned.get("oidc_scopes") or "").split():
                self.add_error("oidc_scopes", _("OpenID Connect needs the openid scope."))
            if not cleaned.get("client_secret") and not self.instance.oidc_client_secret_encrypted:
                self.add_error("client_secret", _("Needed to sign anyone in."))
        if protocol == "saml":
            metadata = cleaned.get("saml_idp_metadata") or ""
            if not metadata.strip():
                self.add_error("saml_idp_metadata", _("Needed to sign anyone in."))
            else:
                from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

                try:
                    idp = OneLogin_Saml2_IdPMetadataParser.parse(metadata).get("idp") or {}
                except Exception as exc:  # noqa: BLE001 - a broken paste
                    self.add_error("saml_idp_metadata", _("Cannot read it: %(error)s") % {"error": exc})
                else:
                    if not idp.get("singleSignOnService", {}).get("url"):
                        self.add_error("saml_idp_metadata", _("It names no single sign-on address."))
                    if not (idp.get("x509cert") or idp.get("x509certMulti")):
                        self.add_error("saml_idp_metadata", _("It has no signing certificate."))
        return cleaned

    def save(self, commit=True):
        row = super().save(commit=False)
        if self.cleaned_data.get("client_secret"):
            row.oidc_client_secret = self.cleaned_data["client_secret"]
        if commit:
            row.save()
        return row
