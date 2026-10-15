# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Settings an administrator changes from the UI, and a record of the changes.

What Loona needs before it can start - the secret key, the database URL,
the broker, data directories - stays in the environment.  Everything that is
policy rather than plumbing lives here, in one row, and takes effect without
a restart: see administration.system.
"""
from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

from core.crypto import decrypt, encrypt
from inventory.models import HostGroup


class SystemSettings(models.Model):
    LOCAL_LOGIN_ALL = "all"
    LOCAL_LOGIN_SUPERUSERS = "superusers"
    LOCAL_LOGIN_CHOICES = [
        (LOCAL_LOGIN_ALL, _("Everyone with a local account")),
        (LOCAL_LOGIN_SUPERUSERS, _("Superusers only (the break-glass account)")),
    ]
    MIRROR_ALL = "all"
    MIRROR_MAPPED = "mapped"
    MIRROR_CHOICES = [
        (MIRROR_ALL, _("Every directory group becomes a team")),
        (MIRROR_MAPPED, _("Only groups mapped to a team below")),
    ]

    # -- general -------------------------------------------------------------
    instance_name = models.CharField(
        max_length=60, blank=True, default="",
        help_text=_('Shown next to the logo, e.g. "Production" or "Lab".'),
    )
    language = models.CharField(
        max_length=10, choices=settings.LANGUAGES, default="en",
        help_text=_("The interface language for everyone."),
    )
    session_hours = models.PositiveIntegerField(
        default=12, help_text=_("How long a sign-in lasts before asking again.")
    )
    local_login = models.CharField(
        max_length=12, choices=LOCAL_LOGIN_CHOICES, default=LOCAL_LOGIN_ALL,
        help_text=_("Once LDAP is in charge, keep local accounts for emergencies only."),
    )
    default_approval_policy = models.CharField(
        max_length=8, choices=HostGroup.APPROVAL_CHOICES, default=HostGroup.APPROVAL_DESTROY,
        help_text=_("The approval rule a new host group starts with."),
    )

    public_url = models.CharField(
        _("Loona's address"), max_length=255, blank=True, default="",
        help_text=_("How people reach this Loona, e.g. https://loona.corp.local - "
                  "used for links in notifications."),
    )

    # -- runs ----------------------------------------------------------------
    job_retention_days = models.PositiveIntegerField(
        default=0, help_text=_("Delete finished runs older than this. 0 keeps them all.")
    )
    max_job_events = models.PositiveIntegerField(
        default=5000, help_text=_("Log lines kept per run. 0 keeps them all.")
    )
    bootstrap_wait_seconds = models.PositiveIntegerField(
        default=300, help_text=_("How long a new machine gets to start accepting SSH.")
    )
    adhoc_modules = models.TextField(
        _("Modules for ad-hoc commands"),
        default="command\nshell\nraw\nping\nsetup\nservice\nsystemd\npackage\napt\ndnf\nyum\n"
                "file\nuser\ngroup\nreboot\nwait_for",
        blank=True,
        help_text=_("One per line; empty turns ad-hoc commands off. Modules that read or write "
                  "files on the Loona server (copy, template, script, fetch, ...) stay "
                  "superuser-only even when listed."),
    )
    module_docs = models.BooleanField(
        default=True,
        help_text=_("Build editor forms for every installed module from ansible-doc."),
    )

    # -- LDAP ----------------------------------------------------------------
    ldap_enabled = models.BooleanField(_("Sign in with LDAP"), default=False)
    ldap_server_uri = models.CharField(_("Server"), max_length=255, blank=True, default="",
                                       help_text=_("ldap://dc1.corp.local or ldaps://dc1.corp.local:636"))
    ldap_start_tls = models.BooleanField(_("StartTLS"), default=False)
    ldap_verify_tls = models.BooleanField(_("Verify the server certificate"), default=True)
    ldap_ca_certificate = models.TextField(
        _("CA certificate"), blank=True, default="",
        help_text=_("PEM, if the server's certificate is signed by a private CA."),
    )
    ldap_timeout = models.PositiveIntegerField(_("Timeout, seconds"), default=5)
    ldap_bind_dn = models.CharField(_("Service account DN"), max_length=500, blank=True, default="")
    ldap_bind_password_encrypted = models.TextField(blank=True, default="")
    ldap_user_base = models.CharField(_("Users under"), max_length=500, blank=True, default="")
    ldap_user_filter = models.CharField(_("User filter"), max_length=500, default="(uid={username})",
                                        help_text=_("Active Directory: (sAMAccountName={username})"))
    ldap_username_attr = models.CharField(_("Login attribute"), max_length=100, default="uid")
    ldap_email_attr = models.CharField(_("Mail attribute"), max_length=100, default="mail")
    ldap_first_name_attr = models.CharField(_("First name attribute"), max_length=100, default="givenName")
    ldap_last_name_attr = models.CharField(_("Last name attribute"), max_length=100, default="sn")
    ldap_group_base = models.CharField(_("Groups under"), max_length=500, blank=True, default="")
    ldap_group_filter = models.CharField(
        _("Group filter"), max_length=500,
        default="(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)"
                "(objectClass=posixGroup)(objectClass=group))",
    )
    ldap_group_name_attr = models.CharField(_("Group name attribute"), max_length=100, default="cn")
    ldap_mirror_groups = models.CharField(_("Teams from groups"), max_length=8,
                                          choices=MIRROR_CHOICES, default=MIRROR_ALL)
    ldap_require_group = models.CharField(_("Only members of"), max_length=500, blank=True, default="",
                                          help_text=_("Group DN. Empty lets any directory user in."))
    ldap_superuser_group = models.CharField(_("Superusers are members of"), max_length=500,
                                            blank=True, default="")
    ldap_staff_group = models.CharField(_("Staff are members of"), max_length=500, blank=True, default="")
    ldap_recheck_minutes = models.PositiveIntegerField(
        _("Re-check signed-in users every, minutes"), default=15,
        help_text=_("Someone removed from the directory is signed out at the next re-check."),
    )

    # -- single sign-on (OIDC or SAML) -------------------------------------------
    SSO_OFF, SSO_OIDC, SSO_SAML = "", "oidc", "saml"
    SSO_CHOICES = [(SSO_OFF, _("Off")), (SSO_OIDC, _("OpenID Connect")), (SSO_SAML, _("SAML 2.0"))]
    sso_protocol = models.CharField(_("Single sign-on"), max_length=4, choices=SSO_CHOICES,
                                    default=SSO_OFF, blank=True)
    sso_label = models.CharField(
        _("Button"), max_length=80, default="Sign in with SSO",
        help_text=_('What the sign-in page offers, e.g. "Sign in with Keycloak".'),
    )
    oidc_issuer = models.CharField(
        _("Issuer"), max_length=500, blank=True, default="",
        help_text=_("e.g. https://keycloak.corp.local/realms/main - Loona reads "
                    "/.well-known/openid-configuration under it."),
    )
    oidc_client_id = models.CharField(_("Client ID"), max_length=255, blank=True, default="")
    oidc_client_secret_encrypted = models.TextField(blank=True, default="")
    oidc_scopes = models.CharField(_("Scopes"), max_length=255, default="openid email profile",
                                   help_text=_("Add the one your provider needs for groups, if any."))
    saml_idp_metadata = models.TextField(
        _("Identity provider metadata"), blank=True, default="",
        help_text=_("The IdP's metadata XML, pasted. Its signing certificate is what Loona trusts."),
    )
    sso_username_attr = models.CharField(
        _("Username from"), max_length=255, blank=True, default="",
        help_text=_("Claim or attribute. Empty: preferred_username (OIDC), the NameID (SAML)."),
    )
    sso_email_attr = models.CharField(_("Email from"), max_length=255, default="email")
    sso_first_name_attr = models.CharField(_("First name from"), max_length=255, default="given_name")
    sso_last_name_attr = models.CharField(_("Last name from"), max_length=255, default="family_name")
    sso_groups_attr = models.CharField(_("Groups from"), max_length=255, default="groups", blank=True)
    sso_mirror_groups = models.CharField(_("Teams from groups"), max_length=8,
                                         choices=MIRROR_CHOICES, default=MIRROR_MAPPED)
    sso_require_group = models.CharField(_("Only members of"), max_length=500, blank=True, default="",
                                         help_text=_("Group name. Empty lets anyone the provider vouches for in."))
    sso_superuser_group = models.CharField(_("Superusers are members of"), max_length=500,
                                           blank=True, default="")
    sso_link_existing = models.BooleanField(
        _("Take over existing accounts with the same username"), default=False,
        help_text=_("Off: a sign-in whose username a local or LDAP account already has is refused. "
                    "On: it becomes that account - but never a superuser, nor an account with a "
                    "password or one-time codes of its own."),
    )

    # -- second factor -----------------------------------------------------------
    MFA_OPTIONAL, MFA_SUPERUSERS, MFA_EVERYONE = "optional", "superusers", "everyone"
    MFA_CHOICES = [
        (MFA_OPTIONAL, _("Whoever turns it on")),
        (MFA_SUPERUSERS, _("Required for superusers")),
        (MFA_EVERYONE, _("Required for everyone")),
    ]
    mfa_policy = models.CharField(
        _("One-time codes"), max_length=12, choices=MFA_CHOICES, default=MFA_OPTIONAL,
        help_text=_("For sign-ins with a password - local or LDAP. Whoever it covers and has none, "
                    "you included, is sent to set them up at once. Single sign-on leaves this "
                    "to the identity provider."),
    )

    # -- outgoing mail ---------------------------------------------------------
    SMTP_SECURITY_CHOICES = [("starttls", _("STARTTLS")), ("ssl", _("SSL/TLS")), ("none", _("None"))]
    smtp_host = models.CharField(_("SMTP server"), max_length=255, blank=True, default="")
    smtp_port = models.PositiveIntegerField(_("SMTP port"), default=587)
    smtp_security = models.CharField(_("Security"), max_length=8, choices=SMTP_SECURITY_CHOICES,
                                     default="starttls")
    smtp_username = models.CharField(_("SMTP login"), max_length=255, blank=True, default="")
    smtp_password_encrypted = models.TextField(blank=True, default="")
    smtp_from = models.CharField(_("From address"), max_length=255, blank=True, default="",
                                 help_text=_('e.g. "Loona <loona@corp.local>"'))

    # -- HashiCorp Vault, for secrets kept there ---------------------------------
    HCV_AUTH_CHOICES = [("token", _("Token")), ("approle", _("AppRole"))]
    hcv_address = models.CharField(
        _("Vault address"), max_length=255, blank=True, default="",
        help_text=_("e.g. https://vault.corp.local:8200. Empty: secrets cannot refer to Vault."),
    )
    hcv_namespace = models.CharField(_("Namespace"), max_length=255, blank=True, default="",
                                     help_text=_("Vault Enterprise / HCP only."))
    hcv_auth = models.CharField(_("Sign in with"), max_length=8, choices=HCV_AUTH_CHOICES, default="token")
    hcv_token_encrypted = models.TextField(blank=True, default="")
    hcv_approle_mount = models.CharField(_("AppRole mount"), max_length=120, default="approle")
    hcv_role_id = models.CharField(_("Role ID"), max_length=255, blank=True, default="")
    hcv_secret_id_encrypted = models.TextField(blank=True, default="")
    hcv_verify_tls = models.BooleanField(_("Verify the server certificate"), default=True)
    hcv_ca_certificate = models.TextField(
        _("CA certificate"), blank=True, default="",
        help_text=_("PEM, if Vault's certificate comes from your own CA."),
    )
    hcv_timeout = models.PositiveIntegerField(_("Timeout, seconds"), default=10)
    hcv_allowed_paths = models.TextField(
        _("Paths others may refer to"), blank=True, default="",
        help_text=_("One prefix per line, e.g. secret/data/loona/{group}/ or secret/data/apps/{project}/. "
        "{group} and {project} become the secret's group or project name. Superusers may refer "
        "to any path Loona can read; everyone else only to these."),
    )

    # -- bookkeeping ---------------------------------------------------------
    last_tick_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    class Meta:
        verbose_name = "system settings"
        verbose_name_plural = "system settings"

    def __str__(self):
        return "System settings"

    @property
    def smtp_password(self) -> str:
        return decrypt(self.smtp_password_encrypted)

    @smtp_password.setter
    def smtp_password(self, value: str):
        self.smtp_password_encrypted = encrypt(value or "")

    @property
    def hcv_token(self) -> str:
        return decrypt(self.hcv_token_encrypted)

    @hcv_token.setter
    def hcv_token(self, value: str):
        self.hcv_token_encrypted = encrypt(value or "")

    @property
    def hcv_secret_id(self) -> str:
        return decrypt(self.hcv_secret_id_encrypted)

    @hcv_secret_id.setter
    def hcv_secret_id(self, value: str):
        self.hcv_secret_id_encrypted = encrypt(value or "")

    @property
    def oidc_client_secret(self) -> str:
        return decrypt(self.oidc_client_secret_encrypted)

    @oidc_client_secret.setter
    def oidc_client_secret(self, value: str):
        self.oidc_client_secret_encrypted = encrypt(value or "")

    @property
    def ldap_bind_password(self) -> str:
        return decrypt(self.ldap_bind_password_encrypted)

    @ldap_bind_password.setter
    def ldap_bind_password(self, value: str):
        self.ldap_bind_password_encrypted = encrypt(value or "")


class AuditEntry(models.Model):
    """Who changed which administrative setting, and from what to what."""

    at = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="+"
    )
    section = models.CharField(max_length=40)
    summary = models.CharField(max_length=255)
    # {"field": [before, after]}, secrets shown as "(changed)".
    changes = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-at"]

    def __str__(self):
        return f"{self.at:%Y-%m-%d %H:%M} {self.user}: {self.summary}"
