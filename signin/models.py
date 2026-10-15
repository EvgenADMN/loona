# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Who signed in through which identity provider, and second factors."""
import hashlib

from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

from core.crypto import decrypt, encrypt


class SsoIdentity(models.Model):
    """An account at an identity provider, tied to one Loona user.

    The provider's subject identifier (OIDC "sub", SAML NameID) is what is
    matched on later sign-ins - not the username, which a provider may let
    people change.
    """

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                related_name="sso_identity")
    protocol = models.CharField(max_length=4)
    issuer = models.CharField(max_length=500)
    subject = models.CharField(max_length=500)
    # Teams the provider's groups put this user in last time - see access.ldap.
    granted_team_ids = models.JSONField(default=list, blank=True)
    synced_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["protocol", "issuer", "subject"],
                                               name="sso_identity_unique")]

    def __str__(self):
        return f"{self.protocol}:{self.subject}"


class TotpDevice(models.Model):
    """An authenticator app holding this user's secret (RFC 6238)."""

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                related_name="totp_device")
    secret_encrypted = models.TextField()
    # Unconfirmed until the first good code: a half-done setup changes nothing.
    confirmed_at = models.DateTimeField(null=True, blank=True)
    # The last time step a code was accepted for; a code works only once.
    last_step = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user}: {'on' if self.confirmed_at else 'being set up'}"

    @property
    def secret(self) -> str:
        return decrypt(self.secret_encrypted)

    @secret.setter
    def secret(self, value: str):
        self.secret_encrypted = encrypt(value)


def hash_code(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").replace(" ", "").lower().encode()).hexdigest()


class RecoveryCode(models.Model):
    """One-time codes for when the phone is gone. Only hashes are kept."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name="recovery_codes")
    code_hash = models.CharField(max_length=64)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _("recovery code")


class SamlRequest(models.Model):
    """A sign-in request Loona sent to the SAML IdP, until its answer comes.

    Kept here rather than in the session: the IdP posts the answer from its
    own site, and browsers do not send a SameSite=Lax session cookie along
    with such a POST.  Each one is good for one answer and ten minutes.
    """

    request_id = models.CharField(max_length=100, unique=True)
    next_url = models.CharField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)


class Throttle(models.Model):
    """Failed sign-ins or codes for one key (an account, an address, both).

    In the database rather than a cache, so every web worker counts the same.
    """

    key = models.CharField(max_length=400, unique=True)
    failures = models.PositiveIntegerField(default=0)
    last_failure_at = models.DateTimeField(db_index=True)
    locked_until = models.DateTimeField(null=True, blank=True)
