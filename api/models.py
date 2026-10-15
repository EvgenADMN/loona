# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Personal API tokens, and trigger URLs that CI or a Git server can call."""
import hashlib
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from core.crypto import decrypt, encrypt

TOKEN_PREFIX = "loona_"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class ApiToken(models.Model):
    """A key to the API that acts as its owner, with the owner's rights.

    Only a hash is kept; the token itself is shown once, when it is made.
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_tokens")
    name = models.CharField(max_length=120, help_text=_('What uses it, e.g. "GitLab deploy pipeline".'))
    # The first characters, so a token found in a log can be matched to a row.
    prefix = models.CharField(max_length=16)
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.prefix}...)"

    @classmethod
    def issue(cls, user, name, expires_at=None) -> tuple["ApiToken", str]:
        raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
        token = cls.objects.create(user=user, name=name, prefix=raw[:12],
                                   token_hash=hash_token(raw), expires_at=expires_at)
        return token, raw

    @property
    def is_live(self) -> bool:
        if self.revoked_at is not None:
            return False
        return self.expires_at is None or self.expires_at > timezone.now()


class Trigger(models.Model):
    """A secret URL that starts a plan or a preview - from CI, or a Git push.

    It runs as the person who made it, with their rights at the time it
    fires; if they lose those rights, the trigger stops working.
    """

    PLAN = "plan"
    PREVIEW = "preview"
    RUN = "run"
    WORKFLOW = "workflow"
    ACTIONS = [
        (PLAN, _("OpenTofu plan")),
        (PREVIEW, _("Playbook preview")),
        (RUN, _("Playbook run now")),
        (WORKFLOW, _("Start a workflow")),
    ]

    name = models.CharField(max_length=120)
    action = models.CharField(max_length=8, choices=ACTIONS)
    tofu_project = models.ForeignKey("infra.TofuProject", on_delete=models.CASCADE, null=True,
                                     blank=True, related_name="triggers")
    playbook = models.ForeignKey("playbooks.Playbook", on_delete=models.CASCADE, null=True,
                                 blank=True, related_name="triggers")
    host_group = models.ForeignKey("inventory.HostGroup", on_delete=models.CASCADE, null=True,
                                   blank=True, related_name="triggers")
    workflow = models.ForeignKey("workflows.Workflow", on_delete=models.CASCADE, null=True,
                                 blank=True, related_name="triggers")
    branch = models.CharField(
        max_length=200, blank=True, default="",
        help_text=_("Only pushes to this branch fire it (GitHub/GitLab push events). Empty: any call."),
    )
    secret_encrypted = models.TextField()
    enabled = models.BooleanField(default=True)
    run_as = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="triggers")
    created_at = models.DateTimeField(auto_now_add=True)
    last_fired_at = models.DateTimeField(null=True, blank=True)
    last_job = models.ForeignKey("runs.Job", on_delete=models.SET_NULL, null=True, blank=True,
                                 related_name="+")
    last_run = models.ForeignKey("workflows.Run", on_delete=models.SET_NULL, null=True, blank=True,
                                 related_name="+")

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    @property
    def secret(self) -> str:
        return decrypt(self.secret_encrypted)

    def new_secret(self) -> str:
        raw = secrets.token_urlsafe(32)
        self.secret_encrypted = encrypt(raw)
        return raw

    @property
    def scope_group(self):
        return self.tofu_project.host_group if self.tofu_project_id else self.host_group


class TriggerDelivery(models.Model):
    """A signed webhook body a trigger has accepted, so the same one cannot
    fire it again.  GitHub's signature covers the body only, not the time or
    the delivery id, so a captured request would otherwise work forever."""

    trigger = models.ForeignKey(Trigger, on_delete=models.CASCADE, related_name="deliveries")
    digest = models.CharField(max_length=64)
    received_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["trigger", "digest"], name="api_one_delivery_per_body")]
