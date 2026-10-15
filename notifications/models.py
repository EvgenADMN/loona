# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Where Loona sends word of what happened, and a record of each attempt."""
import json

from django.db import models
from django.utils.translation import gettext_lazy as _

from core.crypto import decrypt, encrypt
from inventory.models import HostGroup

# What a channel can subscribe to.  Keys are stable: they are stored.
RUN_FAILED = "run_failed"
APPROVAL_NEEDED = "approval_needed"
APPROVAL_DECIDED = "approval_decided"
DRIFT_DETECTED = "drift_detected"
DRIFT_RESOLVED = "drift_resolved"
BOOTSTRAP_FAILED = "bootstrap_failed"
HOST_KEY_CHANGED = "host_key_changed"
WORKFLOW_MESSAGE = "workflow_message"
WORKFLOW_FAILED = "workflow_failed"
TEST = "test"

EVENTS = [
    (RUN_FAILED, _("A run failed")),
    (APPROVAL_NEEDED, _("A plan waits for approval")),
    (APPROVAL_DECIDED, _("A plan was approved or rejected")),
    (DRIFT_DETECTED, _("Drift found, or a drift check failed")),
    (DRIFT_RESOLVED, _("Drift gone again")),
    (BOOTSTRAP_FAILED, _("A new machine could not be set up")),
    (HOST_KEY_CHANGED, _("A server's SSH key did not match its pinned key")),
    (WORKFLOW_MESSAGE, _("A workflow sends a message")),
    (WORKFLOW_FAILED, _("A workflow failed")),
]


class Channel(models.Model):
    EMAIL = "email"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"
    KINDS = [(EMAIL, _("Email")), (TELEGRAM, _("Telegram")), (WEBHOOK, _("Webhook (JSON, Slack/Mattermost compatible)"))]

    name = models.CharField(max_length=120, unique=True)
    kind = models.CharField(max_length=10, choices=KINDS)
    enabled = models.BooleanField(default=True)
    events = models.JSONField(default=list, blank=True)
    host_groups = models.ManyToManyField(
        HostGroup,
        blank=True,
        related_name="notification_channels",
        help_text=_("Only events touching these groups (or groups under them). None: everything."),
    )
    # Recipients, chat id, URL - and the secrets next to them - as one
    # encrypted JSON document; see config.
    config_encrypted = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    @property
    def config(self) -> dict:
        raw = decrypt(self.config_encrypted)
        return json.loads(raw) if raw else {}

    @config.setter
    def config(self, value: dict):
        self.config_encrypted = encrypt(json.dumps(value or {}))

    def wants(self, event: str) -> bool:
        return self.enabled and (event == TEST or event in (self.events or []))


class Delivery(models.Model):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    STATUSES = [(PENDING, _("Pending")), (SENT, _("Sent")), (FAILED, _("Failed"))]
    MAX_ATTEMPTS = 3

    channel = models.ForeignKey(Channel, on_delete=models.CASCADE, related_name="deliveries")
    event = models.CharField(max_length=24)
    subject = models.CharField(max_length=255)
    text = models.TextField()
    url = models.CharField(max_length=500, blank=True, default="")
    # Machine-readable details for webhooks: job id, status, groups, hosts.
    data = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=8, choices=STATUSES, default=PENDING, db_index=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.channel}: {self.subject}"
