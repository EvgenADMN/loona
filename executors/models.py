# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Remote executors: runs for hosts Loona itself cannot reach.

An executor stands for a place - a DMZ, a factory network, another cloud.
One or more agents (``python -m executors.agent``) run there and connect
out to Loona over HTTPS; nothing connects in.  Host groups are assigned to
an executor, and every run on their hosts is prepared by Loona as usual,
then handed to an agent of that executor to carry out.
"""
import hashlib
import secrets
from datetime import timedelta

from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

TOKEN_PREFIX = "lxe_"
# An agent asks for work every few seconds; one not heard of for this long
# counts as offline.
ONLINE_WINDOW = timedelta(seconds=60)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Executor(models.Model):
    name = models.CharField(max_length=120, unique=True, help_text=_('Where it runs, e.g. "DMZ Frankfurt".'))
    description = models.CharField(max_length=255, blank=True, default="")
    enabled = models.BooleanField(
        default=True,
        help_text=_("A disabled executor gets no new runs; they wait until it is enabled again."),
    )
    # Agents sign in with the token; only its hash is kept.
    token_prefix = models.CharField(max_length=16, blank=True, default="")
    token_hash = models.CharField(max_length=64, blank=True, default="", db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("executor_detail", args=[self.pk])

    def issue_token(self) -> str:
        """A new token; the old one stops working. Returns it - shown once."""
        raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
        self.token_prefix, self.token_hash = raw[:12], hash_token(raw)
        self.save(update_fields=["token_prefix", "token_hash"])
        return raw

    @classmethod
    def for_token(cls, raw: str):
        if not raw or not raw.startswith(TOKEN_PREFIX):
            return None
        return cls.objects.filter(token_hash=hash_token(raw)).first()

    @property
    def online_agents(self):
        return [a for a in self.agents.all() if a.is_online]

    @property
    def runner_waiting(self) -> str:
        """Job.runner of a run prepared for this executor, not yet taken."""
        return f"executor/{self.pk}"


class Agent(models.Model):
    """One process that has asked for work - seen, not registered."""

    executor = models.ForeignKey(Executor, on_delete=models.CASCADE, related_name="agents")
    name = models.CharField(max_length=160)
    version = models.CharField(max_length=40, blank=True, default="")
    address = models.CharField(max_length=64, blank=True, default="")
    slots = models.PositiveSmallIntegerField(default=1)
    last_seen_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["executor", "name"], name="agent_unique_name")]

    def __str__(self):
        return f"{self.executor} / {self.name}"

    @property
    def is_online(self) -> bool:
        return timezone.now() - self.last_seen_at < ONLINE_WINDOW
