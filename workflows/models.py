# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Workflows: steps joined by arrows, run as one.

A step is a playbook run, an OpenTofu plan-and-apply, a person's approval or
a message.  An arrow says when the next step follows: on success, on
failure, or always.  See workflows.engine for how a run moves.
"""
from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from inventory.models import HostGroup


class Workflow(models.Model):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True, default="")
    host_group = models.ForeignKey(
        HostGroup, on_delete=models.PROTECT, related_name="workflows", verbose_name=_("Belongs to"),
        help_text=_("Viewers here see the workflow, Operators run it, Admins change it."),
    )
    extra_vars = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("workflow_detail", args=[self.pk])


class Step(models.Model):
    PLAYBOOK = "playbook"
    TOFU = "tofu"
    APPROVAL = "approval"
    MESSAGE = "message"
    KIND_CHOICES = [
        (PLAYBOOK, _("Run a playbook")),
        (TOFU, _("OpenTofu plan and apply")),
        (APPROVAL, _("Wait for approval")),
        (MESSAGE, _("Send a message")),
    ]

    workflow = models.ForeignKey(Workflow, on_delete=models.CASCADE, related_name="steps")
    name = models.CharField(max_length=120)
    kind = models.CharField(max_length=10, choices=KIND_CHOICES, default=PLAYBOOK)
    playbook = models.ForeignKey("playbooks.Playbook", on_delete=models.PROTECT, null=True, blank=True,
                                 related_name="+")
    host_group = models.ForeignKey(HostGroup, on_delete=models.PROTECT, null=True, blank=True,
                                   related_name="+", verbose_name=_("Runs on"))
    limit = models.CharField(max_length=255, blank=True, default="")
    extra_vars = models.JSONField(default=dict, blank=True)
    tofu_project = models.ForeignKey("infra.TofuProject", on_delete=models.PROTECT, null=True, blank=True,
                                     related_name="+", verbose_name=_("OpenTofu project"))
    # What a message says, or what an approver is asked.
    message = models.TextField(blank=True, default="")
    channels = models.ManyToManyField(
        "notifications.Channel", blank=True, related_name="+",
        help_text=_("Empty: every channel that takes workflow messages."),
    )

    class Meta:
        ordering = ["pk"]
        constraints = [models.UniqueConstraint(fields=["workflow", "name"], name="workflows_step_name")]

    def __str__(self):
        return self.name

    @property
    def target(self) -> str:
        if self.kind == self.PLAYBOOK:
            return f"{self.playbook} on {self.host_group}"
        if self.kind == self.TOFU:
            return str(self.tofu_project)
        return ""


class Edge(models.Model):
    SUCCESS = "success"
    FAILURE = "failure"
    ALWAYS = "always"
    CONDITION_CHOICES = [(SUCCESS, _("on success")), (FAILURE, _("on failure")), (ALWAYS, _("always"))]

    workflow = models.ForeignKey(Workflow, on_delete=models.CASCADE, related_name="edges")
    parent = models.ForeignKey(Step, on_delete=models.CASCADE, related_name="out_edges")
    child = models.ForeignKey(Step, on_delete=models.CASCADE, related_name="in_edges")
    condition = models.CharField(max_length=8, choices=CONDITION_CHOICES, default=SUCCESS)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["parent", "child"], name="workflows_one_edge")]

    def fires(self, parent_status: str) -> bool:
        if parent_status == Node.SUCCESSFUL:
            return self.condition in (self.SUCCESS, self.ALWAYS)
        if parent_status == Node.FAILED:
            return self.condition in (self.FAILURE, self.ALWAYS)
        return False


class Run(models.Model):
    RUNNING = "running"
    SUCCESSFUL = "successful"
    FAILED = "failed"
    CANCELED = "canceled"
    STATUS_CHOICES = [(RUNNING, _("Running")), (SUCCESSFUL, _("Successful")), (FAILED, _("Failed")),
                      (CANCELED, _("Canceled"))]

    workflow = models.ForeignKey(Workflow, on_delete=models.CASCADE, related_name="runs")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=RUNNING, db_index=True)
    extra_vars = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    # Set on the runs a Schedule starts.
    schedule = models.ForeignKey("runs.Schedule", on_delete=models.SET_NULL, null=True, blank=True,
                                 related_name="workflow_runs")
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-pk"]

    def __str__(self):
        return f"{self.workflow} #{self.pk}"

    def get_absolute_url(self):
        return reverse("workflow_run", args=[self.pk])

    @property
    def is_final(self):
        return self.status != self.RUNNING


class Node(models.Model):
    """One step within one run."""

    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"
    SETTLING = "settling"
    SUCCESSFUL = "successful"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELED = "canceled"
    STATUS_CHOICES = [
        (PENDING, _("Not started")),
        (RUNNING, _("Running")),
        (WAITING, _("Waiting for approval")),
        (SETTLING, _("Setting up new hosts")),
        (SUCCESSFUL, _("Successful")),
        (FAILED, _("Failed")),
        (SKIPPED, _("Skipped")),
        (CANCELED, _("Canceled")),
    ]
    FINAL = {SUCCESSFUL, FAILED, SKIPPED, CANCELED}

    run = models.ForeignKey(Run, on_delete=models.CASCADE, related_name="nodes")
    step = models.ForeignKey(Step, on_delete=models.CASCADE, related_name="nodes")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=PENDING)
    job = models.ForeignKey("runs.Job", on_delete=models.SET_NULL, null=True, blank=True, related_name="+")
    note = models.TextField(blank=True, default="")
    # Hosts an OpenTofu apply created, which are being brought up.
    waiting_hosts = models.JSONField(default=list, blank=True)
    # An OpenTofu step's outputs, for the playbook steps after it: the plain
    # ones as they are, the sensitive ones encrypted and wiped when the run
    # ends.  See engine.outputs_for.
    outputs = models.JSONField(default=dict, blank=True)
    secret_outputs_encrypted = models.TextField(blank=True, default="")
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name="+")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["pk"]

    @property
    def is_final(self):
        return self.status in self.FINAL

    @property
    def secret_outputs(self) -> dict:
        import json

        from core.crypto import decrypt

        raw = decrypt(self.secret_outputs_encrypted)
        return json.loads(raw) if raw else {}

    @property
    def badge(self) -> str:
        return {self.SUCCESSFUL: "ok", self.FAILED: "fail", self.RUNNING: "run", self.SETTLING: "run",
                self.WAITING: "warn", self.CANCELED: "warn"}.get(self.status, "")
