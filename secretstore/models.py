# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Secrets handed to playbooks as variables: passwords, tokens, keys.

A secret is a variable whose value is encrypted at rest, never shown again
once saved, and kept out of run logs.  It belongs to everything (global), to
a host group (and so to every host in it and in the groups under it) or to an
Ansible project.  The value is either stored here or read from HashiCorp
Vault at run time (secretstore.hashicorp).  See secretstore.resolve for how a
run gets them.
"""
from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Q
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from core.crypto import decrypt, encrypt

variable_name = RegexValidator(
    r"^[A-Za-z_][A-Za-z0-9_]*$",
    "An Ansible variable name: letters, digits and underscores, not starting with a digit.",
)


class Secret(models.Model):
    GLOBAL = "global"
    GROUP = "group"
    PROJECT = "project"
    SCOPES = [(GLOBAL, _("Every run")), (GROUP, _("Hosts of a group")), (PROJECT, _("Runs of a project"))]

    name = models.CharField(
        max_length=120, validators=[variable_name],
        help_text=_("The variable the playbook reads, e.g. db_password."),
    )
    description = models.CharField(max_length=255, blank=True, default="")
    value_encrypted = models.TextField(blank=True, default="")
    # Instead of a value: where in HashiCorp Vault to read it at run time.
    vault_ref = models.CharField(
        _("Vault reference"), max_length=500, blank=True, default="",
        help_text=_("path#key, e.g. secret/data/app#password - read from HashiCorp Vault at every run."),
    )
    host_group = models.ForeignKey(
        "inventory.HostGroup", on_delete=models.CASCADE, null=True, blank=True, related_name="secrets",
    )
    project = models.ForeignKey(
        "playbooks.Project", on_delete=models.CASCADE, null=True, blank=True, related_name="secrets",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [
            models.CheckConstraint(
                condition=Q(host_group__isnull=True) | Q(project__isnull=True),
                name="secretstore_one_scope",
            ),
            models.UniqueConstraint(
                fields=["name"], condition=Q(host_group__isnull=True, project__isnull=True),
                name="secretstore_one_global_per_name",
            ),
            models.UniqueConstraint(
                fields=["name", "host_group"], condition=Q(host_group__isnull=False),
                name="secretstore_one_per_group",
            ),
            models.UniqueConstraint(
                fields=["name", "project"], condition=Q(project__isnull=False),
                name="secretstore_one_per_project",
            ),
        ]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("secret_update", args=[self.pk])

    @property
    def scope(self) -> str:
        if self.host_group_id:
            return self.GROUP
        if self.project_id:
            return self.PROJECT
        return self.GLOBAL

    @property
    def scope_label(self) -> str:
        if self.host_group_id:
            return f"group {self.host_group.name}"
        if self.project_id:
            return f"project {self.project.name}"
        return "global"

    @property
    def in_vault(self) -> bool:
        return bool(self.vault_ref)

    @property
    def value(self) -> str:
        return decrypt(self.value_encrypted)

    @value.setter
    def value(self, plaintext: str):
        self.value_encrypted = encrypt(plaintext or "")
