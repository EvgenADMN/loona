# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""OpenTofu projects: where the configuration comes from, its variables, its state.

A project belongs to a host group.  Everything about who may do what follows
the roles on that group - Viewer sees the project, Operator plans and applies,
Admin destroys, and edits it with the right to write OpenTofu code - and hosts
the project creates will join it.
Runs are ordinary :class:`runs.models.Job` rows, so they share the log view,
cancelling, the worker and the preview/apply flow with playbooks.
"""
import json
import posixpath

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from core.crypto import decrypt, encrypt
from inventory.models import Credential, HostGroup


class TofuProject(models.Model):
    SOURCE_FILES = "files"
    SOURCE_GIT = "git"
    SOURCE_CHOICES = [
        (SOURCE_FILES, _("Files kept in Loona")),
        (SOURCE_GIT, _("Git repository")),
    ]

    name = models.CharField(max_length=160, unique=True)
    description = models.CharField(max_length=255, blank=True, default="")
    host_group = models.ForeignKey(
        HostGroup,
        on_delete=models.PROTECT,
        related_name="tofu_projects",
        help_text=_("Roles on this group decide who may see, run and change the project."),
    )
    source = models.CharField(max_length=8, choices=SOURCE_CHOICES, default=SOURCE_FILES)
    git_url = models.CharField(_("Repository"), max_length=500, blank=True, default="")
    git_ref = models.CharField(
        _("Branch or tag"), max_length=200, blank=True, default="main"
    )
    git_path = models.CharField(
        _("Folder"),
        max_length=300,
        blank=True,
        default="",
        help_text=_("Where the configuration sits in the repository. Empty for the top."),
    )
    git_credential = models.ForeignKey(
        Credential,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="tofu_projects",
        help_text=_("An SSH key for git@ URLs, or a password / token for https."),
    )
    # Bringing up machines the project creates: see infra.bootstrap.
    bootstrap_user = models.CharField(
        max_length=120,
        default="root",
        help_text=_("Account the new machines let Loona in as, unless loona_hosts says otherwise."),
    )
    baseline_playbook = models.ForeignKey(
        "playbooks.Playbook",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
        help_text=_("Runs on every new machine once Loona's key is on it."),
    )
    # The key new machines accept on their first boot, handed to OpenTofu as
    # var.loona_ssh_public_key.  Removed from each machine as soon as it has
    # its own key, so it never becomes a key to the whole fleet.
    bootstrap_public_key = models.TextField(blank=True, default="")
    bootstrap_private_key_encrypted = models.TextField(blank=True, default="")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("tofu_project_detail", args=[self.pk])

    @property
    def bootstrap_private_key(self) -> str:
        return decrypt(self.bootstrap_private_key_encrypted)

    def ensure_bootstrap_key(self) -> str:
        """The bootstrap public key, generated the first time it is asked for."""
        if not self.bootstrap_public_key:
            from inventory.keys import generate_keypair

            private, public = generate_keypair(f"loona-bootstrap-{self.pk}")
            self.bootstrap_public_key = public.strip()
            self.bootstrap_private_key_encrypted = encrypt(private)
            self.save(update_fields=["bootstrap_public_key", "bootstrap_private_key_encrypted"])
        return self.bootstrap_public_key

    def clean(self):
        if self.source == self.SOURCE_GIT and not self.git_url:
            raise ValidationError({"git_url": "A Git project needs a repository URL."})
        from core import gitsource

        try:
            self.git_url = gitsource.check_url(self.git_url)
        except ValidationError as exc:
            raise ValidationError({"git_url": exc.messages}) from exc
        try:
            self.git_ref = gitsource.check_ref(self.git_ref)
        except ValidationError as exc:
            raise ValidationError({"git_ref": exc.messages}) from exc
        from inventory.provisioning import LOGIN

        if self.bootstrap_user and not LOGIN.match(self.bootstrap_user):
            raise ValidationError({"bootstrap_user": _("Letters, digits, dot, dash and underscore, "
                                                       "not starting with a digit.")})
        if self.git_path:
            self.git_path = self.git_path.strip("/")
            if ".." in self.git_path.split("/"):
                raise ValidationError({"git_path": "The folder must stay inside the repository."})

    @property
    def is_git(self):
        return self.source == self.SOURCE_GIT

    @property
    def current_state(self):
        return self.state_versions.order_by("-pk").first()

    @property
    def managed_resources(self) -> list[str]:
        """Addresses of what the project currently manages, from its state."""
        current = self.current_state
        if current is None:
            return []
        try:
            data = json.loads(current.data)
        except ValueError:
            return []
        found = []
        for resource in data.get("resources") or []:
            if resource.get("mode") != "managed":
                continue
            address = ".".join(p for p in (resource.get("module"), resource.get("type"), resource.get("name")) if p)
            for instance in resource.get("instances") or [{}]:
                key = instance.get("index_key")
                found.append(address if key is None else f"{address}[{json.dumps(key)}]")
        return found


class TofuFile(models.Model):
    """One file of a project whose configuration lives in Loona."""

    project = models.ForeignKey(TofuProject, on_delete=models.CASCADE, related_name="files")
    path = models.CharField(max_length=255, help_text=_("e.g. main.tf or modules/vm/main.tf"))
    content = models.TextField(blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["path"]
        constraints = [
            models.UniqueConstraint(fields=["project", "path"], name="infra_one_file_per_path")
        ]

    def __str__(self):
        return self.path

    def clean(self):
        self.path = normalise_path(self.path)


def normalise_path(path: str, example: str = "main.tf") -> str:
    """A relative path that cannot escape the project directory."""
    cleaned = posixpath.normpath((path or "").strip().lstrip("/"))
    if cleaned in ("", ".") or cleaned.startswith("..") or "\\" in cleaned:
        raise ValidationError(_('Give a relative path inside the project, like %(example)s.') % {"example": example})
    return cleaned


class TofuVariable(models.Model):
    """An input variable or environment variable for every run of a project.

    Provider credentials belong here: AWS_ACCESS_KEY_ID as an environment
    variable, or a TF_VAR-style input such as proxmox_api_token.  Values are
    encrypted at rest; sensitive ones are never shown again once saved.
    """

    KIND_TFVAR = "tfvar"
    KIND_ENV = "env"
    KIND_CHOICES = [
        (KIND_TFVAR, _("Input variable")),
        (KIND_ENV, _("Environment variable")),
    ]

    project = models.ForeignKey(
        TofuProject, on_delete=models.CASCADE, related_name="variables"
    )
    kind = models.CharField(max_length=8, choices=KIND_CHOICES, default=KIND_TFVAR)
    name = models.CharField(max_length=200)
    value_encrypted = models.TextField(blank=True, default="")
    sensitive = models.BooleanField(
        default=False, help_text=_("Hidden after saving and kept out of logs where OpenTofu allows.")
    )

    class Meta:
        ordering = ["kind", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "kind", "name"], name="infra_one_variable_per_name"
            )
        ]

    def __str__(self):
        return self.name

    @property
    def value(self) -> str:
        return decrypt(self.value_encrypted)

    @value.setter
    def value(self, raw: str):
        self.value_encrypted = encrypt(raw or "")


class TofuStateVersion(models.Model):
    """One write of a project's state, kept so a bad apply can be looked back on.

    The state holds every attribute of every resource - often passwords and
    keys among them - so it is encrypted like any other secret.
    """

    project = models.ForeignKey(
        TofuProject, on_delete=models.CASCADE, related_name="state_versions"
    )
    serial = models.PositiveIntegerField(default=0)
    lineage = models.CharField(max_length=64, blank=True, default="")
    data_encrypted = models.TextField()
    job = models.ForeignKey(
        "runs.Job", on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-pk"]

    def __str__(self):
        return f"{self.project} #{self.serial}"

    @property
    def data(self) -> str:
        return decrypt(self.data_encrypted)

    @data.setter
    def data(self, raw: str):
        self.data_encrypted = encrypt(raw)


class TofuLock(models.Model):
    """Held while a run changes a project's state; at most one per project."""

    project = models.OneToOneField(TofuProject, on_delete=models.CASCADE, related_name="lock")
    # The run holding it, so a run whose worker died does not leave the
    # project locked for good.
    job = models.ForeignKey(
        "runs.Job", on_delete=models.CASCADE, null=True, blank=True, related_name="+"
    )
    lock_id = models.CharField(max_length=100)
    info = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.project} locked by {self.info.get('Who', '?')}"
