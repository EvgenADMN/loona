# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Playbooks, stored either as structured tasks or as raw YAML."""
from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from . import modules as module_catalog


class Project(models.Model):
    """The files a playbook needs besides itself: roles, templates, vars.

    Either kept in Loona and edited in the browser, or checked out of Git
    for each run.  A preview records the commit (or a digest of the files)
    it ran with, and applying it uses the very same.
    """

    SOURCE_FILES = "files"
    SOURCE_GIT = "git"
    SOURCE_CHOICES = [(SOURCE_FILES, _("Files kept in Loona")), (SOURCE_GIT, _("Git repository"))]

    name = models.CharField(max_length=160, unique=True)
    description = models.CharField(max_length=255, blank=True, default="")
    source = models.CharField(max_length=8, choices=SOURCE_CHOICES, default=SOURCE_FILES)
    git_url = models.CharField(_("Repository"), max_length=500, blank=True, default="")
    git_ref = models.CharField(_("Branch or tag"), max_length=200, blank=True, default="main")
    git_path = models.CharField(_("Folder"), max_length=300, blank=True, default="",
                                help_text=_("Where the Ansible content sits in the repository. Empty for the top."))
    git_credential = models.ForeignKey(
        "inventory.Credential", on_delete=models.SET_NULL, null=True, blank=True, related_name="+",
        help_text=_("An SSH key for git@ URLs, or a password / token for https."),
    )
    vault_credentials = models.ManyToManyField(
        "inventory.Credential", blank=True, related_name="+",
        limit_choices_to={"kind": "vault"},
        verbose_name=_("Vault passwords"),
        help_text=_("Open the project's ansible-vault encrypted files and values during a run."),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("project_detail", args=[self.pk])

    @property
    def is_git(self):
        return self.source == self.SOURCE_GIT


class ProjectFile(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="files")
    path = models.CharField(max_length=255, help_text=_("e.g. site.yml, roles/web/tasks/main.yml, templates/nginx.conf.j2"))
    content = models.TextField(blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["path"]
        constraints = [
            models.UniqueConstraint(fields=["project", "path"], name="playbooks_one_file_per_path")
        ]

    def __str__(self):
        return self.path


class Playbook(models.Model):
    """A single Ansible play.

    A playbook lives in one of two editing modes.  In GRAPHICAL mode the play is
    assembled from :class:`PlaybookTask` rows and the YAML is generated on the
    fly.  In TEXT mode ``text_content`` is the source of truth and the tasks are
    ignored (they are kept so switching back is not destructive).
    """

    MODE_GRAPHICAL = "graphical"
    MODE_TEXT = "text"
    MODE_FILE = "file"
    MODE_CHOICES = [
        (MODE_GRAPHICAL, _("Graphical")),
        (MODE_TEXT, _("YAML")),
        (MODE_FILE, _("A file in the project")),
    ]

    TRISTATE = [("", "Inherit"), ("yes", "Yes"), ("no", "No")]

    name = models.CharField(max_length=160, unique=True)
    description = models.TextField(blank=True, default="")
    mode = models.CharField(max_length=16, choices=MODE_CHOICES, default=MODE_GRAPHICAL)

    # Play level options (graphical mode).
    become = models.BooleanField(default=False, help_text=_("Run tasks with privilege escalation."))
    gather_facts = models.BooleanField(default=True)
    serial = models.CharField(
        max_length=32, blank=True, default="", help_text=_('Batch size, e.g. "2" or "25%".')
    )
    any_errors_fatal = models.BooleanField(default=False)
    extra_vars = models.JSONField(default=dict, blank=True, help_text=_("Play level vars."))

    # Raw YAML (text mode).
    text_content = models.TextField(blank=True, default="")
    # Roles, templates and files come from here, and in file mode the
    # playbook itself does too.
    project = models.ForeignKey(
        Project, on_delete=models.PROTECT, null=True, blank=True, related_name="playbooks",
    )
    file_path = models.CharField(
        _("Playbook file"), max_length=255, blank=True, default="",
        help_text=_("In file mode: the playbook's path in the project, e.g. site.yml."),
    )
    vault_credentials = models.ManyToManyField(
        "inventory.Credential", blank=True, related_name="+",
        limit_choices_to={"kind": "vault"},
        verbose_name=_("Vault passwords"),
        help_text=_("For !vault values in the playbook itself. The project's own come along anyway."),
    )

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
        return reverse("playbook_detail", args=[self.pk])

    @property
    def is_graphical(self):
        return self.mode == self.MODE_GRAPHICAL

    @property
    def task_count(self):
        return self.tasks.count()


class PlaybookTask(models.Model):
    """One task inside a graphical playbook."""

    playbook = models.ForeignKey(Playbook, on_delete=models.CASCADE, related_name="tasks")
    order = models.PositiveIntegerField(default=0)
    name = models.CharField(max_length=200, blank=True, default="")
    module = models.CharField(max_length=120)
    args = models.JSONField(default=dict, blank=True)

    # Task level modifiers.
    when = models.CharField(max_length=400, blank=True, default="", help_text=_("Conditional expression."))
    loop = models.TextField(blank=True, default="", help_text=_("YAML list or a Jinja expression."))
    tags = models.CharField(max_length=200, blank=True, default="", help_text=_("Comma separated."))
    become = models.CharField(max_length=4, choices=Playbook.TRISTATE, blank=True, default="")
    ignore_errors = models.BooleanField(default=False)
    register = models.CharField(max_length=120, blank=True, default="")
    enabled = models.BooleanField(default=True)

    class Meta:
        ordering = ["order", "pk"]

    def __str__(self):
        return self.name or self.module

    @property
    def spec(self):
        """Catalog entry for this task's module, or None if unknown."""
        return module_catalog.get_module(self.module)

    @property
    def module_label(self):
        spec = self.spec
        return spec["label"] if spec else self.module

    @property
    def summary(self):
        """One-line preview of the arguments, for the task list."""
        if not self.args:
            return ""
        parts = []
        for key, value in list(self.args.items())[:3]:
            text = str(value)
            if len(text) > 40:
                text = text[:37] + "..."
            parts.append(f"{key}={text}")
        return "  ".join(parts)


class AnsibleModule(models.Model):
    """What ``ansible-doc`` says about one module, cached.

    The index (name and one-line description) is filled in one go; the full
    option list is fetched the first time the module is picked in the editor.
    See :mod:`playbooks.docs`.
    """

    name = models.CharField(max_length=255, unique=True)
    short_description = models.CharField(max_length=500, blank=True, default="")
    # Normalised editor spec, see docs.spec_from_doc.  Null until first used.
    spec = models.JSONField(null=True, blank=True)
    fetched_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name
