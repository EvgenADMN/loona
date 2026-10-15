# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Hosts, host groups, connection credentials and Loona-managed SSH keys."""
from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from core.crypto import decrypt, encrypt

NAME_HELP = _("Ansible inventory name. Letters, digits, dash, underscore and dots.")
# A name becomes a key of the generated inventory and part of --limit
# patterns, where spaces, commas, colons and the like mean something else.
valid_name = RegexValidator(
    r"^[A-Za-z0-9][A-Za-z0-9_.-]*$",
    "Use letters, digits, dash, underscore and dots, starting with a letter or digit.",
)
# Groups Ansible keeps for itself.
RESERVED_GROUP_NAMES = {"all", "ungrouped"}


class Credential(models.Model):
    """How Loona authenticates to a host."""

    KIND_SSH_KEY = "ssh_key"
    KIND_PASSWORD = "password"
    KIND_VAULT = "vault"
    KIND_CHOICES = [
        (KIND_SSH_KEY, _("SSH private key")),
        (KIND_PASSWORD, _("SSH password")),
        (KIND_VAULT, _("Ansible Vault password")),
    ]
    # What can log in somewhere; a Vault password only opens files.
    LOGIN_KINDS = [KIND_SSH_KEY, KIND_PASSWORD]

    BECOME_CHOICES = [
        ("", _("No privilege escalation")),
        ("sudo", _("sudo")),
        ("su", _("su")),
        ("doas", _("doas")),
        ("pbrun", _("pbrun")),
    ]

    name = models.CharField(max_length=120, unique=True)
    kind = models.CharField(max_length=16, choices=KIND_CHOICES, default=KIND_SSH_KEY)
    username = models.CharField(max_length=120, default="root")
    # Encrypted at rest, see core.crypto.
    secret_encrypted = models.TextField(blank=True, default="")
    become_method = models.CharField(max_length=16, choices=BECOME_CHOICES, blank=True, default="")
    become_username = models.CharField(max_length=120, blank=True, default="root")
    become_secret_encrypted = models.TextField(blank=True, default="")
    vault_id = models.CharField(
        _("Vault ID"), max_length=120, blank=True, default="",
        help_text=_("For a Vault password: the label it was encrypted with (ansible-vault --vault-id). "
        "Empty for files encrypted without one."),
    )
    description = models.CharField(max_length=255, blank=True, default="")
    # Who may attach this credential to their hosts.  Credential managers use
    # every credential regardless; see access.policy.Access.credentials.
    teams = models.ManyToManyField(
        "auth.Group",
        blank=True,
        related_name="credentials",
        help_text=_("Teams whose admins may use this credential on their hosts."),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("credential_list")

    # -- secret access ----------------------------------------------------
    @property
    def secret(self) -> str:
        return decrypt(self.secret_encrypted)

    @secret.setter
    def secret(self, value: str):
        self.secret_encrypted = encrypt(value or "")

    @property
    def become_secret(self) -> str:
        return decrypt(self.become_secret_encrypted)

    @become_secret.setter
    def become_secret(self, value: str):
        self.become_secret_encrypted = encrypt(value or "")


class HostGroup(models.Model):
    """A named set of hosts, mapped 1:1 onto an Ansible inventory group."""

    name = models.CharField(max_length=120, unique=True, help_text=NAME_HELP, validators=[valid_name])
    description = models.CharField(max_length=255, blank=True, default="")
    # Group vars applied to every member, e.g. {"http_port": 8080}.
    variables = models.JSONField(default=dict, blank=True)

    # Which applies need a second person, for this group and the ones under
    # it; the strictest along the way wins.  See access.approvals.
    APPROVAL_NONE = "none"
    APPROVAL_DESTROY = "destroy"
    APPROVAL_CHANGES = "changes"
    APPROVAL_CHOICES = [
        (APPROVAL_NONE, _("Not needed")),
        (APPROVAL_DESTROY, _("To destroy anything")),
        (APPROVAL_CHANGES, _("For every change")),
    ]
    approval_policy = models.CharField(
        max_length=8,
        choices=APPROVAL_CHOICES,
        default=APPROVAL_DESTROY,
        help_text=_("Who else must agree before a preview is applied. Only superusers change this."),
    )
    parents = models.ManyToManyField(
        "self",
        symmetrical=False,
        related_name="children",
        blank=True,
        help_text=_("Groups this one is nested under (children in Ansible terms)."),
    )
    # Runs on this group's hosts are carried out by that executor's agents,
    # for this group and the ones nested under it; the nearest wins.
    executor = models.ForeignKey(
        "executors.Executor", on_delete=models.SET_NULL, null=True, blank=True, related_name="groups",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("group_detail", args=[self.pk])

    def ancestor_ids(self) -> set[int]:
        """This group and every group it is nested under, loops tolerated."""
        found, stack = set(), [self.pk]
        while stack:
            current = stack.pop()
            if current in found:
                continue
            found.add(current)
            stack.extend(
                HostGroup.parents.through.objects.filter(from_hostgroup_id=current).values_list(
                    "to_hostgroup_id", flat=True
                )
            )
        return found

    def descendant_ids(self) -> set[int]:
        """This group and every group nested under it, loops tolerated."""
        found, stack = set(), [self.pk]
        while stack:
            current = stack.pop()
            if current in found:
                continue
            found.add(current)
            stack.extend(
                HostGroup.parents.through.objects.filter(to_hostgroup_id=current).values_list(
                    "from_hostgroup_id", flat=True
                )
            )
        return found

    @property
    def reached_via(self) -> str:
        """The remote executor runs here go through; "" for Loona itself."""
        from executors.routing import describe

        return describe(self)

    def all_hosts(self, _seen=None):
        """Hosts of this group plus every nested child group."""
        _seen = _seen if _seen is not None else set()
        if self.pk in _seen:
            return []
        _seen.add(self.pk)
        found = {h.pk: h for h in self.hosts.all()}
        for child in self.children.all():
            for host in child.all_hosts(_seen):
                found[host.pk] = host
        return list(found.values())


class Host(models.Model):
    """A single managed machine."""

    name = models.CharField(max_length=120, unique=True, help_text=NAME_HELP, validators=[valid_name])
    address = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text=_("IP or DNS name. Defaults to the host name when empty."),
    )
    port = models.PositiveIntegerField(default=22)
    credential = models.ForeignKey(
        Credential, on_delete=models.SET_NULL, null=True, blank=True, related_name="hosts"
    )
    groups = models.ManyToManyField(HostGroup, blank=True, related_name="hosts")
    variables = models.JSONField(default=dict, blank=True)
    enabled = models.BooleanField(default=True)
    description = models.CharField(max_length=255, blank=True, default="")
    # The server's own SSH host keys, one "type base64" per line.  Learned at
    # the first connection (or handed over by OpenTofu before it) and required
    # from then on, so a machine answering in its place is refused.
    ssh_host_keys = models.TextField(blank=True, default="")
    ssh_host_keys_pinned_at = models.DateTimeField(null=True, blank=True)
    # Set for a host an OpenTofu project declared in its loona_hosts output.
    # Such hosts are created, updated and removed by that project's applies;
    # hosts entered by hand are never touched by one.
    tofu_project = models.ForeignKey(
        "infra.TofuProject",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="hosts",
    )
    bootstrapped_at = models.DateTimeField(null=True, blank=True)
    bootstrap_error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("host_detail", args=[self.pk])

    @property
    def reached_via(self) -> str:
        """The remote executor runs here go through; "" for Loona itself."""
        from executors.routing import describe

        return describe(self)

    @property
    def host_key_fingerprints(self) -> list[str]:
        from .hostkeys import fingerprints

        return fingerprints(self.ssh_host_keys)

    @property
    def ansible_host(self) -> str:
        return self.address or self.name


class HostKey(models.Model):
    """The keypair Loona generated for one host, and where it stands.

    Loona never reuses a key across hosts.  The private half is encrypted at
    rest like any other secret and only ever hits the disk inside a job's
    scratch directory, which is shredded when the run ends.
    """

    PENDING = "pending"
    VERIFYING = "verifying"
    ACTIVE = "active"
    FAILED = "failed"
    REVOKING = "revoking"
    REVOKE_FAILED = "revoke_failed"
    STATUS_CHOICES = [
        (PENDING, _("Generated, not installed")),
        (VERIFYING, _("Installed, verifying")),
        (ACTIVE, _("Active")),
        (FAILED, _("Failed")),
        (REVOKING, _("Being revoked")),
        (REVOKE_FAILED, _("Revocation failed")),
    ]
    # Statuses in which Loona connects with this key.  VERIFYING is included
    # because the verification run is itself a connection attempt with it.
    USABLE_STATUSES = {VERIFYING, ACTIVE, REVOKING}

    host = models.OneToOneField(Host, on_delete=models.CASCADE, related_name="managed_key")
    username = models.CharField(
        max_length=120, help_text=_("Remote account the key was added to.")
    )
    public_key = models.TextField(help_text=_("The authorized_keys line, comment included."))
    private_key_encrypted = models.TextField(blank=True, default="")
    fingerprint = models.CharField(max_length=64, blank=True, default="")
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=PENDING)
    error_message = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    # Set once the key has actually reached the remote authorized_keys file.
    installed_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.username}@{self.host.name}"

    @property
    def private_key(self) -> str:
        return decrypt(self.private_key_encrypted)

    @private_key.setter
    def private_key(self, value: str):
        self.private_key_encrypted = encrypt(value or "")

    @property
    def is_usable(self) -> bool:
        return self.status in self.USABLE_STATUSES and bool(self.private_key_encrypted)

    @property
    def is_installed(self) -> bool:
        """Whether the key is expected to sit in the remote authorized_keys."""
        return self.installed_at is not None

    @property
    def badge(self) -> str:
        """CSS modifier for the status badge."""
        return {
            self.ACTIVE: "ok",
            self.FAILED: "fail",
            self.REVOKE_FAILED: "fail",
            self.VERIFYING: "run",
            self.REVOKING: "run",
        }.get(self.status, "warn")


class HostFacts(models.Model):
    """What Ansible last found out about a host, from any run that gathered facts.

    The facts are kept whole, as Ansible reported them; the columns next to
    them are the few that get listed and searched, pulled out once when the
    facts arrive.  See inventory.facts.
    """

    host = models.OneToOneField(Host, on_delete=models.CASCADE, related_name="facts")
    facts = models.JSONField(default=dict, blank=True)
    gathered_at = models.DateTimeField()
    job = models.ForeignKey(
        "runs.Job", on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    os = models.CharField(max_length=120, blank=True, default="")
    os_family = models.CharField(max_length=60, blank=True, default="")
    kernel = models.CharField(max_length=120, blank=True, default="")
    architecture = models.CharField(max_length=40, blank=True, default="")
    cpu_count = models.PositiveIntegerField(null=True, blank=True)
    cpu_model = models.CharField(max_length=160, blank=True, default="")
    memory_mb = models.PositiveIntegerField(null=True, blank=True)
    fqdn = models.CharField(max_length=255, blank=True, default="")
    default_ipv4 = models.CharField(max_length=45, blank=True, default="")
    # Every address the host reported, space-separated - searched as text.
    addresses = models.TextField(blank=True, default="")
    virtualization = models.CharField(max_length=60, blank=True, default="")
    # The listed columns and a few more, lower-cased, for free-text search.
    search_text = models.TextField(blank=True, default="")

    class Meta:
        verbose_name_plural = "host facts"

    def __str__(self):
        return f"facts of {self.host_id}"

    @property
    def memory_gb(self):
        return round(self.memory_mb / 1024) if self.memory_mb else None

    @property
    def address_list(self) -> list[str]:
        return self.addresses.split()
