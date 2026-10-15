# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The one place that answers "may this user touch that".

Rules:

* A grant on a host group covers that group and every group nested under it,
  the same way an Ansible parent group contains its children.
* A user's role on a host is the highest role any of the host's groups gives
  them.  A host in no group is reachable by superusers only.
* A job is only as visible as its least visible target: seeing a run means
  seeing its log, and the log talks about every host it touched.
* Playbooks and credentials are not tied to the inventory, so they use
  ordinary Django model permissions granted to the team.
* Secrets follow what they belong to: a group's secrets are managed by that
  group's admins, a project's by whoever edits playbooks, global ones need
  the secretstore.change_secret permission.  Names are not secret; values
  are never shown to anyone.
"""
from __future__ import annotations

from functools import cached_property

from django.core.exceptions import PermissionDenied
from django.db.models import Exists, OuterRef, Q

from inventory.models import Credential, Host, HostGroup

from .models import GroupGrant, Role

VIEWER = Role.VIEWER
OPERATOR = Role.OPERATOR
ADMIN = Role.ADMIN


class _Everything:
    """Stands in for an id set when the user is not restricted at all."""

    def __contains__(self, item):
        return True

    def __bool__(self):
        return True


EVERYTHING = _Everything()


def for_user(user) -> "Access":
    """The access object for this user, built once per request."""
    access = getattr(user, "_loona_access", None)
    if access is None:
        access = Access(user)
        try:
            user._loona_access = access
        except AttributeError:
            pass
    return access


class Access:
    def __init__(self, user):
        self.user = user
        self.unrestricted = bool(
            getattr(user, "is_active", False) and getattr(user, "is_superuser", False)
        )

    # -- roles on the inventory --------------------------------------------

    @cached_property
    def group_roles(self) -> dict[int, int]:
        """Effective role per host group id, inheritance applied."""
        if not getattr(self.user, "is_authenticated", False):
            return {}
        direct: dict[int, int] = {}
        grants = GroupGrant.objects.filter(team__user=self.user).values_list(
            "host_group_id", "role"
        )
        for group_id, role in grants:
            direct[group_id] = max(role, direct.get(group_id, 0))
        if not direct:
            return {}

        children: dict[int, list[int]] = {}
        edges = HostGroup.parents.through.objects.values_list(
            "from_hostgroup_id", "to_hostgroup_id"
        )
        for child_id, parent_id in edges:
            children.setdefault(parent_id, []).append(child_id)

        # Push each grant down the tree, strongest first, so a weaker grant
        # never has to revisit a subtree a stronger one already claimed.
        effective: dict[int, int] = {}
        for group_id, role in sorted(direct.items(), key=lambda item: -item[1]):
            stack = [group_id]
            while stack:
                current = stack.pop()
                if effective.get(current, 0) >= role:
                    continue
                effective[current] = role
                stack.extend(children.get(current, ()))
        return effective

    def group_ids(self, role=VIEWER):
        if self.unrestricted:
            return EVERYTHING
        return {gid for gid, r in self.group_roles.items() if r >= role}

    def host_ids(self, role=VIEWER):
        if self.unrestricted:
            return EVERYTHING
        return self._host_ids(role)

    def _host_ids(self, role):
        cache = self.__dict__.setdefault("_host_id_cache", {})
        if role not in cache:
            group_ids = self.group_ids(role)
            cache[role] = set(
                Host.groups.through.objects.filter(
                    hostgroup_id__in=group_ids
                ).values_list("host_id", flat=True)
            ) if group_ids else set()
        return cache[role]

    def role_for_group(self, group) -> int:
        if self.unrestricted:
            return ADMIN
        return self.group_roles.get(group.pk, 0)

    def role_for_host(self, host) -> int:
        if self.unrestricted:
            return ADMIN
        roles = self.group_roles
        return max((roles.get(gid, 0) for gid in _group_ids_of(host)), default=0)

    # -- querysets ---------------------------------------------------------

    def hosts(self, role=VIEWER):
        if self.unrestricted:
            return Host.objects.all()
        return Host.objects.filter(pk__in=self._host_ids(role))

    def groups(self, role=VIEWER):
        if self.unrestricted:
            return HostGroup.objects.all()
        return HostGroup.objects.filter(pk__in=self.group_ids(role))

    def jobs(self, role=VIEWER):
        from runs.models import Job

        jobs = Job.objects.all()
        if self.unrestricted:
            return jobs
        host_links = Job.target_hosts.through.objects.filter(job_id=OuterRef("pk"))
        group_links = Job.target_groups.through.objects.filter(job_id=OuterRef("pk"))
        return (
            jobs.filter(Q(Exists(host_links)) | Q(Exists(group_links)))
            .exclude(target_hosts__in=Host.objects.exclude(pk__in=self._host_ids(role)))
            .exclude(
                target_groups__in=HostGroup.objects.exclude(pk__in=self.group_ids(role))
            )
        )

    def credentials(self, kinds=Credential.LOGIN_KINDS):
        """Credentials this user may attach to a host or try a connection with.

        Using a credential is sensitive in its own right: point a host at a
        machine you control, attach a password credential, and the password is
        handed to you on login.  So a team only sees the ones shared with it.
        By default only the kinds that log in somewhere; kinds=None for all.
        """
        found = Credential.objects.all()
        if kinds is not None:
            found = found.filter(kind__in=kinds)
        if self.manage_credentials:
            return found
        return found.filter(
            pk__in=Credential.teams.through.objects.filter(
                group__user=self.user
            ).values("credential_id")
        )

    def secrets(self):
        """Secrets whose names this user may see."""
        from secretstore.models import Secret

        secrets = Secret.objects.select_related("host_group", "project")
        if self.unrestricted:
            return secrets
        return secrets.filter(
            Q(host_group__isnull=True) | Q(host_group_id__in=self.group_ids(VIEWER))
        )

    def can_manage_secret(self, secret) -> bool:
        if secret.host_group_id:
            return self.role_for_group(secret.host_group) >= ADMIN
        if secret.project_id:
            return self.edit_playbooks
        return self.manage_global_secrets

    def require_secret(self, secret):
        if not self.can_manage_secret(secret):
            raise PermissionDenied

    # -- single-object checks ----------------------------------------------

    def can_job(self, job, role=VIEWER) -> bool:
        return self.jobs(role).filter(pk=job.pk).exists()

    def require_host(self, host, role):
        if self.role_for_host(host) < role:
            raise PermissionDenied

    def require_group(self, group, role):
        if self.role_for_group(group) < role:
            raise PermissionDenied

    def require_job(self, job, role):
        if not self.can_job(job, role):
            raise PermissionDenied

    # -- global abilities, for views and templates -------------------------

    @cached_property
    def edit_tofu(self) -> bool:
        """OpenTofu configuration is code that runs on the Loona server, like a
        playbook: writing it takes this global right on top of Admin on the group."""
        return self.user.has_perm("infra.change_tofuproject")

    @cached_property
    def edit_playbooks(self) -> bool:
        return self.user.has_perm("playbooks.change_playbook")

    @cached_property
    def add_playbooks(self) -> bool:
        return self.user.has_perm("playbooks.add_playbook")

    @cached_property
    def delete_playbooks(self) -> bool:
        return self.user.has_perm("playbooks.delete_playbook")

    @cached_property
    def manage_credentials(self) -> bool:
        return self.user.has_perm("inventory.change_credential")

    @cached_property
    def manage_global_secrets(self) -> bool:
        return self.user.has_perm("secretstore.change_secret")

    @cached_property
    def manages_secrets(self) -> bool:
        """May add a secret somewhere."""
        return self.manage_global_secrets or self.edit_playbooks or self.manages_inventory

    @cached_property
    def manage_teams(self) -> bool:
        return self.user.has_perm("auth.change_group")

    @cached_property
    def manages_inventory(self) -> bool:
        """Admin somewhere - enough to add hosts and subgroups there."""
        return bool(self.group_ids(ADMIN))

    @cached_property
    def runs_playbooks(self) -> bool:
        return bool(self.group_ids(OPERATOR))

    # Id sets for templates: {% if host.pk in access.admin_hosts %}.

    @cached_property
    def admin_hosts(self):
        return self.host_ids(ADMIN)

    @cached_property
    def admin_groups(self):
        return self.group_ids(ADMIN)

    @cached_property
    def operator_hosts(self):
        return self.host_ids(OPERATOR)

    @cached_property
    def operator_groups(self):
        return self.group_ids(OPERATOR)

    @cached_property
    def visible_groups(self):
        return self.group_ids(VIEWER)


def _group_ids_of(host):
    cache = getattr(host, "_prefetched_objects_cache", {})
    if "groups" in cache:
        return [g.pk for g in cache["groups"]]
    return list(host.groups.values_list("pk", flat=True))
