# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Build an Ansible inventory out of Loona's host and group records."""
from __future__ import annotations

import os
from pathlib import Path

from .models import Credential, Host, HostGroup


def credential_vars(credential: Credential, keys_dir: Path) -> dict:
    """Connection variables for one credential.

    Private keys are written into ``keys_dir`` (0600) because Ansible needs them
    as files on disk; the caller owns that directory's lifetime.
    """
    if not credential or credential.kind == Credential.KIND_VAULT:
        return {}
    from secretstore.resolve import Unsafe

    # Logins are data, never templates (passwords get the same in runs.executor).
    variables = {"ansible_user": Unsafe(credential.username)}

    if credential.kind == Credential.KIND_SSH_KEY:
        secret = credential.secret
        if secret:
            keys_dir.mkdir(parents=True, exist_ok=True)
            key_path = keys_dir / f"cred_{credential.pk}"
            key_path.write_text(secret.rstrip("\n") + "\n")
            os.chmod(key_path, 0o600)
            variables["ansible_ssh_private_key_file"] = str(key_path)
    else:
        variables["ansible_password"] = credential.secret

    if credential.become_method:
        variables["ansible_become"] = True
        variables["ansible_become_method"] = credential.become_method
        variables["ansible_become_user"] = Unsafe(credential.become_username or "root")
        if credential.become_secret:
            variables["ansible_become_password"] = credential.become_secret
    return variables


# Variables that decide *who* Loona logs in as and *how* it proves it.  They
# are replaced wholesale when a job carries one-off credentials.
AUTH_VARS = (
    "ansible_user",
    "ansible_password",
    "ansible_ssh_private_key_file",
    "ansible_become",
    "ansible_become_method",
    "ansible_become_user",
    "ansible_become_password",
)


def _managed_key_vars(host: Host, keys_dir: Path) -> dict:
    """Connection variables for the key Loona generated for this host.

    The key is written into ``keys_dir`` alongside credential keys; the caller
    shreds that directory when the run ends.
    """
    key = getattr(host, "managed_key", None)
    if not key or not key.is_usable:
        return {}
    secret = key.private_key
    if not secret:
        return {}
    keys_dir.mkdir(parents=True, exist_ok=True)
    key_path = keys_dir / f"host_{host.pk}"
    key_path.write_text(secret.rstrip("\n") + "\n")
    os.chmod(key_path, 0o600)
    return {
        "ansible_user": key.username,
        "ansible_ssh_private_key_file": str(key_path),
    }


def host_vars(host: Host, keys_dir: Path) -> dict:
    from secretstore.resolve import Unsafe

    # Typed into Loona's forms: an address, not a template.
    variables = {"ansible_host": Unsafe(host.ansible_host), "ansible_port": host.port}
    variables.update(credential_vars(host.credential, keys_dir))
    # Loona's own per-host key beats whatever the credential authenticates with;
    # escalation settings from the credential still apply.
    managed = _managed_key_vars(host, keys_dir)
    if managed:
        variables.pop("ansible_password", None)
        variables.update(managed)
    # Per-host overrides win over credential defaults.
    variables.update(host.variables or {})
    return variables


def apply_connection_override(variables: dict, override: dict) -> dict:
    """Swap a host's authentication for the credentials a job carries.

    Used by key provisioning, where the login and password were typed into the
    browser a moment ago and are deliberately never stored on the host.
    """
    if not override:
        return variables
    replaced = {k: v for k, v in variables.items() if k not in AUTH_VARS}
    replaced.update(override)
    return replaced


def build_inventory(hosts, groups, keys_dir: Path) -> dict:
    """Assemble the inventory dict ansible-runner expects.

    Every selected host lands in ``all``.  A host is in its groups however the
    run was aimed - at the host itself, at one of its groups or at a group
    further up - so every group the selected hosts belong to goes in, nested
    as it is in Loona: their variables apply, and a child's beat its parents'.
    """
    hosts = list(hosts)
    inventory = {"all": {"hosts": {}, "children": {}}}

    for host in hosts:
        inventory["all"]["hosts"][host.name] = host_vars(host, keys_dir)

    members: dict[int, list[str]] = {}
    for host in hosts:
        for group in host.groups.all():
            members.setdefault(group.pk, []).append(host.name)
    # The groups that hold a selected host, everything above them, and the
    # groups that were ticked (which may well be empty).
    wanted = {group.pk for group in groups}
    for pk in list(members):
        wanted |= HostGroup.objects.get(pk=pk).ancestor_ids()
    known = {group.pk: group for group in HostGroup.objects.filter(pk__in=wanted)}
    children: dict[int, list[int]] = {}
    for child, parent in HostGroup.parents.through.objects.filter(
        from_hostgroup_id__in=known, to_hostgroup_id__in=known
    ).values_list("from_hostgroup_id", "to_hostgroup_id"):
        children.setdefault(parent, []).append(child)

    for pk, group in sorted(known.items(), key=lambda item: item[1].name):
        entry = {"hosts": {name: {} for name in sorted(members.get(pk, []))}}
        nested = [
            known[child].name
            for child in children.get(pk, [])
            # Ansible refuses an inventory that goes round in a circle.
            if pk not in _reachable(child, children)
        ]
        if nested:
            entry["children"] = {name: {} for name in sorted(nested)}
        if group.variables:
            entry["vars"] = group.variables
        inventory["all"]["children"][group.name] = entry

    return inventory


def _reachable(start: int, children: dict) -> set[int]:
    """start and every group nested under it."""
    found, stack = set(), [start]
    while stack:
        current = stack.pop()
        if current not in found:
            found.add(current)
            stack.extend(children.get(current, []))
    return found


def resolve_targets(hosts=None, groups=None):
    """Expand a host/group selection into the concrete, enabled host list."""
    resolved = {}
    for host in hosts or []:
        if host.enabled:
            resolved[host.pk] = host
    for group in groups or []:
        for host in group.all_hosts():
            if host.enabled:
                resolved[host.pk] = host
    return sorted(resolved.values(), key=lambda h: h.name)
