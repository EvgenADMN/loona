# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Which secrets a run gets, host by host.

Precedence, weakest first: global secrets, then the secrets of the host's
groups (a group's apply to the hosts of every group nested under it; a
deeper group beats the groups above it, and between groups at the same depth
the later name wins, as Ansible orders group variables), then the secrets of
the run's project.

The values become host variables in the run's inventory - which lives in the
run's own directory and is removed with it - marked ``!unsafe`` so that a
password with ``{{`` in it reaches the playbook as typed instead of being
taken for a template.  Only the names are recorded on the job.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml
from django.db.models import Q

from core.crypto import SecretUnreadable
from inventory.models import HostGroup

from . import hashicorp
from .models import Secret


class Unsafe(str):
    """A value Ansible must not template."""


class _Dumper(yaml.SafeDumper):
    pass


_Dumper.add_representer(Unsafe, lambda dumper, value: dumper.represent_scalar("!unsafe", str(value)))


def as_data(value):
    """The same structure with every string marked !unsafe: values Ansible
    must take as they are, never evaluate as templates."""
    if isinstance(value, dict):
        return {str(k): as_data(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [as_data(v) for v in value]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return Unsafe(str(value))


def dump_inventory(inventory: dict) -> str:
    return yaml.dump(inventory, Dumper=_Dumper, default_flow_style=False, sort_keys=False)


@dataclass
class Delivery:
    # host name -> {variable: value}
    per_host: dict = field(default_factory=dict)
    # What hosts outside the inventory (an implicit localhost) see.
    common: dict = field(default_factory=dict)
    # "name (scope)" of every secret some host got.
    used: list = field(default_factory=list)

    @property
    def values(self) -> list[str]:
        found = set(self.common.values())
        for variables in self.per_host.values():
            found.update(variables.values())
        return [str(v) for v in found]


def _depths(edges) -> tuple[dict[int, int], dict[int, list[int]]]:
    """Distance of each group from the top of its tree, and its parents; loops tolerated."""
    parents: dict[int, list[int]] = {}
    for child, parent in edges:
        parents.setdefault(child, []).append(parent)
    depth: dict[int, int] = {}

    def of(group_id, visiting):
        if group_id in depth:
            return depth[group_id]
        if group_id in visiting:
            return 0
        visiting.add(group_id)
        value = 1 + max((of(p, visiting) for p in parents.get(group_id, ())), default=-1)
        visiting.discard(group_id)
        depth[group_id] = value
        return value

    for group_id in {c for c, _ in edges} | {p for _, p in edges}:
        of(group_id, set())
    return depth, parents


def _ancestors(start_ids, parents) -> set[int]:
    found, stack = set(), list(start_ids)
    while stack:
        current = stack.pop()
        if current not in found:
            found.add(current)
            stack.extend(parents.get(current, ()))
    return found


def for_run(hosts, project=None) -> Delivery:
    hosts = list(hosts)
    edges = list(HostGroup.parents.through.objects.values_list("from_hostgroup_id", "to_hostgroup_id"))
    depth, parents = _depths(edges)
    groups_of = {host.name: _ancestors([g.pk for g in host.groups.all()], parents) for host in hosts}
    relevant = set().union(*groups_of.values()) if groups_of else set()

    scope = Q(host_group__isnull=True, project__isnull=True) | Q(host_group_id__in=relevant)
    if project is not None:
        scope |= Q(project=project)
    secrets = list(Secret.objects.filter(scope).select_related("host_group", "project"))
    delivery = Delivery()
    if not secrets:
        return delivery

    global_ = [s for s in secrets if s.scope == Secret.GLOBAL]
    own = [s for s in secrets if s.scope == Secret.PROJECT]
    by_group: dict[int, list[Secret]] = {}
    for secret in secrets:
        if secret.host_group_id:
            by_group.setdefault(secret.host_group_id, []).append(secret)

    def lay(target, items):
        for secret in items:
            target[secret.name] = secret

    # First who gets what, so that only the secrets that win somewhere are
    # read - a shadowed Vault reference is never fetched.
    common: dict = {}
    lay(common, global_)
    lay(common, own)
    chosen: dict[str, dict] = {}
    for host in hosts:
        variables: dict = {}
        lay(variables, global_)
        mine = groups_of[host.name] & set(by_group)
        for group_id in sorted(mine, key=lambda g: (depth.get(g, 0), by_group[g][0].host_group.name)):
            lay(variables, by_group[group_id])
        lay(variables, own)
        if variables:
            chosen[host.name] = variables

    winners = {s.pk: s for s in common.values()}
    for variables in chosen.values():
        winners.update((s.pk, s) for s in variables.values())
    values = _values(sorted(winners.values(), key=lambda s: s.pk))

    delivery.common = {name: values[s.pk] for name, s in common.items()}
    delivery.per_host = {
        host: {name: values[s.pk] for name, s in variables.items()} for host, variables in chosen.items()
    }
    delivery.used = sorted({f"{s.name} ({s.scope_label})" for s in winners.values()})
    return delivery


def _values(secrets) -> dict[int, "Unsafe"]:
    values = {}
    vault = None
    for secret in secrets:
        try:
            if secret.in_vault:
                if vault is None:
                    conf = hashicorp.Conf.from_system()
                    if conf is None:
                        raise hashicorp.VaultError("HashiCorp Vault is not set up in Administration.")
                    # One sign-in for the whole run.
                    vault = hashicorp.Client(conf)
                values[secret.pk] = Unsafe(vault.get(secret.vault_ref))
            else:
                values[secret.pk] = Unsafe(secret.value)
        except SecretUnreadable as exc:
            raise ValueError(f"The secret {secret.name} ({secret.scope_label}) cannot be decrypted: {exc}") from exc
        except hashicorp.VaultError as exc:
            raise ValueError(f"The secret {secret.name} ({secret.scope_label}) could not be read from Vault: {exc}") from exc
    return values
