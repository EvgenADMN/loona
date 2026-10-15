# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Turning an OpenTofu project's ``loona_hosts`` output into Loona hosts.

After every successful apply the project's hosts are made to match what the
output declares: new names become hosts in the project's group (and are
brought up, see :mod:`infra.bootstrap`), known ones are updated, and ones no
longer declared - a destroy, or a machine taken out of the config - are
removed.  Only hosts the project itself created are ever changed.

The output::

    output "loona_hosts" {
      value = {
        "web-01" = {
          address   = "10.0.0.5"        # required
          port      = 22
          user      = "root"            # login the machine accepts at first boot
          groups    = ["web"]           # groups inside the project's group
          vars      = { role = "frontend" }
          host_keys = ["ssh-ed25519 AAAA..."]   # pins the key before first contact
        }
      }
    }

A list of such objects, each with a ``name``, works too.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from django.db import transaction
from django.utils import timezone

from inventory import hostkeys, provisioning
from inventory.models import Host, HostGroup

OUTPUT_NAME = "loona_hosts"
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$")


@dataclass
class Declared:
    name: str
    address: str
    port: int = 22
    user: str = ""
    groups: list = field(default_factory=list)
    vars: dict = field(default_factory=dict)
    host_keys: str = ""


@dataclass
class SyncResult:
    created: list = field(default_factory=list)
    updated: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    problems: list = field(default_factory=list)

    def as_dict(self):
        return {
            "created": [h.name for h in self.created],
            "updated": [h.name for h in self.updated],
            "removed": self.removed,
            "problems": self.problems,
        }


def parse(value) -> tuple[list[Declared], list[str]]:
    """The output's value as declarations, plus what was wrong with it."""
    problems = []
    if value is None:
        return [], []
    if isinstance(value, dict):
        items = [{**(v if isinstance(v, dict) else {}), "name": k} for k, v in value.items()]
    elif isinstance(value, list):
        items = value
    else:
        return [], [f"{OUTPUT_NAME} must be a map or a list, not {type(value).__name__}."]

    declared = []
    for item in items:
        if not isinstance(item, dict):
            problems.append(f"Skipped an entry that is not an object: {item!r}")
            continue
        name = str(item.get("name") or "")
        if not NAME.match(name):
            problems.append(f"Skipped {name!r}: host names are letters, digits, dash, underscore, dot.")
            continue
        address = str(item.get("address") or "").strip()
        if not address:
            problems.append(f"Skipped {name}: no address.")
            continue
        try:
            port = int(item.get("port") or 22)
        except (TypeError, ValueError):
            problems.append(f"Skipped {name}: port {item.get('port')!r} is not a number.")
            continue
        user = str(item.get("user") or "")
        if user and not provisioning.LOGIN.match(user):
            problems.append(f"Skipped {name}: {user!r} is not a login name.")
            continue
        keys = item.get("host_keys") or []
        if isinstance(keys, str):
            keys = [keys]
        declared.append(
            Declared(
                name=name,
                address=address,
                port=port,
                user=user,
                groups=[str(g) for g in (item.get("groups") or [])],
                vars=item.get("vars") if isinstance(item.get("vars"), dict) else {},
                host_keys=hostkeys.normalise("\n".join(str(k) for k in keys)),
            )
        )
    return declared, problems


@transaction.atomic
def sync(project, value) -> SyncResult:
    declared, problems = parse(value)
    result = SyncResult(problems=problems)
    home = project.host_group
    # A project may sort its machines into groups nested under its own, and
    # nowhere else: dropping hosts into another team's group would hand them
    # machines they never asked for.
    allowed_ids = home.descendant_ids()
    allowed = {g.name: g for g in HostGroup.objects.filter(pk__in=allowed_ids)}

    from catalog.services import extra_groups

    requested = extra_groups(project)
    mine = {h.name: h for h in Host.objects.filter(tofu_project=project)}
    for entry in declared:
        host = mine.pop(entry.name, None)
        is_new = host is None
        if is_new:
            if Host.objects.filter(name=entry.name).exists():
                result.problems.append(
                    f"Skipped {entry.name}: a host of that name already exists and was not "
                    "created by this project."
                )
                continue
            host = Host(name=entry.name, tofu_project=project)
        moved = not is_new and (host.address, host.port) != (entry.address, entry.port)
        host.address, host.port = entry.address, entry.port
        host.variables = entry.vars
        host.enabled = True
        if entry.host_keys:
            host.ssh_host_keys = entry.host_keys
            host.ssh_host_keys_pinned_at = timezone.now()
        elif moved:
            host.ssh_host_keys = ""
            host.ssh_host_keys_pinned_at = None
        host.save()

        groups = [home]
        # A catalog item may put its machines in a group under the project's.
        if entry.name in requested and requested[entry.name].pk in allowed_ids:
            groups.append(requested[entry.name])
        for name in entry.groups:
            if name in allowed:
                groups.append(allowed[name])
            else:
                result.problems.append(
                    f"{entry.name}: group {name!r} is not {home.name} or a group under it; ignored."
                )
        host.groups.set(set(groups))
        host._declared_user = entry.user or project.bootstrap_user
        (result.created if is_new else result.updated).append(host)

    for host in mine.values():
        result.removed.append(host.name)
        # The machine is gone or no longer this project's: nothing to revoke a
        # key from, so the host and Loona's copy of its key simply go.
        host.delete()
    return result
