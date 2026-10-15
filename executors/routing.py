# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Which executor reaches a host: the nearest group that names one.

A host's own groups are looked at first, then the groups they are nested
under, and so on up.  The first level where any group names an executor
decides; two different executors at that level is a conflict to be fixed
in the inventory, not guessed at.  No executor anywhere means Loona runs
it itself.
"""
from __future__ import annotations

from inventory.models import HostGroup


class Conflict(Exception):
    pass


def executor_for_host(host):
    """The host's executor, or None for Loona itself. Raises Conflict."""
    return _nearest(set(host.groups.values_list("pk", flat=True)), host.name)


def executor_for_group(group):
    """What runs on this group's own hosts go through. Raises Conflict."""
    return _nearest({group.pk}, group.name)


def _nearest(level: set, label: str):
    seen = set()
    while level:
        seen |= level
        named = {}
        for group in HostGroup.objects.filter(pk__in=level, executor__isnull=False).select_related("executor"):
            named[group.executor_id] = (group.executor, group)
        if len(named) == 1:
            return next(iter(named.values()))[0]
        if len(named) > 1:
            which = ", ".join(sorted(f"{group.name} -> {executor.name}" for executor, group in named.values()))
            raise Conflict(f"{label} is in groups that name different executors ({which}).")
        level = set(
            HostGroup.parents.through.objects.filter(from_hostgroup_id__in=level).values_list(
                "to_hostgroup_id", flat=True
            )
        ) - seen
    return None


def executor_for_hosts(hosts):
    """The one executor all these hosts are behind, or None. Raises Conflict."""
    found = {}
    for host in hosts:
        executor = executor_for_host(host)
        found.setdefault(executor.pk if executor else None, (executor, []))[1].append(host.name)
    if len(found) <= 1:
        return next(iter(found.values()))[0] if found else None
    parts = []
    for executor, names in sorted(found.values(), key=lambda pair: pair[0].name if pair[0] else ""):
        shown = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
        parts.append(f"{shown} via {executor.name if executor else 'Loona itself'}")
    raise Conflict(
        "These hosts are reached from different places: " + "; ".join(parts)
        + ". Run them separately, one target per executor."
    )


def describe(host_or_group) -> str:
    """For a page: the executor runs come through, "" for Loona itself."""
    try:
        if isinstance(host_or_group, HostGroup):
            executor = executor_for_group(host_or_group)
        else:
            executor = executor_for_host(host_or_group)
    except Conflict as exc:
        return str(exc)
    return executor.name if executor else ""
