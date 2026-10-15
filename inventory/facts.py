# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Host facts: what Ansible finds out about a machine, kept and searchable.

Any run that gathers facts - the implicit "Gathering Facts" of a play, an
explicit ``setup`` task, or Loona's own "Gather facts" run - leaves the
latest set on the host.  Facts are read off the run's event stream, so a
playbook needs nothing special to feed them; ``set_fact`` and the like are
not facts about the machine and are left alone.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

import yaml
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from .models import Host, HostFacts

# Modules whose ansible_facts describe the machine itself.
FACT_ACTIONS = {"setup", "gather_facts"}

# Filesystems that are not storage anyone asks about.
PSEUDO_FS = {
    "squashfs", "tmpfs", "devtmpfs", "overlay", "proc", "sysfs", "cgroup", "cgroup2",
    "autofs", "nsfs", "fuse.snapfuse", "efivarfs", "ramfs", "iso9660",
}
# Block devices that are not disks.
PSEUDO_DEVICES = ("loop", "ram", "zram", "sr", "fd", "nbd")


# -- capture ----------------------------------------------------------------


def _in_run(job_id: int, name: str) -> bool:
    from runs.models import Job

    return Job.objects.filter(pk=job_id, resolved_hosts__contains=[name]).exists()


def capture(job_id: int, data: dict, mask=None) -> bool:
    """Keep the facts a runner_on_ok event carries, if it carries any.

    Returns True when facts were stored.
    """
    action = str(data.get("resolved_action") or data.get("task_action") or "")
    if action.rpartition(".")[2] not in FACT_ACTIONS:
        return False
    res = data.get("res") or {}
    found = res.get("ansible_facts")
    # Facts gathered for another machine (delegate_to with delegate_facts)
    # are not this host's.
    if not isinstance(found, dict) or not found or res.get("_ansible_delegated_vars"):
        return False
    host = Host.objects.filter(name=str(data.get("host") or "")).first()
    if host is None:
        return False
    if job_id is not None and not _in_run(job_id, host.name):
        # Only the run's own hosts: a host added mid-play (add_host), or an
        # agent reporting on a name it was never given, does not get to
        # rewrite what Loona knows about someone else's machine.
        return False
    if mask:
        found = mask.deep(found)
    record(host, found, job_id=job_id)
    return True


def record(host: Host, found: dict, job_id: int | None = None) -> HostFacts:
    """Store a fresh set of facts for the host.

    A full gathering replaces what was there; a partial one (gather_subset
    other than plain "all") is laid over it, so a play that only asks for
    the network does not wipe the hardware.
    """
    found = _clean(found)
    current = HostFacts.objects.filter(host=host).first()
    if current and found.get("gather_subset") != ["all"]:
        found = {**current.facts, **found}
    values = {"facts": found, "gathered_at": timezone.now(), "job_id": job_id, **summarize(found)}
    facts, _ = HostFacts.objects.update_or_create(host=host, defaults=values)
    return facts


def _clean(value):
    """PostgreSQL's jsonb has no room for NUL characters."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {_clean(str(k)): _clean(v) for k, v in value.items()}
    return value


def _text(value, limit) -> str:
    return str(value or "").strip()[:limit]


def summarize(f: dict) -> dict:
    """The listed and searched columns, out of a full set of facts."""
    os_name = f.get("ansible_os_name") or " ".join(
        str(p) for p in (f.get("ansible_distribution"), f.get("ansible_distribution_version")) if p
    )
    virt = ""
    if f.get("ansible_virtualization_type") not in (None, "", "NA"):
        virt = f"{f['ansible_virtualization_type']} {f.get('ansible_virtualization_role') or ''}"
    default = f.get("ansible_default_ipv4") or {}
    addresses = [
        a for a in [*(f.get("ansible_all_ipv4_addresses") or []), *(f.get("ansible_all_ipv6_addresses") or [])]
        if isinstance(a, str) and not a.lower().startswith("fe80:")
    ]
    columns = {
        "os": _text(os_name, 120),
        "os_family": _text(f.get("ansible_os_family"), 60),
        "kernel": _text(f.get("ansible_kernel"), 120),
        "architecture": _text(f.get("ansible_architecture"), 40),
        "cpu_count": _number(f.get("ansible_processor_vcpus"))
        or _number(f.get("ansible_processor_count")),
        "cpu_model": _text(_cpu_model(f.get("ansible_processor")), 160),
        "memory_mb": _number(f.get("ansible_memtotal_mb")),
        "fqdn": _text(f.get("ansible_fqdn"), 255),
        "default_ipv4": _text(default.get("address") if isinstance(default, dict) else "", 45),
        "addresses": " ".join(addresses),
        "virtualization": _text(virt, 60),
    }
    product = " ".join(
        str(f.get(k)) for k in ("ansible_system_vendor", "ansible_product_name") if f.get(k)
    )
    columns["search_text"] = " ".join(
        str(v) for v in (*columns.values(), f.get("ansible_hostname"), product,
                         f.get("ansible_distribution_release"))
        if v not in (None, "")
    ).lower()
    return columns


def _number(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _cpu_model(processor) -> str:
    """ansible_processor lists index, vendor and model per core; the model
    is the longest of the first few strings."""
    if not isinstance(processor, list):
        return ""
    names = [p for p in processor[:3] if isinstance(p, str) and not p.isdigit()]
    return max(names, key=len, default="")


# -- reading them back ------------------------------------------------------


def disks(f: dict) -> list[dict]:
    """Mounted filesystems that hold data, biggest first."""
    seen, rows = set(), []
    for mount in f.get("ansible_mounts") or []:
        if not isinstance(mount, dict) or mount.get("fstype") in PSEUDO_FS:
            continue
        total = _number(mount.get("size_total")) or 0
        key = (mount.get("device"), total)
        if not total or key in seen:
            continue
        seen.add(key)
        free = _number(mount.get("size_available")) or 0
        rows.append({
            "mount": mount.get("mount", ""),
            "device": mount.get("device", ""),
            "fstype": mount.get("fstype", ""),
            "size": total,
            "free": free,
            "used_pct": round(100 * (total - free) / total),
        })
    return sorted(rows, key=lambda r: (-r["size"], r["mount"]))


def devices(f: dict) -> list[dict]:
    """Block devices that are disks, not loops or RAM drives."""
    rows = []
    for name, device in sorted((f.get("ansible_devices") or {}).items()):
        if not isinstance(device, dict) or name.startswith(PSEUDO_DEVICES):
            continue
        model = " ".join(str(device[k]) for k in ("vendor", "model") if device.get(k))
        rows.append({"name": name, "size": device.get("size", ""), "model": model,
                     "ssd": str(device.get("rotational")) == "0"})
    return rows


def interfaces(f: dict) -> list[dict]:
    """Network interfaces with an address, the default route's first."""
    default = (f.get("ansible_default_ipv4") or {}).get("interface")
    rows = []
    for name in f.get("ansible_interfaces") or []:
        data = f.get(f"ansible_{name.replace('-', '_').replace('.', '_')}") or {}
        if not isinstance(data, dict):
            continue
        ipv4 = data.get("ipv4") or {}
        v4 = [ipv4] if isinstance(ipv4, dict) else ipv4
        v4 += data.get("ipv4_secondaries") or []
        v4 = [f"{a['address']}/{a.get('prefix') or a.get('netmask', '')}".rstrip("/")
              for a in v4 if isinstance(a, dict) and a.get("address")]
        v6 = [f"{a['address']}/{a.get('prefix', '')}".rstrip("/")
              for a in data.get("ipv6") or [] if isinstance(a, dict) and a.get("address")
              and not a["address"].lower().startswith("fe80:")]
        if not v4 and not v6:
            continue
        rows.append({"name": name, "mac": data.get("macaddress", ""), "addresses": v4 + v6,
                     "up": data.get("active", True), "default": name == default})
    return sorted(rows, key=lambda r: (not r["default"], r["name"]))


def flatten(value, prefix="") -> list[tuple[str, str]]:
    """Every leaf as ("a.b[0].c", "value"), for the full listing."""
    rows = []
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            rows += flatten(value[key], f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(value, list) and value and any(isinstance(v, (dict, list)) for v in value):
        for index, item in enumerate(value):
            rows += flatten(item, f"{prefix}[{index}]")
    else:
        if isinstance(value, list):
            text = ", ".join(str(v) for v in value)
        elif isinstance(value, bool) or value is None:
            text = yaml.safe_dump(value).split("\n")[0]
        else:
            text = str(value)
        rows.append((prefix, text))
    return rows


# -- search -----------------------------------------------------------------

# name -> (help, column lookups for "contains")
TEXT_FILTERS = {
    "os": (_("operating system or its family"), ("facts__os", "facts__os_family")),
    "kernel": (_("kernel version"), ("facts__kernel",)),
    "arch": (_("CPU architecture"), ("facts__architecture",)),
    "cpu": (_("CPU model"), ("facts__cpu_model",)),
    "ip": (_("any address of the host"), ("facts__addresses", "address")),
    "fqdn": (_("fully qualified name"), ("facts__fqdn",)),
    "virt": (_("virtualization, e.g. kvm guest"), ("facts__virtualization",)),
}
# name -> (help, column, unit in MB or 1)
NUMBER_FILTERS = {
    "cpus": (_("virtual CPUs"), "facts__cpu_count", 1),
    "ram": (_("memory in GB, rounded"), "facts__memory_mb", 1024),
}
TOKEN_RE = re.compile(r"^([A-Za-z_][\w.]*)(>=|<=|!=|>|<|=|:)(.*)$")
FACTS_YES = {"yes", "any", "true"}
FACTS_NO = {"no", "none", "missing", "false"}


@dataclass
class Search:
    filter: Q
    errors: list[str]


def help_text() -> list[tuple[str, str]]:
    rows = [(f"{name}:text", text) for name, (text, _lookups) in TEXT_FILTERS.items()]
    rows += [(f"{name}>=n", text) for name, (text, _column, _unit) in NUMBER_FILTERS.items()]
    rows += [
        ("facts:none", _("hosts no run has gathered facts for yet")),
        ("ansible_selinux.status:enabled", _("any fact, by its path")),
        (_("any other word"), _("name, address, description, OS, IPs, hardware")),
    ]
    return rows


def parse(query: str) -> Search:
    """Turn a search box query into a filter over hosts.

    Words are ANDed.  A plain word is looked for everywhere; ``name:value``
    and ``name>=n`` filter on one thing (see help_text).  Quotes keep a
    value with spaces together: os:"red hat".
    """
    try:
        tokens = shlex.split(query)
    except ValueError:
        tokens = query.split()
    result, errors = Q(), []
    for token in tokens:
        try:
            result &= _token(token)
        except ValueError as exc:
            errors.append(str(exc))
    return Search(result, errors)


def _token(token: str) -> Q:
    negate = token.startswith("-") and len(token) > 1
    if negate:
        token = token[1:]
    match = TOKEN_RE.match(token)
    q = _free(token) if not match else _field(*match.groups(), token=token)
    return ~q if negate else q


def _free(word: str) -> Q:
    return (
        Q(name__icontains=word) | Q(address__icontains=word) | Q(description__icontains=word)
        | Q(facts__search_text__contains=word.lower())
    )


def _field(name: str, op: str, value: str, token: str) -> Q:
    key = name.lower()
    if key == "facts" and op in (":", "="):
        if value.lower() in FACTS_NO:
            return Q(facts__isnull=True)
        if value.lower() in FACTS_YES:
            return Q(facts__isnull=False)
        raise ValueError(f"{token}: use facts:none or facts:yes.")
    if key in TEXT_FILTERS:
        if op not in (":", "=", "!="):
            raise ValueError(f"{token}: {key} is text - use {key}:value.")
        q = Q()
        for lookup in TEXT_FILTERS[key][1]:
            q |= Q(**{f"{lookup}__icontains": value})
        return ~q if op == "!=" else q
    if key in NUMBER_FILTERS:
        return _number_filter(key, op, value, token)
    if key.startswith("ansible_"):
        return _raw(name, op, value, token)
    if op == ":":
        # Not a filter name: an IPv6 address or a word with a colon in it.
        return _free(token)
    raise ValueError(f"{token}: unknown filter {name!r}.")


def _number_filter(key, op, value, token) -> Q:
    _help, column, unit = NUMBER_FILTERS[key]
    try:
        number = float(value)
    except ValueError:
        raise ValueError(f"{token}: {key} takes a number.") from None
    if unit == 1:
        low, high = number, number + 1
    else:
        # RAM is compared the way it is shown, rounded: an 8 GB machine
        # reports a little under 8192 MB and still counts as ram>=8.
        low, high = (number - 0.5) * unit, (number + 0.5) * unit
    lookups = {
        ":": Q(**{f"{column}__gte": low, f"{column}__lt": high}),
        "=": Q(**{f"{column}__gte": low, f"{column}__lt": high}),
        ">=": Q(**{f"{column}__gte": low}),
        ">": Q(**{f"{column}__gte": high}),
        "<": Q(**{f"{column}__lt": low}),
        "<=": Q(**{f"{column}__lt": high}),
    }
    if op == "!=":
        return ~lookups["="]
    return lookups[op]


def _raw(path: str, op: str, value: str, token: str) -> Q:
    """A filter on any fact, by its dotted path into the stored JSON."""
    parts = path.split(".")
    if not all(parts):
        raise ValueError(f"{token}: not a fact path.")
    lookup = "facts__facts__" + "__".join(parts)
    if op in (":", "=", "!="):
        if value.lower() in ("true", "false"):
            q = Q(**{lookup: value.lower() == "true"})
        elif op == ":":
            q = Q(**{f"{lookup}__icontains": value})
        else:
            q = Q(**{f"{lookup}__iexact": value})
        return ~q if op == "!=" else q
    try:
        number = float(value)
    except ValueError:
        raise ValueError(f"{token}: {op} needs a number.") from None
    name = {">=": "gte", "<=": "lte", ">": "gt", "<": "lt"}[op]
    return Q(**{f"{lookup}__{name}": number})


# -- the "Gather facts" run -------------------------------------------------


def gather_playbook() -> str:
    play = {"name": "Gather facts", "hosts": "all", "gather_facts": True, "tasks": []}
    return yaml.safe_dump([play], sort_keys=False, default_flow_style=False)


def start(user, hosts=(), groups=()):
    """Gather facts from these hosts and groups now. The caller checks rights."""
    from runs.executor import dispatch
    from runs.models import Job

    hosts, groups = list(hosts), list(groups)
    label = ", ".join([*(g.name for g in groups), *(h.name for h in hosts)])
    job = Job.objects.create(
        kind=Job.KIND_FACTS,
        playbook_name=f"Gather facts: {label}",
        playbook_yaml=gather_playbook(),
        created_by=user if user and user.is_authenticated else None,
    )
    job.target_hosts.set(hosts)
    job.target_groups.set(groups)
    dispatch(job)
    return job
