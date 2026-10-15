# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Pinning each server's SSH host key.

Ansible runs with a known_hosts file Loona writes: the keys it already holds
for the targets.  ``StrictHostKeyChecking=accept-new`` lets a host that has
none yet through and records what it presented; after the run Loona keeps
that as the host's pinned key.  From then on a different key - another
machine at that address, or someone in between - fails the connection
instead of quietly getting the playbook and the credentials with it.

Hashing is switched off so the recorded entries can be matched back to hosts.
"""
from __future__ import annotations

import base64
import hashlib
import logging
from pathlib import Path

from django.utils import timezone

log = logging.getLogger(__name__)

KNOWN_HOSTS = "known_hosts"


def entry_name(address: str, port) -> str:
    port = int(port or 22)
    return address if port == 22 else f"[{address}]:{port}"


def target_of(name: str, variables: dict) -> tuple[str, int] | None:
    """Where ssh will connect for an inventory entry; None if it will not."""
    if variables.get("ansible_connection") in ("local", "docker", "winrm", "psrp"):
        return None
    return str(variables.get("ansible_host") or name), int(variables.get("ansible_port") or 22)


def normalise(keys: str) -> str:
    """Keep only "type base64" pairs, one per line, whatever was pasted in."""
    kept = []
    for line in (keys or "").splitlines():
        parts = line.split()
        # Accept a bare "type key", or a known_hosts line with a host in front.
        if len(parts) >= 3 and not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
            parts = parts[1:]
        if len(parts) >= 2 and parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
            pair = f"{parts[0]} {parts[1]}"
            if pair not in kept:
                kept.append(pair)
    return "\n".join(kept)


def fingerprints(keys: str) -> list[str]:
    out = []
    for pair in normalise(keys).splitlines():
        kind, blob = pair.split()
        try:
            digest = hashlib.sha256(base64.b64decode(blob)).digest()
        except ValueError:
            continue
        label = kind.replace("ssh-", "").replace("ecdsa-sha2-", "ecdsa-").upper()
        out.append(f"{label} SHA256:{base64.b64encode(digest).decode().rstrip('=')}")
    return out


def ssh_args(known_hosts: Path) -> str:
    return (
        "-C -o ControlMaster=auto -o ControlPersist=60s "
        "-o StrictHostKeyChecking=accept-new -o HashKnownHosts=no "
        f"-o UserKnownHostsFile={known_hosts} -o GlobalKnownHostsFile=/dev/null"
    )


def write_known_hosts(directory: Path, targets: list[tuple[str, int, str]]) -> Path:
    """known_hosts for (address, port, pinned keys) triples. Returns its path."""
    path = directory / KNOWN_HOSTS
    lines = []
    for address, port, keys in targets:
        for pair in normalise(keys).splitlines():
            lines.append(f"{entry_name(address, port)} {pair}")
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    path.chmod(0o600)
    return path


def ansible_env(known_hosts: Path) -> dict:
    control = known_hosts.parent / "cp"
    control.mkdir(mode=0o700, exist_ok=True)
    return {
        "ANSIBLE_HOST_KEY_CHECKING": "True",
        "ANSIBLE_SSH_ARGS": ssh_args(known_hosts),
        # SSH multiplexing sockets per run.  Shared ones (~/.ansible/cp) let a
        # run ride a connection another run opened - skipping the host key
        # check, and borrowing whatever login that run used.
        "ANSIBLE_SSH_CONTROL_PATH_DIR": str(control),
    }


def prepare(directory: Path, hosts_by_name: dict, inventory_hosts: dict) -> Path:
    """Write the run's known_hosts from what the targets have pinned."""
    targets = []
    for name, variables in inventory_hosts.items():
        host = hosts_by_name.get(name)
        where = target_of(name, variables)
        if host is None or where is None:
            continue
        targets.append((*where, host.ssh_host_keys))
    return write_known_hosts(directory, targets)


def learn(known_hosts: Path, hosts_by_name: dict, inventory_hosts: dict) -> list:
    """Pin keys the run met for hosts that had none. Returns those hosts."""
    try:
        text = known_hosts.read_text()
    except OSError:
        return []
    seen: dict[str, list[str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            seen.setdefault(parts[0], []).append(f"{parts[1]} {parts[2]}")
    learned = []
    for name, variables in inventory_hosts.items():
        host = hosts_by_name.get(name)
        where = target_of(name, variables)
        if host is None or where is None or host.ssh_host_keys:
            continue
        keys = seen.get(entry_name(*where))
        if not keys:
            continue
        host.ssh_host_keys = "\n".join(keys)
        host.ssh_host_keys_pinned_at = timezone.now()
        host.save(update_fields=["ssh_host_keys", "ssh_host_keys_pinned_at"])
        log.info("Pinned the SSH host key of %s: %s", host.name, fingerprints(host.ssh_host_keys))
        learned.append(host)
    return learned


MISMATCH_MARKERS = ("REMOTE HOST IDENTIFICATION HAS CHANGED", "Host key verification failed")


def is_mismatch(text: str) -> bool:
    return any(marker in (text or "") for marker in MISMATCH_MARKERS)
