# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The SSH keypair Loona manages for a single host.

One key per machine is the whole point: a key that leaks opens exactly that
machine, not the fleet.  Keys are Ed25519 because they are short enough to sit
in a form field and every sshd since OpenSSH 6.5 accepts them.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def generate_keypair(comment: str) -> tuple[str, str]:
    """Return (private key in OpenSSH format, authorized_keys line)."""
    private = ed25519.Ed25519PrivateKey.generate()
    private_text = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_text = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        .decode()
    )
    return private_text, f"{public_text} {comment}"


def fingerprint(public_key: str) -> str:
    """OpenSSH's SHA256 fingerprint of an authorized_keys line."""
    parts = (public_key or "").split()
    if len(parts) < 2:
        return ""
    try:
        blob = base64.b64decode(parts[1])
    except (ValueError, TypeError):
        return ""
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


def key_comment(host_name: str, host_pk: int) -> str:
    """Marker written into authorized_keys so a human can tell where it came from.

    Revocation matches on the key material, not on this, so renaming a host
    later does not strand the key on the server.
    """
    return f"loona-{host_name}-{host_pk}"
