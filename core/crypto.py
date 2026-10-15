# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Symmetric encryption for secrets stored in the database.

Secrets (SSH keys, passwords) never live in the database in plain text.  The key
comes from LOONA_SECRET_STORE_KEY; in DEBUG it is derived from SECRET_KEY so a
fresh checkout works without extra setup.  Rotating either key makes previously
stored secrets unreadable, which is reported instead of crashing.
"""
import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

log = logging.getLogger(__name__)


class SecretUnreadable(Exception):
    """Stored ciphertext cannot be decrypted with the current key."""


def _fernet():
    key = settings.LOONA_SECRET_STORE_KEY
    if not key:
        digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        key = base64.urlsafe_b64encode(digest).decode()
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise SecretUnreadable(
            "Secret cannot be decrypted - LOONA_SECRET_STORE_KEY changed?"
        ) from exc
