# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""A pause after too many wrong passwords or one-time codes.

Each kind of key has a number of failures that locks it for a minute; every
failure after that locks it again, twice as long each time, up to a cap.  A success
clears the account's keys, not the address's: one good password of your own
must not buy more guesses at someone else's.

Password sign-ins count against the account at an address (the guessing
itself), the address (one machine trying many accounts) and the account
(many machines trying one).  The account's own cap is short, because anyone
can trip it.  Codes count against the account, so starting a new sign-in
does not reset them.
"""
from __future__ import annotations

import math
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import Throttle

# kind: (failures until the first lock, longest lock in minutes)
LIMITS = {
    "pair": (5, 60),
    "address": (20, 60),
    "account": (20, 15),
    "code": (5, 60),
}
# Failures older than this (and not locked) are forgotten.
FORGET = timedelta(hours=1)


def client_address(request) -> str:
    if getattr(settings, "LOONA_TRUST_PROXY", False):
        # The proxy appends the address it saw; anything before that the
        # client may have written itself.
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[-1].strip()
        if forwarded:
            return forwarded
    return request.META.get("REMOTE_ADDR", "") or "unknown"


def password_keys(request, username: str) -> dict:
    account = (username or "").strip().lower()[:150]
    address = client_address(request)[:64]
    return {"pair": f"pair:{account}|{address}", "address": f"address:{address}",
            "account": f"account:{account}"}


def code_keys(user) -> dict:
    return {"code": f"code:{user.pk}"}


def wait(keys: dict) -> int:
    """Seconds until a try is allowed again (0: now)."""
    now = timezone.now()
    until = Throttle.objects.filter(key__in=keys.values(), locked_until__gt=now).order_by(
        "-locked_until").values_list("locked_until", flat=True).first()
    return math.ceil((until - now).total_seconds()) if until else 0


@transaction.atomic
def failed(keys: dict):
    now = timezone.now()
    Throttle.objects.filter(last_failure_at__lt=now - timedelta(days=1)).delete()
    for kind, key in keys.items():
        limit, cap = LIMITS[kind]
        row, _ = Throttle.objects.select_for_update().get_or_create(
            key=key, defaults={"last_failure_at": now})
        locked = row.locked_until and row.locked_until > now
        if not locked and row.failures and now - row.last_failure_at > FORGET and row.failures < limit:
            row.failures = 0
        row.failures += 1
        row.last_failure_at = now
        over = row.failures - limit
        if over >= 0:
            row.locked_until = now + timedelta(minutes=min(2 ** over, cap))
        row.save()


def succeeded(keys: dict):
    Throttle.objects.filter(key__in=[v for k, v in keys.items() if k != "address"]).delete()
