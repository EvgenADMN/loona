# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The second factor: one-time codes from an authenticator app.

A password sign-in by someone with codes turned on does not log them in.
It leaves a *pending* sign-in in the session - who, through which backend,
since when - and only a good code turns that into a real one.  Five wrong
codes or five minutes and the password has to be typed again.

Sign-ins through an identity provider skip this: whether they need a second
factor is the provider's business, and it has usually asked already.
"""
from __future__ import annotations

import time

from django.contrib.auth import get_user_model, login
from django.db import transaction
from django.utils import timezone

from administration import system

from . import totp
from .models import RecoveryCode, TotpDevice, hash_code

PENDING = "_loona_signin_pending"
# How the current session signed in: "password", "oidc" or "saml".
METHOD = "_loona_signin_method"
PENDING_SECONDS = 300
MAX_TRIES = 5


# -- policy -------------------------------------------------------------------


def has_codes(user) -> bool:
    return TotpDevice.objects.filter(user=user, confirmed_at__isnull=False).exists()


def required_for(user) -> bool:
    policy = system.get().mfa_policy
    if policy == "everyone":
        return True
    return policy == "superusers" and user.is_superuser


# -- the pending sign-in ----------------------------------------------------------


def start_pending(request, user, enroll: bool, next_url: str = ""):
    request.session[PENDING] = {
        "user": user.pk, "backend": user.backend, "at": time.time(), "tries": 0,
        "enroll": enroll, "next": next_url,
    }


def pending(request):
    """(user, state) of a pending sign-in still worth finishing, else (None, None)."""
    state = request.session.get(PENDING)
    if not state or time.time() - state["at"] > PENDING_SECONDS or state["tries"] >= MAX_TRIES:
        request.session.pop(PENDING, None)
        return None, None
    user = get_user_model().objects.filter(pk=state["user"], is_active=True).first()
    if user is None:
        request.session.pop(PENDING, None)
        return None, None
    return user, state


def count_try(request) -> int:
    state = request.session[PENDING]
    state["tries"] += 1
    request.session[PENDING] = state
    return MAX_TRIES - state["tries"]


def finish(request, user, state):
    request.session.pop(PENDING, None)
    login(request, user, backend=state["backend"])
    request.session[METHOD] = "password"


# -- codes ----------------------------------------------------------------------


@transaction.atomic
def check(user, code: str) -> str | None:
    """"totp" or "recovery" when the code is good (and now spent), else None."""
    device = TotpDevice.objects.select_for_update().filter(user=user, confirmed_at__isnull=False).first()
    if device is None:
        return None
    step = totp.matching_step(device.secret, code, after_step=device.last_step)
    if step is not None:
        device.last_step = step
        device.save(update_fields=["last_step"])
        return "totp"
    used = RecoveryCode.objects.filter(user=user, code_hash=hash_code(code), used_at__isnull=True).update(
        used_at=timezone.now())
    return "recovery" if used else None


def begin_setup(user) -> TotpDevice:
    """A fresh, unconfirmed secret - replacing any earlier unfinished setup."""
    TotpDevice.objects.filter(user=user, confirmed_at__isnull=True).delete()
    device = TotpDevice(user=user)
    device.secret = totp.new_secret()
    device.save()
    return device


@transaction.atomic
def confirm_setup(user, code: str) -> list[str] | None:
    """Turn codes on with the first good code. Returns fresh recovery codes."""
    device = TotpDevice.objects.select_for_update().filter(user=user, confirmed_at__isnull=True).first()
    if device is None:
        return None
    step = totp.matching_step(device.secret, code)
    if step is None:
        return None
    TotpDevice.objects.filter(user=user, confirmed_at__isnull=False).delete()
    device.confirmed_at, device.last_step = timezone.now(), step
    device.save(update_fields=["confirmed_at", "last_step"])
    return new_recovery_codes(user)


def new_recovery_codes(user) -> list[str]:
    codes = totp.recovery_codes()
    RecoveryCode.objects.filter(user=user).delete()
    RecoveryCode.objects.bulk_create(RecoveryCode(user=user, code_hash=hash_code(c)) for c in codes)
    return codes


def turn_off(user):
    TotpDevice.objects.filter(user=user).delete()
    RecoveryCode.objects.filter(user=user).delete()


def recovery_left(user) -> int:
    return RecoveryCode.objects.filter(user=user, used_at__isnull=True).count()
