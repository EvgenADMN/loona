# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Deciding who hears about an event, and getting it to them.

``emit`` never raises: a broken mail server must not fail the run whose
failure it was trying to report.  Deliveries go out in the background; ones
that fail are retried by the scheduler's tick, up to Delivery.MAX_ATTEMPTS.
"""
from __future__ import annotations

import logging
import threading
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import Channel, Delivery

log = logging.getLogger(__name__)


def emit(event: str, subject: str, text: str, path: str = "", groups=None, data=None,
         channels=None) -> list[Delivery]:
    try:
        return _emit(event, subject, text, path, groups, data, channels)
    except Exception:  # noqa: BLE001 - notifying is never worth failing the caller
        log.exception("Could not queue notification %r", subject)
        return []


def _emit(event, subject, text, path, groups, data, channels):
    from administration import system

    base = system.get().public_url.rstrip("/")
    url = f"{base}{path}" if base and path else ""
    created = []
    if channels is not None:
        # Named by the caller: they get it, whatever they subscribe to.
        targets = [c for c in channels if c.enabled]
    else:
        targets = [c for c in Channel.objects.filter(enabled=True)
                   if c.wants(event) and _in_scope(c, groups)]
    for channel in targets:
        created.append(
            Delivery.objects.create(
                channel=channel, event=event, subject=subject[:255], text=text,
                url=url, data=data or {},
            )
        )
    for delivery in created:
        # After the surrounding transaction commits, so the worker sees the row.
        transaction.on_commit(lambda pk=delivery.pk: _queue(pk))
    return created


def _in_scope(channel: Channel, groups) -> bool:
    wanted = set(channel.host_groups.values_list("pk", flat=True))
    if not wanted:
        return True
    return bool(groups) and bool(wanted & set(groups))


def _queue(delivery_id: int):
    if settings.LOONA_RUNNER_MODE == "celery":
        from .tasks import deliver_task

        deliver_task.delay(delivery_id)
    else:
        threading.Thread(target=deliver, args=(delivery_id,), daemon=True).start()


def deliver(delivery_id: int) -> str:
    from runs.executor import refresh_connection

    from .senders import SendFailed, send

    refresh_connection()
    delivery = Delivery.objects.select_related("channel").filter(pk=delivery_id).first()
    if delivery is None or delivery.status == Delivery.SENT:
        return "gone"
    delivery.attempts += 1
    try:
        send(delivery)
    except SendFailed as exc:
        delivery.error = str(exc)[:2000]
        delivery.status = Delivery.FAILED if delivery.attempts >= Delivery.MAX_ATTEMPTS else Delivery.PENDING
        log.warning("Notification %s to %s failed (attempt %s): %s",
                    delivery.pk, delivery.channel, delivery.attempts, exc)
    except Exception as exc:  # noqa: BLE001
        delivery.error = f"{type(exc).__name__}: {exc}"[:2000]
        delivery.status = Delivery.FAILED
        log.exception("Notification %s crashed", delivery.pk)
    else:
        delivery.status = Delivery.SENT
        delivery.sent_at = timezone.now()
        delivery.error = ""
    delivery.save(update_fields=["attempts", "status", "error", "sent_at"])
    return delivery.status


def retry_pending() -> int:
    """From the scheduler: try again what failed, or what got lost on the way."""
    now = timezone.now()
    stale = Delivery.objects.filter(status=Delivery.PENDING).filter(
        created_at__lt=now - timedelta(minutes=1)
    )
    retried = 0
    for delivery in stale[:100]:
        # A first attempt still in flight is left alone for five minutes.
        if delivery.attempts == 0 and delivery.created_at > now - timedelta(minutes=5):
            continue
        deliver(delivery.pk)
        retried += 1
    return retried
