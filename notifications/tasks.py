# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from celery import shared_task


@shared_task(name="loona.notify")
def deliver_task(delivery_id: int) -> str:
    from .dispatch import deliver

    return deliver(delivery_id)
