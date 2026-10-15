# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Putting one Delivery on the wire: email, Telegram or a webhook."""
from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.request

from django.conf import settings
from django.core.mail import EmailMessage, get_connection
from django.utils import timezone

from .models import Channel, Delivery

TIMEOUT = 15


class SendFailed(Exception):
    pass


def send(delivery: Delivery):
    channel = delivery.channel
    handler = {
        Channel.EMAIL: _email,
        Channel.TELEGRAM: _telegram,
        Channel.WEBHOOK: _webhook,
    }[channel.kind]
    handler(delivery, channel.config)


def _body(delivery: Delivery) -> str:
    lines = [delivery.text.strip()]
    if delivery.url:
        lines.append(delivery.url)
    return "\n\n".join(line for line in lines if line)


# -- email ----------------------------------------------------------------------


def _email(delivery, config):
    from administration import system

    row = system.get()
    recipients = [r.strip() for r in config.get("recipients", []) if r.strip()]
    if not recipients:
        raise SendFailed("The channel has no recipients.")
    if not row.smtp_host:
        raise SendFailed("No SMTP server is set in Administration -> Notifications.")
    connection = get_connection(
        settings.LOONA_EMAIL_BACKEND,
        host=row.smtp_host,
        port=row.smtp_port,
        username=row.smtp_username or None,
        password=row.smtp_password or None,
        use_tls=row.smtp_security == "starttls",
        use_ssl=row.smtp_security == "ssl",
        timeout=TIMEOUT,
        fail_silently=False,
    )
    message = EmailMessage(
        subject=f"[Loona] {delivery.subject}",
        body=_body(delivery),
        from_email=row.smtp_from or f"loona@{row.smtp_host}",
        to=recipients,
        connection=connection,
    )
    try:
        message.send()
    except Exception as exc:  # noqa: BLE001 - smtplib raises a zoo
        raise SendFailed(f"{type(exc).__name__}: {exc}") from exc


# -- telegram --------------------------------------------------------------------


def _telegram(delivery, config):
    token, chat = config.get("bot_token", ""), config.get("chat_id", "")
    if not token or not chat:
        raise SendFailed("The channel needs a bot token and a chat id.")
    payload = {
        "chat_id": chat,
        "text": f"{delivery.subject}\n\n{_body(delivery)}"[:4096],
        "disable_web_page_preview": True,
    }
    url = f"{settings.LOONA_TELEGRAM_API.rstrip('/')}/bot{token}/sendMessage"
    answer = _post_json(url, payload, secret_in_url=True)
    if not answer.get("ok"):
        raise SendFailed(f"Telegram said: {answer.get('description', answer)}")


# -- webhook ---------------------------------------------------------------------


def _webhook(delivery, config):
    url = config.get("url", "")
    if not url.startswith(("http://", "https://")):
        raise SendFailed("The channel needs an http(s) URL.")
    payload = {
        "event": delivery.event,
        "subject": delivery.subject,
        # Slack, Mattermost and friends show "text" as the message.
        "text": f"*{delivery.subject}*\n{_body(delivery)}",
        "url": delivery.url,
        "data": delivery.data,
        "sent_at": timezone.now().isoformat(),
    }
    _post_json(url, payload, secret=config.get("secret", ""))


def _post_json(url, payload, secret="", secret_in_url=False) -> dict:
    body = json.dumps(payload, ensure_ascii=False).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "Loona"}
    if secret:
        signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Loona-Signature"] = f"sha256={signature}"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    # A Telegram URL carries the bot token; keep it out of error messages.
    shown = url.split("/bot")[0] + "/bot***" if secret_in_url else url
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:300].decode(errors="replace")
        raise SendFailed(f"{shown} answered {exc.code}: {detail}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise SendFailed(f"Could not reach {shown}: {getattr(exc, 'reason', exc)}") from exc
    try:
        return json.loads(raw or b"{}")
    except ValueError:
        return {"ok": True}
