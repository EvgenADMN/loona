# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The HTTP side agents talk to.  Agents connect out; Loona never calls them.

Every request carries ``Authorization: Bearer lxe_...`` (the executor's
token) and a JSON body naming the agent.  Answers are JSON; 204 means
"nothing for you", 409 "that run is not yours any more".
"""
from __future__ import annotations

import base64
import json
import logging

from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from . import remote
from .models import Agent, Executor

log = logging.getLogger(__name__)

SEEN_EVERY = 5  # seconds between last_seen writes for one agent


def _error(status, message):
    return JsonResponse({"error": message}, status=status)


def agent_view(view):
    @csrf_exempt
    @require_POST
    def wrapped(request, *args, **kwargs):
        header = request.headers.get("Authorization", "")
        executor = Executor.for_token(header[7:].strip() if header.startswith("Bearer ") else "")
        if executor is None:
            return _error(401, "Unknown executor token.")
        protocol = request.headers.get("X-Loona-Executor-Protocol", "")
        if protocol != str(remote.PROTOCOL):
            return _error(426, f"This Loona speaks executor protocol {remote.PROTOCOL}; "
                               f"the agent speaks {protocol or 'none'}. Use the same image version.")
        try:
            body = json.loads(_read(request) or b"{}")
        except (ValueError, UnicodeDecodeError):
            return _error(400, "The body is not JSON, or is too large.")
        name = str(body.get("agent") or "").strip()[:160] if isinstance(body, dict) else ""
        if not name:
            return _error(400, "Name the agent.")
        agent = _seen(executor, name, body, request)
        return view(request, executor, agent, body, *args, **kwargs)

    return wrapped


# A finished OpenTofu plan brings the saved plan and its JSON form along -
# more than Django's usual 2.5 MB for a request.
MAX_BODY = 64 * 1024 * 1024


def _read(request) -> bytes:
    length = int(request.META.get("CONTENT_LENGTH") or 0)
    if length > MAX_BODY:
        raise ValueError("too large")
    # read(), not .body: the size check above replaces Django's own.
    return request.read(length) if length else b""


def _seen(executor, name, body, request) -> Agent:
    agent, created = Agent.objects.get_or_create(executor=executor, name=name)
    now = timezone.now()
    if created or (now - agent.last_seen_at).total_seconds() >= SEEN_EVERY:
        agent.last_seen_at = now
        agent.version = str(body.get("version") or "")[:40]
        agent.address = (request.META.get("REMOTE_ADDR") or "")[:64]
        try:
            agent.slots = max(1, min(int(body.get("slots") or 1), 100))
        except (TypeError, ValueError):
            agent.slots = 1
        agent.save()
    return agent


@agent_view
def claim(request, executor, agent, body):
    taken = remote.claim(executor, agent)
    if taken is None:
        return HttpResponse(status=204)
    job, bundle = taken
    log.info("Job %s taken by agent %s of %s", job.pk, agent.name, executor.name)
    return JsonResponse({"job": job.pk, "bundle": base64.b64encode(bundle).decode()})


@agent_view
def events(request, executor, agent, body, job_id):
    try:
        job = remote.running_job(executor, agent, job_id)
    except remote.Gone:
        return _error(409, "This run is not yours to report on any more.")
    batch = body.get("events") or []
    if not isinstance(batch, list):
        return _error(400, "events must be a list.")
    return JsonResponse({"cancel": remote.events(job, batch)})


@agent_view
def finish(request, executor, agent, body, job_id):
    try:
        job = remote.running_job(executor, agent, job_id)
    except remote.Gone:
        return _error(409, "This run is not yours to report on any more.")
    status = remote.finish(
        job,
        str(body.get("status") or ""),
        return_code=body.get("rc") if isinstance(body.get("rc"), int) else None,
        stats=body.get("stats"),
        known_hosts=body.get("known_hosts") or "",
        error=body.get("error") or "",
        tofu=body.get("tofu"),
    )
    return JsonResponse({"status": status})
