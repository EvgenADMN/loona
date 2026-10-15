# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""OpenTofu's "http" state backend, served by Loona.

One URL per project answers all of it: GET and POST the state, LOCK and
UNLOCK around writes.  Only a run of that very project gets in, with a
password minted for the run and useless once it ends - so the state, which
holds every secret the resources carry, is readable by nothing else.

See https://opentofu.org/docs/language/settings/backends/http/
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets

from django.db import IntegrityError, transaction
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt

from runs.models import Job

from .models import TofuLock, TofuProject, TofuStateVersion

log = logging.getLogger(__name__)


def issue_token(job: Job) -> str:
    """A fresh backend password for this run; only its hash is kept."""
    token = secrets.token_urlsafe(32)
    job.state_token_hash = _hash(token)
    job.save(update_fields=["state_token_hash"])
    return token


def username_for(job: Job) -> str:
    return f"job-{job.pk}"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _authenticated_job(request, project) -> Job | None:
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if not header.startswith("Basic "):
        return None
    try:
        username, _, password = base64.b64decode(header[6:]).decode().partition(":")
    except (ValueError, UnicodeDecodeError):
        return None
    if not username.startswith("job-") or not username[4:].isdigit():
        return None
    job = Job.objects.filter(pk=int(username[4:]), tofu_project=project).first()
    if job is None or job.is_final or not job.state_token_hash:
        return None
    if not hmac.compare_digest(job.state_token_hash, _hash(password)):
        return None
    return job


@csrf_exempt
def state(request, project_pk):
    project = get_object_or_404(TofuProject, pk=project_pk)
    job = _authenticated_job(request, project)
    if job is None:
        response = HttpResponse("Unauthorized", status=401)
        response["WWW-Authenticate"] = 'Basic realm="Loona state"'
        return response

    handler = {
        "GET": _get,
        "POST": _post,
        "LOCK": _lock,
        "UNLOCK": _unlock,
    }.get(request.method)
    if handler is None:
        # DELETE included: dropping a project's state is not a run's business.
        return HttpResponse(status=405)
    return handler(request, project, job)


def _get(request, project, job):
    current = project.current_state
    if current is None:
        return HttpResponse(status=204)
    return HttpResponse(current.data, content_type="application/json")


def _post(request, project, job):
    held = TofuLock.objects.filter(project=project).first()
    if held is not None and request.GET.get("ID") != held.lock_id:
        return JsonResponse(held.info, status=409)
    body = request.body.decode()
    try:
        parsed = json.loads(body)
    except ValueError:
        return HttpResponse("State must be JSON", status=400)
    version = TofuStateVersion(
        project=project,
        serial=int(parsed.get("serial") or 0),
        lineage=str(parsed.get("lineage") or "")[:64],
        job=job,
    )
    version.data = body
    version.save()
    return HttpResponse(status=200)


def _lock(request, project, job):
    info = _lock_info(request)
    try:
        with transaction.atomic():
            TofuLock.objects.create(project=project, job=job, lock_id=info.get("ID", ""), info=info)
    except IntegrityError:
        held = TofuLock.objects.filter(project=project).first()
        return JsonResponse(held.info if held else {}, status=423)
    return HttpResponse(status=200)


def _unlock(request, project, job):
    info = _lock_info(request)
    held = TofuLock.objects.filter(project=project).first()
    if held is None:
        return HttpResponse(status=200)
    if info.get("ID") and info["ID"] != held.lock_id:
        return JsonResponse(held.info, status=409)
    held.delete()
    return HttpResponse(status=200)


def _lock_info(request) -> dict:
    try:
        info = json.loads(request.body or b"{}")
    except ValueError:
        info = {}
    return info if isinstance(info, dict) else {}


def release_locks_of(job: Job) -> int:
    """Drop locks a run took and can no longer release itself."""
    return TofuLock.objects.filter(job=job).delete()[0]
