# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Loona's side of a run carried out by a remote executor.

    worker: prepare the run directory as for a local run -> hand_off()
            (packed, encrypted onto the job, directory gone; job pending)
    agent:  claim()  -> the bundle, which is wiped from the job at once
            events() -> the log, as it happens; answers "cancel?"
            finish() -> status, stats and the SSH host keys met

Everything that needs the database or the secret store happens here, before
the hand-off and after the finish; the agent only needs Ansible, the bundle
and a way out to Loona.  It masks the log itself with the values the bundle
lists, since only it sees the output before it leaves the network.
"""
from __future__ import annotations

import base64
import io
import json
import logging
import os
import shutil
import tarfile
import tempfile
from datetime import timedelta
from pathlib import Path

import yaml
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from core.crypto import decrypt, encrypt
from runs.models import Job, JobEvent

log = logging.getLogger(__name__)

PROTOCOL = 1
SPEC_FILE = "loona.json"
# An agent reports at least every few seconds while a run goes on; this much
# silence means it is gone - stopped, crashed or cut off.
SILENCE = timedelta(minutes=3)
# Galaxy installs live in a cache shared between runs; a remote run takes
# its own copy, since the agent may well have no way to the internet.
VENDORED = "galaxy"
PATH_VARIABLES = ("ANSIBLE_ROLES_PATH", "ANSIBLE_COLLECTIONS_PATH")


class Gone(Exception):
    """The run is not this agent's to report on any more."""


# -- the worker: hand a prepared run over ---------------------------------------------


def hand_off(job: Job, executor, private_data_dir: Path, spec: dict) -> str:
    """Pack the prepared run for the executor and leave it waiting. Returns the status."""
    from runs.executor import _discard_run_dir, _finish

    try:
        bundle = pack(private_data_dir, {**spec, "job": job.pk, "base": str(private_data_dir)})
    except Exception as exc:  # noqa: BLE001 - surfaced to the user
        log.exception("Could not pack job %s for %s", job.pk, executor)
        return _finish(job, Job.ERROR, error_message=f"Could not pack the run for {executor.name}: {exc}")
    finally:
        _discard_run_dir(private_data_dir)
    job.executor = executor
    job.bundle_encrypted = encrypt(base64.b64encode(bundle).decode())
    job.private_data_dir = ""
    job.runner = executor.runner_waiting
    job.save(update_fields=["executor", "bundle_encrypted", "private_data_dir", "runner"])
    note(job, f"Handed to executor {executor.name}; waiting for one of its agents to take it.")
    if Job.objects.filter(pk=job.pk, canceled=True).exists():
        cancel_waiting(job)
    return Job.objects.get(pk=job.pk).status


def pack(private_data_dir: Path, spec: dict) -> bytes:
    _vendor_galaxy(private_data_dir)
    (private_data_dir / SPEC_FILE).write_text(json.dumps(spec))
    os.chmod(private_data_dir / SPEC_FILE, 0o600)

    def keep(info):
        # SSH control sockets and the like are no use anywhere else.
        if not (info.isfile() or info.isdir() or info.issym()):
            return None
        return info

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        tar.add(private_data_dir, arcname=".", filter=keep)
    return buffer.getvalue()


def _vendor_galaxy(private_data_dir: Path):
    envvars = private_data_dir / "env" / "envvars"
    if not envvars.exists():
        return
    values = yaml.safe_load(envvars.read_text()) or {}
    cache = str(Path(settings.LOONA_GALAXY_CACHE).resolve())
    copied = 0
    for name in PATH_VARIABLES:
        if not values.get(name):
            continue
        paths = []
        for entry in str(values[name]).split(":"):
            resolved = str(Path(entry).resolve()) if entry else entry
            if entry and resolved.startswith(cache + os.sep) and Path(entry).is_dir():
                copied += 1
                target = private_data_dir / VENDORED / str(copied)
                shutil.copytree(entry, target, symlinks=True)
                entry = str(target)
            paths.append(entry)
        values[name] = ":".join(paths)
    if copied:
        envvars.write_text(yaml.safe_dump(values, default_flow_style=False))


def note(job: Job, text: str):
    """A line of Loona's own in the run's log."""
    JobEvent.objects.create(job=job, counter=0, event="loona_executor", stdout=text)


def cancel_waiting(job: Job) -> bool:
    """Close a run no agent has taken yet. False if one already has."""
    from runs.executor import _finish

    taken = Job.objects.filter(
        pk=job.pk, status=Job.PENDING, runner__startswith="executor/"
    ).update(runner="executor-canceled", bundle_encrypted="")
    if not taken:
        return False
    job.refresh_from_db()
    _finish(job, Job.CANCELED)
    return True


# -- the agent: take a run, report on it -----------------------------------------------


def claim(executor, agent) -> tuple[Job, bytes] | None:
    """The oldest run waiting for this executor, taken by this agent."""
    if not executor.enabled:
        return None
    waiting = Job.objects.filter(
        executor=executor, status=Job.PENDING, runner=executor.runner_waiting, canceled=False
    )
    for job in waiting.order_by("created_at")[:10]:
        now = timezone.now()
        with transaction.atomic():
            taken = Job.objects.filter(pk=job.pk, status=Job.PENDING, runner=executor.runner_waiting,
                                       canceled=False).update(
                status=Job.RUNNING, runner=f"{executor.runner_waiting}/{agent.name}"[:255],
                started_at=now, heartbeat_at=now,
            )
            if not taken:
                continue
            job.refresh_from_db()
            raw = decrypt(job.bundle_encrypted)
            # Out of the database the moment it is on its way.
            Job.objects.filter(pk=job.pk).update(bundle_encrypted="")
        note(job, f"Taken by agent {agent.name} of {executor.name}.")
        return job, base64.b64decode(raw)
    return None


def running_job(executor, agent, job_id) -> Job:
    """The run this agent is carrying out. Raises Gone."""
    job = Job.objects.filter(pk=job_id, executor=executor).first()
    if job is None or job.status != Job.RUNNING or job.runner != f"{executor.runner_waiting}/{agent.name}"[:255]:
        raise Gone
    return job


def events(job: Job, batch: list) -> bool:
    """Store a batch of the run's events. Returns whether to cancel."""
    from runs.executor import _record_event
    from core.masking import Masker

    Job.objects.filter(pk=job.pk).update(heartbeat_at=timezone.now())
    batch = [event for event in batch if isinstance(event, dict)]
    uuids = [str(event.get("uuid") or "")[:64] for event in batch]
    # A batch sent again after a lost answer is stored once.
    known = set(job.events.filter(uuid__in=[u for u in uuids if u]).values_list("uuid", flat=True))
    counters = {
        "stored": job.events.filter(counter__gt=0).exclude(event__startswith="loona_").count(),
        "truncated": job.events.filter(event="loona_truncated").exists(),
        "adhoc": job.is_adhoc,
        # The agent masked them already; nothing here knows the values.
        "mask": Masker(),
    }
    for event, uuid in zip(batch, uuids):
        if uuid and uuid in known:
            continue
        try:
            _record_event(job.pk, event, counters)
        except Exception:  # noqa: BLE001 - a bad event must not kill the run
            log.exception("Could not store event for job %s", job.pk)
    return Job.objects.filter(pk=job.pk, canceled=True).exists()


AGENT_STATUSES = {Job.SUCCESSFUL, Job.FAILED, Job.CANCELED, Job.ERROR}


def finish(job: Job, status: str, return_code=None, stats=None, known_hosts="", error="", tofu=None) -> str:
    from runs.executor import _finish

    if status not in AGENT_STATUSES:
        status, error = Job.ERROR, error or f"The agent reported an unknown status {status!r}."
    job.heartbeat_at = timezone.now()
    if job.is_tofu:
        from infra.runner import complete_remote

        job.save(update_fields=["heartbeat_at"])
        job.refresh_from_db()
        if job.canceled:
            status = Job.CANCELED
        status, problem = complete_remote(job, status, tofu if isinstance(tofu, dict) else {})
        error = error or problem
        job.refresh_from_db()
        return _finish(job, status, return_code=return_code, error_message=str(error or "")[:4000])
    job.stats = stats if isinstance(stats, dict) else {}
    job.save(update_fields=["stats", "heartbeat_at"])
    if known_hosts:
        try:
            _learn_host_keys(job, str(known_hosts))
        except Exception:  # noqa: BLE001 - the run itself is over either way
            log.exception("Could not pin host keys from job %s", job.pk)
    job.refresh_from_db()
    if job.canceled:
        status = Job.CANCELED
    return _finish(job, status, return_code=return_code, error_message=str(error or "")[:4000])


def _learn_host_keys(job: Job, text: str):
    from inventory import hostkeys
    from inventory.models import Host

    hosts = {h.name: h for h in Host.objects.filter(name__in=job.resolved_hosts)}
    targets = {
        name: {"ansible_host": h.ansible_host, "ansible_port": h.port,
               "ansible_connection": (h.variables or {}).get("ansible_connection")}
        for name, h in hosts.items()
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / hostkeys.KNOWN_HOSTS
        path.write_text(text)
        hostkeys.learn(path, hosts, targets)


# -- runs whose agent went away --------------------------------------------------------

SILENT_MESSAGE = (
    "The agent of executor {executor} carrying out this run stopped reporting. "
    "It may have been cut off part way through, so check the hosts before running it again."
)
ORPHAN_MESSAGE = "The executor this run was waiting for was deleted."


def reap(jobs=None) -> int:
    from runs.executor import _finish

    jobs = Job.objects.all() if jobs is None else jobs
    reaped = 0
    cutoff = timezone.now() - SILENCE
    silent = jobs.filter(status=Job.RUNNING, runner__startswith="executor/", heartbeat_at__lt=cutoff)
    for job in silent:
        if Job.objects.filter(pk=job.pk, status=Job.RUNNING, heartbeat_at__lt=cutoff).update(
            runner="executor-silent"
        ):
            job.refresh_from_db()
            name = job.executor.name if job.executor else "(deleted)"
            _finish(job, Job.ERROR, error_message=SILENT_MESSAGE.format(executor=name))
            reaped += 1
    for job in jobs.filter(status=Job.PENDING, runner__startswith="executor/", canceled=True):
        # Cancelled some other way than runs.services.cancel - by a workflow.
        reaped += cancel_waiting(job)
    orphans = jobs.filter(status=Job.PENDING, runner__startswith="executor/", executor__isnull=True)
    for job in orphans:
        if Job.objects.filter(pk=job.pk, status=Job.PENDING).update(runner="executor-gone", bundle_encrypted=""):
            job.refresh_from_db()
            _finish(job, Job.ERROR, error_message=ORPHAN_MESSAGE)
            reaped += 1
    return reaped


def abandon_waiting(executor) -> int:
    """Before an executor is deleted: close the runs still waiting for it."""
    from runs.executor import _finish

    count = 0
    for job in Job.objects.filter(executor=executor, status=Job.PENDING, runner=executor.runner_waiting):
        if Job.objects.filter(pk=job.pk, status=Job.PENDING).update(runner="executor-gone", bundle_encrypted=""):
            job.refresh_from_db()
            _finish(job, Job.ERROR, error_message=ORPHAN_MESSAGE)
            count += 1
    return count
