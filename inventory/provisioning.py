# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Loona's built-in jobs for the one-key-per-host model.

Every managed machine gets its own keypair.  A key that leaks therefore opens
exactly one server instead of the whole fleet, and retiring a machine is a real
revocation rather than a note to self.

The three playbooks below are generated rather than stored as :class:`Playbook`
rows on purpose: they are part of Loona, not content a user can edit, and a
half-saved edit to "the playbook that removes our access" is not a failure mode
worth having.  They run as ordinary jobs, so they get the same live log,
cancellation and history as anything else.
"""
from __future__ import annotations

import json
import logging
import re
import shutil

from django.db.models import Q
from django.utils import timezone

from administration import system

from .keys import fingerprint, generate_keypair, key_comment
from .probe import ping_playbook
from .models import Host, HostKey

log = logging.getLogger(__name__)

# A login name on the machine: what useradd accepts, nothing a shell, a path
# or a template could make more of.
LOGIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")


def check_login(username: str) -> str:
    if not LOGIN.match(username or ""):
        raise ValueError(f"{username!r} is not a login name.")
    return username


def sshpass_available() -> bool:
    """Ansible needs sshpass to log in with a password rather than a key."""
    return shutil.which("sshpass") is not None


# -- key material -----------------------------------------------------------


def ensure_keypair(host: Host, username: str) -> HostKey:
    check_login(username)
    """Return the host's keypair, generating one the first time it is needed.

    A key that was never installed is regenerated when the target account
    changes, so a mistyped login does not leave a stale key behind.
    """
    key = getattr(host, "managed_key", None)
    if key and key.is_installed:
        return key
    private_text, public_text = generate_keypair(key_comment(host.name, host.pk))
    if key is None:
        key = HostKey(host=host)
    key.username = username
    key.public_key = public_text
    key.private_key = private_text
    key.fingerprint = fingerprint(public_text)
    key.status = HostKey.PENDING
    key.error_message = ""
    key.installed_at = None
    key.verified_at = None
    key.save()
    return key


# -- generated playbooks ----------------------------------------------------


def _yaml(play: dict) -> str:
    from secretstore.resolve import dump_inventory

    return dump_inventory([play])


def _data(value: str):
    """Text Ansible must take as it is, never as a template."""
    from secretstore.resolve import Unsafe

    return Unsafe(value)


def key_install_playbook(host: Host, key: HostKey, wait: bool = False) -> str:
    wait_task = [
        {
            "name": "Wait for the machine to accept SSH",
            # A machine OpenTofu has just created may still be booting.
            "ansible.builtin.wait_for_connection": {
                "timeout": system.get().bootstrap_wait_seconds,
                "sleep": 5,
            },
        }
    ] if wait else []
    return _yaml(
        {
            "name": _data(f"Install Loona's key on {host.name}"),
            "hosts": "all",
            "gather_facts": False,
            "tasks": wait_task + [
                {
                    "name": _data(f"Add Loona's key to ~{key.username}/.ssh/authorized_keys"),
                    "ansible.builtin.authorized_key": {
                        "user": _data(check_login(key.username)),
                        "key": _data(key.public_key),
                        "state": "present",
                        # Never touch keys Loona did not put there.
                        "exclusive": False,
                        "manage_dir": True,
                    },
                }
            ],
        }
    )


def key_revoke_playbook(host: Host, key: HostKey) -> str:
    return _yaml(
        {
            "name": _data(f"Remove Loona's key from {host.name}"),
            "hosts": "all",
            "gather_facts": False,
            "tasks": [
                {
                    "name": _data(f"Drop Loona's key from ~{key.username}/.ssh/authorized_keys"),
                    "ansible.builtin.authorized_key": {
                        "user": _data(check_login(key.username)),
                        "key": _data(key.public_key),
                        "state": "absent",
                        "exclusive": False,
                    },
                }
            ],
        }
    )


# -- starting the jobs ------------------------------------------------------


def password_override(username: str, password: str, become_password: str = "") -> dict:
    """Connection variables for a one-off password login."""
    override = {"ansible_user": check_login(username), "ansible_password": password}
    if become_password:
        override["ansible_become_password"] = become_password
    return override


def _start(host, kind, name, playbook_yaml, user=None, override=None, delete_host=False):
    from runs.executor import dispatch
    from runs.models import Job

    job = Job.objects.create(
        kind=kind,
        playbook_name=name,
        playbook_yaml=playbook_yaml,
        forks=1,
        created_by=user if user and user.is_authenticated else None,
        delete_host_on_success=delete_host,
    )
    if override:
        job.connection_override = override
        job.save(update_fields=["connection_override_encrypted"])
    job.target_hosts.add(host)
    dispatch(job)
    return job


def start_key_install(host: Host, key: HostKey, user=None, override: dict | None = None,
                      wait: bool = False):
    """Push Loona's key into the remote authorized_keys."""
    from runs.models import Job

    # Pushed again with no login typed, the working key is itself the way in:
    # it has to stay usable for this run, which "pending" is not.
    if override is not None or not key.is_usable:
        key.status = HostKey.PENDING
    key.error_message = ""
    key.save(update_fields=["status", "error_message"])
    return _start(
        host,
        Job.KIND_KEY_INSTALL,
        f"Loona: install SSH key on {host.name}",
        key_install_playbook(host, key, wait=wait),
        user=user,
        override=override,
    )


def start_key_verify(host: Host, key: HostKey, user=None):
    """Reconnect using the key that was just installed.

    Without this a failed push would leave Loona quietly switched over to a key
    that does not work, and the next real playbook would be the one to find out.
    """
    from runs.models import Job

    return _start(
        host,
        Job.KIND_KEY_VERIFY,
        f"Loona: verify SSH key on {host.name}",
        ping_playbook(host.name),
        user=user,
    )


def start_key_revoke(host: Host, key: HostKey, user=None, delete_host: bool = False):
    """Take Loona's key off the server, optionally deleting the host after."""
    from runs.models import Job

    key.status = HostKey.REVOKING
    key.error_message = ""
    key.save(update_fields=["status", "error_message"])
    name = f"Loona: remove SSH key from {host.name}"
    if delete_host:
        name += " and delete the host"
    return _start(
        host,
        Job.KIND_KEY_REVOKE,
        name,
        key_revoke_playbook(host, key),
        user=user,
        delete_host=delete_host,
    )


# -- what happens once a job finishes ---------------------------------------


def _failure_reason(job) -> str:
    """The most useful line Loona can show without opening the log."""
    if job.error_message:
        return job.error_message
    last = job.events.filter(
        Q(failed=True) | Q(event__in=("runner_on_failed", "runner_on_unreachable"))
    ).last()
    if last and last.stdout.strip():
        return _message_from_stdout(last.stdout)
    return f"The run ended as {job.get_status_display().lower()}."


def _message_from_stdout(stdout: str) -> str:
    """Ansible prints a banner and then the result as JSON; "msg" is the point."""
    start = stdout.find("{")
    if start != -1:
        try:
            payload = json.loads(stdout[start:])
        except ValueError:
            payload = None
        if isinstance(payload, dict) and payload.get("msg"):
            return str(payload["msg"]).strip()[:2000]
    return stdout.strip()[:2000]


def on_job_finished(job):
    """Advance the key's state machine after one of Loona's own runs.

    Called by the executor rather than by the view, because the browser may well
    be gone by the time a run ends - and a host awaiting deletion has to be
    deleted either way.
    """
    from runs.models import Job

    if job.kind == Job.KIND_BOOTSTRAP:
        from infra import bootstrap

        bootstrap.on_finished(job)
        return
    if not job.is_system:
        return
    host = job.target_hosts.first()
    if host is None:
        return

    succeeded = job.status == Job.SUCCESSFUL
    key = getattr(host, "managed_key", None)
    if key is None:
        # The key record went away while the run was in flight. A deletion that
        # was only waiting on the revocation still has to happen.
        if job.kind == Job.KIND_KEY_REVOKE and succeeded and job.delete_host_on_success:
            host.delete()
        return

    if job.kind == Job.KIND_KEY_INSTALL:
        _after_install(job, host, key, succeeded)
    elif job.kind == Job.KIND_KEY_VERIFY:
        _after_verify(job, key, succeeded)
        if host.tofu_project_id and host.bootstrapped_at is None:
            from infra import bootstrap

            bootstrap.after_key(job, host, succeeded)
    elif job.kind == Job.KIND_KEY_REVOKE:
        _after_revoke(job, host, key, succeeded)


def _after_install(job, host, key, succeeded):
    if not succeeded:
        key.status = HostKey.FAILED
        key.error_message = _failure_reason(job)
        key.save(update_fields=["status", "error_message"])
        if host.tofu_project_id and host.bootstrapped_at is None:
            host.bootstrap_error = f"Could not put Loona's key on the new machine: {key.error_message}"
            host.save(update_fields=["bootstrap_error"])
            from notifications import events

            events.bootstrap_failed(host, job)
        return
    key.status = HostKey.VERIFYING
    key.installed_at = timezone.now()
    key.error_message = ""
    key.save(update_fields=["status", "installed_at", "error_message"])
    start_key_verify(host, key, user=job.created_by)


def _after_verify(job, key, succeeded):
    if succeeded:
        key.status = HostKey.ACTIVE
        key.verified_at = timezone.now()
        key.error_message = ""
    else:
        key.status = HostKey.FAILED
        key.error_message = (
            "The key was added to the server, but Loona could not log in with "
            "it. Until this is fixed Loona falls back to the host's credential. "
            + _failure_reason(job)
        )
    key.save(update_fields=["status", "verified_at", "error_message"])


def _after_revoke(job, host, key, succeeded):
    if not succeeded:
        key.status = HostKey.REVOKE_FAILED
        key.error_message = _failure_reason(job)
        key.save(update_fields=["status", "error_message"])
        return
    # The key is off the server; drop Loona's copy, then the host itself.
    key.delete()
    if job.delete_host_on_success:
        log.info("Deleting host %s after successful key revocation", host.name)
        host.delete()
