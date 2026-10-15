# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""A one-off "can Loona reach this machine" check.

Deliberately not a :class:`~runs.models.Job`.  Nothing changes on the far end,
there is nothing worth keeping in the history, and the answer has to come back
into the page the user is already on - including the new-host form, where no
host record exists yet for a job to point at.

Because it runs inside the request it is kept on a short leash: SSH gets ten
seconds to connect and the whole run twenty-five.
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

import ansible_runner
import yaml
from django.conf import settings
from django.utils.translation import gettext as _

from . import hostkeys

log = logging.getLogger(__name__)

CONNECT_TIMEOUT = 10
RUN_TIMEOUT = 25

LOGIN_TASK = "Log in over SSH"
MANAGE_TASK = "Check that Ansible can manage this host"


def ping_playbook(label: str) -> str:
    """Prove the login works, then that Ansible can actually drive the host.

    The two are separate questions with different fixes: a refused password is
    not the same problem as a machine with no Python on it, and the second one
    matters right away because installing a key needs Python.  ``raw`` needs
    nothing on the far end, so it isolates the login.
    """
    play = {
        "name": f"Check that Loona can reach {label}",
        "hosts": "all",
        "gather_facts": False,
        "tasks": [
            {
                "name": LOGIN_TASK,
                "ansible.builtin.raw": "echo loona-connection-ok",
                "changed_when": False,
            },
            {
                "name": MANAGE_TASK,
                "ansible.builtin.ping": {},
                "ignore_errors": True,
            },
        ],
    }
    return yaml.safe_dump([play], sort_keys=False, default_flow_style=False, width=100)


@dataclass
class ProbeResult:
    """What to show the user, in the three states worth telling apart."""

    level: str  # "ok", "warn" or "fail"
    summary: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.level != "fail"

    @property
    def badge(self) -> str:
        return {"ok": "ok", "warn": "warn"}.get(self.level, "fail")


def check_connection(build_variables, label: str = "this host", host_keys: str = "") -> ProbeResult:
    """Try to log in. ``build_variables(keys_dir)`` returns the connection vars.

    The callable shape exists so private keys can be written into a directory
    this function owns and removes again, the same way a job's scratch dir works.
    """
    base = Path(tempfile.mkdtemp(prefix="probe_", dir=_probe_root()))
    try:
        os.chmod(base, 0o700)
        (base / "project").mkdir()
        (base / "env").mkdir()
        (base / "project" / "playbook.yml").write_text(ping_playbook(label))
        (base / "env" / "settings").write_text("---\nsuppress_ansible_output: true\n")
        variables = build_variables(base / "keys")
        # A pinned key is enforced here too; a host without one is let through
        # but nothing is pinned - that is for the first real run to do.
        where = hostkeys.target_of("target", variables)
        known_hosts = hostkeys.write_known_hosts(base, [(*where, host_keys)] if where else [])
        (base / "env" / "envvars").write_text(
            yaml.safe_dump(
                {
                    "ANSIBLE_FORCE_COLOR": "False",
                    "ANSIBLE_NOCOLOR": "1",
                    "ANSIBLE_TIMEOUT": str(CONNECT_TIMEOUT),
                    **hostkeys.ansible_env(known_hosts),
                }
            )
        )

        # Everything here was typed into a form a moment ago: data, never a
        # template.  ansible-runner's own inventory= would write it as JSON and
        # lose that mark.
        from secretstore.resolve import as_data, dump_inventory

        inventory_file = base / "inventory" / "hosts.yml"
        inventory_file.parent.mkdir(exist_ok=True)
        inventory_file.write_text(dump_inventory({"all": {"hosts": {"target": as_data(variables)}}}))
        os.chmod(inventory_file, 0o600)
        events: list[dict] = []
        runner = ansible_runner.run(
            private_data_dir=str(base),
            playbook="playbook.yml",
            inventory=str(inventory_file),
            forks=1,
            timeout=RUN_TIMEOUT,
            event_handler=lambda event: events.append(event) or True,
            quiet=True,
        )
    except Exception as exc:  # noqa: BLE001 - reported in the page, not raised
        log.exception("Connection probe for %s crashed", label)
        return ProbeResult("fail", _("Loona could not run the check."), str(exc))
    finally:
        # Takes the private key with it.
        shutil.rmtree(base, ignore_errors=True)

    return _read_result(runner, events, variables)


def _probe_root() -> Path:
    root = Path(settings.LOONA_DATA_DIR)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _read_result(runner, events, variables) -> ProbeResult:
    login = _task_outcome(events, LOGIN_TASK)
    manage = _task_outcome(events, MANAGE_TASK)
    user = variables.get("ansible_user", "the configured user")

    if runner.status == "timeout":
        return ProbeResult(
            "fail",
            _('No answer within %(RUN_TIMEOUT)s seconds.') % {"RUN_TIMEOUT": RUN_TIMEOUT},
            _("The address or port is probably wrong, or a firewall is dropping the "
            "connection rather than refusing it."),
        )
    if login is None or login[0] is False:
        detail = login[1] if login else (runner.stdout and "") or ""
        if hostkeys.is_mismatch(detail):
            return ProbeResult(
                "fail",
                _("The server's SSH host key is not the one Loona pinned for this host."),
                _("Either the machine was rebuilt or replaced - then forget the pinned key on "
                "the host page - or something else is answering at this address."),
            )
        return ProbeResult("fail", _('Could not log in as %(user)s.') % {"user": user}, detail)
    if manage is None or manage[0] is False:
        hint = (
            "Most often this means Python is missing on the far end. Loona needs it "
            "to install a key or run any playbook."
        )
        reported = manage[1] if manage else ""
        return ProbeResult(
            "warn",
            _('Logged in as %(user)s, but Ansible cannot manage this host yet.') % {"user": user},
            f"{reported.rstrip('.')}. {hint}" if reported else hint,
        )
    return ProbeResult("ok", _('Logged in as %(user)s. Ansible can manage this host.') % {"user": user})


def _task_outcome(events, task_name):
    """(succeeded, message) for one task, or None if it never ran."""
    outcome = None
    for event in events:
        data = event.get("event_data") or {}
        if data.get("task") != task_name:
            continue
        name = event.get("event") or ""
        if name == "runner_on_ok":
            outcome = (True, "")
        elif name in ("runner_on_failed", "runner_on_unreachable"):
            result = data.get("res") or {}
            message = result.get("msg") or result.get("stderr") or ""
            outcome = (False, _tidy(str(message)))
    return outcome


def _tidy(message: str) -> str:
    """SSH errors arrive as a wall of text; keep the part that names the problem."""
    lines = [line.strip() for line in message.splitlines() if line.strip()]
    trimmed = " ".join(lines)
    return trimmed[:400] + ("..." if len(trimmed) > 400 else "")
