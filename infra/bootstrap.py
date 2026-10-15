# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Bringing up a machine an OpenTofu project just created.

1. Loona logs in with the project's bootstrap key - OpenTofu put its public
   half on the machine through var.loona_ssh_public_key - waiting up to five
   minutes for SSH, and installs the machine's own key (key_install).
2. It logs in again with that key (key_verify), as for any host.
3. A bootstrap job removes the bootstrap key from the machine, then runs the
   project's baseline playbook if it has one.

Each step is an ordinary job with its own log; the chain is driven from
inventory.provisioning.on_job_finished, as key management already is.
"""
from __future__ import annotations

import logging

import yaml
from django.utils import timezone

from inventory import provisioning
from runs.models import Job

log = logging.getLogger(__name__)


def begin(host, project, user=None):
    """Start step 1 for a host the project just declared."""
    username = getattr(host, "_declared_user", "") or project.bootstrap_user
    key = provisioning.ensure_keypair(host, username)
    host.bootstrap_error = ""
    host.bootstrapped_at = None
    host.save(update_fields=["bootstrap_error", "bootstrapped_at"])
    override = {
        "ansible_user": username,
        "loona_private_key": project.bootstrap_private_key,
    }
    return provisioning.start_key_install(host, key, user=user, override=override, wait=True)


def after_key(verify_job, host, succeeded):
    """Step 2 finished; on success, step 3."""
    if not succeeded:
        host.bootstrap_error = "Loona's key went on, but logging in with it failed. See the key page."
        host.save(update_fields=["bootstrap_error"])
        from notifications import events

        events.bootstrap_failed(host, verify_job)
        return
    start_finish(host, user=verify_job.created_by)


def start_finish(host, user=None):
    from runs.executor import dispatch

    project = host.tofu_project
    key = host.managed_key
    plays = [
        {
            "name": f"Remove the bootstrap key from {host.name}",
            "hosts": "all",
            "gather_facts": False,
            "tasks": [
                {
                    "name": "Drop the project's bootstrap key; this machine has its own now",
                    "ansible.builtin.authorized_key": {
                        "user": key.username,
                        "key": project.bootstrap_public_key,
                        "state": "absent",
                        "exclusive": False,
                    },
                }
            ],
        }
    ]
    name = f"Bootstrap {host.name}"
    baseline = project.baseline_playbook
    if baseline is not None:
        from playbooks import yaml_io

        if baseline.mode == baseline.MODE_FILE:
            # Its YAML lives in its project (maybe in Git): import it from there.
            plays.append({"ansible.builtin.import_playbook": baseline.file_path})
        else:
            plays += yaml.safe_load(yaml_io.playbook_yaml(baseline)) or []
        name += f": {baseline.name}"
    job = Job.objects.create(
        kind=Job.KIND_BOOTSTRAP,
        playbook=baseline,
        ansible_project=baseline.project if baseline else None,
        playbook_name=name,
        playbook_yaml=yaml.safe_dump(plays, sort_keys=False, width=100),
        created_by=user if user and user.is_authenticated else None,
    )
    job.target_hosts.add(host)
    dispatch(job)
    return job


def on_finished(job):
    host = job.target_hosts.first()
    if host is None:
        return
    if job.status == Job.SUCCESSFUL:
        host.bootstrapped_at = timezone.now()
        host.bootstrap_error = ""
    else:
        host.bootstrap_error = f"The bootstrap run ended as {job.get_status_display().lower()}; see job #{job.pk}."
    host.save(update_fields=["bootstrapped_at", "bootstrap_error"])
    if job.status != Job.SUCCESSFUL:
        from notifications import events

        events.bootstrap_failed(host, job)
