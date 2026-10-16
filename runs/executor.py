# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Run a Job with ansible-runner and stream its events into the database."""
from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import socket
import threading
from pathlib import Path

import ansible_runner
import yaml
from django.conf import settings
from django.db import close_old_connections, connection

from core.masking import Masker
from core.processes import kill_leftovers as _kill_leftovers
from inventory import hostkeys
from secretstore.resolve import dump_inventory
from inventory.models import Host
from inventory.services import AUTH_VARS, apply_connection_override, build_inventory, resolve_targets

from .models import Job, JobEvent

log = logging.getLogger(__name__)

# Events that carry no useful text for the log viewer.
NOISY_EVENTS = {"verbose"}

# ansible-runner forces colour on so it can render its own output; the log
# viewer colours lines from the event type instead, so the codes are stripped.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def prepare_private_data_dir(job: Job) -> Path:
    """Lay out the private_data_dir ansible-runner needs for this job."""
    base = Path(settings.LOONA_DATA_DIR) / f"job_{job.pk}"
    if base.exists():
        shutil.rmtree(base)
    (base / "project").mkdir(parents=True)
    (base / "env").mkdir(parents=True)
    (base / "keys").mkdir(parents=True)
    # Credentials and inventory land here in clear text; keep it owner-only.
    os.chmod(base, 0o700)

    # Ansible's own stdout is captured through the event stream, so keep it out
    # of the web/worker process log.
    (base / "env" / "settings").write_text("---\nsuppress_ansible_output: true\n")
    write_envvars(base, {})
    return base


def refresh_connection():
    """Drop a stale database connection before a long-running piece of work.

    Runs happen in worker threads and Celery tasks, where a connection may
    have outlived the database's patience.  Inside a transaction there is
    nothing stale to drop - and closing it would break that transaction.
    """
    if not connection.in_atomic_block:
        close_old_connections()


def _prepare_playbook(job, private_data_dir: Path, counters) -> tuple[str, dict]:
    """Put the project (if any) and the playbook in place. Returns (file, env)."""
    from . import projects

    def log(line):
        # Counter 0: these come before anything Ansible says.
        JobEvent.objects.create(job=job, counter=0, event="loona_project", stdout=line)

    project_dir = private_data_dir / "project"
    extra_env = {}
    if job.ansible_project_id:
        try:
            project_dir = projects.materialize(job, private_data_dir, log)
            galaxy_env = projects.galaxy_environment(job.ansible_project, private_data_dir)
            extra_env = projects.install_requirements(project_dir, galaxy_env, log)
            # Only a new run reads the playbook's current file_path. An apply
            # runs the file its preview ran; a bootstrap runs its generated
            # YAML, which imports the baseline itself.
            if not job.plan_id and job.kind == Job.KIND_PLAYBOOK and job.playbook \
                    and job.playbook.mode == job.playbook.MODE_FILE:
                job.playbook_file = job.playbook.file_path
            if job.playbook_file:
                job.playbook_yaml = projects.playbook_from_project(job.playbook_file, project_dir)
                job.save(update_fields=["playbook_yaml", "playbook_file"])
                return job.playbook_file, extra_env
        except projects.ProjectError as exc:
            raise ValueError(str(exc)) from exc
    (project_dir / projects.INLINE_PLAYBOOK).write_text(job.playbook_yaml)
    return projects.INLINE_PLAYBOOK, extra_env


BASE_ENVVARS = {
    "ANSIBLE_FORCE_COLOR": "False",
    "ANSIBLE_NOCOLOR": "1",
    "ANSIBLE_STDOUT_CALLBACK": "default",
}


def write_envvars(base: Path, extra: dict):
    (base / "env" / "envvars").write_text(
        yaml.safe_dump({**BASE_ENVVARS, **extra}, default_flow_style=False)
    )


def build_job_inventory(job: Job, private_data_dir: Path) -> dict:
    if job.is_system:
        # Key management has to reach a host even while it is disabled -
        # revoking access to a machine taken out of service is the whole point.
        hosts = list(job.target_hosts.all())
    else:
        hosts = resolve_targets(job.target_hosts.all(), job.target_groups.all())
    if job.plan_id:
        # Apply exactly what was previewed: a host that joined a target group
        # since then was never shown to anyone, so it sits this one out.
        planned = set(job.plan.resolved_hosts)
        hosts = [h for h in hosts if h.name in planned]
    if not hosts:
        raise ValueError("No enabled hosts selected for this job.")
    inventory = build_inventory(hosts, job.target_groups.all(), private_data_dir / "keys")

    override = dict(job.connection_override)
    if override.get("loona_private_key"):
        # A one-off key (a project's bootstrap key) rather than a password:
        # written next to the other keys, shredded with them.
        key_path = private_data_dir / "keys" / "one_off"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(override.pop("loona_private_key").rstrip("\n") + "\n")
        os.chmod(key_path, 0o600)
        override["ansible_ssh_private_key_file"] = str(key_path)
    if override:
        for name, variables in inventory["all"]["hosts"].items():
            inventory["all"]["hosts"][name] = apply_connection_override(variables, override)
    return inventory


def _secrets(job: Job, inventory: dict, hosts_by_name: dict, private_data_dir: Path) -> tuple[list, Masker]:
    """Put the run's secrets and Vault passwords in place.

    Returns the extra ansible-playbook arguments and the masker that keeps
    every value handed out - secrets, Vault and login passwords - out of the
    log.  Key management and other system runs get no secrets: they run
    Loona's own playbooks, which need none.
    """
    from secretstore import resolve

    hosts = inventory["all"]["hosts"]
    known = []
    if not job.is_system:
        delivery = resolve.for_run(
            [hosts_by_name[name] for name in hosts if name in hosts_by_name], job.ansible_project
        )
        for name, variables in hosts.items():
            # A secret wins over a plain inventory variable of the same name,
            # but not over the login the host's credential (or this job's
            # one-off login) sets: a group-wide ansible_become_password
            # secret fills in only where the credential has none.
            own_login = {k: variables[k] for k in AUTH_VARS if k in variables}
            variables.update(delivery.per_host.get(name, {}))
            variables.update(own_login)
        if delivery.common:
            inventory["all"]["vars"] = dict(delivery.common)
        job.secret_names = delivery.used
        known += delivery.values

    for variables in hosts.values():
        for key in ("ansible_password", "ansible_become_password"):
            if isinstance(variables.get(key), str):
                known.append(variables[key])
                # A password is a password, not a template.
                variables[key] = resolve.Unsafe(variables[key])

    args = []
    if job.extra_vars:
        # Not ansible-runner's extravars either: there a template in a value
        # would be evaluated on this server, for anyone allowed to launch.
        # Extra vars are data.
        path = private_data_dir / "env" / "extra_vars.yml"
        path.parent.mkdir(exist_ok=True)
        path.write_text(dump_inventory(resolve.as_data(job.extra_vars)))
        os.chmod(path, 0o600)
        args.append(f"-e {shlex.quote('@' + str(path))}")
    secret_vars = job.secret_vars
    if secret_vars:
        # Kept out of ansible-runner's own extravars file so they can be
        # marked !unsafe; -e @file is read by Ansible itself.
        path = private_data_dir / "env" / "secret_vars.yml"
        path.write_text(dump_inventory(resolve.as_data(secret_vars)))
        os.chmod(path, 0o600)
        args.append(f"-e {shlex.quote('@' + str(path))}")
        known += _leaves(secret_vars)
    vault_dir = private_data_dir / "vault"
    for index, credential in enumerate(_vault_credentials(job)):
        password = credential.secret
        vault_dir.mkdir(mode=0o700, exist_ok=True)
        path = vault_dir / f"vault_{index}"
        path.write_text(password + "\n")
        os.chmod(path, 0o600)
        args.append(f"--vault-id {shlex.quote((credential.vault_id or 'default') + '@' + str(path))}")
        known.append(password)
    return args, Masker(known)


def _leaves(value) -> list:
    if isinstance(value, dict):
        return [leaf for v in value.values() for leaf in _leaves(v)]
    if isinstance(value, list):
        return [leaf for v in value for leaf in _leaves(v)]
    return [str(value)] if value is not None else []


def _vault_credentials(job: Job) -> list:
    found = {}
    if job.ansible_project_id:
        for credential in job.ansible_project.vault_credentials.all():
            found[credential.pk] = credential
    if job.playbook_id:
        for credential in job.playbook.vault_credentials.all():
            found[credential.pk] = credential
    return [found[pk] for pk in sorted(found)]


# One event's output; a task that prints a whole file is cut, not stored whole.
MAX_EVENT_CHARS = 64_000


def clip(text: str) -> str:
    return text if len(text) <= MAX_EVENT_CHARS else text[:MAX_EVENT_CHARS] + "\n[... cut by Loona ...]"


def _record_event(job_id: int, event: dict, counters: dict):
    data = event.get("event_data") or {}
    mask = counters.get("mask") or Masker()
    stdout = clip(mask(ANSI_RE.sub("", event.get("stdout") or "")))
    name = event.get("event") or ""

    if name in NOISY_EVENTS and not stdout.strip():
        return
    if counters.get("adhoc") and data.get("host"):
        from . import adhoc

        shown = adhoc.output(name, str(data["host"]), data.get("res") or {})
        if shown is not None:
            stdout = mask(ANSI_RE.sub("", shown))

    if name == "runner_on_ok":
        # Kept even once the log itself is truncated.
        from inventory import facts

        try:
            facts.capture(job_id, data, mask)
        except Exception:  # noqa: BLE001 - facts are a by-product of the run
            log.exception("Could not store facts from job %s", job_id)

    from administration import system

    limit = system.get().max_job_events
    if limit and counters["stored"] >= limit:
        if not counters.get("truncated"):
            counters["truncated"] = True
            JobEvent.objects.create(
                job_id=job_id,
                counter=event.get("counter") or 0,
                event="loona_truncated",
                stdout=f"-- log truncated after {limit} events --",
            )
        return

    JobEvent.objects.create(
        job_id=job_id,
        counter=event.get("counter") or 0,
        uuid=(event.get("uuid") or "")[:64],
        event=name[:64],
        host=str(data.get("host") or "")[:160],
        task=mask(str(data.get("task") or ""))[:255],
        stdout=stdout,
        # ansible-runner reports an unreachable host without setting "failed";
        # for anything reading the log back it is one.
        failed=bool(
            event.get("failed") or data.get("failed") or name == "runner_on_unreachable"
        ),
        # Ansible's result sits under "res"; that is where "changed" lives.
        changed=bool(
            event.get("changed")
            or data.get("changed")
            or (data.get("res") or {}).get("changed")
        ),
        diff=mask.deep(_diff_of(name, data)),
    )
    counters["stored"] += 1


# A package manager's "prepared" diff can list hundreds of packages; the log
# row is not the place for megabytes.
MAX_DIFF_CHARS = 64 * 1024


def _diff_of(name: str, data: dict):
    """The --diff payload of a result that changed something, trimmed."""
    if name != "runner_on_ok":
        return None
    res = data.get("res") or {}
    diff = res.get("diff")
    if not diff or not res.get("changed"):
        return None
    return _trim(diff, [MAX_DIFF_CHARS])


def _trim(value, budget):
    if isinstance(value, str):
        if len(value) <= budget[0]:
            budget[0] -= len(value)
            return value
        kept = value[: max(budget[0], 0)]
        budget[0] = 0
        return kept + "\n[... diff truncated by Loona ...]\n"
    if isinstance(value, list):
        return [_trim(v, budget) for v in value]
    if isinstance(value, dict):
        return {k: _trim(v, budget) for k, v in value.items()}
    return value


def _finish(job: Job, status, return_code=None, error_message=""):
    """Record the outcome, then let the inventory act on it."""
    job.forget_connection_override()
    job.mark_finished(status, return_code=return_code, error_message=error_message)
    if not job.can_be_applied:
        # Kept only by a preview that may still be applied - see plans.apply.
        job.forget_secret_vars()
    if job.is_tofu:
        # Normally tofu unlocks the state itself; a crash or kill leaves it
        # held, and a finished run's lock protects nothing.
        from infra.state import release_locks_of

        release_locks_of(job)
    if job.catalog_request_id:
        from catalog import services as catalog

        try:
            catalog.on_job_finished(job)
        except Exception:  # noqa: BLE001
            log.exception("Could not move the catalog request of job %s on", job.pk)
    if job.drift_check_id:
        from . import drift

        try:
            drift.on_finished(job)
        except Exception:  # noqa: BLE001
            log.exception("Could not record drift for job %s", job.pk)
    from notifications import events

    events.job_finished(job)
    try:
        from inventory import provisioning

        provisioning.on_job_finished(job)
    except Exception:  # noqa: BLE001 - the run itself already succeeded or failed
        log.exception("Post-run handling of job %s failed", job.pk)
    # Last: a step waiting for new hosts needs the bootstrap above recorded.
    try:
        from workflows import engine

        engine.on_job_finished(job)
    except Exception:  # noqa: BLE001
        log.exception("Could not move the workflow of job %s on", job.pk)
    return status


def run_job(job_id: int) -> str:
    """Execute a job end to end. Returns the final status."""
    refresh_connection()
    job = Job.objects.get(pk=job_id)
    if job.canceled:
        return _finish(job, Job.CANCELED)

    # Claim the job, so that only one process ever runs it.  Celery hands a
    # task out again when the worker that took it died (acks_late); if that
    # worker had already started, replaying half a playbook is the last thing
    # wanted, so a second delivery stops here.
    me = runner_id()
    if not Job.objects.filter(pk=job_id, status=Job.PENDING, runner="").update(runner=me):
        log.warning("Job %s was already picked up; not running it twice", job_id)
        return Job.objects.get(pk=job_id).status
    job.runner = me
    if job.is_tofu:
        from infra import runner as tofu_runner

        return tofu_runner.run(job)

    counters = {"stored": 0, "adhoc": job.is_adhoc}

    try:
        private_data_dir = prepare_private_data_dir(job)
        inventory = build_job_inventory(job, private_data_dir)
        job.resolved_hosts = sorted(inventory["all"]["hosts"])
        job.save(update_fields=["resolved_hosts"])
        # Pinned SSH host keys in, and the run told to hold hosts to them.
        hosts_by_name = {h.name: h for h in Host.objects.filter(name__in=job.resolved_hosts)}
        remote = _executor_for(hosts_by_name.values())
        known_hosts = hostkeys.prepare(private_data_dir, hosts_by_name, inventory["all"]["hosts"])
        playbook_file, project_env = _prepare_playbook(job, private_data_dir, counters)
        write_envvars(private_data_dir, {**hostkeys.ansible_env(known_hosts), **project_env})
        vault_args, counters["mask"] = _secrets(job, inventory, hosts_by_name, private_data_dir)
        job.save(update_fields=["secret_names"])
        inventory_file = private_data_dir / "inventory" / "hosts.yml"
        inventory_file.parent.mkdir(exist_ok=True)
        inventory_file.write_text(dump_inventory(inventory))
    except Exception as exc:  # noqa: BLE001 - surfaced to the user verbatim
        log.exception("Job %s failed during preparation", job_id)
        job.private_data_dir = ""
        return _finish(job, Job.ERROR, error_message=str(exc))

    cmdline = list(vault_args)
    if job.check_mode:
        cmdline.append("--check")
    if job.diff_mode:
        cmdline.append("--diff")

    if remote is not None:
        from executors.remote import hand_off

        return hand_off(job, remote, private_data_dir, {
            "playbook": playbook_file,
            "inventory": str(inventory_file.relative_to(private_data_dir)),
            "extravars": {},
            "limit": job.limit or "",
            "tags": job.tags or "",
            "skip_tags": job.skip_tags or "",
            "forks": job.forks or 5,
            "verbosity": job.verbosity or 0,
            "cmdline": " ".join(cmdline),
            "known_hosts": str(known_hosts.relative_to(private_data_dir)),
            "mask": counters["mask"].values,
        })

    job.private_data_dir = str(private_data_dir)
    job.save(update_fields=["private_data_dir"])
    job.mark_running(runner=runner_id())

    def event_handler(event):
        try:
            _record_event(job_id, event, counters)
        except Exception:  # noqa: BLE001 - a bad event must not kill the run
            log.exception("Could not store event for job %s", job_id)
        return True

    def cancel_callback():
        refresh_connection()
        return Job.objects.filter(pk=job_id, canceled=True).exists()

    try:
        runner = ansible_runner.run(
            private_data_dir=str(private_data_dir),
            playbook=playbook_file,
            inventory=str(inventory_file),
            extravars={},
            limit=job.limit or None,
            tags=job.tags or None,
            skip_tags=job.skip_tags or None,
            forks=job.forks or 5,
            verbosity=job.verbosity or None,
            cmdline=" ".join(cmdline) or None,
            event_handler=event_handler,
            cancel_callback=cancel_callback,
            quiet=True,
        )
        # Read from the artifacts on disk, so before they are thrown away.
        stats = runner.stats or {}
        hostkeys.learn(known_hosts, hosts_by_name, inventory["all"]["hosts"])
    except Exception as exc:  # noqa: BLE001
        log.exception("Job %s crashed", job_id)
        job.refresh_from_db()
        return _finish(job, Job.ERROR, error_message=counters["mask"](str(exc)))
    finally:
        # Cancelling stops ansible-playbook itself, but the fork that was in
        # the middle of a task and its ssh carry on by themselves; and after
        # any run the ssh connection masters stay for a minute, logged in.
        # Nothing of a finished run is to stay behind.
        _kill_leftovers(private_data_dir)
        _discard_run_dir(private_data_dir)

    job.refresh_from_db()
    job.stats = stats
    job.save(update_fields=["stats"])

    status = {
        "successful": Job.SUCCESSFUL,
        "failed": Job.FAILED,
        "canceled": Job.CANCELED,
        "timeout": Job.ERROR,
    }.get(runner.status, Job.ERROR)
    if job.canceled:
        status = Job.CANCELED

    return _finish(job, status, return_code=runner.rc)


def _executor_for(hosts):
    """The remote executor these hosts are behind; None to run here."""
    from executors import routing

    try:
        return routing.executor_for_hosts(hosts)
    except routing.Conflict as exc:
        raise ValueError(str(exc)) from exc


def _discard_run_dir(private_data_dir: Path):
    """Remove the run's scratch directory once the playbook is done.

    It holds the inventory with every connection variable - passwords
    included - in clear text, plus the private keys.  The events are already
    in the database, so nothing in there is worth keeping.
    """
    try:
        if private_data_dir.exists():
            shutil.rmtree(private_data_dir)
    except OSError:
        log.warning("Could not remove job directory %s", private_data_dir)


def runner_id() -> str:
    """host:pid:started - who is driving a run.

    The start time tells this process from a later one with the same pid.
    In a container that is the usual case, not a rare one: a restarted worker
    hands out the same few pids all over again.
    """
    return f"{socket.gethostname()}:{os.getpid()}:{_started(os.getpid())}"


def _started(pid: int) -> str:
    """When the process started, in clock ticks since boot; "" if unknown."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return ""
    # The command name sits in brackets and may itself hold spaces.
    return stat.rpartition(")")[2].split()[19]


def _runner_parts(runner: str) -> tuple[str, str, str]:
    parts = runner.split(":")
    if len(parts) >= 3 and parts[-2].isdigit():
        return ":".join(parts[:-2]), parts[-2], parts[-1]
    return ":".join(parts[:-1]), parts[-1], ""


def _process_gone(runner: str, answering: set | None = None) -> bool:
    """True only when the runner provably is not alive any more.

    A runner on this machine is looked up directly.  One on another machine
    can only be judged by whether its worker still answers, which the caller
    finds out (see :func:`_answering_workers`) and passes in; without that
    it is left alone.
    """
    host, pid, started = _runner_parts(runner)
    if not pid.isdigit():
        return False
    if host != socket.gethostname():
        return answering is not None and host not in answering
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    # Alive - but is it the same process, or a newer one that got its pid?
    return bool(started) and _started(int(pid)) not in ("", started)


def _answering_workers() -> set | None:
    """Host names of the Celery workers alive right now; None if unknown.

    A worker that does not answer the first time is asked once more, slowly:
    calling a busy worker dead would close a run that is still going.
    """
    if settings.LOONA_RUNNER_MODE != "celery":
        return None
    from loona.celery import app

    found = set()
    try:
        for timeout in (2, 6):
            replies = app.control.inspect(timeout=timeout).ping() or {}
            found |= {name.rpartition("@")[2] for name in replies}
    except Exception:  # noqa: BLE001 - no broker, no verdict
        log.warning("Could not ask the workers who is alive", exc_info=True)
        return None
    return found


DEAD_RUNNER_MESSAGE = (
    "The process running this job stopped before the job finished - a worker "
    "restart or crash. It may have been cut off part way through, so check the "
    "hosts before running it again."
)


def reap_dead_jobs(jobs=None, ask_workers: bool = False) -> int:
    """Close out running jobs whose process has died.

    They are not retried: a playbook cut off half way is not safe to replay
    blindly.  Returns how many were closed.

    ask_workers also settles runs claimed on another machine - a worker
    container that was replaced comes back under a new name, and nobody
    would ever speak for the old one.  It costs seconds, so it is for the
    worker's own start and the scheduler's tick, not for page views.
    """
    from executors import remote

    live = (Job.PENDING, Job.RUNNING)
    jobs = Job.objects.all() if jobs is None else jobs
    # A remote executor's runs are judged by when its agent last reported.
    reaped = remote.reap(jobs)
    # A pending job with a runner was claimed, then its process died while
    # still preparing the run.
    candidates = list(jobs.filter(status__in=live).exclude(runner="").exclude(runner__startswith="executor"))
    answering = None
    if ask_workers and any(_runner_parts(j.runner)[0] != socket.gethostname() for j in candidates):
        answering = _answering_workers()
    for job in candidates:
        if not _process_gone(job.runner, answering):
            continue
        if job.private_data_dir:
            killed = _kill_leftovers(Path(job.private_data_dir))
            if killed:
                log.warning("Stopped %s process(es) job %s left behind", killed, job.pk)
            _discard_run_dir(Path(job.private_data_dir))
        _finish(job, Job.ERROR, error_message=DEAD_RUNNER_MESSAGE)
        log.warning("Job %s was left running by %s, which is gone", job.pk, job.runner)
        reaped += 1
    return reaped


def dispatch(job: Job):
    """Hand the job to Celery, or to a thread when no broker is configured."""
    if settings.LOONA_RUNNER_MODE == "celery":
        from .tasks import run_job_task

        result = run_job_task.delay(job.pk)
        job.task_id = result.id
        job.save(update_fields=["task_id"])
        return

    thread = threading.Thread(target=_run_in_thread, args=(job.pk,), daemon=True)
    thread.start()


def _run_in_thread(job_id: int):
    try:
        run_job(job_id)
    except Exception:  # noqa: BLE001
        log.exception("Background job %s died", job_id)
    finally:
        refresh_connection()
