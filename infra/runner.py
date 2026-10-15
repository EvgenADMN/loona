# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Run OpenTofu for a job: fetch the configuration, init, plan or apply.

A plan job records what it was made from (``tofu_revision``, plus the files
themselves for a Loona-kept project) and keeps the saved plan, encrypted.
An apply job fetches exactly that revision again and applies that saved plan;
OpenTofu itself refuses if the state moved on in between.

Every command runs with ``-chdir=<job dir>``, so the reaper in
runs.executor recognises a tofu process a dead worker left behind.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

from django.conf import settings
from django.utils.translation import gettext_noop

from core import gitsource
from core.crypto import SecretUnreadable
from core.masking import Masker
from runs.models import Job, JobEvent

from . import state as state_backend

log = logging.getLogger(__name__)

PLAN_FILE = "loona.tfplan"
BACKEND_FILE = "_loona_backend.tf"
# A root module that names its own backend (or HCP/TACC "cloud") keeps it.
OWN_BACKEND = re.compile(r"^\s*(backend\s+\"|cloud\s*\{)", re.MULTILINE)
# Grace between asking tofu to stop (it releases its lock) and killing it.
CANCEL_GRACE_SECONDS = 30


class CannotRun(Exception):
    pass


def run(job: Job) -> str:
    """Execute a tofu job end to end. Returns the final status."""
    from runs.executor import _discard_run_dir, _finish

    project = job.tofu_project
    if project is None:
        return _finish(job, Job.ERROR, error_message="The project was deleted.")
    from executors import routing

    try:
        remote = routing.executor_for_group(project.host_group)
    except routing.Conflict as exc:
        return _finish(job, Job.ERROR, error_message=str(exc))
    workdir = Path(settings.LOONA_DATA_DIR) / f"job_{job.pk}"
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)
    os.chmod(workdir, 0o700)
    job.private_data_dir = str(workdir)
    job.save(update_fields=["private_data_dir"])
    if remote is None:
        job.mark_running(runner=job.runner)

    log_ = _Log(job)
    try:
        config = _fetch(job, project, workdir, log_)
        env = _environment(job, project, workdir, config, remote=remote is not None)
        if remote is not None:
            return _hand_off(job, remote, workdir, config, env, log_)
        if job.kind == Job.KIND_TOFU_PLAN:
            status = _plan(job, config, env, log_)
        else:
            status = _apply(job, config, env, log_)
    except CannotRun as exc:
        return _finish(job, Job.ERROR, error_message=log_.mask(str(exc)))
    except Exception as exc:  # noqa: BLE001 - surfaced to the user
        log.exception("OpenTofu job %s crashed", job.pk)
        return _finish(job, Job.ERROR, error_message=log_.mask(str(exc)))
    finally:
        _discard_run_dir(workdir)
    job.refresh_from_db()
    if job.canceled:
        status = Job.CANCELED
    return _finish(job, status, return_code=0 if status == Job.SUCCESSFUL else 1)


# -- getting the configuration ------------------------------------------------


def _fetch(job, project, workdir, log_) -> Path:
    """Put the configuration on disk; return the directory tofu runs in."""
    if project.is_git:
        return _fetch_git(job, project, workdir, log_)
    files = job.plan.tofu_files if job.plan_id else {
        f.path: f.content for f in project.files.all()
    }
    if not files:
        raise CannotRun("The project has no files yet.")
    revision = _digest(files)
    if job.plan_id and revision != job.plan.tofu_revision:
        raise CannotRun("The planned files do not match their recorded digest.")
    config = workdir / "config"
    for path, content in files.items():
        target = (config / path).resolve()
        if config.resolve() not in target.parents:
            raise CannotRun(f"{path} would land outside the project directory.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    job.tofu_files = files
    job.tofu_revision = revision
    job.save(update_fields=["tofu_files", "tofu_revision"])
    log_.line(f"Configuration: {len(files)} file(s) from Loona, digest {revision}")
    return config


def _digest(files: dict) -> str:
    blob = json.dumps(files, sort_keys=True, ensure_ascii=False).encode()
    return "files:" + hashlib.sha256(blob).hexdigest()[:16]


def _fetch_git(job, project, workdir, log_) -> Path:
    repo = workdir / "repo"
    env = gitsource.environment(project.git_credential, workdir, _base_env(workdir))
    try:
        wanted = gitsource.checkout(
            project.git_url, repo, env, ref=project.git_ref,
            revision=job.plan.tofu_revision if job.plan_id else "",
        )
        config = gitsource.subfolder(repo, project.git_path)
    except gitsource.GitError as exc:
        raise CannotRun(str(exc)) from exc
    job.tofu_revision = wanted
    job.save(update_fields=["tofu_revision"])
    log_.line(f"Configuration: {project.git_url} at {wanted[:12]}")
    return config


# -- the environment tofu runs in ------------------------------------------------


def _base_env(workdir) -> dict:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(workdir),
        "LANG": "C.UTF-8",
        # Module sources tofu fetches with git, too.
        "GIT_ALLOW_PROTOCOL": gitsource.protocols(),
    }
    for key in ("SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "no_proxy"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


# Where a remote executor's agent puts its own address: it reaches Loona's
# state backend the same way it reaches Loona.
AGENT_URL = "{LOONA_URL}"


def _environment(job, project, workdir, config, remote=False) -> dict:
    """What tofu runs with.  For a remote executor only the project's part:
    the agent adds PATH, HOME, caches and the like of its own machine."""
    env = {} if remote else _base_env(workdir)
    if not remote:
        cache = Path(settings.LOONA_TOFU_PLUGIN_CACHE)
        cache.mkdir(parents=True, exist_ok=True)
        env.update(
            {
                "TF_IN_AUTOMATION": "1",
                "TF_INPUT": "0",
                "TF_PLUGIN_CACHE_DIR": str(cache),
                "TF_DATA_DIR": str(workdir / ".tofu"),
            }
        )
    # For cloud-init or authorized_keys on machines the project creates; an
    # undeclared variable passed this way is simply ignored by OpenTofu.
    env["TF_VAR_loona_ssh_public_key"] = project.ensure_bootstrap_key()
    if not job.plan_id:
        # A saved plan carries its variables; only a plan is told them.
        from catalog.services import VARIABLE, requests_for

        requests = requests_for(job)
        if requests is not None:
            env[f"TF_VAR_{VARIABLE}"] = json.dumps(requests)
            job.stats = {**(job.stats or {}), "catalog": sorted(requests)}
            job.save(update_fields=["stats"])
    for variable in project.variables.all():
        name = variable.name if variable.kind == variable.KIND_ENV else f"TF_VAR_{variable.name}"
        env[name] = variable.value

    if _has_own_backend(config):
        job.stats = {**(job.stats or {}), "tofu_state": "own backend"}
    else:
        (config / BACKEND_FILE).write_text('terraform {\n  backend "http" {}\n}\n')
        address = f"{AGENT_URL if remote else settings.LOONA_INTERNAL_URL}/infra/state/{project.pk}/"
        # The password travels in the environment, not on a command line.
        env.update(
            {
                "TF_HTTP_ADDRESS": address,
                "TF_HTTP_LOCK_ADDRESS": address,
                "TF_HTTP_UNLOCK_ADDRESS": address,
                "TF_HTTP_USERNAME": state_backend.username_for(job),
                "TF_HTTP_PASSWORD": state_backend.issue_token(job),
            }
        )
    return env


def _has_own_backend(config: Path) -> bool:
    for tf in config.glob("*.tf"):
        if tf.name != BACKEND_FILE and OWN_BACKEND.search(tf.read_text(errors="replace")):
            return True
    return False


# -- the steps ---------------------------------------------------------------------


def plan_args(destroy: bool) -> list:
    args = ["plan", "-input=false", "-no-color", "-detailed-exitcode", f"-out={PLAN_FILE}"]
    return args + (["-destroy"] if destroy else [])


INIT_ARGS = ["init", "-input=false", "-no-color"]
APPLY_ARGS = ["apply", "-input=false", "-no-color", PLAN_FILE]


def _plan(job, config, env, log_) -> str:
    _tofu(job, config, env, log_, "init", INIT_ARGS)
    rc = _tofu(job, config, env, log_, "plan", plan_args(job.tofu_destroy), ok=(0, 2))
    if job_canceled(job):
        return Job.CANCELED
    shown = _tofu_json(config, env, ["show", "-json", PLAN_FILE])
    return planned(job, shown, (config / PLAN_FILE).read_bytes(), has_changes=rc == 2)


def planned(job, shown: dict, plan_file: bytes, has_changes: bool) -> str:
    """Keep what a plan produced - here or on a remote executor."""
    job.tofu_plan_file = plan_file
    job.stats = {**(job.stats or {}), "tofu": summarize_plan(shown, has_changes=has_changes)}
    job.save(update_fields=["tofu_plan_encrypted", "stats"])
    if job.workflow_node_id:
        # A plan with nothing to change is never applied, yet the steps after
        # it still need the outputs; an apply replaces these with its own.
        from workflows.engine import keep_outputs

        keep_outputs(job, (shown.get("planned_values") or {}).get("outputs") or {})
    return Job.SUCCESSFUL


def _saved_plan(job) -> bytes:
    plan = job.plan
    if plan is None or not plan.tofu_plan_encrypted:
        raise CannotRun("There is no saved plan to apply.")
    return plan.tofu_plan_file


def _apply(job, config, env, log_) -> str:
    saved = _saved_plan(job)
    _tofu(job, config, env, log_, "init", INIT_ARGS)
    (config / PLAN_FILE).write_bytes(saved)
    _tofu(job, config, env, log_, "apply", APPLY_ARGS)
    if job_canceled(job):
        return Job.CANCELED
    return applied(job, _tofu_json(config, env, ["output", "-json"]), log_)


def applied(job, outputs: dict, log_=None) -> str:
    """Act on what an apply left behind - here or on a remote executor."""
    log_ = log_ or _Log(job)
    if job.workflow_node_id:
        from workflows.engine import keep_outputs

        keep_outputs(job, outputs)
    hosts = _sync_hosts(job, outputs, log_)
    job.stats = {
        **(job.stats or {}),
        "tofu": {**job.plan.stats.get("tofu", {}), "outputs": mask_outputs(outputs), "hosts": hosts},
    }
    job.save(update_fields=["stats"])
    return Job.SUCCESSFUL


# -- on a remote executor ------------------------------------------------------------


def _hand_off(job, executor, workdir, config, env, log_) -> str:
    """Pack the configuration and the commands for an agent of the executor."""
    from executors.remote import hand_off

    if job.kind == Job.KIND_TOFU_APPLY:
        (config / PLAN_FILE).write_bytes(_saved_plan(job))
        steps = [["init", INIT_ARGS, [0]], ["apply", APPLY_ARGS, [0]]]
        collect = {"outputs": ["output", "-json"]}
    else:
        steps = [["init", INIT_ARGS, [0]], ["plan", plan_args(job.tofu_destroy), [0, 2]]]
        collect = {"show": ["show", "-json", PLAN_FILE], "plan_file": PLAN_FILE}
    return hand_off(job, executor, workdir, {
        "kind": "tofu",
        "config": str(config.relative_to(workdir)),
        "env": env,
        "steps": steps,
        "collect": collect,
        "mask": log_.mask.values,
        "counter": log_.counter,
    })


def complete_remote(job, status: str, result: dict) -> tuple[str, str]:
    """An agent finished the commands: do what a local run does after them.
    Returns (status, error)."""
    if status != Job.SUCCESSFUL:
        return status, ""
    try:
        if job.kind == Job.KIND_TOFU_PLAN:
            import base64

            return planned(job, result.get("show") or {}, base64.b64decode(result.get("plan_file") or ""),
                           has_changes=result.get("plan_rc") == 2), ""
        return applied(job, result.get("outputs") or {}), ""
    except Exception as exc:  # noqa: BLE001 - surfaced to the user
        log.exception("Could not take in the remote result of job %s", job.pk)
        return Job.ERROR, f"The executor finished, but its result could not be taken in: {exc}"


def _sync_hosts(job, outputs, log_) -> dict:
    """Make the project's hosts match loona_hosts; start bringing up new ones."""
    from . import bootstrap, lifecycle

    project = job.tofu_project
    declared = (outputs.get(lifecycle.OUTPUT_NAME) or {}).get("value")
    if declared is None and not project.hosts.exists():
        return {}
    result = lifecycle.sync(project, declared)
    for problem in result.problems:
        log_.line(f"Hosts: {problem}", step="hosts")
    for label, names in (("added", [h.name for h in result.created]),
                         ("updated", [h.name for h in result.updated]),
                         ("removed", result.removed)):
        if names:
            log_.line(f"Hosts {label}: {', '.join(names)}", step="hosts")
    for host in result.created:
        bootstrap.begin(host, project, user=job.created_by)
    return result.as_dict()


def job_canceled(job) -> bool:
    from runs.executor import refresh_connection

    refresh_connection()
    return Job.objects.filter(pk=job.pk, canceled=True).exists()


def _tofu_json(config, env, args):
    done = subprocess.run(
        [settings.LOONA_TOFU_BINARY, f"-chdir={config}", *args],
        env=env, capture_output=True, text=True, timeout=300,
    )
    if done.returncode != 0:
        raise CannotRun(f"tofu {args[0]} failed: {done.stderr.strip()[-800:]}")
    return json.loads(done.stdout or "{}")


def _tofu(job, config, env, log_, step, args, ok=(0,)) -> int:
    """Run one tofu command, streaming its output into the job log."""
    log_.line(f"$ tofu {' '.join(args)}", step=step)
    try:
        process = subprocess.Popen(
            [settings.LOONA_TOFU_BINARY, f"-chdir={config}", *args],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            errors="replace",
            start_new_session=True,
        )
    except OSError as exc:
        raise CannotRun(f"Could not start OpenTofu ({settings.LOONA_TOFU_BINARY}): {exc}")

    lines: queue.Queue = queue.Queue()
    reader = threading.Thread(target=_pump, args=(process.stdout, lines), daemon=True)
    reader.start()
    asked_to_stop = None
    last_check = 0.0
    while True:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            line = ""
        if line is None:
            break
        if line:
            log_.line(line.rstrip("\n"), step=step)
        now = time.monotonic()
        if now - last_check >= 1:
            last_check = now
            if asked_to_stop is None and job_canceled(job):
                # SIGINT is tofu's "stop cleanly": it finishes the resource in
                # hand, writes state and releases the lock.
                os.killpg(process.pid, signal.SIGINT)
                asked_to_stop = now
                log_.line("Cancel requested - asking OpenTofu to stop.", step=step)
            elif asked_to_stop is not None and now - asked_to_stop > CANCEL_GRACE_SECONDS:
                os.killpg(process.pid, signal.SIGKILL)
    rc = process.wait()
    if rc not in ok and not job_canceled(job):
        raise CannotRun(f"tofu {args[0]} failed (exit {rc}); see the log.")
    return rc


def _pump(stream, lines):
    for line in stream:
        lines.put(line)
    lines.put(None)


class _Log:
    """Writes a run's output into JobEvent rows, as the playbook runner does."""

    def __init__(self, job):
        self.job = job
        self.counter = job.events.count()
        # OpenTofu hides what the configuration marks sensitive, but not a
        # value a provider echoes back in an error, nor one in the environment.
        values = []
        for variable in job.tofu_project.variables.filter(sensitive=True) if job.tofu_project else []:
            try:
                values.append(variable.value)
            except SecretUnreadable:
                pass  # the run itself reports it
        self.mask = Masker(values)

    def line(self, text, step=""):
        self.counter += 1
        text = self.mask(text)
        JobEvent.objects.create(
            job=self.job,
            counter=self.counter,
            event="tofu_output",
            task=step,
            stdout=text,
            failed=text.startswith("Error:") or text.startswith("│ Error:"),
        )


# -- summaries, safe to keep unencrypted ---------------------------------------------

SENSITIVE = "(sensitive)"
UNKNOWN = "(known after apply)"


def summarize_plan(shown: dict, has_changes: bool) -> dict:
    """Counts and per-resource attribute changes, secrets masked."""
    counts = {"add": 0, "change": 0, "destroy": 0}
    resources = []
    for rc in shown.get("resource_changes") or []:
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        if actions in (["no-op"], ["read"]):
            continue
        if "create" in actions:
            counts["add"] += 1
        if "delete" in actions:
            counts["destroy"] += 1
        if actions == ["update"]:
            counts["change"] += 1
        resources.append(
            {
                "address": rc.get("address", ""),
                "action": _action_word(actions),
                "attributes": _attribute_changes(change),
            }
        )
    return {**counts, "has_changes": has_changes, "resources": resources}


# Shown on the plan page through |tr.
ACTION_WORDS = [gettext_noop("create"), gettext_noop("destroy"), gettext_noop("update"), gettext_noop("replace")]


def _action_word(actions) -> str:
    if actions == ["create"]:
        return "create"
    if actions == ["delete"]:
        return "destroy"
    if actions == ["update"]:
        return "update"
    if set(actions) == {"delete", "create"}:
        return "replace"
    return "/".join(actions)


def _attribute_changes(change: dict) -> list:
    before = change.get("before") or {}
    after = change.get("after") or {}
    unknown = change.get("after_unknown") or {}
    hidden_before = change.get("before_sensitive") or {}
    hidden_after = change.get("after_sensitive") or {}
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []
    rows = []
    for key in sorted(set(before) | set(after) | set(unknown if isinstance(unknown, dict) else {})):
        old, new = before.get(key), after.get(key)
        is_unknown = isinstance(unknown, dict) and unknown.get(key) is True
        if old == new and not is_unknown:
            continue
        rows.append(
            {
                "name": key,
                "before": _show(old, _is_hidden(hidden_before, key)),
                "after": UNKNOWN if is_unknown else _show(new, _is_hidden(hidden_after, key)),
            }
        )
    return rows


def _is_hidden(marks, key) -> bool:
    if marks is True:
        return True
    return isinstance(marks, dict) and bool(marks.get(key))


def _show(value, hidden) -> str | None:
    if value is None:
        return None
    if hidden:
        return SENSITIVE
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def mask_outputs(outputs: dict) -> dict:
    return {
        name: SENSITIVE if data.get("sensitive") else data.get("value")
        for name, data in (outputs or {}).items()
    }
