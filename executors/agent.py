# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The remote executor agent: runs Loona's playbooks where Loona cannot reach.

    LOONA_URL=https://loona.example.com LOONA_EXECUTOR_TOKEN=lxe_... \\
        python -m executors.agent

or, from the image, ``docker run ... loona:latest executor``.  It connects
out to Loona, asks for runs of its executor, carries them out with
ansible-runner and reports back as they go.  Nothing connects in to it.

No database, no Django: what a run needs - inventory, keys, playbook,
roles, secrets - arrives prepared in one bundle and is deleted with the run.

Settings (environment, or the matching --options):

    LOONA_URL                  Loona's address as the agent reaches it.
    LOONA_EXECUTOR_TOKEN       The executor's token (Administration - Executors).
    LOONA_EXECUTOR_NAME        This agent's name; the host name by default.
    LOONA_EXECUTOR_SLOTS       How many runs at once (2).
    LOONA_EXECUTOR_WORKDIR     Where runs are unpacked (/var/lib/loona/executor).
    LOONA_EXECUTOR_POLL        Seconds between asking for work (3).
    LOONA_CA_FILE              CA bundle to check Loona's certificate with.
    LOONA_EXECUTOR_ALLOW_HTTP  "true" to talk plain http to anything but
                               localhost - the bundles carry secrets.
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import logging
import os
import queue
import shutil
import signal
import socket
import ssl
import subprocess
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from core.masking import Masker
from core.processes import kill_leftovers
from core.version import __version__

log = logging.getLogger("loona.executor")

# Must match executors.remote.PROTOCOL (a test holds them together).
PROTOCOL = 1
SPEC_FILE = "loona.json"
# Files in the bundle that name paths of the run directory, as it was laid
# out in Loona; they are pointed at where it is unpacked here.
REWRITTEN = ("env", "inventory")

# What goes up in one request, and how big one event may be.  Bigger
# results are cut down rather than refused (Django's default limit is 2.5 MB).
MAX_BATCH_BYTES = 1_000_000
MAX_EVENT_BYTES = 400_000
MAX_STDOUT_CHARS = 64_000
# Report at least this often while a run goes on - Loona counts silence.
HEARTBEAT_SECONDS = 10
FLUSH_SECONDS = 1.0
# How long to keep trying to report a finished run before giving up.
FINISH_PATIENCE_SECONDS = 15 * 60

RUNNER_STATUS = {"successful": "successful", "failed": "failed", "canceled": "canceled", "timeout": "error"}


class Refused(Exception):
    """Loona said no for good - a wrong token or another protocol."""


class Gone(Exception):
    """Loona says the run is not ours any more."""


class Unreachable(Exception):
    """No answer this time; worth trying again."""


# -- talking to Loona -----------------------------------------------------------------


class Client:
    def __init__(self, url: str, token: str, name: str, slots: int, ca_file: str = "",
                 allow_http: bool = False):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise SystemExit(f"LOONA_URL must be an http(s):// address, not {url!r}.")
        local = parts.hostname in ("localhost", "127.0.0.1", "::1")
        if parts.scheme == "http" and not (local or allow_http):
            raise SystemExit(
                "LOONA_URL is plain http: the runs carry passwords and keys. Use https, "
                "or set LOONA_EXECUTOR_ALLOW_HTTP=true if the path is otherwise protected."
            )
        self.root = url.rstrip("/")
        self.base = self.root + "/api/executor/v1/"
        self.token = token
        self.name = name
        self.slots = slots
        self.ca_file = ca_file
        self.context = ssl.create_default_context(cafile=ca_file or None)
        self.version = _ansible_version()

    def post(self, path: str, payload: dict, timeout: float = 60):
        """(status, answer) - raises Refused, Gone or Unreachable."""
        body = json.dumps({"agent": self.name, "version": self.version, "slots": self.slots, **payload})
        request = urllib.request.Request(
            self.base + path,
            data=body.encode(),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "X-Loona-Executor-Protocol": str(PROTOCOL),
                "User-Agent": f"loona-executor/{__version__}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=self.context) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            message = _error_text(exc)
            if exc.code in (401, 403, 426):
                raise Refused(message) from exc
            if exc.code == 409:
                raise Gone(message) from exc
            raise Unreachable(f"HTTP {exc.code}: {message}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise Unreachable(str(getattr(exc, "reason", exc))) from exc


def _error_text(exc) -> str:
    try:
        return json.loads(exc.read()).get("error") or str(exc)
    except Exception:  # noqa: BLE001
        return str(exc)


def _ansible_version() -> str:
    try:
        from ansible.release import __version__

        return f"ansible-core {__version__}"[:40]
    except ImportError:
        return ""


# -- the bundle -----------------------------------------------------------------------


def unpack(bundle: bytes, target: Path) -> dict:
    """Lay the run out in target. Returns its spec."""
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    os.chmod(target, 0o700)
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as tar:
        # "data" refuses absolute paths, links out of the tree and devices.
        tar.extractall(target, filter="data")
    spec_file = target / SPEC_FILE
    spec = json.loads(spec_file.read_text())
    spec_file.unlink()
    base = spec.get("base") or ""
    if base and base != str(target):
        for folder in REWRITTEN:
            for path in (target / folder).rglob("*") if (target / folder).is_dir() else []:
                if path.is_file() and not path.is_symlink():
                    text = path.read_text(errors="surrogateescape")
                    if base in text:
                        path.write_text(text.replace(base, str(target)), errors="surrogateescape")
        spec["cmdline"] = (spec.get("cmdline") or "").replace(base, str(target))
    return spec


# -- one run ----------------------------------------------------------------------------


class Reporter:
    """Sends a run's events up in batches, and hears back whether to stop."""

    def __init__(self, client: Client, job_id: int, mask: Masker):
        self.client, self.job_id, self.mask = client, job_id, mask
        self.queue: queue.Queue = queue.Queue()
        self.pending: list = []
        self.cancel = threading.Event()
        self.gone = threading.Event()
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._loop, name=f"report-{job_id}", daemon=True)
        self.last_sent = 0.0
        self.thread.start()

    def add(self, event: dict) -> bool:
        self.queue.put(_shrink(self.mask.deep(event)))
        return True

    def should_stop(self) -> bool:
        return self.cancel.is_set() or self.gone.is_set()

    def close(self):
        """Send what is left. Raises Gone."""
        self.done.set()
        self.thread.join()
        deadline = time.monotonic() + FINISH_PATIENCE_SECONDS
        while self.pending or not self.queue.empty():
            if self.gone.is_set():
                break
            if not self._flush() and time.monotonic() > deadline:
                log.error("Run %s: giving up on %s log events", self.job_id, len(self.pending))
                break
            if self.pending:
                time.sleep(5)
        if self.gone.is_set():
            raise Gone(f"Loona closed run {self.job_id} while it was going.")

    def _loop(self):
        while not self.done.is_set():
            self.done.wait(FLUSH_SECONDS)
            if self.done.is_set():
                break
            due = time.monotonic() - self.last_sent >= HEARTBEAT_SECONDS
            if not self.queue.empty() or self.pending or due:
                self._flush()

    def _flush(self) -> bool:
        while True:
            try:
                self.pending.append(self.queue.get_nowait())
            except queue.Empty:
                break
        batch, size = [], 0
        for event in self.pending:
            length = len(json.dumps(event))
            if batch and size + length > MAX_BATCH_BYTES:
                break
            batch.append(event)
            size += length
        try:
            _, answer = self.client.post(f"jobs/{self.job_id}/events/", {"events": batch})
        except Gone:
            self.gone.set()
            return False
        except (Unreachable, Refused) as exc:
            log.warning("Run %s: could not report (%s); will retry", self.job_id, exc)
            return False
        del self.pending[: len(batch)]
        self.last_sent = time.monotonic()
        if answer and answer.get("cancel"):
            self.cancel.set()
        return True


def _shrink(event: dict) -> dict:
    if len(json.dumps(event)) <= MAX_EVENT_BYTES:
        return event
    event = dict(event)
    data = dict(event.get("event_data") or {})
    if "res" in data:
        data["res"] = {"msg": "(The result was too large to send from the remote executor.)",
                       "changed": bool((data.get("res") or {}).get("changed"))}
    event["event_data"] = data
    stdout = event.get("stdout") or ""
    if len(stdout) > MAX_STDOUT_CHARS:
        event["stdout"] = stdout[:MAX_STDOUT_CHARS] + "\n[... cut by the remote executor ...]"
    return event


def carry_out(client: Client, workdir: Path, job_id: int, bundle: bytes):
    run_dir = workdir / f"job_{job_id}"
    reporter = None
    outcome = {"status": "error", "rc": None, "stats": {}, "known_hosts": "", "error": ""}
    mask = Masker()
    try:
        spec = unpack(bundle, run_dir)
        del bundle
        mask = Masker(spec.get("mask") or [])
        reporter = Reporter(client, job_id, mask)
        if spec.get("kind") == "tofu":
            log.info("Run %s: OpenTofu %s", job_id, " / ".join(step[0] for step in spec["steps"]))
            run_tofu(client, workdir, run_dir, spec, reporter, outcome)
        else:
            log.info("Run %s: starting %s", job_id, spec.get("playbook"))
            run_playbook(run_dir, spec, reporter, outcome)
    except Exception as exc:  # noqa: BLE001 - reported to Loona
        log.exception("Run %s crashed", job_id)
        outcome["error"] = mask(f"The remote executor could not carry out the run: {exc}")
    finally:
        kill_leftovers(run_dir)
        shutil.rmtree(run_dir, ignore_errors=True)

    try:
        if reporter is not None:
            reporter.close()
            if reporter.cancel.is_set():
                outcome["status"] = "canceled"
        _report_finish(client, job_id, outcome)
        log.info("Run %s: %s", job_id, outcome["status"])
    except Gone as exc:
        log.warning("Run %s: %s", job_id, exc)


def run_playbook(run_dir: Path, spec: dict, reporter: Reporter, outcome: dict):
    import ansible_runner

    runner = ansible_runner.run(
        private_data_dir=str(run_dir),
        playbook=spec["playbook"],
        inventory=str(run_dir / spec["inventory"]),
        extravars=spec.get("extravars") or {},
        limit=spec.get("limit") or None,
        tags=spec.get("tags") or None,
        skip_tags=spec.get("skip_tags") or None,
        forks=spec.get("forks") or 5,
        verbosity=spec.get("verbosity") or None,
        cmdline=spec.get("cmdline") or None,
        event_handler=reporter.add,
        cancel_callback=reporter.should_stop,
        quiet=True,
    )
    outcome["stats"] = runner.stats or {}
    outcome["rc"] = runner.rc
    outcome["status"] = RUNNER_STATUS.get(runner.status, "error")
    known = run_dir / (spec.get("known_hosts") or "known_hosts")
    if known.is_file():
        outcome["known_hosts"] = known.read_text()


# -- OpenTofu ---------------------------------------------------------------------------

TOFU_BINARY = os.environ.get("LOONA_TOFU_BINARY", "tofu")
# Between asking tofu to stop (it finishes the resource in hand, writes the
# state and releases the lock) and killing it.
CANCEL_GRACE_SECONDS = 30
PASSED_ON = ("PATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
             "http_proxy", "https_proxy", "no_proxy", "TF_CLI_CONFIG_FILE")


class TofuFailed(Exception):
    pass


def ca_bundle(ca_file: str, workdir: Path) -> str:
    """The system's CA certificates plus LOONA_CA_FILE, in one file for tofu."""
    paths = ssl.get_default_verify_paths()
    parts = []
    for path in (paths.cafile, paths.openssl_cafile, "/etc/ssl/certs/ca-certificates.crt"):
        if path and Path(path).is_file():
            parts.append(Path(path).read_text())
            break
    parts.append(Path(ca_file).read_text())
    bundle = workdir / "ca-bundle.pem"
    bundle.write_text("\n".join(parts))
    return str(bundle)


def run_tofu(client: Client, workdir: Path, run_dir: Path, spec: dict, reporter: Reporter, outcome: dict):
    """The commands Loona listed, in its configuration; what it asked for back."""
    config = run_dir / spec["config"]
    cache = workdir / "tofu-plugins"
    cache.mkdir(parents=True, exist_ok=True)
    env = {key: os.environ[key] for key in PASSED_ON if key in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.update({
        "HOME": str(run_dir), "LANG": "C.UTF-8", "TF_IN_AUTOMATION": "1", "TF_INPUT": "0",
        "TF_PLUGIN_CACHE_DIR": str(cache), "TF_DATA_DIR": str(run_dir / ".tofu"),
    })
    if client.ca_file and "SSL_CERT_FILE" not in env:
        # tofu reaches Loona's state backend at LOONA_URL itself, so it must
        # trust the same CA the agent does - and the public ones, for providers.
        env["SSL_CERT_FILE"] = ca_bundle(client.ca_file, workdir)
    for key, value in (spec.get("env") or {}).items():
        env[key] = str(value).replace("{LOONA_URL}", client.root)
    counter = [int(spec.get("counter") or 0)]
    result = {}
    try:
        for name, args, ok in spec["steps"]:
            rc = _tofu_step(config, env, name, args, ok, reporter, counter)
            if reporter.should_stop():
                outcome["status"] = "canceled"
                return
            if name == "plan":
                result["plan_rc"] = rc
        for key, what in (spec.get("collect") or {}).items():
            if isinstance(what, list):
                result[key] = _tofu_json(config, env, what)
            else:
                result[key] = base64.b64encode((config / what).read_bytes()).decode()
    except TofuFailed as exc:
        outcome.update(status="failed", rc=1, error=reporter.mask(str(exc)))
        return
    outcome.update(status="successful", rc=0, tofu=result)


def _tofu_step(config, env, name, args, ok, reporter, counter) -> int:
    def line(text):
        counter[0] += 1
        reporter.add({"event": "tofu_output", "counter": counter[0], "uuid": f"tofu-{counter[0]}",
                      "stdout": text, "failed": text.startswith(("Error:", "│ Error:")),
                      "event_data": {"task": name}})

    line(f"$ tofu {' '.join(args)}")
    try:
        process = subprocess.Popen(
            [TOFU_BINARY, f"-chdir={config}", *args], env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, errors="replace",
            start_new_session=True,
        )
    except OSError as exc:
        raise TofuFailed(f"Could not start OpenTofu ({TOFU_BINARY}): {exc}") from exc
    lines: queue.Queue = queue.Queue()
    reader = threading.Thread(target=_pump, args=(process.stdout, lines), daemon=True)
    reader.start()
    asked_to_stop = None
    while True:
        try:
            text = lines.get(timeout=0.5)
        except queue.Empty:
            text = ""
        if text is None:
            break
        if text:
            line(text.rstrip("\n"))
        now = time.monotonic()
        if asked_to_stop is None and reporter.should_stop():
            os.killpg(process.pid, signal.SIGINT)
            asked_to_stop = now
            line("Cancel requested - asking OpenTofu to stop.")
        elif asked_to_stop is not None and now - asked_to_stop > CANCEL_GRACE_SECONDS:
            os.killpg(process.pid, signal.SIGKILL)
    rc = process.wait()
    if rc not in ok and not reporter.should_stop():
        raise TofuFailed(f"tofu {args[0]} failed (exit {rc}); see the log.")
    return rc


def _pump(stream, lines):
    for text in stream:
        lines.put(text)
    lines.put(None)


def _tofu_json(config, env, args):
    done = subprocess.run([TOFU_BINARY, f"-chdir={config}", *args], env=env, capture_output=True,
                          text=True, timeout=300)
    if done.returncode != 0:
        raise TofuFailed(f"tofu {args[0]} failed: {done.stderr.strip()[-800:]}")
    return json.loads(done.stdout or "{}")


def _report_finish(client, job_id, outcome):
    deadline = time.monotonic() + FINISH_PATIENCE_SECONDS
    while True:
        try:
            client.post(f"jobs/{job_id}/finish/", outcome)
            return
        except (Unreachable, Refused) as exc:
            if time.monotonic() > deadline:
                log.error("Run %s: could not report its end (%s); Loona will mark it as lost", job_id, exc)
                return
            log.warning("Run %s: could not report its end (%s); retrying", job_id, exc)
            time.sleep(10)


# -- the loop ---------------------------------------------------------------------------


class Agent:
    def __init__(self, client: Client, workdir: Path, poll: float):
        self.client, self.workdir, self.poll = client, workdir, poll
        self.running: dict[int, threading.Thread] = {}
        self.stopping = threading.Event()

    def serve(self):
        self.workdir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.workdir, 0o700)
        self._clear_leftovers()
        log.info("Agent %s (Loona %s) working for %s with %s slot(s)",
                 self.client.name, __version__, self.client.base, self.client.slots)
        failures = 0
        while not self.stopping.is_set():
            self.running = {pk: t for pk, t in self.running.items() if t.is_alive()}
            if len(self.running) >= self.client.slots:
                self.stopping.wait(self.poll)
                continue
            try:
                status, answer = self.client.post("claim/", {"running": sorted(self.running)})
                failures = 0
            except Refused as exc:
                log.error("Loona refused this agent: %s", exc)
                self.stopping.wait(60)
                continue
            except (Unreachable, Gone) as exc:
                failures += 1
                wait = min(self.poll * 2 ** min(failures, 5), 60)
                log.warning("Loona is not answering (%s); trying again in %ss", exc, int(wait))
                self.stopping.wait(wait)
                continue
            if status == 200 and answer and answer.get("job"):
                job_id = int(answer["job"])
                thread = threading.Thread(
                    target=carry_out,
                    args=(self.client, self.workdir, job_id, base64.b64decode(answer["bundle"])),
                    name=f"run-{job_id}",
                    daemon=True,
                )
                self.running[job_id] = thread
                thread.start()
                continue  # there may be more waiting
            self.stopping.wait(self.poll)
        for thread in self.running.values():
            thread.join()

    def _clear_leftovers(self):
        # Runs a previous agent here was cut off in the middle of: Loona has
        # or will mark them as lost; what is left of them must not stay.
        for entry in self.workdir.glob("job_*"):
            kill_leftovers(entry)
            shutil.rmtree(entry, ignore_errors=True)


def main(argv=None):
    env = os.environ.get
    parser = argparse.ArgumentParser(prog="python -m executors.agent", description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", default=env("LOONA_URL", ""))
    parser.add_argument("--token", default=env("LOONA_EXECUTOR_TOKEN", ""))
    parser.add_argument("--name", default=env("LOONA_EXECUTOR_NAME", "") or socket.gethostname())
    parser.add_argument("--slots", type=int, default=int(env("LOONA_EXECUTOR_SLOTS", "2")))
    parser.add_argument("--workdir", default=env("LOONA_EXECUTOR_WORKDIR", "/var/lib/loona/executor"))
    parser.add_argument("--poll", type=float, default=float(env("LOONA_EXECUTOR_POLL", "3")))
    parser.add_argument("--ca-file", default=env("LOONA_CA_FILE", ""))
    parser.add_argument("--allow-http", action="store_true",
                        default=env("LOONA_EXECUTOR_ALLOW_HTTP", "").lower() in ("1", "true", "yes"))
    args = parser.parse_args(argv)
    logging.basicConfig(level=env("LOONA_LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not args.url or not args.token:
        parser.error("set LOONA_URL and LOONA_EXECUTOR_TOKEN")
    client = Client(args.url, args.token, args.name, max(1, args.slots), args.ca_file, args.allow_http)
    agent = Agent(client, Path(args.workdir), max(0.5, args.poll))

    def stop(signum, frame):
        log.info("Stopping: no new runs; waiting for the ones going on")
        agent.stopping.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    agent.serve()


if __name__ == "__main__":
    main()
