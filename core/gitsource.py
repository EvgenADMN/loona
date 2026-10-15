# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Checking out a Git repository for a run, pinned to one commit.

Shared by OpenTofu projects and Ansible projects: a preview records the
commit it saw, and applying it checks out that same commit, even if the
branch has moved on since.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

from inventory.models import Credential

# The only ways git may fetch.  Its ext:: transport runs a command and file://
# reads the Loona server's own disk, and a repository URL is typed by people
# who must not be able to do either.  GIT_ALLOW_PROTOCOL overrides any
# protocol.*.allow in git's config.  The tests widen this to file.
PROTOCOLS = "https:http:ssh:git"

# https://host/..., ssh://..., git://..., or the scp form [user@]host:path.
URL = re.compile(r"^(?:(?:https?|ssh|git)://(?:[^\s/@]+@)?[A-Za-z0-9\[][^\s/@]*(?:[/:]|$)|(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*:(?!:|//)\S)")


class GitError(Exception):
    pass


def protocols() -> str:
    return getattr(settings, "LOONA_GIT_PROTOCOLS", PROTOCOLS)


def check_url(url: str) -> str:
    """A repository URL git may be given; raises ValidationError otherwise."""
    url = (url or "").strip()
    if url.startswith("file://") and "file" in protocols().split(":"):
        return url
    if url and (url.startswith("-") or not URL.match(url)):
        raise ValidationError(_("Give an https://, ssh:// or git@host:path address of the repository."))
    return url


def check_ref(ref: str) -> str:
    """A branch, tag or commit; never something git would take for an option."""
    ref = (ref or "").strip()
    if ref.startswith("-") or any(c.isspace() for c in ref):
        raise ValidationError(_("Give a branch, tag or commit name."))
    return ref


def environment(credential, workdir: Path, base: dict | None = None) -> dict:
    """Env for git: never prompts, and logs in with the credential if any.

    Secrets reach git through files and variables in the run's own directory,
    never on a command line.
    """
    env = dict(base or {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(workdir)})
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ALLOW_PROTOCOL"] = protocols()
    env["GIT_PROTOCOL_FROM_USER"] = "0"
    if credential is None:
        return env
    if credential.kind == Credential.KIND_SSH_KEY:
        key = workdir / "git_key"
        key.write_text(credential.secret.rstrip("\n") + "\n")
        os.chmod(key, 0o600)
        env["GIT_SSH_COMMAND"] = (
            f"ssh -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new "
            f"-o UserKnownHostsFile={workdir / 'known_hosts'}"
        )
    else:
        askpass = workdir / "git_askpass"
        askpass.write_text(
            '#!/bin/sh\ncase "$1" in\n  Username*) echo "$LOONA_GIT_USERNAME" ;;\n'
            '  *) echo "$LOONA_GIT_PASSWORD" ;;\nesac\n'
        )
        os.chmod(askpass, 0o700)
        env["GIT_ASKPASS"] = str(askpass)
        env["LOONA_GIT_USERNAME"] = credential.username
        env["LOONA_GIT_PASSWORD"] = credential.secret
    return env


def checkout(url: str, dest: Path, env: dict, ref: str = "", revision: str = "") -> str:
    """Clone url into dest at revision (a commit) or ref; return the commit."""
    try:
        check_url(url)
        check_ref(ref)
        check_ref(revision)
    except ValidationError as exc:
        raise GitError(" ".join(exc.messages)) from exc
    _git(["clone", "--quiet", "--no-checkout", "--", url, str(dest)], env)
    wanted = revision or resolve(dest, ref or "HEAD", env)
    _git(["-C", str(dest), "checkout", "--quiet", "--detach", wanted], env)
    return wanted


def ls_remote(url: str, ref: str, env: dict, timeout: int = 60) -> subprocess.CompletedProcess:
    """git ls-remote, with url and ref checked first; raises GitError if they are not usable."""
    try:
        check_url(url)
        check_ref(ref)
    except ValidationError as exc:
        raise GitError(" ".join(exc.messages)) from exc
    return subprocess.run(["git", "ls-remote", "--", url, ref], env=env, capture_output=True,
                          text=True, timeout=timeout)


def resolve(repo: Path, ref: str, env: dict) -> str:
    for candidate in (f"origin/{ref}", ref):
        done = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}"],
            env=env, capture_output=True, text=True,
        )
        if done.returncode == 0:
            return done.stdout.strip()
    raise GitError(f"The repository has no branch, tag or commit called {ref!r}.")


def subfolder(repo: Path, path: str) -> Path:
    """A folder inside the checkout; refuses anything that leaves it."""
    folder = (repo / path).resolve() if path else repo.resolve()
    if repo.resolve() not in (folder, *folder.parents) or not folder.is_dir():
        raise GitError(f"There is no folder {path!r} in the repository.")
    return folder


def _git(args, env):
    try:
        done = subprocess.run(["git", *args], env=env, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(f"git {args[0]} did not run: {exc}") from exc
    if done.returncode != 0:
        raise GitError("git " + args[0] + " failed: " + (done.stderr or done.stdout).strip()[-800:])
