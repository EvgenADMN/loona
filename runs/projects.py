# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Putting an Ansible project on disk for a run, and its Galaxy requirements.

The project lands in the run's ``project/`` directory - where ansible-runner
starts ansible-playbook - so roles/, templates/, files/ and vars/ are found
the way Ansible always finds them, relative to the playbook.

``requirements.yml`` (at the top, or roles/ or collections/) is installed
with ansible-galaxy into a cache keyed by its content: the second run with
the same requirements downloads nothing.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml
from django.conf import settings
from django.utils.translation import gettext as _

from core import gitsource

INLINE_PLAYBOOK = "_loona_playbook.yml"
REQUIREMENTS = ("requirements.yml", "roles/requirements.yml", "collections/requirements.yml")


class ProjectError(Exception):
    pass


def digest(files: dict) -> str:
    blob = json.dumps(files, sort_keys=True, ensure_ascii=False).encode()
    return "files:" + hashlib.sha256(blob).hexdigest()[:16]


def materialize(job, private_data_dir: Path, log) -> Path:
    """Write the job's project into private_data_dir/project. Returns that dir.

    A preview records the revision it used; applying it (job.plan) reuses it.
    """
    project = job.ansible_project
    target = private_data_dir / "project"
    pinned = job.plan if job.plan_id else None
    if project.is_git:
        repo = private_data_dir / "repo"
        env = gitsource.environment(project.git_credential, private_data_dir)
        try:
            revision = gitsource.checkout(
                project.git_url, repo, env, ref=project.git_ref,
                revision=pinned.project_revision if pinned else "",
            )
            folder = gitsource.subfolder(repo, project.git_path)
        except gitsource.GitError as exc:
            raise ProjectError(str(exc)) from exc
        shutil.copytree(folder, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git"))
        shutil.rmtree(repo, ignore_errors=True)
        job.project_revision = revision
        log(f"Project {project.name}: {project.git_url} at {revision[:12]}")
    else:
        files = pinned.project_files if pinned else {f.path: f.content for f in project.files.all()}
        for path, content in files.items():
            dest = (target / path).resolve()
            if target.resolve() not in dest.parents:
                raise ProjectError(_('%(path)s would land outside the project directory.') % {"path": path})
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)
        job.project_files = files
        job.project_revision = digest(files)
        log(f"Project {project.name}: {len(files)} file(s), digest {job.project_revision}")
    job.save(update_fields=["project_revision", "project_files"])
    return target


def playbook_from_project(job, project_dir: Path) -> str:
    """File mode: the playbook's own YAML, from the version just checked out."""
    path = job.playbook.file_path if job.playbook else ""
    source = (project_dir / path).resolve()
    if not path or project_dir.resolve() not in source.parents or not source.is_file():
        raise ProjectError(_('The project has no playbook file %(path)s.') % {"path": repr(path)})
    return source.read_text()


def galaxy_environment(project, private_data_dir: Path) -> dict:
    """What ansible-galaxy runs with.

    A Git project's own login comes along, so roles kept in the same private
    server as the playbooks install without a second credential.
    """
    credential = project.git_credential if project.is_git else None
    return gitsource.environment(credential, private_data_dir, base={"HOME": str(private_data_dir)})


def install_requirements(project_dir: Path, env: dict, log) -> dict:
    """Galaxy roles and collections the project asks for. Returns env additions."""
    extra = {}
    roles_paths, collection_paths = [], []
    for name in REQUIREMENTS:
        file = project_dir / name
        if not file.is_file():
            continue
        content = file.read_text()
        wants_roles, wants_collections = _what(content)
        cache = _cache_for(content)
        if not (cache / "done").exists():
            log(f"Installing {name} (first time for this content)")
            _install(file, cache, wants_roles, wants_collections, env, log)
        else:
            log(f"{name}: using the cached install")
        if wants_roles:
            roles_paths.append(str(cache / "roles"))
        if wants_collections:
            collection_paths.append(str(cache / "collections"))
    if roles_paths:
        extra["ANSIBLE_ROLES_PATH"] = ":".join([str(project_dir / "roles"), *roles_paths])
    if collection_paths:
        # Ours first, then whatever the image ships with.
        extra["ANSIBLE_COLLECTIONS_PATH"] = ":".join(
            [*collection_paths, os.path.expanduser("~/.ansible/collections"),
             "/usr/share/ansible/collections"]
        )
    return extra


def _what(content) -> tuple[bool, bool]:
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ProjectError(_('requirements.yml is not valid YAML: %(exc)s') % {"exc": exc}) from exc
    if isinstance(data, list):  # the old roles-only form
        return True, False
    if isinstance(data, dict):
        return bool(data.get("roles")), bool(data.get("collections"))
    return False, False


def _cache_for(content: str) -> Path:
    key = hashlib.sha256(content.encode()).hexdigest()[:24]
    return Path(settings.LOONA_GALAXY_CACHE) / key


def _install(file, cache, roles, collections, env, log):
    cache.parent.mkdir(parents=True, exist_ok=True)
    # Built next to the cache and moved into place, so a half-finished
    # install is never mistaken for a finished one.
    work = Path(tempfile.mkdtemp(dir=cache.parent, prefix="installing-"))
    try:
        if roles:
            _galaxy(["role", "install", "-r", str(file), "-p", str(work / "roles")], env, log)
        if collections:
            _galaxy(["collection", "install", "-r", str(file), "-p", str(work / "collections")], env, log)
        (work / "done").write_text("ok\n")
        if cache.exists():
            shutil.rmtree(cache)
        work.rename(cache)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _galaxy(args, env, log):
    try:
        done = subprocess.run(["ansible-galaxy", *args], env={**os.environ, **env},
                              capture_output=True, text=True, timeout=900, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProjectError(_('ansible-galaxy did not run: %(exc)s') % {"exc": exc}) from exc
    for line in (done.stdout + done.stderr).splitlines()[-30:]:
        if line.strip():
            log(line)
    if done.returncode != 0:
        raise ProjectError(_('ansible-galaxy %(join)s failed; see the log.') % {"join": ' '.join(args[:2])})
