# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Back up and restore everything Loona keeps.

All of Loona's state lives in PostgreSQL - inventory, playbooks, runs,
OpenTofu state, settings.  The disk only holds caches and per-run scratch
space.  A backup is therefore one archive (tar.gz):

    manifest.json        Loona version, applied migrations, a fingerprint of
                         the encryption key, every table's columns and rows
    tables/<name>.copy   the table's rows in PostgreSQL's COPY text format

Restoring rebuilds the schema the backup was taken from (by migrating to the
migrations it lists), copies the rows back, and only then migrates to this
Loona's schema - so a backup from an older Loona goes through the same
migrations an upgrade in place would.

The encryption key is never in the archive.  Secrets inside stay encrypted
with it, so a backup is only as good as the key kept next to it: restore
checks the fingerprint before touching anything.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from django.apps import apps
from django.conf import settings
from django.core.management import call_command
from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from . import crypto
from .version import __version__

FORMAT = 1
# Rebuilt by migrate (django_migrations) or not worth carrying over.
SKIP_TABLES = {"django_migrations", "django_session"}
CHUNK = 1 << 20


class BackupError(Exception):
    """The archive cannot be restored here; the message says why."""


def key_source() -> str:
    return "LOONA_SECRET_STORE_KEY" if settings.LOONA_SECRET_STORE_KEY else "LOONA_SECRET_KEY"


def key_fingerprint() -> str:
    """Identifies the encryption key without giving anything of it away."""
    key = settings.LOONA_SECRET_STORE_KEY
    if not key:
        key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest()).decode()
    return hashlib.sha256(b"loona-key-fingerprint:" + key.encode()).hexdigest()[:16]


@dataclass
class Probe:
    checked: int = 0
    unreadable: list[str] = field(default_factory=list)


def probe_secrets(per_field: int = 3) -> Probe:
    """Try to decrypt a few stored values of every encrypted field."""
    probe = Probe()
    for model in apps.get_models():
        for name in (f.name for f in model._meta.concrete_fields if f.name.endswith("_encrypted")):
            try:
                with transaction.atomic():
                    values = list(model._default_manager.exclude(**{name: ""})
                                  .values_list("pk", name)[:per_field])
            except DatabaseError:
                continue  # not migrated yet
            for pk, value in values:
                probe.checked += 1
                try:
                    crypto.decrypt(value)
                except crypto.SecretUnreadable:
                    probe.unreadable.append(f"{model._meta.label}#{pk}.{name}")
    return probe


def _applied_leaves() -> list[list[str]]:
    """The newest applied migration of every app: enough to rebuild the schema."""
    loader = MigrationExecutor(connection).loader
    applied = set(loader.applied_migrations)
    leaves = []
    for node in sorted(applied):
        children = loader.graph.node_map[node].children if node in loader.graph.node_map else set()
        if not any(child in applied and child[0] == node[0] for child in children):
            leaves.append(list(node))
    return leaves


def _tables() -> list[str]:
    return sorted(t for t in connection.introspection.table_names() if t not in SKIP_TABLES)


def _columns(cursor, table: str) -> list[str]:
    cursor.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = %s ORDER BY ordinal_position",
        [table],
    )
    return [row[0] for row in cursor.fetchall()]


def _copy_sql(table: str, columns: list[str], direction: str) -> str:
    q = connection.ops.quote_name
    return f"COPY {q(table)} ({', '.join(q(c) for c in columns)}) {direction}"


def create(out) -> dict:
    """Write a backup archive to the binary stream `out`; return its manifest."""
    tables: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="loona-backup-") as tmp:
        # One snapshot: rows written while the dump runs are either all in or all out.
        # (Inside someone else's transaction - a test - its snapshot has to do.)
        ours = not connection.in_atomic_block
        with transaction.atomic(), connection.cursor() as cursor:
            if ours:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            migrations = _applied_leaves()
            for table in _tables():
                columns = _columns(cursor, table)
                rows = 0
                with open(Path(tmp) / f"{table}.copy", "wb") as target:
                    with cursor.copy(_copy_sql(table, columns, "TO STDOUT")) as copy:
                        for chunk in copy:
                            # The text format puts one row on each line.
                            rows += bytes(chunk).count(b"\n")
                            target.write(chunk)
                tables[table] = {"columns": columns, "rows": rows}
        manifest = {
            "format": FORMAT,
            "loona_version": __version__,
            "created_at": timezone.now().isoformat(),
            "migrations": migrations,
            "key": {"source": key_source(), "fingerprint": key_fingerprint()},
            "tables": tables,
        }
        raw = json.dumps(manifest, indent=2).encode()
        with tarfile.open(fileobj=out, mode="w|gz") as tar:
            info = tarfile.TarInfo("manifest.json")
            info.size, info.mtime, info.mode = len(raw), int(timezone.now().timestamp()), 0o600
            tar.addfile(info, io.BytesIO(raw))
            for table in tables:
                tar.add(Path(tmp) / f"{table}.copy", arcname=f"tables/{table}.copy")
    return manifest


def rows(manifest: dict) -> int:
    return sum(t["rows"] for t in manifest["tables"].values())


def read(stream, workdir: Path) -> dict:
    """Unpack an archive from `stream` into `workdir`; return its manifest."""
    manifest = None
    try:
        with tarfile.open(fileobj=stream, mode="r|gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                if member.name == "manifest.json":
                    manifest = json.load(tar.extractfile(member))
                elif member.name.startswith("tables/") and member.name.endswith(".copy"):
                    name = Path(member.name).name
                    if name != member.name[len("tables/"):]:
                        continue  # nothing outside workdir
                    with open(workdir / name, "wb") as target:
                        source = tar.extractfile(member)
                        while chunk := source.read(CHUNK):
                            target.write(chunk)
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        raise BackupError(f"Not a Loona backup, or a damaged one: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise BackupError("Not a Loona backup (no manifest.json, or an unknown format).")
    missing = [t for t in manifest["tables"] if not (workdir / f"{t}.copy").is_file()]
    if missing:
        raise BackupError(f"The archive is incomplete: no rows for {', '.join(missing[:3])}.")
    return manifest


def check(manifest: dict, ignore_key: bool = False) -> list[str]:
    """Reasons this Loona cannot take the backup in; empty when it can."""
    problems = []
    loader = MigrationExecutor(connection).loader
    unknown = [f"{app}.{name}" for app, name in manifest["migrations"]
               if (app, name) not in loader.graph.nodes]
    if unknown:
        problems.append(
            f"The backup was made by Loona {manifest['loona_version']}, which knows migrations this "
            f"Loona {__version__} does not ({', '.join(unknown[:3])}{', ...' if len(unknown) > 3 else ''}). "
            "Restore it with that version or newer."
        )
    key = manifest["key"]
    if key["fingerprint"] != key_fingerprint() and not ignore_key:
        problems.append(
            f"The backup's secrets are encrypted with another key (it used {key['source']}, "
            f"fingerprint {key['fingerprint']}; this Loona has {key_source()}, fingerprint "
            f"{key_fingerprint()}). Start Loona with the {key['source']} it was made with. "
            "--ignore-key restores anyway, leaving every password, key and secret unreadable."
        )
    return problems


def is_empty() -> bool:
    """No Loona tables at all, or no users in them."""
    if "auth_user" not in connection.introspection.table_names():
        return True
    with connection.cursor() as cursor:
        cursor.execute("SELECT EXISTS (SELECT 1 FROM auth_user)")
        return not cursor.fetchone()[0]


def _drop_everything() -> None:
    tables = connection.introspection.table_names()
    if tables:
        with connection.cursor() as cursor:
            cursor.execute("DROP TABLE " + ", ".join(connection.ops.quote_name(t) for t in tables) + " CASCADE")


def restore(manifest: dict, workdir: Path, replace: bool = False) -> None:
    """Rebuild the backup's schema, copy its rows in, then migrate to today's schema."""
    if not is_empty():
        if not replace:
            raise BackupError(
                "This database already has users. Restore into an empty database, "
                "or pass --replace to delete everything in it first."
            )
        _drop_everything()
    elif replace:
        _drop_everything()

    executor = MigrationExecutor(connection)
    executor.migrate([tuple(node) for node in manifest["migrations"]])

    q = connection.ops.quote_name
    with transaction.atomic(), connection.cursor() as cursor:
        for table, spec in manifest["tables"].items():
            if _columns(cursor, table) != spec["columns"]:
                raise BackupError(
                    f"Table {table} here does not match the backup's after migrating to its "
                    "migrations; the archive was not made by Loona, or was edited."
                )
        # Rows a migration may have put in, such as content types.
        cursor.execute("TRUNCATE " + ", ".join(q(t) for t in manifest["tables"]) + " CASCADE")
        for table, spec in manifest["tables"].items():
            with open(workdir / f"{table}.copy", "rb") as source:
                with cursor.copy(_copy_sql(table, spec["columns"], "FROM STDIN")) as copy:
                    while chunk := source.read(CHUNK):
                        copy.write(chunk)
            # Next ids continue after the restored ones.
            for column in spec["columns"]:
                cursor.execute("SELECT pg_get_serial_sequence(%s, %s)", [q(table), column])
                sequence = cursor.fetchone()[0]
                if sequence:
                    cursor.execute(
                        f"SELECT setval(%s, COALESCE((SELECT MAX({q(column)}) FROM {q(table)}), 0) + 1, false)",
                        [sequence],
                    )
    call_command("migrate", interactive=False, verbosity=0)
