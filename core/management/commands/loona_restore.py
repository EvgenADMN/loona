# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Restore a loona_backup archive into an empty database.

    python manage.py loona_restore loona.tar.gz --check     say what would happen
    python manage.py loona_restore loona.tar.gz
    docker compose run --rm -T web python manage.py loona_restore - < loona.tar.gz

Loona must run with the encryption key the backup was made with; the
command checks before it changes anything.  The backup may come from an
older Loona: the schema is brought up to date after the rows are in.
"""
import sys
import tempfile
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from core import backup
from core.version import __version__


class Command(BaseCommand):
    help = "Load a loona_backup archive into an empty database ('-' reads standard input)."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Archive to read, or - for standard input.")
        parser.add_argument("--check", action="store_true",
                            help="Only check the archive against this Loona; change nothing.")
        parser.add_argument("--replace", action="store_true",
                            help="Delete everything in this database first.")
        parser.add_argument("--ignore-key", action="store_true",
                            help="Restore although the encryption key differs; secrets stay unreadable.")

    def handle(self, *args, path, check=False, replace=False, ignore_key=False, **options):
        with tempfile.TemporaryDirectory(prefix="loona-restore-") as tmp:
            try:
                if path == "-":
                    manifest = backup.read(sys.stdin.buffer, Path(tmp))
                else:
                    with open(path, "rb") as stream:
                        manifest = backup.read(stream, Path(tmp))
            except OSError as exc:
                raise CommandError(f"Cannot read {path}: {exc}") from exc
            except backup.BackupError as exc:
                raise CommandError(str(exc)) from exc

            rows = backup.rows(manifest)
            self.stdout.write(
                f"Backup of Loona {manifest['loona_version']} from {manifest['created_at']}: {rows} rows."
            )
            problems = backup.check(manifest, ignore_key=ignore_key)
            if problems:
                raise CommandError("\n".join(problems))
            if check:
                state = "empty" if backup.is_empty() else "NOT empty (needs --replace)"
                self.stdout.write(f"It can be restored into this Loona {__version__}; the database is {state}.")
                return

            try:
                backup.restore(manifest, Path(tmp), replace=replace)
            except backup.BackupError as exc:
                raise CommandError(str(exc)) from exc

        probe = backup.probe_secrets()
        if probe.unreadable:
            self.stdout.write(self.style.WARNING(
                f"Restored, but {len(probe.unreadable)} of {probe.checked} sampled secret(s) cannot be "
                f"decrypted with this key (e.g. {', '.join(probe.unreadable[:3])})."
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                f"Restored {rows} rows; {probe.checked} sampled secret(s) decrypt with this key."
            ))
