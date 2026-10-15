# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Back up everything Loona keeps into one archive.

    python manage.py loona_backup                    into <data dir>/backups/
    python manage.py loona_backup /srv/loona.tar.gz
    docker compose exec -T web python manage.py loona_backup - > loona.tar.gz

The encryption key is not in the archive: keep LOONA_SECRET_STORE_KEY (or, if
it is not set, LOONA_SECRET_KEY) somewhere safe, apart from the backups.
"""
import os
import sys
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from core import backup
from core.version import __version__


class Command(BaseCommand):
    help = "Write every row Loona keeps into one tar.gz; '-' writes to standard output."

    def add_arguments(self, parser):
        parser.add_argument("path", nargs="?", help="Archive to write, or - for standard output.")

    def handle(self, *args, path=None, **options):
        # With the archive on standard output, talk on standard error.
        say = self.stderr if path == "-" else self.stdout
        probe = backup.probe_secrets()
        if probe.unreadable:
            say.write(self.style.WARNING(
                f"{len(probe.unreadable)} stored secret(s) cannot be decrypted with the current key "
                f"(e.g. {', '.join(probe.unreadable[:3])}); they will be just as unreadable after a restore."
            ))
        if path == "-":
            manifest = backup.create(sys.stdout.buffer)
            sys.stdout.buffer.flush()
        else:
            target = Path(path) if path else (
                Path(settings.LOONA_DATA_DIR).parent / "backups"
                / f"loona-{__version__}-{timezone.now():%Y%m%d-%H%M%S}.tar.gz"
            )
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Password hashes and encrypted secrets: owner only, from the first byte.
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as out:
                manifest = backup.create(out)
            say.write(f"Backup written to {target}")
        say.write(
            f"{backup.rows(manifest)} rows from Loona {manifest['loona_version']}. Secrets in it need "
            f"{manifest['key']['source']} (fingerprint {manifest['key']['fingerprint']}) - "
            "it is not in the archive; keep it safe, apart from the backups."
        )
