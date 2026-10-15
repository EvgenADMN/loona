# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Start due drift checks and tidy up after dead workers.

The container runs this every minute through celery beat.  Without Celery,
call it from cron:

    * * * * *  cd /srv/loona && .venv/bin/python manage.py loona_tick
"""
from django.core.management.base import BaseCommand

from runs.housekeeping import tick


class Command(BaseCommand):
    help = "Start due drift checks, close out dead runs, forget old ones."

    def handle(self, *args, **options):
        done = tick()
        if any(done.values()):
            self.stdout.write(
                f"{done['checks']} check(s) started, {done['reaped']} dead run(s) closed, "
                f"{done['deleted']} old run(s) deleted."
            )
