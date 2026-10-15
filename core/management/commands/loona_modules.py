# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Re-read the modules ansible-doc knows about.

Run after installing or upgrading collections on the Loona server, so the
editor offers the new modules and their current options:

    python manage.py loona_modules
"""
from django.core.management.base import BaseCommand, CommandError

from playbooks import docs


class Command(BaseCommand):
    help = "Refresh the editor's list of installed Ansible modules from ansible-doc."

    def handle(self, *args, **options):
        try:
            count = docs.refresh_index()
        except docs.DocsUnavailable as exc:
            raise CommandError(f"ansible-doc is not usable: {exc}") from exc
        self.stdout.write(self.style.SUCCESS(f"{count} modules indexed."))
