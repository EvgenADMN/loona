# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Rewrite core/i18n_labels.py from the forms, for makemessages to find."""
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand

from core.i18n_check import auto_labels

HEADER = '''# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Form labels Django makes from field names, listed so makemessages finds them.

They are translated where they are shown (the |tr filter).  core.tests checks
this list against the forms; regenerate it with ``python manage.py loona_labels``
when it says so.
"""
from django.utils.translation import gettext_noop as _

LABELS = [
'''


class Command(BaseCommand):
    help = "Regenerate core/i18n_labels.py."

    def handle(self, *args, **options):
        labels = sorted(auto_labels())
        body = HEADER + "".join(f"    _({label!r}),\n" for label in labels) + "]\n"
        (Path(settings.BASE_DIR) / "core" / "i18n_labels.py").write_text(body, encoding="utf-8")
        self.stdout.write(f"{len(labels)} labels.")
