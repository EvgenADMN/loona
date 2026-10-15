# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.conf import settings
from django.test.runner import DiscoverRunner


class LoonaTestRunner(DiscoverRunner):
    """Keeps the suite independent of the machine it runs on.

    Tests that exercise ansible-doc feed it canned output and switch it back
    on with override_settings.
    """

    def setup_test_environment(self, **kwargs):
        super().setup_test_environment(**kwargs)
        settings.LOONA_MODULE_DOCS = False
        # Settings rows roll back with each test; a cached copy must not
        # outlive the test that wrote it.
        from administration import system

        system.TTL = 0
