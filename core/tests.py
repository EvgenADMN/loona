# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from .models import UserPreference


class ThemePreferenceTests(TestCase):
    """The chosen palette belongs to the account, not to the browser."""

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_superuser("admin", password="x")
        self.other = User.objects.create_user("colleague", password="x")

    def test_a_new_account_starts_dark(self):
        self.assertEqual(UserPreference.theme_for(self.user), UserPreference.DARK)

    def test_toggling_flips_and_sticks(self):
        self.assertEqual(UserPreference.toggle_theme(self.user), UserPreference.LIGHT)
        self.assertEqual(UserPreference.theme_for(self.user), UserPreference.LIGHT)
        self.assertEqual(UserPreference.toggle_theme(self.user), UserPreference.DARK)

    def test_one_account_does_not_change_another(self):
        UserPreference.toggle_theme(self.user)
        self.assertEqual(UserPreference.theme_for(self.other), UserPreference.DARK)

    def test_the_choice_survives_a_new_session(self):
        UserPreference.toggle_theme(self.user)
        self.client.force_login(self.user)
        self.assertContains(self.client.get(reverse("dashboard")), 'data-theme="light"')
        self.client.logout()
        self.client.force_login(self.user)
        self.assertContains(self.client.get(reverse("dashboard")), 'data-theme="light"')

    def test_signed_out_pages_follow_the_machine(self):
        # No attribute at all, so prefers-color-scheme decides.
        response = self.client.get(reverse("login"))
        self.assertNotContains(response, "data-theme")


class ThemeToggleViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_superuser("admin", password="x")
        self.client.force_login(self.user)

    def test_an_htmx_toggle_answers_with_nothing_to_swap(self):
        response = self.client.post(reverse("theme_toggle"), HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(UserPreference.theme_for(self.user), UserPreference.LIGHT)

    def test_without_htmx_it_returns_where_you_were(self):
        response = self.client.post(
            reverse("theme_toggle"), HTTP_REFERER="/inventory/hosts/"
        )
        self.assertRedirects(response, "/inventory/hosts/", fetch_redirect_response=False)

    def test_it_cannot_be_flipped_by_following_a_link(self):
        self.assertEqual(self.client.get(reverse("theme_toggle")).status_code, 405)
        self.assertEqual(UserPreference.theme_for(self.user), UserPreference.DARK)

    def test_signing_in_is_required(self):
        self.client.logout()
        response = self.client.post(reverse("theme_toggle"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])


class DashboardCountTests(TestCase):
    """The overview counts playbook work, not Loona's own key runs."""

    def setUp(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))

    def test_key_runs_are_left_out_of_the_job_count(self):
        from runs.models import Job

        Job.objects.create(playbook_name="p", playbook_yaml="---")
        Job.objects.create(
            playbook_name="k", playbook_yaml="---", kind=Job.KIND_KEY_INSTALL
        )
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.context["counts"]["jobs"], 1)
        self.assertEqual(len(response.context["recent_jobs"]), 1)


class LicenseHeaderTests(SimpleTestCase):
    """Every source file of Loona's own says what license it is under."""

    def test_every_source_file_has_the_spdx_header(self):
        import subprocess
        from pathlib import Path

        from django.conf import settings

        root = Path(settings.BASE_DIR)
        try:
            files = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                                   cwd=root, capture_output=True, text=True, check=True).stdout.split()
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")
        missing = []
        for name in files:
            if "/migrations/" in name or not (name.endswith((".py", ".sh")) or name in (
                    "Dockerfile", "compose.yaml", "static/js/survey-editor.js", "static/css/loona.css")):
                continue
            path = root / name
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            if text.strip() and "SPDX-License-Identifier: GPL-3.0-or-later" not in "\n".join(text.splitlines()[:3]):
                missing.append(name)
        self.assertEqual(missing, [], "add the two header lines (see any other file) to these")


class TranslationTests(TestCase):
    """The Russian interface: complete, compiled, and chosen per person."""

    PO = "locale/ru/LC_MESSAGES/django.po"

    def entries(self):
        import json
        import re
        from pathlib import Path

        from django.conf import settings

        text = (Path(settings.BASE_DIR) / self.PO).read_text(encoding="utf-8")
        found = []
        for block in text.split("\n\n")[1:]:
            if "#, fuzzy" in block:
                found.append(("FUZZY", block))
                continue
            parts = {}
            key = None
            for line in block.splitlines():
                m = re.match(r'^(msgctxt|msgid|msgid_plural|msgstr(?:\[\d\])?) (".*")$', line)
                if m:
                    key = m.group(1)
                    parts[key] = json.loads(m.group(2))
                elif line.startswith('"') and key:
                    parts[key] += json.loads(line)
            if "msgid" in parts:
                msgid = (parts["msgctxt"], parts["msgid"]) if "msgctxt" in parts else parts["msgid"]
                found.append((msgid, [v for k, v in parts.items() if k.startswith("msgstr")]))
        return found

    def test_everything_is_translated(self):
        missing = [msgid for msgid, forms in self.entries() if msgid == "FUZZY" or not all(forms)]
        self.assertEqual(missing, [])

    def test_the_compiled_catalog_matches(self):
        import gettext
        from pathlib import Path

        from django.conf import settings

        with open(Path(settings.BASE_DIR) / self.PO.replace(".po", ".mo"), "rb") as fh:
            compiled = gettext.GNUTranslations(fh)
        def compiled_text(msgid):
            if isinstance(msgid, tuple):
                return compiled.pgettext(*msgid)
            return compiled.gettext(msgid)

        stale = [msgid for msgid, forms in self.entries() if compiled_text(msgid) != forms[0]]
        self.assertEqual(stale, [], "run compilemessages")

    def test_a_person_picks_their_language(self):
        from django.contrib.auth import get_user_model

        user = get_user_model().objects.create_user("ivan", password="x")
        self.client.force_login(user)
        self.assertContains(self.client.get("/"), "Overview")
        self.client.post("/language/", {"language": "ru", "next": "/"})
        page = self.client.get("/")
        self.assertContains(page, "Обзор")
        self.assertContains(page, '<html lang="ru"')
        self.client.post("/language/", {"language": "", "next": "https://evil.example/"})
        self.assertContains(self.client.get("/"), "Overview")

    def test_the_default_comes_from_administration_and_the_api_stays_english(self):
        from administration import system
        from administration.models import SystemSettings
        from django.contrib.auth import get_user_model

        SystemSettings.objects.update_or_create(pk=1, defaults={"language": "ru"})
        system.invalidate()
        self.addCleanup(system.invalidate)
        user = get_user_model().objects.create_user("ivan", password="x")
        self.client.force_login(user)
        self.assertContains(self.client.get("/"), "Обзор")
        response = self.client.get("/api/v1/jobs/999999/")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers.get("Content-Language"), "en")


class LabelCatalogTests(SimpleTestCase):
    def test_the_label_list_is_current(self):
        from core.i18n_check import auto_labels
        from core.i18n_labels import LABELS

        self.assertEqual(sorted(auto_labels()), sorted(LABELS), "run python manage.py loona_labels")


class ProductionSettingsTests(SimpleTestCase):
    """Settings read in a fresh interpreter, the way a container starts."""

    def _settings(self, **env):
        import json
        import os
        import subprocess
        import sys

        from django.conf import settings

        clean = {k: v for k, v in os.environ.items() if not k.startswith("LOONA_")}
        # Empty values stop the repo's .env from filling them in.
        clean.update({"LOONA_DEBUG": "", "LOONA_SECRET_KEY": "", "LOONA_HTTPS": "",
                      "LOONA_TRUST_PROXY": "", "LOONA_HSTS_SECONDS": "0"}, **env)
        code = (
            "import json, loona.settings as s;"
            "print(json.dumps([s.DEBUG, s.SESSION_COOKIE_SECURE, s.CSRF_COOKIE_SECURE,"
            " getattr(s, 'SECURE_PROXY_SSL_HEADER', None), s.SECURE_HSTS_SECONDS]))"
        )
        done = subprocess.run([sys.executable, "-c", code], cwd=settings.BASE_DIR,
                              env=clean, capture_output=True, text=True)
        return done.returncode, (json.loads(done.stdout) if done.returncode == 0 else done.stderr)

    def test_no_secret_key_outside_debug_refuses_to_start(self):
        code, err = self._settings()
        self.assertNotEqual(code, 0)
        self.assertIn("Set LOONA_SECRET_KEY", err)

    def test_debug_is_off_unless_asked(self):
        code, (debug, session, csrf, proxy, hsts) = self._settings(LOONA_SECRET_KEY="k")
        self.assertEqual(code, 0)
        self.assertEqual((debug, session, csrf, proxy, hsts), (False, False, False, None, 0))

    def test_https_behind_a_proxy(self):
        code, values = self._settings(LOONA_SECRET_KEY="k", LOONA_HTTPS="true",
                                      LOONA_TRUST_PROXY="true", LOONA_HSTS_SECONDS="600")
        self.assertEqual(code, 0)
        self.assertEqual(values, [False, True, True, ["HTTP_X_FORWARDED_PROTO", "https"], 600])


class VersionTests(SimpleTestCase):
    """core/version.py is the version; everything that repeats it must agree."""

    def test_dockerfile_and_changelog_follow(self):
        import re

        from django.conf import settings

        from .version import __version__

        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")
        dockerfile = (settings.BASE_DIR / "Dockerfile").read_text()
        self.assertIn(f'org.opencontainers.image.version="{__version__}"', dockerfile)
        changelog = (settings.BASE_DIR / "CHANGELOG.md").read_text()
        newest = re.search(r"^## (\S+)", changelog, re.M).group(1)
        self.assertEqual(newest, __version__)



class VersionShownTests(TestCase):
    def test_in_the_api_and_on_the_administration_page(self):
        from .version import __version__

        admin = get_user_model().objects.create_superuser("root", "", "pw-root-123")
        self.client.force_login(admin)
        self.assertEqual(self.client.get("/api/v1/me/").json()["loona_version"], __version__)
        self.assertContains(self.client.get(reverse("admin_overview")), __version__)
