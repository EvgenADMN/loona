# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
import io
import tarfile
import tempfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.test import TestCase, TransactionTestCase, override_settings

from inventory.models import Credential, HostGroup

from . import backup

OTHER_KEY = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE="


def _archive() -> bytes:
    out = io.BytesIO()
    backup.create(out)
    return out.getvalue()


class BackupArchiveTests(TestCase):
    def setUp(self):
        get_user_model().objects.create_user("ann", password="pw-ann-123")
        cred = Credential(name="root-pw", kind=Credential.KIND_PASSWORD)
        cred.secret = "hunter2"
        cred.save()

    def test_archive_holds_rows_not_the_key(self):
        raw = _archive()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = backup.read(io.BytesIO(raw), Path(tmp))
            self.assertEqual(manifest["tables"]["auth_user"]["rows"], 1)
            self.assertNotIn("django_migrations", manifest["tables"])
            self.assertIn("inventory", {app for app, _ in manifest["migrations"]})
            rows = (Path(tmp) / "inventory_credential.copy").read_text()
            self.assertIn("root-pw", rows)
            self.assertNotIn("hunter2", rows)
            self.assertEqual(backup.check(manifest), [])

    def test_another_key_is_refused_before_anything_changes(self):
        raw = _archive()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = backup.read(io.BytesIO(raw), Path(tmp))
            with override_settings(LOONA_SECRET_STORE_KEY=OTHER_KEY):
                problems = backup.check(manifest)
                self.assertEqual(len(problems), 1)
                self.assertIn("another key", problems[0])
                self.assertEqual(backup.check(manifest, ignore_key=True), [])

    def test_a_newer_loona_backup_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = backup.read(io.BytesIO(_archive()), Path(tmp))
            manifest["migrations"].append(["inventory", "9999_from_the_future"])
            self.assertIn("9999_from_the_future", backup.check(manifest)[0])

    def test_not_a_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(backup.BackupError):
                backup.read(io.BytesIO(b"plain text"), Path(tmp))
            empty = io.BytesIO()
            with tarfile.open(fileobj=empty, mode="w:gz"):
                pass
            with self.assertRaises(backup.BackupError):
                backup.read(io.BytesIO(empty.getvalue()), Path(tmp))

    def test_restore_refuses_a_database_with_users(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.tar.gz"
            path.write_bytes(_archive())
            with self.assertRaisesMessage(CommandError, "already has users"):
                call_command("loona_restore", str(path), stdout=io.StringIO())
            out = io.StringIO()
            call_command("loona_restore", str(path), "--check", stdout=out)
            self.assertIn("NOT empty", out.getvalue())

    def test_backup_file_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.tar.gz"
            call_command("loona_backup", str(path), stdout=io.StringIO())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_unreadable_secrets_are_reported(self):
        with override_settings(LOONA_SECRET_STORE_KEY=OTHER_KEY):
            probe = backup.probe_secrets()
        self.assertGreaterEqual(probe.checked, 1)
        self.assertIn(f"inventory.Credential#{Credential.objects.get().pk}.secret_encrypted", probe.unreadable)


class RestoreRoundTripTests(TransactionTestCase):
    """The whole way: drop every table, rebuild them, rows back, ids go on."""

    def test_replace_brings_everything_back(self):
        get_user_model().objects.create_user("ann", password="pw-ann-123")
        top = HostGroup.objects.create(name="top")
        HostGroup.objects.create(name="child").parents.add(top)
        cred = Credential(name="root-pw", kind=Credential.KIND_PASSWORD)
        cred.secret = "hunter2"
        cred.save()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.tar.gz"
            path.write_bytes(_archive())
            HostGroup.objects.filter(name="child").delete()
            out = io.StringIO()
            call_command("loona_restore", str(path), "--replace", stdout=out)
        self.assertIn("decrypt with this key", out.getvalue())
        self.assertEqual(set(HostGroup.objects.values_list("name", flat=True)), {"top", "child"})
        self.assertEqual(list(HostGroup.objects.get(name="child").parents.all()), [top])
        self.assertEqual(Credential.objects.get().secret, "hunter2")
        self.assertTrue(get_user_model().objects.get(username="ann").check_password("pw-ann-123"))
        newest = HostGroup.objects.order_by("-pk").first().pk
        self.assertGreater(HostGroup.objects.create(name="new").pk, newest)
