# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""SSH host key pinning against a real sshd.

Skipped unless a target is given: an sshd that lets the key in.

    LOONA_SSH_TEST_TARGET=127.0.0.1:2222 LOONA_SSH_TEST_KEY=./test_key \\
        python manage.py test inventory.tests_ssh_live
"""
import os
import tempfile
import unittest
from pathlib import Path

from django.test import TestCase, override_settings

from runs import executor
from runs.models import Job

from . import probe, services
from .forms import HostForm
from .keys import generate_keypair
from .models import Credential, Host, HostGroup

TARGET = os.getenv("LOONA_SSH_TEST_TARGET", "")
KEY = os.getenv("LOONA_SSH_TEST_KEY", "")
PING = "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.ping:\n"


@unittest.skipUnless(TARGET and KEY, "set LOONA_SSH_TEST_TARGET and LOONA_SSH_TEST_KEY")
class HostKeyPinningTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        override = override_settings(LOONA_DATA_DIR=f"{self.tmp.name}/jobs")
        override.enable()
        self.addCleanup(override.disable)
        address, port = TARGET.rsplit(":", 1)
        credential = Credential.objects.create(name="test", kind=Credential.KIND_SSH_KEY, username="root")
        credential.secret = Path(KEY).read_text()
        credential.save()
        self.host = Host.objects.create(name="sshd", address=address, port=int(port), credential=credential)

    def run_ping(self):
        job = Job.objects.create(playbook_name="ping", playbook_yaml=PING)
        job.target_hosts.add(self.host)
        executor.run_job(job.pk)
        job.refresh_from_db()
        self.host.refresh_from_db()
        return job

    def test_the_first_run_pins_the_key_and_later_runs_hold_to_it(self):
        self.assertEqual(self.host.ssh_host_keys, "")
        self.assertEqual(self.run_ping().status, Job.SUCCESSFUL)
        pinned = self.host.ssh_host_keys
        self.assertTrue(pinned.startswith(("ssh-", "ecdsa-")))
        self.assertTrue(self.host.host_key_fingerprints[0].startswith(("ED25519", "ECDSA", "RSA")))
        self.assertEqual(self.run_ping().status, Job.SUCCESSFUL)
        self.assertEqual(self.host.ssh_host_keys, pinned)

    def test_a_different_key_at_the_same_address_is_refused(self):
        self.run_ping()
        impostor = generate_keypair("impostor")[1].split()[:2]
        # Pin a key the server does not have, for every type it offers.
        self.host.ssh_host_keys = "\n".join(
            f"{line.split()[0]} {impostor[1] if line.startswith('ssh-ed25519') else impostor[1]}"
            for line in self.host.ssh_host_keys.splitlines()
        ).replace("ecdsa-sha2-nistp256", "ssh-ed25519").replace("ssh-rsa", "ssh-ed25519")
        self.host.save()
        tampered = self.host.ssh_host_keys

        job = self.run_ping()
        self.assertEqual(job.status, Job.FAILED)
        self.assertTrue(job.events.filter(stdout__contains="HOST IDENTIFICATION HAS CHANGED").exists()
                        or job.events.filter(stdout__contains="Host key verification failed").exists())
        self.assertEqual(self.host.ssh_host_keys, tampered, "a refused key must not be re-pinned")

        result = probe.check_connection(
            lambda keys_dir: services.host_vars(self.host, keys_dir), "sshd", self.host.ssh_host_keys
        )
        self.assertEqual(result.level, "fail")
        self.assertIn("host key", result.summary)


class PinResetTests(TestCase):
    def test_moving_a_host_to_another_address_forgets_its_key(self):
        group = HostGroup.objects.create(name="g")
        host = Host.objects.create(name="h", address="10.0.0.1", ssh_host_keys="ssh-ed25519 AAAA")
        host.groups.add(group)
        data = {"name": "h", "address": "10.0.0.2", "port": 22, "credential": "", "groups": [group.pk],
                "enabled": "on", "description": "", "variables": ""}
        from django.contrib.auth import get_user_model

        root = get_user_model().objects.create_superuser("root")
        form = HostForm(data, instance=host, user=root)
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        host.refresh_from_db()
        self.assertEqual(host.ssh_host_keys, "")

    def test_editing_something_else_keeps_it(self):
        group = HostGroup.objects.create(name="g")
        host = Host.objects.create(name="h", address="10.0.0.1", ssh_host_keys="ssh-ed25519 AAAA")
        host.groups.add(group)
        data = {"name": "h", "address": "10.0.0.1", "port": 22, "credential": "", "groups": [group.pk],
                "enabled": "on", "description": "renamed", "variables": ""}
        from django.contrib.auth import get_user_model

        form = HostForm(data, instance=host, user=get_user_model().objects.create_superuser("root"))
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        host.refresh_from_db()
        self.assertEqual(host.ssh_host_keys, "ssh-ed25519 AAAA")
