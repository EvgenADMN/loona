# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""loona_hosts -> Loona hosts, without running OpenTofu."""
from unittest.mock import patch

from django.test import TestCase

from inventory.models import Host, HostGroup

from . import lifecycle
from .models import TofuProject

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake"


class SyncTests(TestCase):
    def setUp(self):
        self.home = HostGroup.objects.create(name="lab")
        self.web = HostGroup.objects.create(name="lab-web")
        self.web.parents.add(self.home)
        self.foreign = HostGroup.objects.create(name="prod")
        self.project = TofuProject.objects.create(name="lab", host_group=self.home)

    def test_declared_hosts_are_created_in_the_projects_group(self):
        result = lifecycle.sync(self.project, {
            "web-01": {"address": "10.0.0.5", "groups": ["lab-web"], "vars": {"role": "web"}},
            "db-01": {"address": "10.0.0.6", "port": 2222, "user": "admin"},
        })
        self.assertEqual(sorted(h.name for h in result.created), ["db-01", "web-01"])
        web = Host.objects.get(name="web-01")
        self.assertEqual(web.tofu_project, self.project)
        self.assertEqual(set(web.groups.all()), {self.home, self.web})
        self.assertEqual(web.variables, {"role": "web"})
        self.assertEqual(Host.objects.get(name="db-01").port, 2222)
        users = {h.name: h._declared_user for h in result.created}
        # Declared per host, or the project's default.
        self.assertEqual(users, {"db-01": "admin", "web-01": "root"})

    def test_a_list_form_works_too(self):
        lifecycle.sync(self.project, [{"name": "a", "address": "10.0.0.1"}])
        self.assertTrue(Host.objects.filter(name="a", tofu_project=self.project).exists())

    def test_groups_outside_the_project_are_refused(self):
        result = lifecycle.sync(self.project, {"web-01": {"address": "10.0.0.5", "groups": ["prod"]}})
        self.assertEqual(set(Host.objects.get(name="web-01").groups.all()), {self.home})
        self.assertIn("prod", result.problems[0])

    def test_a_host_entered_by_hand_is_never_taken_over(self):
        Host.objects.create(name="web-01", address="192.168.1.1")
        result = lifecycle.sync(self.project, {"web-01": {"address": "10.0.0.5"}})
        self.assertEqual(result.created, [])
        manual = Host.objects.get(name="web-01")
        self.assertIsNone(manual.tofu_project)
        self.assertEqual(manual.address, "192.168.1.1")
        self.assertIn("already exists", result.problems[0])

    def test_hosts_no_longer_declared_are_removed(self):
        lifecycle.sync(self.project, {"a": {"address": "10.0.0.1"}, "b": {"address": "10.0.0.2"}})
        result = lifecycle.sync(self.project, {"a": {"address": "10.0.0.1"}})
        self.assertEqual(result.removed, ["b"])
        self.assertFalse(Host.objects.filter(name="b").exists())
        # After a destroy the output is gone altogether.
        result = lifecycle.sync(self.project, None)
        self.assertEqual(result.removed, ["a"])

    def test_host_keys_from_opentofu_are_pinned_before_first_contact(self):
        lifecycle.sync(self.project, {"a": {"address": "10.0.0.1", "host_keys": [KEY + " root@a"]}})
        host = Host.objects.get(name="a")
        self.assertEqual(host.ssh_host_keys, KEY)
        self.assertIsNotNone(host.ssh_host_keys_pinned_at)

    def test_a_moved_machine_loses_its_learned_pin(self):
        lifecycle.sync(self.project, {"a": {"address": "10.0.0.1"}})
        Host.objects.filter(name="a").update(ssh_host_keys=KEY)
        lifecycle.sync(self.project, {"a": {"address": "10.0.0.1"}})
        self.assertEqual(Host.objects.get(name="a").ssh_host_keys, KEY)
        lifecycle.sync(self.project, {"a": {"address": "10.0.0.9"}})
        self.assertEqual(Host.objects.get(name="a").ssh_host_keys, "")

    def test_bad_entries_are_reported_not_fatal(self):
        result = lifecycle.sync(self.project, {
            "ok": {"address": "10.0.0.1"},
            "no-address": {},
            "bad name!": {"address": "10.0.0.2"},
            "bad-port": {"address": "10.0.0.3", "port": "ssh"},
        })
        self.assertEqual([h.name for h in result.created], ["ok"])
        self.assertEqual(len(result.problems), 3)
