# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Host facts: captured from runs, summarized, shown and searched."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from rest_framework.test import APIClient

from access.models import GroupGrant, Role
from api.models import ApiToken
from core.masking import Masker
from runs.executor import _record_event, run_job
from runs.models import Job

from . import facts
from .models import Host, HostFacts, HostGroup

User = get_user_model()

GiB = 1024 ** 3


def sample(**overrides):
    found = {
        "gather_subset": ["all"],
        "ansible_distribution": "Ubuntu",
        "ansible_distribution_version": "22.04",
        "ansible_distribution_release": "jammy",
        "ansible_os_family": "Debian",
        "ansible_kernel": "6.8.0-40-generic",
        "ansible_architecture": "x86_64",
        "ansible_processor": ["0", "GenuineIntel", "Intel(R) Xeon(R) Gold 6230", "1", "GenuineIntel",
                              "Intel(R) Xeon(R) Gold 6230"],
        "ansible_processor_vcpus": 4,
        "ansible_memtotal_mb": 7951,
        "ansible_fqdn": "web1.example.org",
        "ansible_hostname": "web1",
        "ansible_default_ipv4": {"interface": "eth0", "address": "10.0.4.11"},
        "ansible_all_ipv4_addresses": ["10.0.4.11", "172.17.0.1"],
        "ansible_all_ipv6_addresses": ["fe80::1", "fd00::11"],
        "ansible_interfaces": ["lo", "eth0", "docker0"],
        "ansible_eth0": {"active": True, "macaddress": "52:54:00:aa:bb:cc",
                         "ipv4": {"address": "10.0.4.11", "prefix": "24"},
                         "ipv6": [{"address": "fe80::1", "prefix": "64"}, {"address": "fd00::11", "prefix": "64"}]},
        "ansible_docker0": {"active": False, "ipv4": {"address": "172.17.0.1", "prefix": "16"}},
        "ansible_lo": {"active": True},
        "ansible_virtualization_type": "kvm",
        "ansible_virtualization_role": "guest",
        "ansible_system_vendor": "QEMU",
        "ansible_product_name": "Standard PC",
        "ansible_uptime_seconds": 90061,
        "ansible_selinux": {"status": "disabled"},
        "ansible_mounts": [
            {"mount": "/", "device": "/dev/vda1", "fstype": "ext4", "size_total": 40 * GiB, "size_available": 2 * GiB},
            {"mount": "/srv", "device": "/dev/vdb", "fstype": "xfs", "size_total": 100 * GiB, "size_available": 80 * GiB},
            {"mount": "/snap/core/1", "device": "/dev/loop0", "fstype": "squashfs", "size_total": 1, "size_available": 0},
        ],
        "ansible_devices": {"vda": {"size": "40.00 GB", "rotational": "0"}, "loop0": {"size": "1 MB"}},
    }
    found.update(overrides)
    return found


def facts_event(host="web1", found=None, action="gather_facts", res_extra=None):
    return {
        "event": "runner_on_ok",
        "counter": 3,
        "stdout": f"ok: [{host}]",
        "event_data": {
            "host": host,
            "task": "Gathering Facts",
            "task_action": action,
            "resolved_action": f"ansible.builtin.{action}",
            "res": {"ansible_facts": found if found is not None else sample(), "changed": False,
                    **(res_extra or {})},
        },
    }


class CaptureTests(TestCase):
    def setUp(self):
        self.host = Host.objects.create(name="web1")
        self.job = Job.objects.create(playbook_name="site", playbook_yaml="- hosts: all",
                                      resolved_hosts=["web1"])

    def record(self, event, mask=None):
        _record_event(self.job.pk, event, {"stored": 0, "mask": mask or Masker()})

    def test_only_the_runs_own_hosts_get_facts(self):
        """An agent, or an add_host in a play, does not write another machine's facts."""
        Host.objects.create(name="db9")
        self.record(facts_event(host="db9"))
        self.assertFalse(HostFacts.objects.filter(host__name="db9").exists())

    def test_a_facts_task_leaves_its_facts_on_the_host(self):
        self.record(facts_event())
        stored = HostFacts.objects.get(host=self.host)
        self.assertEqual(stored.job, self.job)
        self.assertEqual(stored.os, "Ubuntu 22.04")
        self.assertEqual(stored.cpu_count, 4)
        self.assertEqual(stored.cpu_model, "Intel(R) Xeon(R) Gold 6230")
        self.assertEqual(stored.memory_gb, 8)
        self.assertEqual(stored.default_ipv4, "10.0.4.11")
        # Link-local addresses say nothing about the host.
        self.assertEqual(stored.address_list, ["10.0.4.11", "172.17.0.1", "fd00::11"])
        self.assertEqual(stored.virtualization, "kvm guest")
        self.assertIn("qemu standard pc", stored.search_text)
        self.assertEqual(stored.facts["ansible_selinux"], {"status": "disabled"})

    def test_set_fact_and_strangers_are_not_facts_about_a_machine(self):
        self.record(facts_event(action="set_fact", found={"foo": 1}))
        self.record(facts_event(host="not-in-inventory"))
        self.assertFalse(HostFacts.objects.exists())

    def test_facts_gathered_for_a_delegate_are_not_this_hosts(self):
        self.record(facts_event(res_extra={"_ansible_delegated_vars": {"ansible_host": "db1"}}))
        self.assertFalse(HostFacts.objects.exists())

    def test_secrets_in_facts_are_masked(self):
        found = sample(ansible_env={"DB_PASSWORD": "hunter2-secret"})
        self.record(facts_event(found=found), mask=Masker(["hunter2-secret"]))
        self.assertEqual(HostFacts.objects.get().facts["ansible_env"]["DB_PASSWORD"], "********")

    def test_a_partial_gathering_is_laid_over_a_full_one(self):
        self.record(facts_event())
        self.record(facts_event(found={"gather_subset": ["network"], "ansible_default_ipv4": {"address": "10.9.9.9"}}))
        stored = HostFacts.objects.get()
        self.assertEqual(stored.default_ipv4, "10.9.9.9")
        self.assertEqual(stored.os, "Ubuntu 22.04")
        # A full one starts over.
        self.record(facts_event(found={"gather_subset": ["all"], "ansible_distribution": "Debian"}))
        stored.refresh_from_db()
        self.assertEqual(stored.os, "Debian")
        self.assertNotIn("ansible_selinux", stored.facts)

    def test_facts_are_kept_after_the_log_is_truncated(self):
        with patch("administration.system.get") as get:
            get.return_value.max_job_events = 1
            counters = {"stored": 5, "mask": Masker(), "truncated": True}
            _record_event(self.job.pk, facts_event(), counters)
        self.assertTrue(HostFacts.objects.filter(host=self.host).exists())

    def test_nul_characters_do_not_break_storage(self):
        self.record(facts_event(found=sample(ansible_cmdline={"x": "a\x00b"})))
        self.assertEqual(HostFacts.objects.get().facts["ansible_cmdline"], {"x": "ab"})


class ReadingTests(TestCase):
    def test_disks_skip_pseudo_filesystems_and_flag_usage(self):
        rows = facts.disks(sample())
        self.assertEqual([r["mount"] for r in rows], ["/srv", "/"])
        self.assertEqual(rows[1]["used_pct"], 95)

    def test_interfaces_put_the_default_route_first_and_skip_unaddressed(self):
        rows = facts.interfaces(sample())
        self.assertEqual([r["name"] for r in rows], ["eth0", "docker0"])
        self.assertEqual(rows[0]["addresses"], ["10.0.4.11/24", "fd00::11/64"])

    def test_devices_skip_loops(self):
        self.assertEqual([d["name"] for d in facts.devices(sample())], ["vda"])

    def test_flatten_gives_paths(self):
        rows = dict(facts.flatten(sample()))
        self.assertEqual(rows["ansible_selinux.status"], "disabled")
        self.assertEqual(rows["ansible_mounts[1].mount"], "/srv")
        self.assertEqual(rows["ansible_all_ipv4_addresses"], "10.0.4.11, 172.17.0.1")


class SearchTests(TestCase):
    def setUp(self):
        self.web = Host.objects.create(name="web1", description="frontend")
        facts.record(self.web, sample())
        self.db = Host.objects.create(name="db1")
        facts.record(self.db, sample(
            ansible_distribution="Rocky", ansible_distribution_version="9.4", ansible_os_family="RedHat",
            ansible_processor_vcpus=16, ansible_memtotal_mb=64000,
            ansible_default_ipv4={"address": "10.0.5.20"}, ansible_all_ipv4_addresses=["10.0.5.20"],
            ansible_all_ipv6_addresses=[], ansible_selinux={"status": "enabled"},
            ansible_virtualization_type="NA", ansible_architecture="aarch64",
        ))
        self.bare = Host.objects.create(name="new1", address="10.0.6.1")

    def find(self, query):
        search = facts.parse(query)
        self.assertEqual(search.errors, [], query)
        return sorted(Host.objects.filter(search.filter).distinct().values_list("name", flat=True))

    def test_filters(self):
        self.assertEqual(self.find("os:ubuntu"), ["web1"])
        self.assertEqual(self.find("os:redhat"), ["db1"])
        self.assertEqual(self.find('os:"rocky 9"'), ["db1"])
        self.assertEqual(self.find("os!=ubuntu"), ["db1", "new1"])
        self.assertEqual(self.find("arch:aarch64"), ["db1"])
        self.assertEqual(self.find("virt:kvm"), ["web1"])
        self.assertEqual(self.find("cpus>=8"), ["db1"])
        self.assertEqual(self.find("cpus:4"), ["web1"])
        self.assertEqual(self.find("ip:10.0."), ["db1", "new1", "web1"])
        self.assertEqual(self.find("ip:fd00::11"), ["web1"])
        self.assertEqual(self.find("facts:none"), ["new1"])
        self.assertEqual(self.find("ansible_selinux.status:enabled"), ["db1"])
        self.assertEqual(self.find("ansible_processor_vcpus>4"), ["db1"])

    def test_ram_is_compared_as_shown_rounded(self):
        # 7951 MB is shown as 8 GB, so it is an 8 GB machine.
        self.assertEqual(self.find("ram>=8"), ["db1", "web1"])
        self.assertEqual(self.find("ram:8"), ["web1"])
        self.assertEqual(self.find("ram<8"), [])
        self.assertEqual(self.find("ram>8"), ["db1"])

    def test_free_words_search_names_and_facts(self):
        self.assertEqual(self.find("frontend"), ["web1"])
        self.assertEqual(self.find("jammy"), ["db1", "web1"])
        self.assertEqual(self.find("qemu -db1"), ["web1"])
        # An IPv6 address is a word, not a filter called "fd00".
        self.assertEqual(self.find("fd00::11"), ["web1"])

    def test_mistakes_are_reported(self):
        self.assertEqual(len(facts.parse("cpu>=4").errors), 1)  # cpu is the model; cpus counts
        self.assertEqual(len(facts.parse("ram>=lots").errors), 1)
        self.assertEqual(len(facts.parse("facts:maybe").errors), 1)
        self.assertEqual(len(facts.parse("bogus>=1").errors), 1)


class ViewTests(TestCase):
    def setUp(self):
        self.lab = HostGroup.objects.create(name="lab")
        self.host = Host.objects.create(name="web1")
        self.host.groups.add(self.lab)
        self.team = Group.objects.create(name="devs")
        self.user = User.objects.create_user("dev", password="Dev-pass-123")
        self.user.groups.add(self.team)
        self.grant = GroupGrant.objects.create(team=self.team, host_group=self.lab, role=Role.VIEWER)
        self.client.force_login(self.user)

    def test_pages_show_the_facts(self):
        page = self.client.get(f"/inventory/hosts/{self.host.pk}/")
        self.assertContains(page, "No facts yet")
        self.assertNotContains(page, "Gather facts</button>")
        facts.record(self.host, sample())
        page = self.client.get(f"/inventory/hosts/{self.host.pk}/")
        self.assertContains(page, "Ubuntu 22.04")
        self.assertContains(page, "1d 1h")
        self.assertContains(page, "/srv")
        page = self.client.get(f"/inventory/hosts/{self.host.pk}/facts/")
        self.assertContains(page, "ansible_selinux.status")
        listing = self.client.get("/inventory/hosts/", {"q": "ram>=8 os:ubuntu"})
        self.assertContains(listing, "web1")
        self.assertContains(listing, "4 vCPU")
        self.assertContains(self.client.get("/inventory/hosts/", {"q": "os:windows"}), "No hosts match")
        self.assertContains(self.client.get("/inventory/hosts/", {"q": "cpus>=many"}), "takes a number")

    @patch("runs.executor.dispatch")
    def test_gathering_takes_an_operator(self, dispatch):
        url = f"/inventory/hosts/{self.host.pk}/facts/gather/"
        self.assertEqual(self.client.post(url).status_code, 403)
        self.assertEqual(self.client.post(f"/inventory/groups/{self.lab.pk}/gather-facts/").status_code, 403)
        self.grant.role = Role.OPERATOR
        self.grant.save()
        response = self.client.post(url)
        job = Job.objects.get()
        self.assertRedirects(response, job.get_absolute_url(), fetch_redirect_response=False)
        self.assertEqual(job.kind, Job.KIND_FACTS)
        self.assertEqual(list(job.target_hosts.all()), [self.host])
        self.client.post(f"/inventory/groups/{self.lab.pk}/gather-facts/")
        self.assertEqual(list(Job.objects.first().target_groups.all()), [self.lab])
        self.assertEqual(dispatch.call_count, 2)

    @patch("runs.executor.dispatch")
    def test_a_disabled_host_is_not_contacted(self, dispatch):
        self.grant.role = Role.OPERATOR
        self.grant.save()
        self.host.enabled = False
        self.host.save()
        self.client.post(f"/inventory/hosts/{self.host.pk}/facts/gather/")
        self.client.post(f"/inventory/groups/{self.lab.pk}/gather-facts/")
        self.assertFalse(Job.objects.exists())


class ApiTests(TestCase):
    def setUp(self):
        self.lab = HostGroup.objects.create(name="lab")
        self.host = Host.objects.create(name="web1")
        self.host.groups.add(self.lab)
        self.other = Host.objects.create(name="db1")
        facts.record(self.other, sample())
        team = Group.objects.create(name="devs")
        self.grant = GroupGrant.objects.create(team=team, host_group=self.lab, role=Role.VIEWER)
        user = User.objects.create_user("dev", password="Dev-pass-123")
        user.groups.add(team)
        self.api = APIClient()
        _, raw = ApiToken.issue(user, "test")
        self.api.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")

    def test_facts_are_listed_searched_and_read_within_rights(self):
        facts.record(self.host, sample())
        hosts = self.api.get("/api/v1/hosts/", {"q": "os:ubuntu ram>=8"}).json()["results"]
        # db1 matches too, but is not this user's to see.
        self.assertEqual([h["name"] for h in hosts], ["web1"])
        self.assertEqual(hosts[0]["facts"]["cpu_count"], 4)
        self.assertNotIn("facts", hosts[0]["facts"])
        full = self.api.get(f"/api/v1/hosts/{self.host.pk}/facts/").json()
        self.assertEqual(full["facts"]["ansible_selinux"]["status"], "disabled")
        self.assertEqual(self.api.get(f"/api/v1/hosts/{self.other.pk}/facts/").status_code, 404)
        self.assertEqual(self.api.get("/api/v1/hosts/", {"q": "cpus>=x"}).status_code, 400)

    def test_a_host_without_facts(self):
        self.assertIsNone(self.api.get(f"/api/v1/hosts/{self.host.pk}/").json()["facts"])
        self.assertEqual(self.api.get(f"/api/v1/hosts/{self.host.pk}/facts/").status_code, 404)

    @patch("runs.executor.dispatch")
    def test_gathering(self, dispatch):
        self.assertEqual(self.api.post(f"/api/v1/hosts/{self.host.pk}/gather_facts/").status_code, 403)
        self.grant.role = Role.OPERATOR
        self.grant.save()
        response = self.api.post(f"/api/v1/hosts/{self.host.pk}/gather_facts/")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["kind"], Job.KIND_FACTS)
        self.assertEqual(self.api.post(f"/api/v1/groups/{self.lab.pk}/gather_facts/").status_code, 201)


class LiveGatheringTests(TestCase):
    """The whole way: a real ansible-playbook run on this machine."""

    def test_a_gather_run_fills_in_the_host(self):
        host = Host.objects.create(name="localhost-facts", address="127.0.0.1",
                                   variables={"ansible_connection": "local"})
        with patch("runs.executor.dispatch"):
            job = facts.start(None, hosts=[host])
        self.assertEqual(run_job(job.pk), Job.SUCCESSFUL, job.events.values_list("stdout", flat=True))
        stored = HostFacts.objects.get(host=host)
        self.assertEqual(stored.job_id, job.pk)
        self.assertTrue(stored.kernel)
        self.assertTrue(stored.memory_mb)
        self.assertGreater(len(stored.facts), 50)
