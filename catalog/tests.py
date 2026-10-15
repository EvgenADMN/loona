# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The catalog: from a request to a host, and back out."""
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import LiveServerTestCase, TestCase, override_settings
from rest_framework.test import APIClient

from access import approvals
from access.models import GroupGrant, Role
from api.models import ApiToken
from infra import lifecycle
from infra.models import TofuFile, TofuProject
from infra.services import start_plan
from inventory.models import Host, HostGroup
from runs import executor, plans
from runs import services as run_services
from runs.models import Job

from . import services
from .models import CatalogItem, CatalogRequest

User = get_user_model()
SIZE = {"variable": "size", "label": "Size", "type": "choice", "choices": ["small", "large"],
        "required": True}


class CatalogTestCase(TestCase):
    def setUp(self):
        self.infra = HostGroup.objects.create(name="infra", approval_policy=HostGroup.APPROVAL_NONE)
        self.vms = HostGroup.objects.create(name="vms")
        self.vms.parents.add(self.infra)
        self.project = TofuProject.objects.create(name="cloud", host_group=self.infra)
        self.requesters = Group.objects.create(name="requesters")
        self.admins = Group.objects.create(name="admins")
        GroupGrant.objects.create(team=self.admins, host_group=self.infra, role=Role.ADMIN)
        self.item = CatalogItem.objects.create(name="Small VM", tofu_project=self.project,
                                               host_group=self.vms, fields=[SIZE])
        self.item.teams.add(self.requesters)
        self.alice = User.objects.create_user("alice", password="Alice-pass-123")
        self.alice.groups.add(self.requesters)
        self.boss = User.objects.create_user("boss", password="Boss-pass-123")
        self.boss.groups.add(self.admins)
        self.stranger = User.objects.create_user("eve", password="Eve-pass-123")

    def submit(self, name="vm1", user=None, size="small"):
        with patch("runs.executor.dispatch"), self.captureOnCommitCallbacks(execute=True):
            return services.submit(self.item, user or self.alice, name, {"size": size})

    def finish_plan(self, request, add=1, destroy=0, change=0, ok=True):
        job = request.job
        job.status = Job.SUCCESSFUL if ok else Job.FAILED
        job.resolved_hosts = []
        job.stats = {"tofu": {"add": add, "change": change, "destroy": destroy,
                              "has_changes": bool(add or destroy or change), "resources": []}}
        job.tofu_plan_encrypted = "x"
        job.save()
        with patch("runs.executor.dispatch"):
            services.on_job_finished(job)
        request.refresh_from_db()
        return job

    def finish_apply(self, request, address="10.0.0.9", ok=True):
        job = request.job
        if ok and not request.retiring:
            host = Host.objects.create(name=request.name, address=address, tofu_project=self.project)
            host.groups.add(self.infra, self.vms)
        if ok and request.retiring:
            Host.objects.filter(name=request.name).delete()
        job.status = Job.SUCCESSFUL if ok else Job.FAILED
        job.save()
        services.on_job_finished(job)
        request.refresh_from_db()


class FlowTests(CatalogTestCase):
    def test_request_plan_approve_apply_retire(self):
        request = self.submit()
        self.assertEqual(request.status, CatalogRequest.PLANNING)
        plan = request.job
        self.assertEqual((plan.kind, plan.catalog_request, plan.created_by),
                         (Job.KIND_TOFU_PLAN, request, self.alice))

        self.finish_plan(request)
        self.assertEqual(request.status, CatalogRequest.WAITING)
        self.assertIn("need an admin", approvals.requirement(plan))
        # The requester made the plan, so cannot approve it; an admin can.
        self.assertIsNotNone(approvals.why_not_approver(self.alice, plan))
        with patch("runs.services.dispatch"):
            _, apply_job = run_services.decide(plan, self.boss, approve=True)
        request.refresh_from_db()
        self.assertEqual((request.status, request.job), (CatalogRequest.APPLYING, apply_job))
        self.assertEqual(apply_job.catalog_request, request)

        self.finish_apply(request)
        self.assertEqual((request.status, request.address), (CatalogRequest.ACTIVE, "10.0.0.9"))
        self.assertEqual(request.host.name, "vm1")

        with patch("runs.executor.dispatch"):
            services.retire(request, self.alice)
        request.refresh_from_db()
        self.assertTrue(request.retiring)
        self.assertEqual(request.stage, "Retiring: planning")
        self.finish_plan(request, add=0, destroy=1)
        self.assertEqual(request.status, CatalogRequest.WAITING)
        with patch("runs.services.dispatch"):
            run_services.decide(request.job, self.boss, approve=True)
        request.refresh_from_db()
        self.finish_apply(request)
        self.assertEqual(request.status, CatalogRequest.RETIRED)
        self.assertFalse(Host.objects.filter(name="vm1").exists())

    def test_rejections(self):
        request = self.submit()
        self.finish_plan(request)
        run_services.decide(request.job, self.boss, approve=False, comment="too big")
        request.refresh_from_db()
        self.assertEqual(request.status, CatalogRequest.REJECTED)
        self.assertIn("too big", request.error)
        # The name is free again.
        self.assertFalse(services.name_taken("vm1"))

        active = CatalogRequest.objects.create(item=self.item, requested_by=self.alice, name="vm2",
                                               status=CatalogRequest.ACTIVE)
        with patch("runs.executor.dispatch"):
            services.retire(active, self.alice)
        active.refresh_from_db()
        self.finish_plan(active, add=0, destroy=1)
        run_services.decide(active.job, self.boss, approve=False)
        active.refresh_from_db()
        self.assertEqual((active.status, active.retiring), (CatalogRequest.ACTIVE, False))

    def test_without_approval_a_clean_plan_applies_itself(self):
        self.item.approval_required = False
        self.item.save()
        request = self.submit()
        with patch("runs.executor.dispatch") as dispatch:
            job = request.job
            job.status, job.tofu_plan_encrypted = Job.SUCCESSFUL, "x"
            job.stats = {"tofu": {"add": 1, "change": 0, "destroy": 0, "has_changes": True}}
            job.save()
            services.on_job_finished(job)
        request.refresh_from_db()
        self.assertEqual(request.status, CatalogRequest.APPLYING)
        self.assertEqual(request.job.plan, job)
        dispatch.assert_called_once()

        # A plan that would also destroy something waits for an admin all the same.
        other = self.submit("vm3")
        self.finish_plan(other, add=1, destroy=1)
        self.assertEqual(other.status, CatalogRequest.WAITING)

    def test_failures_are_explained_and_can_be_retried(self):
        request = self.submit()
        self.finish_plan(request, ok=False)
        self.assertEqual(request.status, CatalogRequest.FAILED)
        with patch("runs.executor.dispatch"):
            services.retry(request, self.alice)
        request.refresh_from_db()
        self.finish_plan(request, add=0)
        self.assertIn("var.loona_requests", request.error)

        request = self.submit("vm4")
        self.finish_plan(request)
        with patch("runs.services.dispatch"):
            run_services.decide(request.job, self.boss, approve=True)
        request.refresh_from_db()
        job = request.job
        job.status = Job.SUCCESSFUL
        job.save()
        services.on_job_finished(job)  # applied, but no such host came out
        request.refresh_from_db()
        self.assertIn("loona_hosts output has no vm4", request.error)

    def test_withdraw(self):
        request = self.submit()
        self.finish_plan(request)
        with self.assertRaises(Exception):
            services.withdraw(request, self.stranger)
        services.withdraw(request, self.alice)
        request.refresh_from_db()
        self.assertEqual(request.status, CatalogRequest.REJECTED)

    def test_quota_and_names(self):
        self.item.max_per_user = 1
        self.item.save()
        self.submit("vm1")
        with self.assertRaises(services.Refused):
            self.submit("vm2")
        Host.objects.create(name="taken")
        self.item.max_per_user = 0
        self.item.save()
        with self.assertRaises(services.Refused):
            self.submit("taken")
        with self.assertRaises(services.Refused):
            self.submit("vm1", user=self.boss)

    def test_who_may_request(self):
        self.assertTrue(services.can_request(self.alice, self.item))
        self.assertTrue(services.can_request(self.boss, self.item))  # admin of the group
        self.assertFalse(services.can_request(self.stranger, self.item))
        self.item.enabled = False
        self.item.save()
        self.assertFalse(services.can_request(self.alice, self.item))


class VariableTests(CatalogTestCase):
    def test_every_plan_is_told_what_exists(self):
        def make(name, status, retiring=False):
            return CatalogRequest.objects.create(item=self.item, requested_by=self.alice, name=name,
                                                 status=status, retiring=retiring, values={"size": "large", "n": 2, "ok": True})
        make("active1", CatalogRequest.ACTIVE)
        make("applying1", CatalogRequest.APPLYING)
        make("waiting1", CatalogRequest.WAITING)
        make("failed1", CatalogRequest.FAILED)
        make("retiring1", CatalogRequest.WAITING, retiring=True)
        make("gone1", CatalogRequest.RETIRED, retiring=True)
        mine = make("mine", CatalogRequest.PLANNING)

        by_hand = start_plan(self.project, self.boss)
        found = services.requests_for(by_hand)
        self.assertEqual(sorted(found), ["active1", "applying1", "retiring1"])
        self.assertEqual(found["active1"], {"name": "active1", "item": "Small VM", "owner": "alice",
                                            "values": {"size": "large", "n": "2", "ok": "true"}})
        by_hand.catalog_request = mine
        self.assertIn("mine", services.requests_for(by_hand))
        mine.retiring = True
        self.assertNotIn("mine", services.requests_for(by_hand))

        lonely = TofuProject.objects.create(name="other", host_group=self.infra)
        self.assertIsNone(services.requests_for(start_plan(lonely, self.boss)))

    def test_hosts_join_the_items_group(self):
        CatalogRequest.objects.create(item=self.item, requested_by=self.alice, name="vm1",
                                      status=CatalogRequest.APPLYING)
        lifecycle.sync(self.project, {"vm1": {"address": "10.0.0.1"}, "plain": {"address": "10.0.0.2"}})
        self.assertEqual({g.name for g in Host.objects.get(name="vm1").groups.all()}, {"infra", "vms"})
        self.assertEqual({g.name for g in Host.objects.get(name="plain").groups.all()}, {"infra"})


class ViewTests(CatalogTestCase):
    def test_requesting_through_the_pages(self):
        self.client.force_login(self.alice)
        self.assertContains(self.client.get("/catalog/"), "Small VM")
        page = self.client.get(f"/catalog/items/{self.item.pk}/request/")
        self.assertContains(page, "Machine name")
        self.assertContains(page, "large")
        self.assertContains(self.client.post(f"/catalog/items/{self.item.pk}/request/",
                                             {"name": "bad name", "q_size": "small"}), "Use letters")
        with patch("runs.executor.dispatch"), self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(f"/catalog/items/{self.item.pk}/request/", {"name": "vm1", "q_size": "small"})
        request = CatalogRequest.objects.get()
        self.assertRedirects(response, request.get_absolute_url(), fetch_redirect_response=False)
        page = self.client.get(request.get_absolute_url())
        self.assertContains(page, "Planning")
        # Alice has no role on the project's group, so the run itself is not hers to open.
        self.assertNotContains(page, f'href="/runs/{request.job.pk}/"')
        self.assertEqual(self.client.get(f"/catalog/items/{self.item.pk}/edit/").status_code, 403)

        self.client.force_login(self.stranger)
        self.assertEqual(self.client.get(request.get_absolute_url()).status_code, 404)
        self.assertEqual(self.client.get(f"/catalog/items/{self.item.pk}/request/").status_code, 403)

        self.client.force_login(self.boss)
        self.finish_plan(request)
        page = self.client.get(request.get_absolute_url())
        self.assertContains(page, "Review and approve")
        self.assertContains(self.client.get(request.job.get_absolute_url()), "catalog")
        self.assertContains(self.client.get("/catalog/"), "Requests from others")

    def test_items_are_kept_by_admins(self):
        self.client.force_login(self.boss)
        survey = json.dumps([SIZE, {"variable": "disk", "type": "integer", "min": 10, "max": 100, "default": 20}])
        response = self.client.post("/catalog/items/new/", {
            "name": "Big VM", "tofu_project": self.project.pk, "host_group": "", "teams": [self.requesters.pk],
            "approval_required": "on", "max_per_user": 2, "enabled": "on", "fields_spec": survey,
        })
        self.assertEqual(response.status_code, 302, response.content.decode()[-2000:])
        item = CatalogItem.objects.get(name="Big VM")
        self.assertEqual((item.host_group, item.fields[1]["default"]), (self.infra, 20))
        bad = self.client.post("/catalog/items/new/", {
            "name": "Pw", "tofu_project": self.project.pk, "max_per_user": 0,
            "fields_spec": json.dumps([{"variable": "pw", "type": "password"}]),
        })
        self.assertContains(bad, "cannot ask for a password")
        elsewhere = HostGroup.objects.create(name="elsewhere")
        GroupGrant.objects.create(team=self.admins, host_group=elsewhere, role=Role.ADMIN)
        bad = self.client.post("/catalog/items/new/", {
            "name": "X", "tofu_project": self.project.pk, "host_group": elsewhere.pk, "max_per_user": 0,
            "fields_spec": "[]",
        })
        self.assertContains(bad, "or a group under it")
        self.assertContains(self.client.get("/catalog/items/new/"), "survey-editor.js")


class ApiTests(CatalogTestCase):
    def test_request_list_and_retire(self):
        api = APIClient()
        _, raw = ApiToken.issue(self.alice, "t")
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {raw}")
        self.assertEqual([i["name"] for i in api.get("/api/v1/catalog/items/").json()], ["Small VM"])
        url = f"/api/v1/catalog/items/{self.item.pk}/request/"
        self.assertEqual(api.post(url, {"name": "vm1", "values": {"size": "huge"}}, format="json").json().keys(),
                         {"size"})
        with patch("runs.executor.dispatch"), self.captureOnCommitCallbacks(execute=True):
            response = api.post(url, {"name": "vm1", "values": {"size": "large"}}, format="json")
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()["values"], {"size": "large"})
        listed = api.get("/api/v1/catalog/requests/").json()["results"]
        self.assertEqual(listed[0]["status"], "planning")
        self.assertEqual(api.post(f"/api/v1/catalog/requests/{listed[0]['id']}/retire/").status_code, 409)


CONFIG = """
variable "loona_requests" {
  type = map(object({
    name   = string
    item   = string
    owner  = string
    values = map(string)
  }))
  default = {}
}
resource "terraform_data" "vm" {
  for_each = var.loona_requests
  input    = "${each.value.owner}:${each.value.values["size"]}"
}
output "loona_hosts" {
  value = { for k, vm in terraform_data.vm : k => { address = "127.0.0.1", vars = { spec = vm.output } } }
}
"""


@unittest.skipUnless(shutil.which(settings.LOONA_TOFU_BINARY), "tofu is not installed here")
class LiveTests(LiveServerTestCase):
    """The whole way with the real tofu binary; the machine's SSH setup is not started."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        override = override_settings(LOONA_INTERNAL_URL=self.live_server_url,
                                     LOONA_DATA_DIR=f"{self.tmp.name}/jobs",
                                     LOONA_TOFU_PLUGIN_CACHE=f"{self.tmp.name}/plugins")
        override.enable()
        self.addCleanup(override.disable)
        group = HostGroup.objects.create(name="lab", approval_policy=HostGroup.APPROVAL_NONE)
        self.project = TofuProject.objects.create(name="lab", host_group=group)
        TofuFile.objects.create(project=self.project, path="main.tf", content=CONFIG)
        self.item = CatalogItem.objects.create(name="VM", tofu_project=self.project, host_group=group,
                                               fields=[SIZE], approval_required=False)
        self.user = User.objects.create_superuser("root")
        self.dispatched = []
        for target in ("runs.executor.dispatch", "infra.bootstrap.begin"):
            patcher = patch(target, side_effect=lambda job, *a, **k: self.dispatched.append(job))
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_all(self):
        while self.dispatched:
            job = self.dispatched.pop(0)
            if isinstance(job, Job):
                executor.run_job(job.pk)

    def test_request_to_host_and_back(self):
        request = services.submit(self.item, self.user, "vm1", {"size": "large"})
        self.dispatched.append(request.job)
        self.run_all()
        request.refresh_from_db()
        self.assertEqual(request.status, CatalogRequest.ACTIVE, request.error)
        host = Host.objects.get(name="vm1")
        self.assertEqual(host.variables, {"spec": "root:large"})

        # A plan made by hand keeps the machine.
        by_hand = start_plan(self.project, self.user)
        executor.run_job(by_hand.pk)
        by_hand.refresh_from_db()
        self.assertFalse(by_hand.stats["tofu"]["has_changes"])
        self.assertEqual(by_hand.stats["catalog"], ["vm1"])

        services.retire(request, self.user)
        self.run_all()
        request.refresh_from_db()
        self.assertEqual(request.status, CatalogRequest.RETIRED, request.error)
        self.assertFalse(Host.objects.filter(name="vm1").exists())
