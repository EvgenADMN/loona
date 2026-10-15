# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Scheduled runs, cron expressions and maintenance windows."""
import unittest
from datetime import datetime, time, timedelta
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from access import approvals
from access.models import GroupGrant, MaintenanceWindow, Role
from core.cron import Cron, CronError
from inventory.models import Host, HostGroup
from playbooks.models import Playbook, PlaybookTask

from . import plans, schedules, services
from .models import Job, Schedule

UTC = ZoneInfo("UTC")


class CronTests(unittest.TestCase):
    def next(self, expression, after, zone="UTC"):
        return Cron.parse(expression).next_after(after, zone)

    def test_next_times(self):
        thursday = datetime(2026, 10, 15, 12, 30, tzinfo=UTC)
        self.assertEqual(self.next("0 3 * * mon-fri", thursday), datetime(2026, 10, 16, 3, 0, tzinfo=UTC))
        self.assertEqual(self.next("*/15 * * * *", thursday), datetime(2026, 10, 15, 12, 45, tzinfo=UTC))
        self.assertEqual(self.next("@weekly", thursday), datetime(2026, 10, 18, 0, 0, tzinfo=UTC))
        self.assertEqual(self.next("0 0 29 2 *", thursday), datetime(2028, 2, 29, 0, 0, tzinfo=UTC))
        # Strictly after: the minute itself does not count.
        self.assertEqual(self.next("30 12 * * *", thursday), datetime(2026, 10, 16, 12, 30, tzinfo=UTC))

    def test_both_day_fields_mean_either(self):
        # The 1st of the month or any Monday, as cron has it.
        self.assertEqual(self.next("0 9 1 * mon", datetime(2026, 10, 15, tzinfo=UTC)),
                         datetime(2026, 10, 19, 9, 0, tzinfo=UTC))

    def test_local_time_and_dst(self):
        berlin = ZoneInfo("Europe/Berlin")
        got = self.next("30 3 * * *", datetime(2026, 10, 15, 12, 0, tzinfo=UTC), "Europe/Berlin")
        self.assertEqual(got.astimezone(berlin).replace(tzinfo=None), datetime(2026, 10, 16, 3, 30))
        # 02:30 does not exist on 2027-03-28 in Berlin; that day is skipped.
        got = self.next("30 2 * * *", datetime(2027, 3, 27, 12, 0, tzinfo=UTC), "Europe/Berlin")
        self.assertEqual(got.astimezone(berlin).date().isoformat(), "2027-03-29")

    def test_mistakes_are_explained(self):
        for bad, words in [("* * *", "Five fields"), ("61 * * * *", "0-59"), ("0 3 * * funday", "day of week"),
                           ("*/0 * * * *", "step"), ("5-1 * * * *", "backwards")]:
            with self.assertRaisesRegex(CronError, words, msg=bad):
                Cron.parse(bad)


class WindowTests(unittest.TestCase):
    def window(self, days, start, end, zone="UTC"):
        return MaintenanceWindow(weekdays=days, start=time(*start), end=time(*end), timezone=zone)

    def test_same_day(self):
        w = self.window([5], (2, 0), (6, 0))  # Saturday 02:00-06:00
        self.assertTrue(w.contains(datetime(2026, 10, 17, 2, 0, tzinfo=UTC)))
        self.assertFalse(w.contains(datetime(2026, 10, 17, 6, 0, tzinfo=UTC)))
        self.assertFalse(w.contains(datetime(2026, 10, 18, 3, 0, tzinfo=UTC)))

    def test_past_midnight(self):
        w = self.window([5], (22, 0), (4, 0))  # Saturday 22:00 - Sunday 04:00
        self.assertTrue(w.contains(datetime(2026, 10, 17, 23, 0, tzinfo=UTC)))
        self.assertTrue(w.contains(datetime(2026, 10, 18, 3, 59, tzinfo=UTC)))
        self.assertFalse(w.contains(datetime(2026, 10, 17, 3, 0, tzinfo=UTC)))
        self.assertFalse(w.contains(datetime(2026, 10, 18, 22, 30, tzinfo=UTC)))

    def test_in_its_own_time_zone(self):
        w = self.window([0, 1, 2, 3, 4], (9, 0), (17, 0), "Asia/Tokyo")
        self.assertTrue(w.contains(datetime(2026, 10, 15, 1, 0, tzinfo=UTC)))  # 10:00 in Tokyo
        self.assertFalse(w.contains(datetime(2026, 10, 15, 12, 0, tzinfo=UTC)))  # 21:00 in Tokyo


def _closed(group):
    """A window that is not open now: only on the day after tomorrow."""
    day = (timezone.now().weekday() + 2) % 7
    return MaintenanceWindow.objects.create(host_group=group, weekdays=[day], start=time(0, 0), end=time(0, 0))


def _open(group):
    return MaintenanceWindow.objects.create(host_group=group, weekdays=list(range(7)), start=time(0, 0), end=time(0, 0))


class Base(TestCase):
    def setUp(self):
        User = get_user_model()
        self.prod = HostGroup.objects.create(name="prod", approval_policy=HostGroup.APPROVAL_NONE)
        self.web = HostGroup.objects.create(name="web", approval_policy=HostGroup.APPROVAL_NONE)
        self.web.parents.add(self.prod)
        self.host = Host.objects.create(name="h1", variables={"ansible_connection": "local"})
        self.host.groups.add(self.web)
        self.playbook = Playbook.objects.create(name="Patch")
        PlaybookTask.objects.create(playbook=self.playbook, order=0, module="ansible.builtin.ping")
        ops = Group.objects.create(name="ops")
        GroupGrant.objects.create(team=ops, host_group=self.prod, role=Role.ADMIN)
        self.alice = User.objects.create_user("alice", password="pw")
        self.bob = User.objects.create_user("bob", password="pw")
        for user in (self.alice, self.bob):
            user.groups.add(ops)
        patcher = patch("runs.services.dispatch")
        self.dispatched = patcher.start()
        self.addCleanup(patcher.stop)

    def launch_form(self, user):
        from .forms import JobLaunchForm

        form = JobLaunchForm({"target_groups": [self.web.pk], "target_hosts": [], "limit": "", "extra_vars": "",
                              "tags": "", "skip_tags": "", "forks": 5, "verbosity": 0}, user=user)
        self.assertTrue(form.is_valid(), form.errors)
        return form


class WindowRuleTests(Base):
    def test_no_windows_no_restriction(self):
        self.assertIsNone(approvals.run_now_refusal([self.web], []))
        services.launch(self.launch_form(self.alice), self.playbook, self.alice, preview=False)

    def test_outside_a_parents_window_run_now_is_off(self):
        _closed(self.prod)
        with self.assertRaisesRegex(services.Refused, "prod is outside its maintenance windows"):
            services.launch(self.launch_form(self.alice), self.playbook, self.alice, preview=False)

    def test_inside_the_window_it_runs(self):
        _open(self.prod)
        services.launch(self.launch_form(self.alice), self.playbook, self.alice, preview=False)

    def test_a_preview_outside_needs_approval_and_then_applies(self):
        _closed(self.prod)
        plan = services.launch(self.launch_form(self.alice), self.playbook, self.alice, preview=True)
        Job.objects.filter(pk=plan.pk).update(status=Job.SUCCESSFUL, resolved_hosts=["h1"],
                                              stats={"changed": {"h1": 1}, "ok": {"h1": 1}})
        plan.refresh_from_db()
        self.assertIn("outside its maintenance windows", approvals.requirement(plan))
        with self.assertRaisesRegex(plans.CannotApply, "not been approved"):
            services.apply(plan, self.alice)
        with self.assertRaises(services.Refused):
            services.decide(plan, self.alice, approve=True)  # not their own
        _, job = services.decide(plan, self.bob, approve=True)
        self.assertEqual(job.plan, plan)

    def test_once_the_window_opens_no_approval_is_needed(self):
        window = _closed(self.prod)
        plan = services.launch(self.launch_form(self.alice), self.playbook, self.alice, preview=True)
        Job.objects.filter(pk=plan.pk).update(status=Job.SUCCESSFUL, resolved_hosts=["h1"],
                                              stats={"changed": {"h1": 1}, "ok": {"h1": 1}})
        plan.refresh_from_db()
        window.weekdays = list(range(7))
        window.save()
        self.assertIsNone(approvals.requirement(plan))
        services.apply(plan, self.alice)


class ScheduleRunTests(Base):
    def schedule(self, **fields):
        return Schedule.objects.create(**{"name": "nightly", "playbook": self.playbook, "host_group": self.web,
                                          "cron": "0 3 * * *", "run_as": self.alice, **fields})

    def test_first_tick_only_plans_ahead(self):
        schedule = self.schedule()
        self.assertEqual(schedules.run_due(), 0)
        schedule.refresh_from_db()
        self.assertGreater(schedule.next_run_at, timezone.now())

    def test_a_due_schedule_starts_once(self):
        schedule = self.schedule(next_run_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(schedules.run_due(), 1)
        self.assertEqual(schedules.run_due(), 0)
        schedule.refresh_from_db()
        job = schedule.last_job
        self.assertEqual((job.schedule, job.created_by, job.check_mode), (schedule, self.alice, False))
        self.assertIn("schedule nightly", job.playbook_name)
        self.assertGreater(schedule.next_run_at, timezone.now())

    def test_a_long_missed_run_is_skipped_and_said_so(self):
        schedule = self.schedule(next_run_at=timezone.now() - timedelta(hours=5))
        self.assertEqual(schedules.run_due(), 0)
        schedule.refresh_from_db()
        self.assertIn("scheduler was not running", schedule.last_note)
        self.assertFalse(Job.objects.exists())

    def test_outside_the_window_it_becomes_a_preview(self):
        _closed(self.prod)
        schedule = self.schedule(next_run_at=timezone.now())
        schedules.run_due()
        schedule.refresh_from_db()
        self.assertTrue(schedule.last_job.check_mode)
        self.assertIn("applying it needs approval", schedule.last_note)

    def test_preview_only(self):
        schedule = self.schedule(action=Schedule.PREVIEW)
        schedules.fire(schedule)
        self.assertTrue(Job.objects.get().is_plan)

    def test_not_while_the_last_run_is_going(self):
        schedule = self.schedule()
        schedules.fire(schedule)
        schedule.refresh_from_db()
        self.assertIsNone(schedules.fire(schedule))
        schedule.refresh_from_db()
        self.assertIn("still going", schedule.last_note)
        self.assertEqual(Job.objects.count(), 1)

    def test_an_owner_without_rights_starts_nothing(self):
        schedule = self.schedule()
        self.alice.groups.clear()
        self.assertIsNone(schedules.fire(Schedule.objects.get(pk=schedule.pk)))
        schedule.refresh_from_db()
        self.assertIn("may no longer run", schedule.last_note)


class SchedulePageTests(Base):
    def data(self, **extra):
        return {"name": "nightly", "playbook": self.playbook.pk, "host_group": self.web.pk, "action": "run",
                "cron": "0 3 * * mon-fri", "timezone": "Europe/Berlin", "limit": "", "tags": "",
                "skip_tags": "", "extra_vars": "", "enabled": "on", **extra}

    def test_create_and_list(self):
        self.client.force_login(self.alice)
        response = self.client.post(reverse("schedule_create"), self.data())
        self.assertRedirects(response, reverse("schedule_list"))
        schedule = Schedule.objects.get()
        local = schedule.next_run_at.astimezone(ZoneInfo("Europe/Berlin"))
        self.assertEqual((local.hour, local.minute), (3, 0))
        self.assertLess(local.weekday(), 5)
        self.assertContains(self.client.get(reverse("schedule_list")), "0 3 * * mon-fri")

    def test_bad_cron_and_zone_are_refused(self):
        self.client.force_login(self.alice)
        response = self.client.post(reverse("schedule_create"), self.data(cron="every night", timezone="Mars/Base"))
        self.assertContains(response, "Five fields")
        self.assertContains(response, "Not a time zone")

    def test_extra_vars_are_checked_like_a_launch(self):
        self.client.force_login(self.alice)
        response = self.client.post(reverse("schedule_create"), self.data(extra_vars="ansible_user: root"))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Schedule.objects.exists())

    def test_saving_someone_elses_schedule_makes_it_yours(self):
        schedule = Schedule.objects.create(name="n", playbook=self.playbook, host_group=self.web,
                                           cron="@daily", run_as=self.alice)
        self.client.force_login(self.bob)
        self.client.post(reverse("schedule_update", args=[schedule.pk]), self.data())
        schedule.refresh_from_db()
        self.assertEqual(schedule.run_as, self.bob)

    def test_a_viewer_cannot_manage(self):
        viewer = get_user_model().objects.create_user("vic", password="pw")
        team = Group.objects.create(name="viewers")
        GroupGrant.objects.create(team=team, host_group=self.prod, role=Role.VIEWER)
        viewer.groups.add(team)
        schedule = Schedule.objects.create(name="n", playbook=self.playbook, host_group=self.web,
                                           cron="@daily", run_as=self.alice)
        self.client.force_login(viewer)
        self.assertContains(self.client.get(reverse("schedule_list")), "n")
        self.assertEqual(self.client.post(reverse("schedule_run", args=[schedule.pk])).status_code, 403)
        self.assertEqual(self.client.post(reverse("schedule_delete", args=[schedule.pk])).status_code, 403)

    def test_windows_on_the_group_page_superuser_only(self):
        root = get_user_model().objects.create_superuser("root", password="pw")
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(reverse("window_add", args=[self.prod.pk])).status_code, 403)
        self.client.force_login(root)
        self.client.post(reverse("window_add", args=[self.prod.pk]),
                         {"weekdays": [5], "start": "22:00", "end": "04:00", "timezone": "UTC", "description": "Sat night"})
        self.assertEqual(MaintenanceWindow.objects.get().days_label, "Sat")
        page = self.client.get(reverse("group_detail", args=[self.web.pk]))
        self.assertContains(page, "from prod")
        self.assertContains(page, "22:00-04:00")


class ScheduleApiTests(Base):
    def test_create_and_read(self):
        from api.models import ApiToken

        token = ApiToken.issue(self.alice, "t")[1]
        response = self.client.post(reverse("api-schedule-list"),
                                    {"name": "n", "playbook": "Patch", "group": "web", "cron": "@daily"},
                                    content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {token}")
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()["run_as"], "alice")
        self.assertIsNotNone(response.json()["next_run_at"])
        groups = self.client.get(reverse("api-group-list"), HTTP_AUTHORIZATION=f"Bearer {token}").json()
        self.assertIn("maintenance_windows", (groups.get("results") or groups)[0])


class WorkflowScheduleTests(Base):
    """A schedule can start a workflow instead of a playbook."""

    def setUp(self):
        super().setUp()
        from workflows.models import Step, Workflow

        self.workflow = Workflow.objects.create(name="Deploy", host_group=self.web)
        Step.objects.create(workflow=self.workflow, name="patch", kind=Step.PLAYBOOK,
                            playbook=self.playbook, host_group=self.web)

    def schedule(self, **fields):
        return Schedule.objects.create(**{"name": "nightly deploy", "workflow": self.workflow,
                                          "host_group": self.web, "cron": "0 3 * * *",
                                          "run_as": self.alice, **fields})

    def test_a_due_schedule_starts_the_workflow(self):
        schedule = self.schedule(next_run_at=timezone.now() - timedelta(minutes=1),
                                 extra_vars={"version": "1.5"})
        self.assertEqual(schedules.run_due(), 1)
        schedule.refresh_from_db()
        run = schedule.last_workflow_run
        self.assertEqual((run.workflow, run.created_by, run.schedule), (self.workflow, self.alice, schedule))
        self.assertEqual(run.extra_vars, {"version": "1.5"})
        self.assertEqual(run.nodes.get().job.created_by, self.alice)

    def test_not_while_the_last_run_is_going(self):
        schedule = self.schedule()
        self.assertIsNotNone(schedules.fire(schedule))
        schedule.refresh_from_db()
        self.assertIsNone(schedules.fire(schedule))
        schedule.refresh_from_db()
        self.assertIn("still going", schedule.last_note)

    def test_an_owner_without_rights_on_a_step_starts_nothing(self):
        from workflows.models import Step

        other = HostGroup.objects.create(name="other")
        Step.objects.create(workflow=self.workflow, name="elsewhere", kind=Step.PLAYBOOK,
                            playbook=self.playbook, host_group=other)
        schedule = self.schedule()
        self.assertIsNone(schedules.fire(schedule))
        schedule.refresh_from_db()
        self.assertIn("Not started", schedule.last_note)

    def test_create_from_the_page(self):
        self.client.force_login(self.alice)
        response = self.client.post(reverse("schedule_create"), {
            "name": "nightly", "what": "workflow", "workflow": self.workflow.pk, "playbook": self.playbook.pk,
            "host_group": "", "action": "preview", "cron": "@daily", "timezone": "UTC", "limit": "web",
            "tags": "", "skip_tags": "", "extra_vars": "", "enabled": "on"})
        self.assertRedirects(response, reverse("schedule_list"))
        schedule = Schedule.objects.get()
        self.assertEqual((schedule.workflow, schedule.playbook, schedule.host_group), (self.workflow, None, self.web))
        self.assertEqual((schedule.action, schedule.limit), (Schedule.RUN, ""))
        page = self.client.get(reverse("schedule_list"))
        self.assertContains(page, "workflow <a")
        self.assertContains(self.client.get(reverse("schedule_create") + f"?workflow={self.workflow.pk}"),
                            'value="workflow" id="id_what_1" checked')

    def test_a_workflow_must_be_picked(self):
        self.client.force_login(self.alice)
        response = self.client.post(reverse("schedule_create"), {
            "name": "n", "what": "workflow", "workflow": "", "cron": "@daily", "timezone": "UTC",
            "action": "run", "extra_vars": ""})
        self.assertContains(response, "Pick the workflow")

    def test_run_now_opens_the_workflow_run(self):
        schedule = self.schedule()
        self.client.force_login(self.alice)
        response = self.client.post(reverse("schedule_run", args=[schedule.pk]))
        schedule.refresh_from_db()
        self.assertRedirects(response, schedule.last_workflow_run.get_absolute_url(), fetch_redirect_response=False)

    def test_api(self):
        from api.models import ApiToken

        token = ApiToken.issue(self.alice, "t")[1]
        response = self.client.post(reverse("api-schedule-list"),
                                    {"name": "n", "workflow": "Deploy", "cron": "@daily"},
                                    content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {token}")
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual((response.json()["workflow"], response.json()["group"]), ("Deploy", "web"))
