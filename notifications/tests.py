# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Notifications: who gets told what, and that it really leaves."""
import hashlib
import hmac
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse

from administration import system
from administration.models import AuditEntry
from infra.models import TofuProject
from inventory.models import Host, HostGroup
from runs import executor
from runs.models import DriftCheck, Job, JobEvent
from playbooks.models import Playbook

from . import dispatch, events
from .models import (APPROVAL_NEEDED, BOOTSTRAP_FAILED, DRIFT_DETECTED, DRIFT_RESOLVED,
                     HOST_KEY_CHANGED, RUN_FAILED, Channel, Delivery)


class Receiver:
    """A local HTTP server that records what it is sent."""

    def __init__(self, status=200, answer=b'{"ok": true}'):
        received = self.received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append({"path": self.path, "headers": dict(self.headers), "body": body})
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(answer)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


def channel(kind, events_, groups=(), **config):
    c = Channel(name=f"{kind}-{len(Channel.objects.all())}", kind=kind, events=list(events_))
    c.config = config
    c.save()
    c.host_groups.set(groups)
    return c


def settle(test):
    """Run on_commit callbacks, then deliveries synchronously."""
    for d in Delivery.objects.filter(status=Delivery.PENDING):
        dispatch.deliver(d.pk)


class SendingTests(TestCase):
    def setUp(self):
        self.receiver = Receiver()
        self.addCleanup(self.receiver.close)

    def test_a_webhook_gets_json_signed_with_the_secret(self):
        c = channel(Channel.WEBHOOK, [RUN_FAILED], url=self.receiver.url + "/hook", secret="s3")
        [d] = dispatch.emit(RUN_FAILED, "Run failed: #1 x", "details", "/runs/1/", channels=[c])
        self.assertEqual(dispatch.deliver(d.pk), Delivery.SENT)
        [hit] = self.receiver.received
        payload = json.loads(hit["body"])
        self.assertEqual(payload["event"], RUN_FAILED)
        self.assertIn("Run failed", payload["text"])
        expected = "sha256=" + hmac.new(b"s3", hit["body"], hashlib.sha256).hexdigest()
        self.assertEqual(hit["headers"]["X-Loona-Signature"], expected)

    def test_telegram_gets_the_message_and_the_token_stays_out_of_errors(self):
        with override_settings(LOONA_TELEGRAM_API=self.receiver.url):
            c = channel(Channel.TELEGRAM, [RUN_FAILED], bot_token="123:SECRET", chat_id="-100")
            [d] = dispatch.emit(RUN_FAILED, "Subject", "Body", channels=[c])
            dispatch.deliver(d.pk)
        [hit] = self.receiver.received
        self.assertEqual(hit["path"], "/bot123:SECRET/sendMessage")
        self.assertEqual(json.loads(hit["body"])["chat_id"], "-100")

        broken = Receiver(status=401, answer=b'{"ok": false, "description": "Unauthorized"}')
        self.addCleanup(broken.close)
        with override_settings(LOONA_TELEGRAM_API=broken.url):
            [d] = dispatch.emit(RUN_FAILED, "Subject", "Body", channels=[c])
            dispatch.deliver(d.pk)
        d.refresh_from_db()
        self.assertIn("401", d.error)
        self.assertNotIn("SECRET", d.error)

    @override_settings(LOONA_EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_email_goes_to_every_recipient(self):
        row = system.get()
        row.smtp_host, row.smtp_from = "mail.test", "Loona <loona@test>"
        row.public_url = "https://loona.test"
        row.save()
        c = channel(Channel.EMAIL, [RUN_FAILED], recipients=["a@x.org", "b@x.org"])
        [d] = dispatch.emit(RUN_FAILED, "Run failed: #7 deploy", "It broke.", "/runs/7/", channels=[c])
        dispatch.deliver(d.pk)
        [message] = mail.outbox
        self.assertEqual(message.to, ["a@x.org", "b@x.org"])
        self.assertEqual(message.subject, "[Loona] Run failed: #7 deploy")
        self.assertIn("https://loona.test/runs/7/", message.body)

    def test_a_failing_endpoint_is_retried_then_given_up_on(self):
        broken = Receiver(status=500, answer=b"boom")
        self.addCleanup(broken.close)
        c = channel(Channel.WEBHOOK, [RUN_FAILED], url=broken.url)
        [d] = dispatch.emit(RUN_FAILED, "s", "t", channels=[c])
        statuses = [dispatch.deliver(d.pk) for _ in range(Delivery.MAX_ATTEMPTS)]
        self.assertEqual(statuses, [Delivery.PENDING, Delivery.PENDING, Delivery.FAILED])
        self.assertEqual(len(broken.received), 3)

    def test_emit_never_raises(self):
        with patch.object(dispatch, "_emit", side_effect=RuntimeError("db down")):
            self.assertEqual(dispatch.emit(RUN_FAILED, "s", "t"), [])


class WhoHearsTests(TestCase):
    def setUp(self):
        self.prod = HostGroup.objects.create(name="prod", approval_policy=HostGroup.APPROVAL_NONE)
        self.web = HostGroup.objects.create(name="prod-web", approval_policy=HostGroup.APPROVAL_NONE)
        self.web.parents.add(self.prod)
        self.lab = HostGroup.objects.create(name="lab", approval_policy=HostGroup.APPROVAL_NONE)
        self.host = Host.objects.create(name="web1", variables={"ansible_connection": "local"})
        self.host.groups.add(self.web)
        self.everything = channel(Channel.WEBHOOK, [RUN_FAILED, HOST_KEY_CHANGED], url="http://x")
        self.prod_only = channel(Channel.WEBHOOK, [RUN_FAILED], [self.prod], url="http://x")
        self.lab_only = channel(Channel.WEBHOOK, [RUN_FAILED], [self.lab], url="http://x")
        self.quiet = channel(Channel.WEBHOOK, [DRIFT_DETECTED], url="http://x")

    def failed_job(self):
        job = Job.objects.create(playbook_name="deploy", playbook_yaml="", status=Job.FAILED,
                                 resolved_hosts=["web1"])
        job.target_hosts.add(self.host)
        JobEvent.objects.create(job=job, counter=1, event="runner_on_failed", host="web1",
                                task="Install nginx", failed=True, stdout="fatal")
        return job

    def test_a_failed_run_reaches_the_channels_that_want_it_for_its_groups(self):
        events.job_finished(self.failed_job())
        got = {d.channel for d in Delivery.objects.all()}
        # A channel on prod hears about prod/web; lab and drift-only channels do not.
        self.assertEqual(got, {self.everything, self.prod_only})
        text = Delivery.objects.first().text
        self.assertIn("web1: Install nginx", text)

    def test_a_real_failed_playbook_is_reported(self):
        playbook = Playbook.objects.create(name="broken", mode=Playbook.MODE_TEXT, text_content=(
            "- hosts: all\n  gather_facts: false\n  tasks:\n    - name: Fail on purpose\n"
            "      ansible.builtin.fail:\n        msg: nope\n"))
        job = Job.objects.create(playbook=playbook, playbook_name="broken",
                                 playbook_yaml=playbook.text_content)
        job.target_hosts.add(self.host)
        with tempfile.TemporaryDirectory() as tmp, self.settings(LOONA_DATA_DIR=tmp):
            executor.run_job(job.pk)
        delivery = Delivery.objects.filter(channel=self.everything).get()
        self.assertEqual(delivery.event, RUN_FAILED)
        self.assertIn("web1: Fail on purpose", delivery.text)
        self.assertEqual(delivery.data["job"], job.pk)

    def test_a_host_key_mismatch_is_its_own_alarm(self):
        job = self.failed_job()
        JobEvent.objects.create(job=job, counter=2, event="runner_on_unreachable", host="web1", failed=True,
                                stdout="@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@")
        events.job_finished(job)
        alarm = Delivery.objects.get(event=HOST_KEY_CHANGED)
        self.assertIn("web1", alarm.subject)

    def test_a_plan_waiting_for_approval_is_announced(self):
        HostGroup.objects.filter(pk=self.prod.pk).update(approval_policy=HostGroup.APPROVAL_DESTROY)
        waiting = channel(Channel.WEBHOOK, [APPROVAL_NEEDED], url="http://x")
        project = TofuProject.objects.create(name="web", host_group=self.web)
        plan = Job.objects.create(kind=Job.KIND_TOFU_PLAN, tofu_project=project, playbook_name="web: plan",
                                  status=Job.SUCCESSFUL,
                                  stats={"tofu": {"has_changes": True, "add": 0, "change": 0, "destroy": 3}})
        plan.target_groups.set([self.web])
        events.job_finished(plan)
        d = Delivery.objects.get(channel=waiting)
        self.assertIn("-3", d.text)

    def test_drift_is_told_on_change_not_at_every_check(self):
        told = channel(Channel.WEBHOOK, [DRIFT_DETECTED, DRIFT_RESOLVED], url="http://x")
        check = DriftCheck.objects.create(name="web", playbook=Playbook.objects.create(name="p"),
                                          host_group=self.web)

        def finish(changed_hosts):
            job = Job.objects.create(playbook_name="p", status=Job.SUCCESSFUL, check_mode=True,
                                     drift_check=check,
                                     stats={"changed": {h: 1 for h in changed_hosts}, "ok": {"web1": 1}})
            from runs import drift
            drift.on_finished(job)

        finish(["web1"])
        finish(["web1"])
        finish([])
        self.assertEqual([d.event for d in Delivery.objects.filter(channel=told).order_by("pk")],
                         [DRIFT_DETECTED, DRIFT_RESOLVED])

    def test_a_machine_that_could_not_be_set_up_is_reported(self):
        told = channel(Channel.WEBHOOK, [BOOTSTRAP_FAILED], url="http://x")
        self.host.bootstrap_error = "SSH never came up"
        events.bootstrap_failed(self.host)
        self.assertIn("SSH never came up", Delivery.objects.get(channel=told).text)


class ChannelPageTests(TestCase):
    def setUp(self):
        self.root = get_user_model().objects.create_superuser("root")
        self.client.force_login(self.root)
        self.receiver = Receiver()
        self.addCleanup(self.receiver.close)

    def test_create_keep_secrets_and_send_a_test(self):
        self.client.post(reverse("admin_channel_create"), {
            "name": "ops hook", "kind": "webhook", "enabled": "on", "events": [RUN_FAILED],
            "url": self.receiver.url, "secret": "topsecret"})
        c = Channel.objects.get()
        self.assertEqual(c.config["secret"], "topsecret")
        self.assertNotIn("topsecret", c.config_encrypted)
        self.assertNotIn("topsecret", str(AuditEntry.objects.get().changes))
        # Saving again without retyping the secret keeps it.
        self.client.post(reverse("admin_channel_edit", args=[c.pk]), {
            "name": "ops hook", "kind": "webhook", "enabled": "on", "events": [RUN_FAILED],
            "url": self.receiver.url, "secret": ""})
        c.refresh_from_db()
        self.assertEqual(c.config["secret"], "topsecret")
        response = self.client.post(reverse("admin_channel_test", args=[c.pk]), follow=True)
        self.assertContains(response, "Test sent to ops hook")
        self.assertEqual(len(self.receiver.received), 1)

    def test_no_secret_reaches_the_audit_log(self):
        with override_settings(LOONA_TELEGRAM_API=self.receiver.url):
            self.client.post(reverse("admin_channel_create"), {
                "name": "tg", "kind": "telegram", "enabled": "on", "events": [RUN_FAILED],
                "bot_token": "999:TOKEN", "chat_id": "1"})
        self.client.post(reverse("admin_notifications"), {
            "smtp-smtp_host": "mail.test", "smtp-smtp_port": 587, "smtp-smtp_security": "starttls",
            "smtp-smtp_username": "loona", "smtp-smtp_password": "mailpass", "smtp-smtp_from": ""})
        logged = str(list(AuditEntry.objects.values_list("changes", flat=True)))
        self.assertNotIn("999:TOKEN", logged)
        self.assertNotIn("mailpass", logged)
        self.assertEqual(system.get().smtp_password, "mailpass")

    def test_a_broken_channel_says_why(self):
        c = channel(Channel.WEBHOOK, [RUN_FAILED], url="http://127.0.0.1:9/nothing-here")
        response = self.client.post(reverse("admin_channel_test", args=[c.pk]), follow=True)
        self.assertContains(response, "Could not reach")

    def test_superusers_only(self):
        self.client.force_login(get_user_model().objects.create_user("dev"))
        self.assertEqual(self.client.get(reverse("admin_notifications")).status_code, 403)
