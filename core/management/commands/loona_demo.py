# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Seed a fresh install with something to click on."""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from inventory.models import Credential, Host, HostGroup
from playbooks.models import Playbook, PlaybookTask


class Command(BaseCommand):
    help = "Create a demo user, a localhost target and two example playbooks."

    def add_arguments(self, parser):
        parser.add_argument("--username", default="admin")
        parser.add_argument("--password", default="admin")

    def handle(self, *args, **options):
        User = get_user_model()
        user, created = User.objects.get_or_create(
            username=options["username"],
            defaults={"is_staff": True, "is_superuser": True},
        )
        if created:
            user.set_password(options["password"])
            user.save()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Created superuser {user.username} / {options['password']}"
                )
            )

        group, _ = HostGroup.objects.get_or_create(
            name="local",
            defaults={"description": "The Loona server itself. Handy for smoke tests."},
        )
        host, _ = Host.objects.get_or_create(
            name="localhost",
            defaults={"address": "127.0.0.1", "description": "Local connection"},
        )
        host.variables = {"ansible_connection": "local"}
        host.save()
        host.groups.add(group)

        ping, created = Playbook.objects.get_or_create(
            name="Ping check",
            defaults={
                "description": "Verify Loona can reach the selected hosts.",
                "gather_facts": False,
                "created_by": user,
            },
        )
        if created:
            PlaybookTask.objects.create(
                playbook=ping, order=0, name="Ping the host", module="ansible.builtin.ping"
            )
            PlaybookTask.objects.create(
                playbook=ping,
                order=1,
                name="Report who we are",
                module="ansible.builtin.command",
                args={"cmd": "id"},
                register="whoami",
            )
            PlaybookTask.objects.create(
                playbook=ping,
                order=2,
                name="Show the result",
                module="ansible.builtin.debug",
                args={"var": "whoami.stdout"},
            )

        Playbook.objects.get_or_create(
            name="Raw YAML example",
            defaults={
                "description": "Same idea, written by hand in the YAML editor.",
                "mode": Playbook.MODE_TEXT,
                "created_by": user,
                "text_content": (
                    "---\n"
                    "- name: Raw YAML example\n"
                    "  hosts: all\n"
                    "  gather_facts: true\n"
                    "  tasks:\n"
                    "    - name: Show the distribution\n"
                    "      ansible.builtin.debug:\n"
                    "        msg: \"{{ ansible_distribution }} {{ ansible_distribution_version }}\"\n"
                ),
            },
        )

        self.stdout.write(self.style.SUCCESS("Demo data ready."))
