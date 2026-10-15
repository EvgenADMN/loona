# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from . import yaml_io
from .models import Playbook, PlaybookTask


class YamlGenerationTests(TestCase):
    def setUp(self):
        self.playbook = Playbook.objects.create(name="Web setup", become=True)
        PlaybookTask.objects.create(
            playbook=self.playbook,
            order=0,
            name="Install nginx",
            module="ansible.builtin.apt",
            args={"name": "nginx", "state": "present", "update_cache": True},
        )
        PlaybookTask.objects.create(
            playbook=self.playbook,
            order=1,
            name="Start nginx",
            module="ansible.builtin.service",
            args={"name": "nginx", "state": "started"},
            when="ansible_os_family == 'Debian'",
        )

    def test_generated_yaml_is_a_single_play(self):
        play = yaml_io.parse_play(yaml_io.build_yaml(self.playbook))
        self.assertEqual(play["hosts"], "all")
        self.assertTrue(play["become"])
        self.assertEqual(len(play["tasks"]), 2)
        self.assertEqual(play["tasks"][0]["ansible.builtin.apt"]["name"], "nginx")

    def test_disabled_tasks_are_left_out(self):
        self.playbook.tasks.filter(order=1).update(enabled=False)
        play = yaml_io.parse_play(yaml_io.build_yaml(self.playbook))
        self.assertEqual(len(play["tasks"]), 1)

    def test_round_trip_preserves_tasks(self):
        settings, tasks = yaml_io.import_yaml(yaml_io.build_yaml(self.playbook))
        self.assertTrue(settings["become"])
        self.assertEqual([t["module"] for t in tasks],
                         ["ansible.builtin.apt", "ansible.builtin.service"])
        self.assertEqual(tasks[1]["when"], "ansible_os_family == 'Debian'")


class YamlImportTests(TestCase):
    def test_short_module_names_are_expanded(self):
        _, tasks = yaml_io.import_yaml(
            "- hosts: all\n  tasks:\n    - name: Ping\n      ping:\n"
        )
        self.assertEqual(tasks[0]["module"], "ansible.builtin.ping")

    def test_free_form_command_becomes_cmd(self):
        _, tasks = yaml_io.import_yaml(
            "- hosts: all\n  tasks:\n    - command: /usr/bin/uptime\n"
        )
        self.assertEqual(tasks[0]["args"], {"cmd": "/usr/bin/uptime"})

    def test_multiple_plays_are_rejected(self):
        with self.assertRaises(yaml_io.ConversionError):
            yaml_io.import_yaml("- hosts: a\n  tasks: []\n- hosts: b\n  tasks: []\n")

    def test_any_fully_named_module_is_imported_with_all_its_arguments(self):
        _, tasks = yaml_io.import_yaml(
            "- hosts: all\n  tasks:\n    - community.docker.docker_container:\n"
            "        name: web\n        ports: ['80:80']\n"
        )
        self.assertEqual(tasks[0]["module"], "community.docker.docker_container")
        self.assertEqual(tasks[0]["args"], {"name": "web", "ports": ["80:80"]})

    def test_a_short_name_nothing_provides_is_rejected(self):
        with self.assertRaises(yaml_io.ConversionError) as ctx:
            yaml_io.import_yaml("- hosts: all\n  tasks:\n    - frobnicate:\n        x: 1\n")
        self.assertIn("frobnicate", str(ctx.exception))

    def test_roles_are_rejected_with_a_reason(self):
        with self.assertRaises(yaml_io.ConversionError) as ctx:
            yaml_io.import_yaml("- hosts: all\n  roles:\n    - common\n")
        self.assertIn("roles", str(ctx.exception))

    def test_invalid_yaml_is_reported(self):
        with self.assertRaises(yaml_io.ConversionError):
            yaml_io.import_yaml("- hosts: all\n  tasks:\n   - foo: [\n")


class ModeSwitchTests(TestCase):
    def test_switching_to_text_fills_the_editor(self):
        playbook = Playbook.objects.create(name="P")
        PlaybookTask.objects.create(
            playbook=playbook, order=0, module="ansible.builtin.ping", args={}
        )
        playbook.text_content = yaml_io.build_yaml(playbook)
        playbook.mode = Playbook.MODE_TEXT
        playbook.save()
        self.assertIn("ansible.builtin.ping", playbook.text_content)
        self.assertEqual(yaml_io.playbook_yaml(playbook), playbook.text_content)


class EditorButtonTests(TestCase):
    """The editor control is two buttons, so the target is picked, not toggled."""

    def setUp(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))
        self.playbook = Playbook.objects.create(name="P")
        PlaybookTask.objects.create(
            playbook=self.playbook, order=0, module="ansible.builtin.ping", args={}
        )

    def _press(self, mode=None):
        data = {"mode": mode} if mode else {}
        self.client.post(
            reverse("playbook_switch_mode", args=[self.playbook.pk]), data
        )
        self.playbook.refresh_from_db()
        return self.playbook.mode

    def test_the_yaml_button_moves_a_graphical_playbook(self):
        self.assertEqual(self._press("text"), Playbook.MODE_TEXT)
        self.assertIn("ansible.builtin.ping", self.playbook.text_content)

    def test_the_graphical_button_moves_a_yaml_playbook_back(self):
        self._press("text")
        self.assertEqual(self._press("graphical"), Playbook.MODE_GRAPHICAL)

    def test_pressing_the_button_you_are_already_on_changes_nothing(self):
        self.assertEqual(self._press("graphical"), Playbook.MODE_GRAPHICAL)
        self._press("text")
        self.assertEqual(self._press("text"), Playbook.MODE_TEXT)

    def test_a_request_without_a_target_changes_nothing(self):
        self.assertEqual(self._press(), Playbook.MODE_GRAPHICAL)

    def test_an_unknown_target_is_ignored(self):
        self.assertEqual(self._press("sideways"), Playbook.MODE_GRAPHICAL)

    def test_yaml_the_editor_cannot_model_keeps_you_in_yaml(self):
        self._press("text")
        self.playbook.text_content = "- hosts: all\n  roles: [common]\n"
        self.playbook.save(update_fields=["text_content"])
        self.assertEqual(self._press("graphical"), Playbook.MODE_TEXT)

    def test_both_buttons_are_on_the_page(self):
        response = self.client.get(self.playbook.get_absolute_url())
        self.assertContains(response, 'name="mode" value="graphical"')
        self.assertContains(response, 'name="mode" value="text"')
        self.assertContains(response, 'aria-pressed="true"')


class EditorSwapTests(TestCase):
    """Switching editors happens in place, and quietly."""

    def setUp(self):
        User = get_user_model()
        self.client.force_login(User.objects.create_superuser("admin", password="x"))
        self.playbook = Playbook.objects.create(name="P")
        PlaybookTask.objects.create(
            playbook=self.playbook, order=0, module="ansible.builtin.ping", args={}
        )
        self.url = reverse("playbook_switch_mode", args=[self.playbook.pk])

    def _swap(self, mode):
        return self.client.post(self.url, {"mode": mode}, HTTP_HX_REQUEST="true")

    def test_the_editor_comes_back_instead_of_a_redirect(self):
        response = self._swap("text")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="editor"')
        self.assertContains(response, "Playbook YAML")
        self.assertNotContains(response, "<html")

    def test_swapping_back_returns_the_graphical_editor(self):
        self._swap("text")
        response = self._swap("graphical")
        self.assertContains(response, "Tasks")
        self.assertContains(response, "ansible.builtin.ping")

    def test_a_successful_switch_says_nothing(self):
        response = self._swap("text")
        self.assertEqual(list(response.context["messages"]), [])
        self.assertNotContains(response, "Switched to")

    def test_a_switch_that_cannot_happen_explains_itself_in_place(self):
        self._swap("text")
        self.playbook.text_content = "- hosts: all\n  roles: [common]\n"
        self.playbook.save(update_fields=["text_content"])
        response = self._swap("graphical")
        self.assertContains(response, "Cannot switch to the graphical editor")
        self.assertContains(response, "Playbook YAML")
        self.playbook.refresh_from_db()
        self.assertEqual(self.playbook.mode, Playbook.MODE_TEXT)

    def test_without_htmx_it_still_reloads_the_page(self):
        response = self.client.post(self.url, {"mode": "text"})
        self.assertRedirects(response, self.playbook.get_absolute_url())
