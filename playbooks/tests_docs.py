# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Editor forms built from ansible-doc, against canned ansible-doc output."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from . import docs, yaml_io
from . import modules as catalog
from .forms import TaskForm
from .models import AnsibleModule, Playbook, PlaybookTask

UFW = {
    "short_description": "Manage firewall with C(UFW)",
    "options": {
        "rule": {"type": "str", "choices": ["allow", "deny", "limit", "reject"],
                 "description": ["Add firewall rule."]},
        "port": {"type": "str", "aliases": ["to_port"], "description": "Destination port."},
        "from_ip": {"type": "str", "default": "any", "aliases": ["from", "src"],
                    "description": ["Source IP address."]},
        "delete": {"type": "bool", "default": "no", "description": "Delete rule."},
        "state": {"type": "str", "choices": {"enabled": "", "disabled": "", "reloaded": ""},
                  "description": "O(state=enabled) reloads firewall and enables on boot."},
        "comment": {"type": "str", "description": "Add a comment to the rule."},
        "log_levels": {"type": "list", "elements": "str", "description": "Levels."},
        "routes": {"type": "list", "elements": "dict", "suboptions": {"to": {}},
                   "description": "Routes."},
        "interface": {"type": "str", "required": True, "description": "Interface."},
    },
}
APT = {
    "short_description": "Manages apt-packages",
    "options": {
        "name": {"type": "list", "elements": "str", "aliases": ["package", "pkg"],
                 "description": "A list of package names."},
        "state": {"type": "str", "default": "present",
                  "choices": ["absent", "build-dep", "latest", "present", "fixed"]},
        "update_cache": {"type": "bool", "default": "no", "aliases": ["update-cache"]},
        "cache_valid_time": {"type": "int", "default": 0},
        "autoremove": {"type": "bool", "default": "no"},
    },
}
DOCS = {"community.general.ufw": UFW, "ansible.builtin.apt": APT}
LISTING = {
    "community.general.ufw": "Manage firewall with UFW",
    "ansible.builtin.apt": "Manages apt-packages",
    "ansible.builtin.copy": "Copy files to remote locations",
    "community.aws.s3_copy": "Copy objects in S3",
    "one.coll.dupe": "one",
    "two.coll.dupe": "two",
}


def fake_ansible_doc(*args):
    if args[:2] == ("-l", "-t"):
        return dict(LISTING)
    name = args[-1]
    return {name: {"doc": DOCS[name]}} if name in DOCS else {}


class DocsTestCase(TestCase):
    def setUp(self):
        patcher = patch.object(docs, "_ansible_doc", side_effect=fake_ansible_doc)
        self.ansible_doc = patcher.start()
        self.addCleanup(patcher.stop)
        override = override_settings(LOONA_MODULE_DOCS=True)
        override.enable()
        self.addCleanup(override.disable)


class SpecTests(DocsTestCase):
    def test_options_become_fields_of_the_right_kind(self):
        fields = {f["name"]: f for f in docs.get_spec("community.general.ufw")["fields"]}
        self.assertEqual(fields["rule"]["type"], "choice")
        self.assertEqual(fields["state"]["choices"], ["enabled", "disabled", "reloaded"])
        self.assertEqual(fields["delete"]["type"], "bool")
        self.assertIs(fields["delete"]["default"], False)
        self.assertEqual(fields["log_levels"]["type"], "list")
        self.assertEqual(fields["routes"]["type"], "yaml")
        self.assertEqual(fields["from_ip"]["aliases"], ["from", "src"])
        self.assertIn("Default: any", fields["from_ip"]["help"])

    def test_markup_is_turned_into_plain_text(self):
        spec = docs.get_spec("community.general.ufw")
        self.assertEqual(spec["description"], "Manage firewall with UFW")
        state = next(f for f in spec["fields"] if f["name"] == "state")
        self.assertTrue(state["help"].startswith("state=enabled reloads"))

    def test_required_options_come_first(self):
        spec = docs.get_spec("community.general.ufw")
        self.assertEqual(spec["fields"][0]["name"], "interface")

    def test_a_spec_is_fetched_once_and_then_cached(self):
        docs.get_spec("community.general.ufw")
        docs.get_spec("community.general.ufw")
        fetches = [c for c in self.ansible_doc.call_args_list if c.args[-1] == "community.general.ufw"]
        self.assertEqual(len(fetches), 1)
        self.assertIsNotNone(AnsibleModule.objects.get(name="community.general.ufw").spec)


class ResolveTests(DocsTestCase):
    def test_a_module_outside_the_catalog_gets_its_required_and_usual_fields_up_front(self):
        spec = catalog.resolve("community.general.ufw")
        self.assertEqual(spec["source"], "ansible-doc")
        self.assertEqual(spec["featured"][0], "interface")
        self.assertIn("state", spec["featured"])
        self.assertEqual(len(spec["fields"]), len(UFW["options"]))

    def test_a_catalog_module_keeps_its_wording_and_gains_every_other_option(self):
        spec = catalog.resolve("ansible.builtin.apt")
        self.assertEqual(spec["source"], "catalog+doc")
        self.assertEqual(spec["label"], "APT package")
        names = [f["name"] for f in spec["fields"]]
        self.assertIn("autoremove", names)
        self.assertNotIn("autoremove", spec["featured"])

    def test_short_names_resolve_the_way_ansible_would(self):
        self.assertEqual(catalog.canonical_name("copy"), "ansible.builtin.copy")
        self.assertEqual(catalog.canonical_name("ufw"), "community.general.ufw")
        # Two collections provide it: guessing would be wrong half the time.
        self.assertIsNone(catalog.canonical_name("dupe"))

    def test_search_puts_builtins_first(self):
        names = [m["name"] for m in catalog.search("copy")]
        self.assertLess(names.index("ansible.builtin.copy"), names.index("community.aws.s3_copy"))

    def test_without_ansible_doc_the_catalog_still_works(self):
        self.ansible_doc.side_effect = docs.DocsUnavailable("not installed")
        spec = catalog.resolve("ansible.builtin.apt")
        self.assertEqual(spec["source"], "catalog")

    def test_file_content_keeps_its_last_line_break(self):
        field = {"name": "content", "type": "textarea"}
        self.assertEqual(catalog.coerce_value(field, "  indented\nlast\n"), "  indented\nlast\n")
        self.assertIsNone(catalog.coerce_value(field, " \n"))
        self.assertEqual(catalog.coerce_value({"name": "dest", "type": "text"}, " /etc/motd "), "/etc/motd")

    def test_one_unreadable_collection_does_not_cost_the_whole_index(self):
        listings = {"ansible.builtin": {"ansible.builtin.copy": "Copy files"},
                    "community.general": {"community.general.ufw": "Manage firewall"}}

        def ansible_doc(*args):
            if args == ("-l", "-t", "module") or args[-1] == "broken.one":
                raise docs.DocsFailed("'_AnsibleTaggedDict' object has no attribute 'strip'")
            return listings[args[-1]]

        self.ansible_doc.side_effect = ansible_doc
        with patch.object(docs, "_collections", return_value=["broken.one", "community.general"]):
            self.assertEqual(docs.refresh_index(), 2)
        self.assertEqual(set(AnsibleModule.objects.values_list("name", flat=True)),
                         {"ansible.builtin.copy", "community.general.ufw"})


class TaskFormTests(DocsTestCase):
    def setUp(self):
        super().setUp()
        self.playbook = Playbook.objects.create(name="p")

    def data(self, module, **args):
        data = {"module": module, "name": "", "when": "", "loop": "", "tags": "",
                "become": "", "register": "", "enabled": "on", "extra_args": ""}
        data.update({f"arg__{k}" if k != "extra_args" else k: v for k, v in args.items()})
        return data

    def test_an_argument_under_an_alias_lands_in_its_field(self):
        task = PlaybookTask(playbook=self.playbook, module="community.general.ufw",
                            args={"src": "10.0.0.0/8", "interface": "eth0"})
        form = TaskForm(instance=task)
        self.assertEqual(form["arg__from_ip"].initial, "10.0.0.0/8")
        self.assertEqual(form["extra_args"].initial, {})

    def test_arguments_no_field_knows_survive_an_edit(self):
        task = PlaybookTask.objects.create(
            playbook=self.playbook, module="community.general.ufw",
            args={"interface": "eth0", "direction": "in"},
        )
        form = TaskForm(self.data("community.general.ufw", interface="eth0",
                                  extra_args="direction: in"), instance=task)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save().args, {"interface": "eth0", "direction": "in"})

    def test_defaults_stay_out_of_the_yaml(self):
        form = TaskForm(self.data("community.general.ufw", interface="eth0"),
                        instance=PlaybookTask(playbook=self.playbook))
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save(commit=False).args, {"interface": "eth0"})

    def test_list_and_yaml_fields_are_parsed(self):
        form = TaskForm(self.data("community.general.ufw", interface="eth0",
                                  log_levels="low\nhigh", routes="- to: 10.0.0.1"),
                        instance=PlaybookTask(playbook=self.playbook))
        self.assertTrue(form.is_valid(), form.errors)
        args = form.save(commit=False).args
        self.assertEqual(args["log_levels"], ["low", "high"])
        self.assertEqual(args["routes"], [{"to": "10.0.0.1"}])

    def test_broken_yaml_is_an_error_not_a_silent_drop(self):
        form = TaskForm(self.data("community.general.ufw", interface="eth0", routes="- to: ["),
                        instance=PlaybookTask(playbook=self.playbook))
        self.assertFalse(form.is_valid())
        self.assertIn("arg__routes", form.errors)

    def test_a_required_option_from_the_docs_is_enforced(self):
        form = TaskForm(self.data("community.general.ufw"),
                        instance=PlaybookTask(playbook=self.playbook))
        self.assertFalse(form.is_valid())
        self.assertIn("arg__interface", form.errors)

    def test_an_extra_argument_cannot_shadow_a_field(self):
        form = TaskForm(self.data("community.general.ufw", interface="eth0",
                                  extra_args="port: 22"),
                        instance=PlaybookTask(playbook=self.playbook))
        self.assertFalse(form.is_valid())
        self.assertIn("extra_args", form.errors)

    def test_a_module_the_server_lacks_keeps_everything_in_other_arguments(self):
        task = PlaybookTask(playbook=self.playbook, module="acme.corp.thing", args={"a": 1})
        form = TaskForm(instance=task)
        self.assertEqual(form.spec["source"], "unknown")
        self.assertEqual(form["extra_args"].initial, {"a": 1})


class ImportAnyModuleTests(DocsTestCase):
    def test_a_short_name_from_a_collection_imports(self):
        _, tasks = yaml_io.import_yaml(
            "- hosts: all\n  tasks:\n    - ufw:\n        rule: allow\n        port: '22'\n"
        )
        self.assertEqual(tasks[0]["module"], "community.general.ufw")

    def test_yaml_to_editor_and_back_loses_nothing(self):
        source = (
            "- hosts: all\n  tasks:\n    - community.general.ufw:\n        interface: eth0\n"
            "        src: 10.0.0.0/8\n        direction: in\n        routes:\n        - to: 10.0.0.1\n"
        )
        playbook = Playbook.objects.create(name="p")
        _, tasks = yaml_io.import_yaml(source)
        task = PlaybookTask.objects.create(playbook=playbook, **tasks[0])
        # Open the task in the editor and save it without touching anything.
        form = TaskForm(instance=task)
        data = {name: form[name].value() for name in form.fields}
        data = {k: v for k, v in data.items() if v not in (None, False)}
        data["extra_args"] = form.fields["extra_args"].prepare_value(form["extra_args"].initial)
        saved = TaskForm(data, instance=task)
        self.assertTrue(saved.is_valid(), saved.errors)
        self.assertEqual(
            saved.save().args,
            {"interface": "eth0", "from_ip": "10.0.0.0/8", "direction": "in",
             "routes": [{"to": "10.0.0.1"}]},
        )


class EditorViewTests(DocsTestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(get_user_model().objects.create_superuser("admin", password="x"))
        self.playbook = Playbook.objects.create(name="p")

    def test_search_finds_modules_beyond_the_catalog(self):
        response = self.client.get(reverse("module_search", args=[self.playbook.pk]), {"q": "firewall"})
        self.assertContains(response, "community.general.ufw")

    def test_the_panel_for_a_collection_module_has_its_options(self):
        response = self.client.get(
            reverse("task_fields", args=[self.playbook.pk]), {"module": "ufw"}
        )
        self.assertContains(response, 'value="community.general.ufw"')
        self.assertContains(response, 'name="arg__interface"')
        self.assertContains(response, "All options")

    def test_adding_a_collection_task_end_to_end(self):
        response = self.client.post(
            reverse("task_create", args=[self.playbook.pk]),
            {"module": "community.general.ufw", "arg__interface": "eth0", "arg__rule": "allow",
             "arg__port": "22", "enabled": "on", "extra_args": ""},
        )
        self.assertEqual(response.status_code, 302)
        task = self.playbook.tasks.get()
        self.assertEqual(task.args, {"interface": "eth0", "rule": "allow", "port": "22"})
        self.assertIn("community.general.ufw:", yaml_io.playbook_yaml(self.playbook))
