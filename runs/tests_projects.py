# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Ansible projects - roles, templates, playbook files, Git, Galaxy - on real runs."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from inventory.models import Host, HostGroup
from playbooks.forms import PlaybookTextForm
from playbooks.models import Playbook, Project, ProjectFile

from . import executor, plans
from .models import Job

HAS_GIT = shutil.which("git") is not None


class ProjectRunTests(TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        override = override_settings(LOONA_DATA_DIR=str(self.tmp / "jobs"),
                                     LOONA_GALAXY_CACHE=str(self.tmp / "galaxy"),
                                     LOONA_GIT_PROTOCOLS="file")
        override.enable()
        self.addCleanup(override.disable)
        self.group = HostGroup.objects.create(name="local", approval_policy=HostGroup.APPROVAL_NONE)
        self.host = Host.objects.create(name="localhost", variables={"ansible_connection": "local"})
        self.host.groups.add(self.group)
        self.user = get_user_model().objects.create_superuser("root")
        self.out = self.tmp / "out"
        self.out.mkdir()

    def files_project(self, files):
        project = Project.objects.create(name=f"p{Project.objects.count()}")
        for path, content in files.items():
            ProjectFile.objects.create(project=project, path=path, content=content)
        return project

    def launch(self, playbook, preview=False, extra_vars=""):
        from runs import services
        from runs.forms import JobLaunchForm

        form = JobLaunchForm({"target_groups": [self.group.pk], "target_hosts": [], "limit": "",
                              "extra_vars": extra_vars, "tags": "", "skip_tags": "", "forks": 5, "verbosity": 0},
                             user=self.user)
        self.assertTrue(form.is_valid(), form.errors)
        with patch("runs.services.dispatch", side_effect=lambda job: executor.run_job(job.pk)):
            job = services.launch(form, playbook, self.user, preview=preview)
        job.refresh_from_db()
        return job

    def role_files(self, greeting="hello"):
        return {
            "roles/motd/tasks/main.yml": (
                "- name: Write the message of the day\n  ansible.builtin.template:\n"
                f"    src: motd.j2\n    dest: {self.out}/motd\n"
            ),
            "roles/motd/templates/motd.j2": greeting + " from {{ inventory_hostname }}\n",
        }

    def test_an_inline_playbook_uses_the_projects_role_and_template(self):
        project = self.files_project(self.role_files())
        playbook = Playbook.objects.create(name="motd", mode=Playbook.MODE_TEXT, project=project,
                                           text_content="- hosts: all\n  gather_facts: false\n  roles:\n    - motd\n")
        job = self.launch(playbook)
        self.assertEqual(job.status, Job.SUCCESSFUL, job.error_message)
        self.assertEqual((self.out / "motd").read_text(), "hello from localhost\n")
        self.assertTrue(job.project_revision.startswith("files:"))

    def test_extra_vars_are_data_not_templates(self):
        """A template in an extra var would be evaluated on the Loona server; it stays text."""
        project = self.files_project({"site.yml": (
            "- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.copy:\n"
            f"        dest: {self.out}/said\n        content: \"{{{{ said }}}} {{{{ nested.deep[0] }}}}\"\n")})
        playbook = Playbook.objects.create(name="say", mode=Playbook.MODE_FILE, project=project, file_path="site.yml")
        job = self.launch(playbook, extra_vars='said: "{{ 6 * 7 }}"\nnested: {deep: ["{{ lookup(\'env\', \'HOME\') }}"]}')
        self.assertEqual(job.status, Job.SUCCESSFUL, job.error_message)
        self.assertEqual((self.out / "said").read_text(), "{{ 6 * 7 }} {{ lookup('env', 'HOME') }}")

    def test_a_playbook_file_with_several_plays_and_a_handler(self):
        site = (
            "- hosts: all\n  gather_facts: false\n  tasks:\n"
            f"    - ansible.builtin.copy:\n        dest: {self.out}/one\n        content: first\n"
            "      notify: say done\n"
            f"  handlers:\n    - name: say done\n      ansible.builtin.copy:\n        dest: {self.out}/handled\n        content: yes\n"
            "- hosts: all\n  gather_facts: false\n  roles:\n    - motd\n"
        )
        project = self.files_project({"site.yml": site, **self.role_files()})
        playbook = Playbook.objects.create(name="site", mode=Playbook.MODE_FILE, project=project, file_path="site.yml")
        job = self.launch(playbook)
        self.assertEqual(job.status, Job.SUCCESSFUL, job.error_message)
        self.assertTrue((self.out / "one").exists() and (self.out / "handled").exists())
        self.assertTrue((self.out / "motd").exists())
        self.assertEqual(job.playbook_yaml, site, "the run records the file it ran")

    def test_apply_uses_the_project_files_the_preview_saw(self):
        project = self.files_project(self.role_files("previewed"))
        playbook = Playbook.objects.create(name="motd", mode=Playbook.MODE_TEXT, project=project,
                                           text_content="- hosts: all\n  gather_facts: false\n  roles:\n    - motd\n")
        preview = self.launch(playbook, preview=True)
        self.assertFalse((self.out / "motd").exists())
        from .views import _moved_on

        self.assertFalse(_moved_on(preview))
        ProjectFile.objects.filter(path="roles/motd/templates/motd.j2").update(content="edited later\n")
        self.assertTrue(_moved_on(Job.objects.get(pk=preview.pk)), "the preview page warns about edited files")
        with patch("runs.services.dispatch"):
            applied = plans.apply(preview, self.user)
        executor.run_job(applied.pk)
        applied.refresh_from_db()
        self.assertEqual(applied.status, Job.SUCCESSFUL, applied.error_message)
        self.assertEqual((self.out / "motd").read_text(), "previewed from localhost\n")
        self.assertEqual(applied.project_revision, preview.project_revision)

    def test_apply_runs_the_file_the_preview_ran(self):
        def writes(word):
            return (f"- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.copy:\n"
                    f"        dest: {self.out}/{word}\n        content: {word}\n")
        project = self.files_project({"safe.yml": writes("safe"), "alternate.yml": writes("alternate")})
        playbook = Playbook.objects.create(name="site", mode=Playbook.MODE_FILE, project=project, file_path="safe.yml")
        preview = self.launch(playbook, preview=True)
        self.assertEqual((preview.status, preview.playbook_file), (Job.SUCCESSFUL, "safe.yml"), preview.error_message)
        playbook.file_path = "alternate.yml"
        playbook.save()
        with patch("runs.services.dispatch"):
            applied = plans.apply(preview, self.user)
        executor.run_job(applied.pk)
        applied.refresh_from_db()
        self.assertEqual(applied.status, Job.SUCCESSFUL, applied.error_message)
        self.assertTrue((self.out / "safe").exists())
        self.assertFalse((self.out / "alternate").exists())

    def test_a_bootstrap_runs_its_own_yaml_around_a_file_baseline(self):
        from . import projects

        project = self.files_project({"base.yml": "- hosts: all\n  tasks: []\n"})
        baseline = Playbook.objects.create(name="base", mode=Playbook.MODE_FILE, project=project, file_path="base.yml")
        generated = "- name: Remove the bootstrap key\n  hosts: all\n  tasks: []\n- ansible.builtin.import_playbook: base.yml\n"
        job = Job.objects.create(kind=Job.KIND_BOOTSTRAP, playbook=baseline, ansible_project=project,
                                 playbook_name="Bootstrap", playbook_yaml=generated)
        run_dir = self.tmp / "bootstrap"
        (run_dir / "project").mkdir(parents=True)
        entry, _ = executor._prepare_playbook(job, run_dir, {})
        self.assertEqual(entry, projects.INLINE_PLAYBOOK)
        self.assertEqual((run_dir / "project" / entry).read_text(), generated)
        self.assertEqual(Job.objects.get(pk=job.pk).playbook_yaml, generated)

    def test_a_missing_playbook_file_fails_clearly(self):
        project = self.files_project({"other.yml": "- hosts: all\n  tasks: []\n"})
        playbook = Playbook.objects.create(name="gone", mode=Playbook.MODE_FILE, project=project, file_path="site.yml")
        job = self.launch(playbook)
        self.assertEqual(job.status, Job.ERROR)
        self.assertIn("site.yml", job.error_message)

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_a_git_project_is_pinned_to_the_previewed_commit(self):
        repo = self.git_repo({"playbooks/site.yml": self.site_writing("v1")})
        project = Project.objects.create(name="git", source=Project.SOURCE_GIT, git_url=f"file://{repo}",
                                         git_path="playbooks")
        playbook = Playbook.objects.create(name="site", mode=Playbook.MODE_FILE, project=project, file_path="site.yml")
        preview = self.launch(playbook, preview=True)
        self.assertEqual(preview.status, Job.SUCCESSFUL, preview.error_message)
        self.assertEqual(len(preview.project_revision), 40)

        (repo / "playbooks" / "site.yml").write_text(self.site_writing("v2"))
        self.git(repo, "commit", "-qam", "v2")
        with patch("runs.services.dispatch"):
            applied = plans.apply(preview, self.user)
        executor.run_job(applied.pk)
        applied.refresh_from_db()
        self.assertEqual((self.out / "version").read_text(), "v1")
        # A fresh run takes the branch as it is now.
        self.launch(playbook)
        self.assertEqual((self.out / "version").read_text(), "v2")

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_galaxy_requirements_are_installed_once_and_then_cached(self):
        role_repo = self.git_repo({
            "tasks/main.yml": f"- ansible.builtin.copy:\n    dest: {self.out}/from-galaxy\n    content: ok\n",
            "meta/main.yml": "galaxy_info:\n  author: test\n  description: test\n  license: MIT\n  min_ansible_version: '2.9'\n",
        })
        project = self.files_project({
            "requirements.yml": f"roles:\n  - src: git+file://{role_repo}\n    name: shared_role\n",
        })
        playbook = Playbook.objects.create(name="uses galaxy", mode=Playbook.MODE_TEXT, project=project,
                                           text_content="- hosts: all\n  gather_facts: false\n  roles:\n    - shared_role\n")
        first = self.launch(playbook)
        self.assertEqual(first.status, Job.SUCCESSFUL, first.error_message + self.log(first))
        self.assertTrue((self.out / "from-galaxy").exists())
        second = self.launch(playbook)
        self.assertEqual(second.status, Job.SUCCESSFUL)
        self.assertIn("using the cached install", self.log(second))

    def test_requirements_are_fetched_with_the_git_projects_own_login(self):
        from inventory.models import Credential

        from . import projects

        credential = Credential.objects.create(name="deploy", kind=Credential.KIND_SSH_KEY, username="git")
        credential.secret = "-----BEGIN OPENSSH PRIVATE KEY-----"
        credential.save()
        project = Project.objects.create(name="private", source=Project.SOURCE_GIT,
                                         git_url="git@git.example.com:infra/ansible.git", git_credential=credential)
        env = projects.galaxy_environment(project, self.tmp)
        self.assertIn(str(self.tmp / "git_key"), env["GIT_SSH_COMMAND"])
        self.assertNotIn("GIT_SSH_COMMAND", projects.galaxy_environment(self.files_project({}), self.tmp))

    def log(self, job):
        return "\n".join(job.events.values_list("stdout", flat=True))

    def site_writing(self, version):
        return (f"- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.copy:\n"
                f"        dest: {self.out}/version\n        content: {version}\n")

    def git(self, repo, *args):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                       env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                            "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(self.tmp), "PATH": "/usr/bin:/bin"})

    def git_repo(self, files):
        repo = Path(tempfile.mkdtemp(dir=self.tmp))
        for path, content in files.items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(content)
        self.git(repo, "init", "-q", "-b", "main")
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-qm", "first")
        return repo


class TextPlaybookTests(TestCase):
    def test_several_plays_are_accepted_in_yaml_mode(self):
        playbook = Playbook.objects.create(name="p", mode=Playbook.MODE_TEXT)
        text = "- hosts: web\n  tasks: []\n- hosts: db\n  tasks: []\n- ansible.builtin.import_playbook: other.yml\n"
        self.assertTrue(PlaybookTextForm({"text_content": text}, instance=playbook).is_valid())
        self.assertFalse(PlaybookTextForm({"text_content": "- tasks: []\n"}, instance=playbook).is_valid())

    def test_yaml_that_does_not_parse_comes_back_to_the_editor(self):
        self.client.force_login(get_user_model().objects.create_superuser("root"))
        playbook = Playbook.objects.create(name="p", mode=Playbook.MODE_TEXT, text_content="- hosts: all\n")
        broken = "- hosts: all\n  tasks: [oops\n"
        response = self.client.post(f"/playbooks/{playbook.pk}/save-text/", {"text_content": broken})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "tasks: [oops")
        playbook.refresh_from_db()
        self.assertEqual(playbook.text_content, "- hosts: all\n")


class ProjectPageTests(TestCase):
    def test_editing_takes_the_playbook_permission_and_a_used_project_stays(self):
        dev = get_user_model().objects.create_user("dev")
        self.client.force_login(dev)
        self.assertEqual(self.client.get("/playbooks/projects/new/").status_code, 403)
        self.assertEqual(self.client.get("/playbooks/projects/").status_code, 200)

        root = get_user_model().objects.create_superuser("root")
        self.client.force_login(root)
        self.client.post("/playbooks/projects/new/", {"name": "web", "description": "", "source": "files",
                                                      "git_url": "", "git_ref": "main", "git_path": ""})
        project = Project.objects.get(name="web")
        self.assertTrue(project.files.filter(path="site.yml").exists())
        Playbook.objects.create(name="uses it", project=project)
        self.client.post(f"/playbooks/projects/{project.pk}/delete/")
        self.assertTrue(Project.objects.filter(pk=project.pk).exists())

    def test_a_file_is_stored_as_typed_but_with_unix_line_breaks(self):
        self.client.force_login(get_user_model().objects.create_superuser("root"))
        project = Project.objects.create(name="web")
        # What a browser sends for a textarea: CRLF, and the last line break kept.
        self.client.post(f"/playbooks/projects/{project.pk}/files/new/",
                         {"path": "templates/motd.j2", "content": "  indented\r\nlast line\r\n"})
        self.assertEqual(project.files.get().content, "  indented\nlast line\n")

    def test_a_file_cannot_be_put_outside_the_project(self):
        self.client.force_login(get_user_model().objects.create_superuser("root"))
        project = Project.objects.create(name="web")
        response = self.client.post(f"/playbooks/projects/{project.pk}/files/new/",
                                    {"path": "../../etc/passwd", "content": "x"})
        self.assertContains(response, "roles/web/tasks/main.yml")
        self.assertFalse(project.files.exists())
