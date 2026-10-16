# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Ansible projects: roles, templates and playbook files, from Git or edited here."""
import subprocess
import tempfile
from pathlib import Path

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.db.models import ProtectedError
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _

from access import policy
from core import gitsource
from core.forms import TextFileField, style
from infra.models import normalise_path
from inventory.forms import check_git_credential_stays
from inventory.models import Credential

from .forms import vault_choices
from .models import Project, ProjectFile

EDIT = "playbooks.change_playbook"


class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ["name", "description", "source", "git_url", "git_ref", "git_path", "git_credential",
                  "vault_credentials"]
        widgets = {"source": forms.RadioSelect, "vault_credentials": forms.CheckboxSelectMultiple,
                   "git_url": forms.TextInput(attrs={"placeholder": "git@git.example.com:infra/ansible.git"})}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.access = policy.for_user(user)
        credentials = self.access.credentials()
        if self.instance.git_credential_id:
            credentials = credentials | Credential.objects.filter(pk=self.instance.git_credential_id)
        self.fields["git_credential"].queryset = credentials.distinct()
        self.fields["git_credential"].required = False
        self.fields["vault_credentials"].queryset = vault_choices(user, self.instance)
        style(self)

    def clean_git_url(self):
        return gitsource.check_url(self.cleaned_data["git_url"])

    def clean_git_ref(self):
        return gitsource.check_ref(self.cleaned_data["git_ref"])

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("source") == Project.SOURCE_GIT and not cleaned.get("git_url"):
            self.add_error("git_url", _("A Git project needs a repository URL."))
        path = (cleaned.get("git_path") or "").strip("/")
        if ".." in path.split("/"):
            self.add_error("git_path", _("The folder must stay inside the repository."))
        cleaned["git_path"] = path
        check_git_credential_stays(self, self.access)
        return cleaned


class ProjectFileForm(forms.ModelForm):
    content = TextFileField(widget=forms.Textarea(attrs={"rows": 28, "class": "code editor", "spellcheck": "false"}))

    class Meta:
        model = ProjectFile
        fields = ["path", "content"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)

    def clean_path(self):
        path = normalise_path(self.cleaned_data["path"], example="roles/web/tasks/main.yml")
        clash = ProjectFile.objects.filter(project=self.instance.project, path=path)
        if self.instance.pk:
            clash = clash.exclude(pk=self.instance.pk)
        if clash.exists():
            raise forms.ValidationError(_("The project already has a file with that path."))
        return path


STARTER = {
    "site.yml": "- hosts: all\n  roles:\n    - example\n",
    "roles/example/tasks/main.yml": "- name: Say hello\n  ansible.builtin.debug:\n    msg: \"Hello from {{ inventory_hostname }}\"\n",
    "requirements.yml": "# Roles and collections from Galaxy, installed before each run (and cached).\n"
                        "# collections:\n#   - name: community.general\n# roles:\n#   - name: geerlingguy.nginx\n",
}


@login_required
def project_list(request):
    return render(request, "playbooks/project_list.html",
                  {"projects": Project.objects.prefetch_related("playbooks")})


@login_required
@permission_required(EDIT, raise_exception=True)
def project_edit(request, pk=None):
    project = get_object_or_404(Project, pk=pk) if pk else Project()
    form = ProjectForm(request.POST or None, instance=project, user=request.user)
    if request.method == "POST" and form.is_valid():
        created = project.pk is None
        project = form.save()
        if created and not project.is_git:
            for path, content in STARTER.items():
                ProjectFile.objects.create(project=project, path=path, content=content)
        messages.success(request, _('Project %(project)s saved.') % {"project": project})
        return redirect(project)
    return render(request, "playbooks/project_form.html", {"form": form, "project": project})


@login_required
@permission_required(EDIT, raise_exception=True)
@require_POST
def project_delete(request, pk):
    project = get_object_or_404(Project, pk=pk)
    try:
        project.delete()
    except ProtectedError:
        messages.error(request, _("Playbooks still use this project; move them off it first."))
        return redirect(project)
    messages.success(request, _('Project %(project)s deleted.') % {"project": project})
    return redirect("project_list")


@login_required
def project_detail(request, pk):
    project = get_object_or_404(Project, pk=pk)
    return render(request, "playbooks/project_detail.html", {
        "project": project,
        "files": project.files.all(),
        "playbooks": project.playbooks.all(),
    })


@login_required
@permission_required(EDIT, raise_exception=True)
@require_POST
def project_check(request, pk):
    """Can Loona read the repository with the credential given?"""
    project = get_object_or_404(Project, pk=pk)
    with tempfile.TemporaryDirectory() as tmp:
        env = gitsource.environment(project.git_credential, Path(tmp))
        try:
            done = gitsource.ls_remote(project.git_url, project.git_ref or "HEAD", env)
        except gitsource.GitError as exc:
            messages.error(request, str(exc))
            return redirect(project)
        except (OSError, subprocess.TimeoutExpired) as exc:
            messages.error(request, _('git did not run: %(exc)s') % {"exc": exc})
            return redirect(project)
    if done.returncode != 0:
        messages.error(request, _('Could not read the repository: %(strip)s') % {"strip": done.stderr.strip()[-400:]})
    elif not done.stdout.strip():
        messages.warning(request, _('Reached the repository, but it has no %(value)s.') % {"value": project.git_ref or 'HEAD'})
    else:
        commit = done.stdout.split()[0]
        messages.success(request, _('Readable. %(value)s is at %(commit)s.') % {"value": project.git_ref or 'HEAD', "commit": commit[:12]})
    return redirect(project)


@login_required
@permission_required(EDIT, raise_exception=True)
def file_edit(request, pk, file_pk=None):
    project = get_object_or_404(Project, pk=pk)
    instance = get_object_or_404(ProjectFile, pk=file_pk, project=project) if file_pk else ProjectFile(project=project)
    form = ProjectFileForm(request.POST or None, instance=instance)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, _('%(path)s saved.') % {"path": instance.path})
        return redirect(project)
    return render(request, "playbooks/project_file_form.html",
                  {"form": form, "project": project, "file": instance})


@login_required
@permission_required(EDIT, raise_exception=True)
@require_POST
def file_delete(request, pk, file_pk):
    project = get_object_or_404(Project, pk=pk)
    get_object_or_404(ProjectFile, pk=file_pk, project=project).delete()
    return redirect(project)
