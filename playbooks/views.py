# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.db import transaction
from django.db.models import Max, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _

from . import modules as module_catalog
from . import yaml_io
from .forms import ImportYamlForm, PlaybookForm, PlaybookTextForm, TaskForm
from .models import Playbook, PlaybookTask


@login_required
def playbook_list(request):
    query = request.GET.get("q", "").strip()
    playbooks = Playbook.objects.all()
    if query:
        playbooks = playbooks.filter(
            Q(name__icontains=query) | Q(description__icontains=query)
        )
    return render(
        request,
        "playbooks/playbook_list.html",
        {"playbooks": playbooks, "q": query},
    )


@login_required
@permission_required("playbooks.add_playbook", raise_exception=True)
def playbook_create(request):
    form = PlaybookForm(request.POST or None, user=request.user)
    if request.method == "POST" and form.is_valid():
        playbook = form.save(commit=False)
        playbook.created_by = request.user
        playbook.save()
        form.save_m2m()
        messages.success(request, _('Playbook %(playbook)s created.') % {"playbook": playbook})
        return redirect(playbook)
    return render(
        request,
        "playbooks/playbook_form.html",
        {"form": form, "title": _("New playbook")},
    )


@login_required
def playbook_detail(request, pk):
    """The editor. Graphical and text modes share this page."""
    playbook = get_object_or_404(Playbook, pk=pk)
    return render(request, "playbooks/playbook_detail.html", _editor_context(playbook))


def _editor_context(playbook, switch_error=""):
    """Everything either editor needs, so a mode switch can re-render in place."""
    return {
        "playbook": playbook,
        "tasks": playbook.tasks.all(),
        "generated_yaml": _safe_yaml(playbook),
        "text_form": PlaybookTextForm(instance=playbook),
        "switch_error": switch_error,
    }


def _safe_yaml(playbook):
    try:
        return yaml_io.playbook_yaml(playbook)
    except Exception as exc:  # noqa: BLE001 - preview must never break the page
        return f"# Could not render YAML: {exc}"


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
@require_POST
def playbook_save_text(request, pk):
    playbook = get_object_or_404(Playbook, pk=pk)
    form = PlaybookTextForm(request.POST, instance=playbook)
    if form.is_valid():
        form.save()
        messages.success(request, _("Playbook YAML saved."))
        return redirect(playbook)
    # Back to the editor with what was typed and why it was refused.
    playbook.refresh_from_db()
    context = _editor_context(playbook)
    context["text_form"] = form
    return render(request, "playbooks/playbook_detail.html", context)


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
def playbook_settings(request, pk):
    playbook = get_object_or_404(Playbook, pk=pk)
    form = PlaybookForm(request.POST or None, instance=playbook, user=request.user)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, _("Playbook settings saved."))
        return redirect(playbook)
    return render(
        request,
        "playbooks/playbook_form.html",
        {"form": form, "playbook": playbook, "title": _("Settings - %(playbook)s") % {"playbook": playbook}},
    )


@login_required
@permission_required("playbooks.delete_playbook", raise_exception=True)
@require_POST
def playbook_delete(request, pk):
    playbook = get_object_or_404(Playbook, pk=pk)
    name = playbook.name
    playbook.delete()
    messages.success(request, _('Playbook %(name)s deleted.') % {"name": name})
    return redirect("playbook_list")


@login_required
@permission_required("playbooks.add_playbook", raise_exception=True)
@require_POST
def playbook_duplicate(request, pk):
    """Copy a playbook and its tasks under a free name."""
    source = get_object_or_404(Playbook, pk=pk)
    tasks = list(source.tasks.all())
    vaults = list(source.vault_credentials.all())

    base = f"{source.name} (copy)"
    name, suffix = base, 2
    while Playbook.objects.filter(name=name).exists():
        name = f"{base} {suffix}"
        suffix += 1

    source.pk = None
    source.name = name
    source.created_by = request.user
    source.save()
    source.vault_credentials.set(vaults)
    PlaybookTask.objects.bulk_create(
        [
            PlaybookTask(
                playbook=source,
                order=t.order,
                name=t.name,
                module=t.module,
                args=t.args,
                when=t.when,
                loop=t.loop,
                tags=t.tags,
                become=t.become,
                ignore_errors=t.ignore_errors,
                register=t.register,
                enabled=t.enabled,
            )
            for t in tasks
        ]
    )
    messages.success(request, _('Copied to %(name)s.') % {"name": name})
    return redirect(source)


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
@require_POST
def playbook_switch_mode(request, pk):
    """Move a playbook between the graphical and the YAML editor.

    The editor is picked, not toggled: the control is two buttons, so pressing
    the one you are already on has to be a no-op rather than flipping you to the
    other.

    Graphical -> YAML always succeeds.  YAML -> graphical only succeeds when the
    play fits the editor's model; otherwise the playbook stays in text mode and
    the reason is shown.
    """
    playbook = get_object_or_404(Playbook, pk=pk)
    if playbook.mode == Playbook.MODE_FILE:
        # A file from a project has no editor to switch to; see its settings.
        return _editor_response(request, playbook)
    target = request.POST.get("mode", "")
    if target not in dict(Playbook.MODE_CHOICES) or target == playbook.mode:
        return _editor_response(request, playbook)

    if target == Playbook.MODE_TEXT:
        playbook.text_content = yaml_io.build_yaml(playbook)
        playbook.mode = Playbook.MODE_TEXT
        playbook.save(update_fields=["text_content", "mode"])
        return _editor_response(request, playbook)

    try:
        settings_dict, tasks = yaml_io.import_yaml(playbook.text_content)
    except yaml_io.ConversionError as exc:
        # The one thing worth saying out loud: the switch did not happen, and why.
        reason = f"Cannot switch to the graphical editor. {exc}"
        if not request.headers.get("HX-Request"):
            messages.error(request, reason)
        return _editor_response(request, playbook, switch_error=reason)

    _apply_import(playbook, settings_dict, tasks, replace=True)
    playbook.mode = Playbook.MODE_GRAPHICAL
    playbook.save()
    return _editor_response(request, playbook)


def _editor_response(request, playbook, switch_error=""):
    """Swap the editor in place for htmx; fall back to a reload without it.

    Switching editors is not news - the page itself shows which one you are in -
    so nothing is announced at the top of the page on the way through.
    """
    if request.headers.get("HX-Request"):
        return render(
            request, "playbooks/_editor.html", _editor_context(playbook, switch_error)
        )
    return redirect(playbook)


def _apply_import(playbook, settings_dict, tasks, replace=True):
    with transaction.atomic():
        for key, value in settings_dict.items():
            setattr(playbook, key, value)
        playbook.save()
        if replace:
            playbook.tasks.all().delete()
            start = 0
        else:
            start = (playbook.tasks.aggregate(m=Max("order"))["m"] or 0) + 1
        PlaybookTask.objects.bulk_create(
            [
                PlaybookTask(playbook=playbook, order=start + index, **task)
                for index, task in enumerate(tasks)
            ]
        )


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
def playbook_import(request, pk):
    playbook = get_object_or_404(Playbook, pk=pk)
    form = ImportYamlForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        settings_dict, tasks = form.imported
        _apply_import(playbook, settings_dict, tasks, replace=form.cleaned_data["replace"])
        messages.success(request, _('Imported %(len)s tasks.') % {"len": len(tasks)})
        return redirect(playbook)
    return render(
        request,
        "playbooks/playbook_import.html",
        {"form": form, "playbook": playbook},
    )


@login_required
def playbook_export(request, pk):
    playbook = get_object_or_404(Playbook, pk=pk)
    filename = playbook.name.lower().replace(" ", "_") + ".yml"
    response = HttpResponse(_safe_yaml(playbook), content_type="application/x-yaml")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


# -- tasks ------------------------------------------------------------------


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
def task_create(request, pk):
    playbook = get_object_or_404(Playbook, pk=pk)
    module_name = request.POST.get("module") or request.GET.get("module") or module_catalog.MODULES[0]["name"]
    task = PlaybookTask(playbook=playbook, module=module_name)

    if request.method == "POST":
        form = TaskForm(request.POST, instance=task, module_name=module_name)
        if form.is_valid():
            task = form.save(commit=False)
            task.playbook = playbook
            task.order = (playbook.tasks.aggregate(m=Max("order"))["m"] or 0) + 1
            task.save()
            messages.success(request, _("Task added."))
            if "add_another" in request.POST:
                return redirect(reverse("task_create", args=[playbook.pk]) + f"?module={module_name}")
            return redirect(playbook)
    else:
        form = TaskForm(instance=task, module_name=module_name)

    return render(
        request,
        "playbooks/task_form.html",
        {
            "form": form,
            "playbook": playbook,
            "title": _("Add task"),
        },
    )


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
def task_update(request, pk):
    task = get_object_or_404(PlaybookTask, pk=pk)
    playbook = task.playbook
    module_name = request.POST.get("module") or request.GET.get("module") or task.module

    if request.method == "POST":
        form = TaskForm(request.POST, instance=task, module_name=module_name)
        if form.is_valid():
            form.save()
            messages.success(request, _("Task saved."))
            return redirect(playbook)
    else:
        form = TaskForm(instance=task, module_name=module_name)

    return render(
        request,
        "playbooks/task_form.html",
        {
            "form": form,
            "playbook": playbook,
            "task": task,
            "title": _("Edit task"),
        },
    )


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
def task_fields(request, pk):
    """HTMX partial: the module panel for another module."""
    playbook = get_object_or_404(Playbook, pk=pk)
    requested = request.GET.get("module") or module_catalog.MODULES[0]["name"]
    module_name = module_catalog.canonical_name(requested) or requested
    task_pk = request.GET.get("task")
    instance = (
        get_object_or_404(PlaybookTask, pk=task_pk, playbook=playbook)
        if task_pk
        else PlaybookTask(playbook=playbook)
    )
    # Arguments belong to the previous module, so start from a clean slate.
    if instance.module != module_name:
        instance.args = {}
    form = TaskForm(instance=instance, module_name=module_name)
    return render(request, "playbooks/_task_fields.html", {"form": form})


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
def module_search(request, pk):
    """HTMX partial: modules matching the search box."""
    playbook = get_object_or_404(Playbook, pk=pk)
    return render(
        request,
        "playbooks/_module_results.html",
        {
            "playbook": playbook,
            "results": module_catalog.search(request.GET.get("q", "")),
            "q": request.GET.get("q", "").strip(),
            "task_pk": request.GET.get("task", ""),
        },
    )


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
@require_POST
def task_delete(request, pk):
    task = get_object_or_404(PlaybookTask, pk=pk)
    playbook = task.playbook
    task.delete()
    messages.success(request, _("Task removed."))
    return redirect(playbook)


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
@require_POST
def task_move(request, pk, direction):
    """Swap a task with its neighbour, keeping the order field contiguous."""
    task = get_object_or_404(PlaybookTask, pk=pk)
    siblings = list(task.playbook.tasks.all())
    index = next(i for i, t in enumerate(siblings) if t.pk == task.pk)
    target = index - 1 if direction == "up" else index + 1
    if 0 <= target < len(siblings):
        siblings[index], siblings[target] = siblings[target], siblings[index]
        with transaction.atomic():
            for position, sibling in enumerate(siblings):
                if sibling.order != position:
                    sibling.order = position
                    sibling.save(update_fields=["order"])
    return redirect(task.playbook)


@login_required
@permission_required("playbooks.change_playbook", raise_exception=True)
@require_POST
def task_toggle(request, pk):
    task = get_object_or_404(PlaybookTask, pk=pk)
    task.enabled = not task.enabled
    task.save(update_fields=["enabled"])
    return redirect(task.playbook)
