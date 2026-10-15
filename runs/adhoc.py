# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Ad-hoc commands: one module on some hosts, typed in rather than kept.

``ansible web -m shell -a "df -h"`` as a Loona run.  The command becomes a
one-task play and goes through everything a playbook run does - targets,
secrets, pinned host keys, masking, previews, approvals, maintenance
windows, history - so typing it in is no way around any of them.

Two things set it apart from a playbook:

* Who: Admin on every target.  A playbook was written by someone trusted
  with playbooks; a typed command is whatever its author wants it to be.
* Templating: for anyone but a superuser the command is passed to Ansible as
  ``!unsafe``, so a template in it stays text instead of being evaluated on
  the Loona server.  For the same reason, modules that work with files on
  the Loona server are for superusers only, listed or not.
"""
from __future__ import annotations

import json
import re

import yaml
from django import forms
from django.utils.translation import gettext_lazy as _

from access import policy
from administration import system
from core.forms import style
from secretstore.resolve import Unsafe, dump_inventory

from .models import Job

MODULE_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+){0,2}$")
BUILTIN_PREFIXES = ("ansible.builtin.", "ansible.legacy.")
# Modules that take the command line itself rather than key=value pairs.
FREE_FORM = {"command", "shell", "raw", "win_shell", "win_command"}
# Modules that read or write files on the machine running Ansible - here,
# the Loona server with its keys and settings - or that reach into Loona's
# own variables.  Superusers only.
CONTROLLER_MODULES = {
    "copy", "template", "script", "fetch", "unarchive", "assemble", "synchronize",
    "include_vars", "add_host", "group_by", "set_fact", "debug", "slurp", "win_copy",
    "win_template", "patch", "known_hosts", "tempfile", "local_action",
    "include_tasks", "import_tasks", "include_role", "import_role", "import_playbook",
}
MAX_OUTPUT = 64 * 1024


def short_name(module: str) -> str:
    for prefix in BUILTIN_PREFIXES:
        if module.startswith(prefix):
            return module[len(prefix):]
    return module


def allowed_modules() -> list[str]:
    return [short_name(m) for m in system.get().adhoc_modules.split()]


def enabled() -> bool:
    return bool(allowed_modules())


def why_not_module(module: str, user) -> str | None:
    """None if this user may run this module ad hoc, else the reason."""
    if not MODULE_RE.match(module):
        return "Not a module name."
    name = short_name(module)
    if name not in allowed_modules():
        return f"{module} is not among the modules allowed for ad-hoc commands (Administration - General)."
    # By the last part of the name: ansible.posix.synchronize and
    # ansible.windows.win_copy are the same thing as synchronize and win_copy.
    if name.rpartition(".")[2] in CONTROLLER_MODULES and not user.is_superuser:
        return f"{module} works with files on the Loona server; only a superuser may run it ad hoc."
    return None


def parse_args(module: str, text: str):
    """The module's arguments: the line itself for free-form modules,
    otherwise key=value pairs or a YAML mapping. Raises ValueError."""
    text = (text or "").strip()
    if short_name(module) in FREE_FORM:
        if not text:
            raise ValueError("Type the command to run.")
        return text
    if not text:
        return {}
    if text.startswith("{"):
        try:
            value = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"Not valid YAML: {exc.problem or exc}") from None
        if not isinstance(value, dict):
            raise ValueError("Give a mapping: {name: nginx, state: started}.")
        return value
    tokens = split_kv(text)
    args = {}
    for token in tokens:
        key, sep, value = token.partition("=")
        if not sep or not re.match(r"^[A-Za-z_]\w*$", key):
            raise ValueError(f"{token!r}: arguments go as key=value, e.g. name=nginx state=restarted.")
        args[key] = value
    return args


def split_kv(text: str) -> list[str]:
    """Split on spaces, as Ansible does: quotes and {{ }} / {% %} hold together."""
    tokens, current, quote, depth = [], "", "", 0
    i = 0
    while i < len(text):
        pair = text[i:i + 2]
        char = text[i]
        if not quote and pair in ("{{", "{%"):
            depth, current, i = depth + 1, current + pair, i + 2
            continue
        if not quote and depth and pair in ("}}", "%}"):
            depth, current, i = depth - 1, current + pair, i + 2
            continue
        if quote:
            if char == quote:
                quote = ""
            else:
                current += char
        elif char in "'\"" and not depth:
            quote = char
        elif char.isspace() and not depth:
            if current:
                tokens.append(current)
            current = ""
        else:
            current += char
        i += 1
    if quote or depth:
        raise ValueError("An opening quote or {{ is never closed.")
    if current:
        tokens.append(current)
    return tokens


def _unsafe(value):
    if isinstance(value, str):
        return Unsafe(value)
    if isinstance(value, list):
        return [_unsafe(v) for v in value]
    if isinstance(value, dict):
        return {k: _unsafe(v) for k, v in value.items()}
    return value


def label(module: str, args_text: str) -> str:
    text = " ".join((args_text or "").split())
    return f"{short_name(module)}: {text}" if text else short_name(module)


def playbook(module: str, args_text: str, become: bool, templated: bool) -> str:
    """The one-task play the command runs as."""
    args = parse_args(module, args_text)
    name = label(module, args_text)
    if not templated:
        args, name = _unsafe(args), Unsafe(name)
    fqcn = module if "." in module else f"ansible.builtin.{module}"
    task = {"name": name, fqcn: args}
    if become:
        task["become"] = True
    play = {"name": "Ad-hoc command", "hosts": "all", "gather_facts": False, "tasks": [task]}
    return dump_inventory([play])


class AdhocForm(forms.ModelForm):
    adhoc_module = forms.CharField(label=_("Module"), max_length=120)

    class Meta:
        model = Job
        fields = ["target_groups", "target_hosts", "limit", "adhoc_module", "adhoc_args",
                  "adhoc_become", "diff_mode", "forks", "verbosity"]
        widgets = {
            "target_groups": forms.CheckboxSelectMultiple,
            "target_hosts": forms.CheckboxSelectMultiple,
            "limit": forms.TextInput(attrs={"placeholder": "web*:!web03"}),
            "adhoc_args": forms.Textarea(attrs={"rows": 3, "class": "code",
                                                "placeholder": _("df -h /   or   name=nginx state=restarted")}),
        }
        labels = {
            "limit": _("Limit pattern"),
            "adhoc_args": _("Arguments"),
            "adhoc_become": _("Become (sudo)"),
            "diff_mode": _("Show diffs"),
        }

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.access = policy.for_user(user)
        self.fields["target_groups"].queryset = self.access.groups(policy.ADMIN).prefetch_related("hosts")
        self.fields["target_hosts"].queryset = self.access.hosts(policy.ADMIN).filter(enabled=True)
        self.fields["adhoc_module"].widget.attrs.update({"list": "adhoc-modules", "autocomplete": "off"})
        self.fields["verbosity"] = forms.TypedChoiceField(
            choices=[(0, _("Normal")), (1, "-v"), (2, _("-vv")), (3, _("-vvv")), (4, _("-vvvv"))],
            coerce=int, initial=0, label=_("Verbosity"),
        )
        style(self)

    def clean_limit(self):
        from .forms import check_limit

        return check_limit(self.cleaned_data["limit"])

    def clean_adhoc_module(self):
        module = self.cleaned_data["adhoc_module"].strip()
        reason = why_not_module(module, self.user)
        if reason:
            raise forms.ValidationError(reason)
        return module

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("target_groups") and not cleaned.get("target_hosts"):
            raise forms.ValidationError(_("Select at least one host or host group."))
        if cleaned.get("adhoc_module"):
            try:
                parse_args(cleaned["adhoc_module"], cleaned.get("adhoc_args", ""))
            except ValueError as exc:
                self.add_error("adhoc_args", str(exc))
        return cleaned


# -- output -----------------------------------------------------------------

HIDDEN_KEYS = {"invocation", "stdout_lines", "stderr_lines", "ansible_facts", "warnings",
               "deprecations"}


def output(event: str, host: str, res: dict) -> str | None:
    """What `ansible` itself prints for a result: the command's output
    rather than a bare "changed: [web1]"."""
    if event == "runner_on_unreachable":
        return f"{host} | UNREACHABLE! => {res.get('msg', '')}".rstrip()
    if event not in ("runner_on_ok", "runner_on_failed"):
        return None
    failed = event == "runner_on_failed"
    word = "FAILED" if failed else ("CHANGED" if res.get("changed") else "SUCCESS")
    if "rc" in res and ("stdout" in res or "stderr" in res):
        parts = [f"{host} | {word} | rc={res.get('rc')} >>"]
        parts += [res[k].rstrip("\n") for k in ("stdout", "stderr") if res.get(k)]
        if failed and res.get("msg") and not res.get("stderr"):
            parts.append(str(res["msg"]))
        text = "\n".join(parts)
    else:
        shown = {k: v for k, v in res.items() if not k.startswith("_") and k not in HIDDEN_KEYS}
        text = f"{host} | {word} => {json.dumps(shown, indent=2, default=str, ensure_ascii=False)}"
    if len(text) > MAX_OUTPUT:
        text = text[:MAX_OUTPUT] + "\n[... output truncated by Loona ...]"
    return text
