# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Two-way conversion between structured tasks and playbook YAML.

Graphical -> YAML always works.  YAML -> graphical only works for plays that fit
the editor's model; anything else raises :class:`ConversionError` with a reason,
so the UI can explain why a playbook has to stay in text mode.
"""
from __future__ import annotations

import yaml

from . import modules as module_catalog

# Task keys the graphical editor knows how to round-trip.
SUPPORTED_TASK_KEYS = {
    "name",
    "when",
    "loop",
    "with_items",
    "tags",
    "become",
    "ignore_errors",
    "register",
}

# Play keys the graphical editor knows how to round-trip.
SUPPORTED_PLAY_KEYS = {
    "name",
    "hosts",
    "become",
    "gather_facts",
    "serial",
    "any_errors_fatal",
    "vars",
    "tasks",
}

# Modules whose short form takes a bare string rather than a mapping.
FREE_FORM_MODULES = {
    "ansible.builtin.command": "cmd",
    "ansible.builtin.shell": "cmd",
    "ansible.builtin.script": "cmd",
    "command": "cmd",
    "shell": "cmd",
    "script": "cmd",
}


class ConversionError(Exception):
    """The YAML cannot be represented in the graphical editor."""


class _BlockDumper(yaml.SafeDumper):
    """Dumper that renders multi-line strings as readable block scalars."""


def _str_representer(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_BlockDumper.add_representer(str, _str_representer)


def dump(data) -> str:
    return yaml.dump(
        data,
        Dumper=_BlockDumper,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=100,
    )


# -- graphical -> YAML ------------------------------------------------------


def task_to_dict(task) -> dict:
    """Render one PlaybookTask as an Ansible task mapping."""
    out = {}
    if task.name:
        out["name"] = task.name
    out[task.module] = dict(task.args or {})
    if task.when:
        out["when"] = task.when
    if task.loop:
        out["loop"] = parse_loop(task.loop)
    if task.tags:
        out["tags"] = [t.strip() for t in task.tags.split(",") if t.strip()]
    if task.become:
        out["become"] = task.become == "yes"
    if task.ignore_errors:
        out["ignore_errors"] = True
    if task.register:
        out["register"] = task.register
    return out


def parse_loop(raw: str):
    """A loop is either a YAML list or a Jinja expression; keep both usable."""
    raw = raw.strip()
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError:
        return raw
    if isinstance(parsed, (list, dict)):
        return parsed
    return raw


def build_play(playbook, hosts: str = "all") -> dict:
    """Build the play mapping for a graphical playbook."""
    play = {
        "name": playbook.name,
        "hosts": hosts,
        "gather_facts": playbook.gather_facts,
    }
    if playbook.become:
        play["become"] = True
    if playbook.serial:
        play["serial"] = _coerce_serial(playbook.serial)
    if playbook.any_errors_fatal:
        play["any_errors_fatal"] = True
    if playbook.extra_vars:
        play["vars"] = playbook.extra_vars
    play["tasks"] = [
        task_to_dict(t) for t in playbook.tasks.filter(enabled=True).order_by("order", "pk")
    ]
    return play


def _coerce_serial(value: str):
    value = value.strip()
    if value.isdigit():
        return int(value)
    return value


def build_yaml(playbook, hosts: str = "all") -> str:
    """YAML for a graphical playbook, including the document marker."""
    return "---\n" + dump([build_play(playbook, hosts)])


def playbook_yaml(playbook, hosts: str = "all") -> str:
    """The YAML that will actually be handed to ansible-runner.

    In file mode the playbook lives in its project; from Git it is only read
    at run time, from the commit the run checks out.
    """
    if playbook.mode == playbook.MODE_TEXT:
        return playbook.text_content
    if playbook.mode == playbook.MODE_FILE:
        project = playbook.project
        if project is None:
            return ""
        if project.is_git:
            return f"# {playbook.file_path} from {project.git_url}, read at run time\n"
        found = project.files.filter(path=playbook.file_path).first()
        return found.content if found else ""
    return build_yaml(playbook, hosts)


def validate_playbook(text: str) -> None:
    """A whole playbook - any number of plays or imports. Raises ConversionError."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConversionError(f"Invalid YAML: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise ConversionError("A playbook is a list of plays.")
    for index, play in enumerate(data, start=1):
        if not isinstance(play, dict):
            raise ConversionError(f"Item {index} is not a play.")
        if not ({"hosts", "import_playbook", "ansible.builtin.import_playbook"} & set(play)):
            raise ConversionError(f"Play {index} says neither hosts: nor import_playbook:.")


# -- YAML -> graphical ------------------------------------------------------


def _normalize_module_name(key: str) -> str | None:
    """Map a task key onto a module name, accepting short names."""
    return module_catalog.canonical_name(key)


def parse_play(text: str) -> dict:
    """Parse playbook YAML into a single play mapping, or raise."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConversionError(f"Invalid YAML: {exc}") from exc

    if data is None:
        raise ConversionError("The playbook is empty.")
    if not isinstance(data, list):
        raise ConversionError("A playbook must be a list of plays.")
    if len(data) != 1:
        raise ConversionError(
            f"The graphical editor handles one play; this playbook has {len(data)}."
        )
    play = data[0]
    if not isinstance(play, dict):
        raise ConversionError("The play must be a mapping.")
    return play


def import_yaml(text: str) -> tuple[dict, list[dict]]:
    """Convert playbook YAML into play settings plus a list of task dicts.

    Returns ``(play_settings, tasks)`` where ``tasks`` entries carry the same
    field names as :class:`~playbooks.models.PlaybookTask`.
    """
    play = parse_play(text)

    unsupported = set(play) - SUPPORTED_PLAY_KEYS
    if unsupported:
        raise ConversionError(
            "Play uses options the graphical editor does not model: "
            + ", ".join(sorted(unsupported))
        )

    raw_tasks = play.get("tasks") or []
    if not isinstance(raw_tasks, list):
        raise ConversionError("'tasks' must be a list.")

    settings = {
        "become": bool(play.get("become", False)),
        "gather_facts": bool(play.get("gather_facts", True)),
        "serial": str(play.get("serial", "") or ""),
        "any_errors_fatal": bool(play.get("any_errors_fatal", False)),
        "extra_vars": play.get("vars") or {},
    }
    if not isinstance(settings["extra_vars"], dict):
        raise ConversionError("'vars' must be a mapping.")

    tasks = []
    for index, raw in enumerate(raw_tasks, start=1):
        tasks.append(_import_task(raw, index))
    return settings, tasks


def _import_task(raw, index: int) -> dict:
    if not isinstance(raw, dict):
        raise ConversionError(f"Task {index} is not a mapping.")

    module_key = None
    for key in raw:
        if key in SUPPORTED_TASK_KEYS:
            continue
        if _normalize_module_name(key):
            if module_key:
                raise ConversionError(
                    f"Task {index} names more than one module ({module_key}, {key})."
                )
            module_key = key
        else:
            raise ConversionError(
                f"Task {index} uses '{key}', which the graphical editor does not support."
            )

    if not module_key:
        raise ConversionError(f"Task {index} has no recognised module.")

    module = _normalize_module_name(module_key)
    args = raw[module_key]
    if isinstance(args, str):
        free_form = FREE_FORM_MODULES.get(module_key) or FREE_FORM_MODULES.get(module)
        if not free_form:
            raise ConversionError(
                f"Task {index}: '{module_key}' was given a bare string; the editor needs named arguments."
            )
        args = {free_form: args}
    elif args is None:
        args = {}
    elif not isinstance(args, dict):
        raise ConversionError(f"Task {index}: arguments for '{module_key}' must be a mapping.")

    loop = raw.get("loop", raw.get("with_items", ""))
    tags = raw.get("tags", "")
    if isinstance(tags, list):
        tags = ", ".join(str(t) for t in tags)

    become = raw.get("become", None)
    return {
        "name": str(raw.get("name", "") or ""),
        "module": module,
        "args": args,
        "when": _stringify(raw.get("when", "")),
        "loop": "" if loop in ("", None) else dump(loop).strip(),
        "tags": str(tags or ""),
        "become": "" if become is None else ("yes" if become else "no"),
        "ignore_errors": bool(raw.get("ignore_errors", False)),
        "register": str(raw.get("register", "") or ""),
        "enabled": True,
    }


def _stringify(value):
    """'when' accepts a string or a list of conditions; keep it editable."""
    if isinstance(value, list):
        return " and ".join(str(v) for v in value)
    return str(value or "")
