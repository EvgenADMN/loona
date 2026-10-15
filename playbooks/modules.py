# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Catalog of Ansible modules exposed by the graphical playbook editor.

Each entry describes the fields the editor renders and how they are coerced into
Ansible module arguments.  Adding a module here is enough to make it available in
the UI - no template or view changes needed.

Field types: text, textarea, choice, bool, int, keyvalue (dict rendered as YAML),
list (one item per line) and yaml (any value, written as YAML).

Modules outside this catalog get their fields from ansible-doc, see
:func:`resolve` and :mod:`playbooks.docs`.  The catalog still decides the
friendly label, the category and which fields come first.
"""
from __future__ import annotations

import yaml
from django.utils.translation import gettext_lazy as _


def _f(name, type="text", label=None, required=False, default=None, choices=None, help=""):
    return {
        "name": name,
        "type": type,
        "label": label or name.replace("_", " ").capitalize(),
        "required": required,
        "default": default,
        "choices": choices or [],
        "help": help,
        "aliases": [],
        # Curated defaults are written into the task: "state: present" says
        # what the task does even to someone who does not know the module.
        "prefill": True,
    }


MODULES = [
    # -- Packages ---------------------------------------------------------
    {
        "name": "ansible.builtin.package",
        "label": "Package (generic)",
        "category": "Packages",
        "description": "Install or remove packages using the OS native package manager.",
        "fields": [
            _f("name", required=True, help="Package name, or several separated by commas."),
            _f("state", "choice", choices=["present", "absent", "latest"], default="present"),
        ],
    },
    {
        "name": "ansible.builtin.apt",
        "label": "APT package",
        "category": "Packages",
        "description": "Manage packages on Debian/Ubuntu.",
        "fields": [
            _f("name", required=True, help="Package name, or several separated by commas."),
            _f("state", "choice", choices=["present", "absent", "latest"], default="present"),
            _f("update_cache", "bool", default=False, help="Run apt-get update first."),
            _f("cache_valid_time", "int", help="Skip update if cache is newer than N seconds."),
        ],
    },
    {
        "name": "ansible.builtin.dnf",
        "label": "DNF/YUM package",
        "category": "Packages",
        "description": "Manage packages on RHEL/Fedora/CentOS.",
        "fields": [
            _f("name", required=True),
            _f("state", "choice", choices=["present", "absent", "latest"], default="present"),
            _f("update_cache", "bool", default=False),
        ],
    },
    {
        "name": "ansible.builtin.pip",
        "label": "Python package (pip)",
        "category": "Packages",
        "description": "Install Python packages with pip.",
        "fields": [
            _f("name", required=True),
            _f("state", "choice", choices=["present", "absent", "latest", "forcereinstall"], default="present"),
            _f("virtualenv", help="Path to a virtualenv to install into."),
        ],
    },
    # -- Services ---------------------------------------------------------
    {
        "name": "ansible.builtin.service",
        "label": "Service",
        "category": "Services",
        "description": "Start, stop, restart or enable a service.",
        "fields": [
            _f("name", required=True),
            _f("state", "choice", choices=["started", "stopped", "restarted", "reloaded"], default="started"),
            _f("enabled", "choice", choices=["", "yes", "no"], help="Start on boot."),
        ],
    },
    {
        "name": "ansible.builtin.systemd_service",
        "label": "Systemd unit",
        "category": "Services",
        "description": "Manage a systemd unit, with daemon-reload support.",
        "fields": [
            _f("name", required=True),
            _f("state", "choice", choices=["", "started", "stopped", "restarted", "reloaded"]),
            _f("enabled", "choice", choices=["", "yes", "no"]),
            _f("daemon_reload", "bool", default=False),
            _f("scope", "choice", choices=["", "system", "user", "global"]),
        ],
    },
    # -- Files ------------------------------------------------------------
    {
        "name": "ansible.builtin.file",
        "label": "File / directory",
        "category": "Files",
        "description": "Set attributes, create directories, remove or link paths.",
        "fields": [
            _f("path", required=True),
            _f("state", "choice", choices=["file", "directory", "touch", "absent", "link"], default="directory"),
            _f("owner"),
            _f("group"),
            _f("mode", help='Octal as a string, e.g. "0755".'),
            _f("src", help="Target path when state is link."),
        ],
    },
    {
        "name": "ansible.builtin.copy",
        "label": "Copy file",
        "category": "Files",
        "description": "Copy a file to the managed host, or write inline content.",
        "fields": [
            _f("dest", required=True),
            _f("src", help="Path on the Loona server (relative to the project dir)."),
            _f("content", "textarea", help="Inline content. Use instead of src."),
            _f("owner"),
            _f("group"),
            _f("mode"),
            _f("backup", "bool", default=False),
        ],
    },
    {
        "name": "ansible.builtin.template",
        "label": "Jinja2 template",
        "category": "Files",
        "description": "Render a Jinja2 template onto the managed host.",
        "fields": [
            _f("src", required=True, help="Template path inside the project dir."),
            _f("dest", required=True),
            _f("owner"),
            _f("group"),
            _f("mode"),
            _f("validate", help='Validation command, e.g. "nginx -t -c %s".'),
        ],
    },
    {
        "name": "ansible.builtin.lineinfile",
        "label": "Line in file",
        "category": "Files",
        "description": "Ensure a single line is present or absent in a file.",
        "fields": [
            _f("path", required=True),
            _f("line"),
            _f("regexp", help="Regex identifying the line to replace."),
            _f("state", "choice", choices=["present", "absent"], default="present"),
            _f("insertafter"),
            _f("create", "bool", default=False),
        ],
    },
    {
        "name": "ansible.builtin.blockinfile",
        "label": "Block in file",
        "category": "Files",
        "description": "Manage a marked block of lines inside a file.",
        "fields": [
            _f("path", required=True),
            _f("block", "textarea", required=True),
            _f("marker", default="# {mark} ANSIBLE MANAGED BLOCK"),
            _f("state", "choice", choices=["present", "absent"], default="present"),
            _f("create", "bool", default=False),
        ],
    },
    {
        "name": "ansible.builtin.unarchive",
        "label": "Unpack archive",
        "category": "Files",
        "description": "Unpack an archive onto the managed host.",
        "fields": [
            _f("src", required=True),
            _f("dest", required=True),
            _f("remote_src", "bool", default=False, help="Archive already lives on the host."),
            _f("creates", help="Skip if this path already exists."),
        ],
    },
    {
        "name": "ansible.builtin.get_url",
        "label": "Download file",
        "category": "Files",
        "description": "Download a file from an HTTP/HTTPS/FTP URL.",
        "fields": [
            _f("url", required=True),
            _f("dest", required=True),
            _f("mode"),
            _f("checksum", help='e.g. "sha256:abc123...".'),
        ],
    },
    # -- Commands ---------------------------------------------------------
    {
        "name": "ansible.builtin.command",
        "label": "Command",
        "category": "Commands",
        "description": "Run a command without a shell. Safer than shell.",
        "fields": [
            _f("cmd", "textarea", required=True, label=_("Command")),
            _f("chdir"),
            _f("creates", help="Skip if this path exists."),
            _f("removes", help="Skip unless this path exists."),
        ],
    },
    {
        "name": "ansible.builtin.shell",
        "label": "Shell",
        "category": "Commands",
        "description": "Run a command through the shell (pipes, redirects, globs).",
        "fields": [
            _f("cmd", "textarea", required=True, label=_("Command")),
            _f("chdir"),
            _f("creates"),
            _f("executable", help='e.g. "/bin/bash".'),
        ],
    },
    {
        "name": "ansible.builtin.script",
        "label": "Run local script",
        "category": "Commands",
        "description": "Copy a local script to the host and execute it there.",
        "fields": [
            _f("cmd", "text", required=True, label=_("Script path + args")),
            _f("chdir"),
            _f("creates"),
        ],
    },
    # -- Users ------------------------------------------------------------
    {
        "name": "ansible.builtin.user",
        "label": "User account",
        "category": "Users",
        "description": "Create, modify or remove a user account.",
        "fields": [
            _f("name", required=True),
            _f("state", "choice", choices=["present", "absent"], default="present"),
            _f("groups", help="Comma separated supplementary groups."),
            _f("append", "bool", default=False),
            _f("shell", default="/bin/bash"),
            _f("create_home", "bool", default=True),
            _f("system", "bool", default=False),
        ],
    },
    {
        "name": "ansible.builtin.group",
        "label": "Group",
        "category": "Users",
        "description": "Create or remove a system group.",
        "fields": [
            _f("name", required=True),
            _f("state", "choice", choices=["present", "absent"], default="present"),
            _f("system", "bool", default=False),
        ],
    },
    {
        "name": "ansible.posix.authorized_key",
        "label": "Authorized SSH key",
        "category": "Users",
        "description": "Add or remove an SSH public key for a user.",
        "fields": [
            _f("user", required=True),
            _f("key", "textarea", required=True),
            _f("state", "choice", choices=["present", "absent"], default="present"),
            _f("exclusive", "bool", default=False),
        ],
    },
    # -- Misc -------------------------------------------------------------
    {
        "name": "ansible.builtin.git",
        "label": "Git checkout",
        "category": "Deploy",
        "description": "Clone or update a git repository on the host.",
        "fields": [
            _f("repo", required=True),
            _f("dest", required=True),
            _f("version", default="HEAD", help="Branch, tag or commit."),
            _f("force", "bool", default=False),
        ],
    },
    {
        "name": "ansible.builtin.cron",
        "label": "Cron job",
        "category": "Deploy",
        "description": "Manage a crontab entry.",
        "fields": [
            _f("name", required=True, help="Unique description of the job."),
            _f("job", "textarea"),
            _f("minute", default="*"),
            _f("hour", default="*"),
            _f("day", default="*"),
            _f("month", default="*"),
            _f("weekday", default="*"),
            _f("user"),
            _f("state", "choice", choices=["present", "absent"], default="present"),
        ],
    },
    {
        "name": "ansible.builtin.uri",
        "label": "HTTP request",
        "category": "Deploy",
        "description": "Call an HTTP endpoint and check the response.",
        "fields": [
            _f("url", required=True),
            _f("method", "choice", choices=["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"], default="GET"),
            _f("status_code", default="200"),
            _f("body", "textarea"),
            _f("body_format", "choice", choices=["", "raw", "json", "form-urlencoded"]),
            _f("validate_certs", "bool", default=True),
        ],
    },
    {
        "name": "ansible.builtin.wait_for",
        "label": "Wait for",
        "category": "Deploy",
        "description": "Block until a port opens, a file appears or a timeout hits.",
        "fields": [
            _f("host", default="127.0.0.1"),
            _f("port", "int"),
            _f("path"),
            _f("state", "choice", choices=["started", "stopped", "present", "absent"], default="started"),
            _f("timeout", "int", default=300),
        ],
    },
    {
        "name": "ansible.builtin.reboot",
        "label": "Reboot host",
        "category": "Deploy",
        "description": "Reboot and wait for the host to come back.",
        "fields": [
            _f("reboot_timeout", "int", default=600),
            _f("msg", help="Message shown to logged-in users."),
        ],
    },
    {
        "name": "ansible.builtin.debug",
        "label": "Debug message",
        "category": "Diagnostics",
        "description": "Print a message or the value of a variable.",
        "fields": [
            _f("msg", "textarea"),
            _f("var", help="Variable name to dump. Use instead of msg."),
        ],
    },
    {
        "name": "ansible.builtin.ping",
        "label": "Ping",
        "category": "Diagnostics",
        "description": "Verify Loona can reach and authenticate to the host.",
        "fields": [],
    },
    {
        "name": "ansible.builtin.setup",
        "label": "Gather facts",
        "category": "Diagnostics",
        "description": "Collect system facts from the host.",
        "fields": [
            _f("filter", help='Fact name glob, e.g. "ansible_distribution*".'),
        ],
    },
]

MODULES_BY_NAME = {m["name"]: m for m in MODULES}


def categories():
    """Modules grouped by category, preserving catalog order."""
    grouped = {}
    for module in MODULES:
        grouped.setdefault(module["category"], []).append(module)
    return grouped


def get_module(name):
    return MODULES_BY_NAME.get(name)


def coerce_value(field, raw):
    """Turn one raw form value into the Python value Ansible expects."""
    ftype = field["type"]
    if ftype == "bool":
        return bool(raw) and str(raw).lower() not in ("false", "0", "off", "no", "")
    if raw is None:
        return None
    if ftype == "textarea" and isinstance(raw, str):
        # File content and scripts keep their indentation and last line break.
        return raw if raw.strip() else None
    raw = raw.strip() if isinstance(raw, str) else raw
    if raw == "":
        return None
    if ftype == "int":
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None
    if ftype == "keyvalue":
        try:
            parsed = yaml.safe_load(raw)
        except yaml.YAMLError:
            return None
        return parsed if isinstance(parsed, dict) else None
    if ftype == "list":
        if isinstance(raw, list):
            return raw or None
        items = [line.strip() for line in str(raw).splitlines() if line.strip()]
        return items or None
    if ftype == "yaml":
        if not isinstance(raw, str):
            return raw
        try:
            return yaml.safe_load(raw)
        except yaml.YAMLError:
            return None
    return raw


# -- any module ---------------------------------------------------------------

# Options shown up front for a module the catalog does not describe.
FEATURED_LIMIT = 6


def canonical_name(key: str) -> str | None:
    """The fully qualified name for a task key, or None if it is no module.

    Accepts what Ansible accepts in practice: a full name, a builtin short
    name ("copy"), or a short name only one installed collection provides
    ("ufw" -> community.general.ufw).  A full name Loona has never heard of is
    kept as is - it may come from a collection that is only installed where
    the playbook will run.
    """
    from . import docs

    if get_module(key) or docs.is_installed(key):
        return key
    for candidate in (f"ansible.builtin.{key}", f"ansible.posix.{key}"):
        if get_module(candidate) or docs.is_installed(candidate):
            return candidate
    if "." not in key:
        matches = docs.names_ending_with(key)
        return matches[0] if len(matches) == 1 else None
    return key if key.count(".") >= 2 else None


def resolve(name: str) -> dict:
    """Everything the editor needs to render one module.

    The catalog's hand-written fields come first ("featured"); every other
    option ansible-doc knows follows.  ``source`` says where the fields came
    from: "catalog", "ansible-doc", both ("catalog+doc"), or "unknown".
    """
    from . import docs

    curated = get_module(name)
    doc = docs.get_spec(name)
    if doc is None and curated is None:
        return {
            "name": name,
            "label": name,
            "category": "",
            "description": "Loona has no documentation for this module - it is "
            "probably not installed on the Loona server. Its arguments go in "
            "Other arguments.",
            "fields": [],
            "featured": [],
            "source": "unknown",
        }
    if doc is None:
        return {
            **curated,
            "featured": [f["name"] for f in curated["fields"]],
            "source": "catalog",
        }

    by_name = {f["name"]: f for f in doc["fields"]}
    if curated:
        featured = []
        for field in curated["fields"]:
            # The catalog's wording and default, ansible-doc's aliases.
            merged = {**field, "aliases": by_name.get(field["name"], {}).get("aliases", [])}
            featured.append(merged)
        featured_names = [f["name"] for f in featured]
    else:
        # Every required option, topped up with the usual suspects.
        required = [f["name"] for f in doc["fields"] if f["required"]]
        common = [n for n in COMMON_FIELDS if n in by_name and n not in required]
        featured_names = required + common[: max(0, FEATURED_LIMIT - len(required))]
        featured = [by_name[n] for n in featured_names]
    rest = [f for f in doc["fields"] if f["name"] not in featured_names]
    return {
        "name": name,
        "label": curated["label"] if curated else doc["label"],
        "category": curated["category"] if curated else "",
        "description": (curated or doc)["description"],
        "fields": featured + rest,
        "featured": featured_names,
        "source": "catalog+doc" if curated else "ansible-doc",
    }


COMMON_FIELDS = ("name", "state", "src", "dest", "path", "content", "msg", "url")


def search(query: str, limit: int = 30) -> list[dict]:
    """Modules matching a search box, the catalog's own first.

    With no query, the catalog is the answer: it is the short list of what
    people reach for most.
    """
    from . import docs

    query = query.strip()
    curated = [
        {"name": m["name"], "label": m["label"], "description": m["description"],
         "category": m["category"]}
        for m in MODULES
        if not query or all(
            w.lower() in f"{m['name']} {m['label']} {m['description']}".lower()
            for w in query.split()
        )
    ]
    if not query:
        return curated
    seen = {m["name"] for m in curated}
    found = []
    for row in docs.search(query):
        if row.name in seen:
            continue
        found.append({"name": row.name, "label": row.name, "description":
                      row.short_description, "category": ""})
    words = [w.lower() for w in query.split()]

    def rank(m):
        short = m["name"].rsplit(".", 1)[-1].lower()
        return (
            short != "_".join(words),  # "docker container" -> docker_container
            not all(w in short for w in words),  # the name says it, not just the blurb
            not m["name"].startswith("ansible."),  # builtin and posix first
            len(m["name"]),
            m["name"],
        )

    found.sort(key=rank)
    return (curated + found)[:limit]

