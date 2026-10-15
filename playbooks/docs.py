# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Editor fields for any module, read from ``ansible-doc``.

Two calls do all the work: ``ansible-doc -l`` lists every module the server
has (a second or so, cached in :class:`AnsibleModule`), and ``ansible-doc
<module>`` returns one module's options, converted here into the same field
dicts the hand-written catalog in :mod:`playbooks.modules` uses.

Nothing here is required: without ansible-doc the editor falls back to the
hand-written catalog and puts everything else into "Other arguments".
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings
from django.utils import timezone

from .models import AnsibleModule

log = logging.getLogger(__name__)


class DocsUnavailable(Exception):
    pass


class DocsFailed(DocsUnavailable):
    """ansible-doc is there and ran, but exited with an error."""


# ansible-doc markup: C(code), I(italic), O(option), V(value), M(module)...
_MARKUP = re.compile(r"\b(?:[CIBUMOVEP]|RV)\(([^()]*)\)")
_LINK = re.compile(r"\bL\(([^,()]*),[^()]*\)")

# Free text that is usually more than one line.
LONG_TEXT = {"content", "msg", "block", "script", "cmd", "body", "template"}


def plain(text) -> str:
    """ansible-doc description (a string or list of them) as plain text."""
    if isinstance(text, list):
        text = " ".join(str(part) for part in text)
    text = _LINK.sub(r"\1", str(text or ""))
    # O(state=present) and V(foo) both read best as just the text inside.
    text = _MARKUP.sub(lambda m: m.group(1), text)
    return " ".join(text.split())


def _ansible_doc(*args) -> dict:
    from administration import system

    if not (settings.LOONA_MODULE_DOCS and system.get().module_docs):
        raise DocsUnavailable("module documentation is switched off")
    try:
        done = subprocess.run(
            ["ansible-doc", "-j", *args],
            # ansible refuses to run with a non-blocking stdin.
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DocsUnavailable(str(exc)) from exc
    if done.returncode != 0:
        raise DocsFailed(done.stderr.strip()[:500])
    try:
        return json.loads(done.stdout or "{}")
    except ValueError as exc:
        raise DocsUnavailable(f"ansible-doc returned something that is not JSON: {exc}")


# -- the index -------------------------------------------------------------


def _listing() -> dict:
    """Every installed module with its one-line description."""
    try:
        return _ansible_doc("-l", "-t", "module")
    except DocsFailed as exc:
        whole = exc
    # One module with a malformed description makes ansible-doc give up on
    # the entire listing. Asked collection by collection, only the collection
    # it trips over is lost.
    names = ["ansible.builtin", *_collections()]
    found, skipped = {}, []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for name, modules in zip(names, pool.map(_collection_listing, names)):
            if modules is None:
                skipped.append(name)
            else:
                found.update(modules)
    if not found:
        raise whole
    log.warning("ansible-doc could not list %s; their modules are left out of the editor.", ", ".join(skipped))
    return found


def _collection_listing(name: str) -> dict | None:
    try:
        return _ansible_doc("-l", "-t", "module", name)
    except DocsUnavailable:
        return None


def _collections() -> list[str]:
    try:
        done = subprocess.run(
            ["ansible-galaxy", "collection", "list", "--format", "json"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120,
        )
        paths = json.loads(done.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []
    return sorted({name for found in paths.values() for name in found})


def refresh_index() -> int:
    """Re-read the list of installed modules. Returns how many there are."""
    listing = _listing()
    known = dict(AnsibleModule.objects.values_list("name", "short_description"))
    new = [
        AnsibleModule(name=name, short_description=plain(text)[:500])
        for name, text in listing.items()
        if name not in known
    ]
    AnsibleModule.objects.bulk_create(new, batch_size=500, ignore_conflicts=True)
    # A collection may have been upgraded: its modules' options may differ.
    AnsibleModule.objects.filter(name__in=listing).update(spec=None, fetched_at=None)
    AnsibleModule.objects.exclude(name__in=list(listing)).delete()
    return len(listing)


def ensure_index():
    """Fill the index on first use; quietly do nothing without ansible-doc."""
    if AnsibleModule.objects.exists():
        return
    try:
        refresh_index()
    except DocsUnavailable as exc:
        log.info("No module index: %s", exc)


def search(query: str, limit: int = 30):
    ensure_index()
    rows = AnsibleModule.objects.all()
    for word in query.split():
        rows = rows.filter(name__icontains=word) | rows.filter(
            short_description__icontains=word
        )
    return list(rows.order_by("name")[: limit * 4])


def is_installed(name: str) -> bool:
    ensure_index()
    return AnsibleModule.objects.filter(name=name).exists()


def names_ending_with(short: str) -> list[str]:
    ensure_index()
    return list(
        AnsibleModule.objects.filter(name__endswith=f".{short}").values_list("name", flat=True)
    )


# -- one module ------------------------------------------------------------


def get_spec(name: str) -> dict | None:
    """Editor spec for one module, from the cache or ansible-doc."""
    row = AnsibleModule.objects.filter(name=name).first()
    if row is not None and row.spec is not None:
        return row.spec
    try:
        raw = _ansible_doc("-t", "module", name)
    except DocsUnavailable as exc:
        log.info("No documentation for %s: %s", name, exc)
        return None
    entry = raw.get(name) or next(iter(raw.values()), None)
    if not entry or "doc" not in entry:
        return None
    spec = spec_from_doc(name, entry["doc"])
    AnsibleModule.objects.update_or_create(
        name=name,
        defaults={
            "spec": spec,
            "short_description": spec["description"][:500],
            "fetched_at": timezone.now(),
        },
    )
    return spec


def spec_from_doc(name: str, doc: dict) -> dict:
    options = doc.get("options") or {}
    fields = [field_from_option(key, opt) for key, opt in options.items()]
    # Required first, then alphabetical - the order ansible-doc itself uses.
    fields.sort(key=lambda f: (not f["required"], f["name"]))
    return {
        "name": name,
        "label": name.rsplit(".", 1)[-1].replace("_", " ").capitalize(),
        "description": plain(doc.get("short_description", "")),
        "fields": fields,
    }


def field_from_option(key: str, opt: dict) -> dict:
    kind = opt.get("type", "str")
    choices = opt.get("choices")
    if isinstance(choices, dict):
        choices = list(choices)
    default = opt.get("default")
    suboptions = bool(opt.get("suboptions"))

    if kind in ("bool", "boolean"):
        ftype, default = "bool", to_bool(default)
    elif choices and kind not in ("list", "dict"):
        ftype = "choice"
    elif kind == "int":
        ftype = "int"
    elif kind == "list" and not suboptions and opt.get("elements", "str") in ("str", "path"):
        ftype = "list"
    elif kind in ("dict", "list", "raw", "json", "jsonarg") or suboptions:
        ftype = "yaml"
    elif key in LONG_TEXT:
        ftype = "textarea"
    else:
        ftype = "text"

    full = plain(opt.get("description", ""))
    help_text = summary(full)
    if default not in (None, "", [], {}) and ftype != "bool":
        help_text = f"{help_text} Default: {default}.".strip()
    return {
        "name": key,
        "type": ftype,
        "label": key.replace("_", " ").capitalize(),
        "required": bool(opt.get("required")),
        "default": default,
        "choices": [str(c) for c in (choices or [])],
        "help": help_text,
        # The whole description, for a tooltip: some run to a dozen sentences.
        "description": full,
        "aliases": list(opt.get("aliases") or []),
        # Only curated fields pre-fill their default into the task; for the
        # rest the default is Ansible's business and stays out of the YAML.
        "prefill": False,
    }


def summary(text: str, limit: int = 160) -> str:
    """The first sentence, and never more than ``limit`` characters."""
    first = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
    if len(first) > limit:
        first = first[: limit - 1].rsplit(" ", 1)[0] + "…"
    return first


def to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("yes", "true", "on", "1")
