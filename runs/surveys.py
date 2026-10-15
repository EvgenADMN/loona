# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Survey questions on a launch template: checking them, asking them, answers to vars.

A survey is a list of questions stored as JSON on the template::

    {"variable": "app_version", "label": "Version", "type": "choice",
     "choices": ["1.4", "1.5"], "default": "1.5", "required": true, "help": ""}

Types: text, textarea, password, integer, float, choice, multichoice, boolean.
Password answers are kept apart from the other extra vars - see
Job.secret_vars - and masked in the log.
"""
from __future__ import annotations

import re

from django import forms
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy

from core.forms import style

TYPES = ["text", "textarea", "password", "integer", "float", "choice", "multichoice", "boolean"]
TYPE_LABELS = {
    "text": gettext_lazy("Text"), "textarea": gettext_lazy("Text, several lines"), "password": gettext_lazy("Password (kept secret)"),
    "integer": gettext_lazy("Whole number"), "float": gettext_lazy("Number"), "choice": gettext_lazy("One of a list"),
    "multichoice": gettext_lazy("Several of a list"), "boolean": gettext_lazy("Yes / no"),
}
VARIABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
MAX_QUESTIONS = 50


def clean_spec(spec, unrestricted: bool) -> list[dict]:
    """The survey, checked and normalised; raises forms.ValidationError with every problem."""
    from .forms import CONNECTION_VAR

    if not isinstance(spec, list):
        raise forms.ValidationError(_("The survey must be a list of questions."))
    if len(spec) > MAX_QUESTIONS:
        raise forms.ValidationError(_('At most %(MAX_QUESTIONS)s questions.') % {"MAX_QUESTIONS": MAX_QUESTIONS})
    problems, cleaned, seen = [], [], set()
    for number, raw in enumerate(spec, 1):
        if not isinstance(raw, dict):
            problems.append(f"Question {number} is not a question.")
            continue
        variable = str(raw.get("variable") or "").strip()
        where = f"Question {number} ({variable or 'no variable'})"
        kind = raw.get("type") or "text"
        question = {
            "variable": variable,
            "label": str(raw.get("label") or "").strip()[:200] or variable,
            "help": str(raw.get("help") or "").strip()[:500],
            "type": kind,
            "required": bool(raw.get("required")),
        }
        if not VARIABLE.match(variable):
            problems.append(f"{where}: the variable must be letters, digits and underscores.")
        elif variable in seen:
            problems.append(f"{where}: asked twice.")
        elif not unrestricted and CONNECTION_VAR.match(variable):
            problems.append(f"{where}: only a superuser may ask for connection settings.")
        seen.add(variable)
        if kind not in TYPES:
            problems.append(f"{where}: unknown type {kind!r}.")
            continue
        if kind in ("choice", "multichoice"):
            choices = raw.get("choices") or []
            if isinstance(choices, str):
                choices = choices.splitlines()
            choices = [str(c).strip() for c in choices if str(c).strip()]
            if not choices:
                problems.append(f"{where}: list the choices, one per line.")
            if len(set(choices)) != len(choices):
                problems.append(f"{where}: a choice is listed twice.")
            question["choices"] = choices
        if kind in ("integer", "float"):
            for bound in ("min", "max"):
                value = raw.get(bound)
                if value in (None, ""):
                    continue
                try:
                    question[bound] = int(value) if kind == "integer" else float(value)
                except (TypeError, ValueError):
                    problems.append(f"{where}: {bound} is not a number.")
            if "min" in question and "max" in question and question["min"] > question["max"]:
                problems.append(f"{where}: min is above max.")
        default = raw.get("default")
        if kind == "password":
            # A stored default would be a secret kept in the clear.
            default = None
        if default not in (None, "", []):
            try:
                question["default"] = _field(question).clean(_as_data(question, default))
            except forms.ValidationError as exc:
                problems.append(f"{where}: the default does not fit - {' '.join(exc.messages)}")
        cleaned.append(question)
    if problems:
        raise forms.ValidationError(problems)
    return cleaned


def _as_data(question, value):
    """A stored value as a form field would receive it."""
    if question["type"] == "multichoice":
        return value if isinstance(value, list) else [value]
    if question["type"] == "boolean":
        return value in (True, "true", "True", "on", "yes", 1)
    return str(value)


def _field(question) -> forms.Field:
    kind = question["type"]
    common = {"label": question["label"], "help_text": question.get("help", ""),
              "required": question.get("required", False) and kind != "boolean"}
    if kind == "textarea":
        from core.forms import TextFileField

        return TextFileField(widget=forms.Textarea(attrs={"rows": 4}), **common)
    if kind == "password":
        return forms.CharField(widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "off"}),
                               strip=False, **common)
    if kind == "integer":
        return forms.IntegerField(min_value=question.get("min"), max_value=question.get("max"), **common)
    if kind == "float":
        return forms.FloatField(min_value=question.get("min"), max_value=question.get("max"), **common)
    if kind == "choice":
        choices = [(c, c) for c in question["choices"]]
        if not common["required"]:
            choices = [("", "-")] + choices
        return forms.ChoiceField(choices=choices, **common)
    if kind == "multichoice":
        return forms.MultipleChoiceField(choices=[(c, c) for c in question["choices"]],
                                         widget=forms.CheckboxSelectMultiple, **common)
    if kind == "boolean":
        return forms.BooleanField(**common)
    return forms.CharField(max_length=1000, **common)


class SurveyForm(forms.Form):
    def __init__(self, survey, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.survey = survey
        for question in survey:
            field = _field(question)
            if "default" in question:
                field.initial = question["default"]
            self.fields[f"q_{question['variable']}"] = field
        style(self)

    def answers(self) -> tuple[dict, dict]:
        """(extra vars, secret vars) from the answers; empty optional ones left out."""
        plain, secret = {}, {}
        for question in self.survey:
            value = self.cleaned_data.get(f"q_{question['variable']}")
            if value in (None, "", []) and question["type"] != "boolean":
                continue
            (secret if question["type"] == "password" else plain)[question["variable"]] = value
        return plain, secret
