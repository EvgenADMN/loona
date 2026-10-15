# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Form widgets and fields shared across Loona's apps."""
from django import forms
from django.utils.translation import gettext_lazy as _
import yaml


class TextFileField(forms.CharField):
    """Text that ends up in a file somewhere: a template, a script, a key.

    Kept as typed, except for the line breaks.  A browser sends every one of
    them as CRLF whatever was on screen, and stored that way a template would
    render a DOS file on the server and a script would fail on its first line.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("strip", False)
        kwargs.setdefault("required", False)
        super().__init__(*args, **kwargs)

    def to_python(self, value):
        value = super().to_python(value)
        return value.replace("\r\n", "\n").replace("\r", "\n") if value else value


class VariablesField(forms.CharField):
    """A YAML (or JSON) mapping edited as free text and stored as a dict."""

    widget = forms.Textarea(attrs={"rows": 5, "class": "code", "spellcheck": "false"})

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("required", False)
        kwargs.setdefault(
            "help_text", _("YAML or JSON mapping, e.g. http_port: 8080. Leave empty for none.")
        )
        super().__init__(*args, **kwargs)

    def prepare_value(self, value):
        if isinstance(value, dict):
            if not value:
                return ""
            return yaml.safe_dump(value, sort_keys=False, allow_unicode=True).strip()
        return value

    def clean(self, value):
        value = (value or "").strip()
        if not value:
            return {}
        try:
            parsed = yaml.safe_load(value)
        except yaml.YAMLError as exc:
            raise forms.ValidationError(_('Invalid YAML: %(exc)s') % {"exc": exc}) from exc
        if not isinstance(parsed, dict):
            raise forms.ValidationError(_("Variables must be a mapping of names to values."))
        return parsed


def style(form):
    """Attach Loona's input classes to every widget of a form."""
    for field in form.fields.values():
        widget = field.widget
        if isinstance(widget, (forms.CheckboxInput, forms.RadioSelect, forms.CheckboxSelectMultiple)):
            continue
        css = widget.attrs.get("class", "")
        widget.attrs["class"] = (css + " input").strip()
    return form
