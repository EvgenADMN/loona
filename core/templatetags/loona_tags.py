# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Template helpers for rendering forms and job state."""
import os

from django import forms, template
from django.contrib.staticfiles import finders
from django.templatetags.static import static
from django.utils.timesince import timesince
from django.utils.translation import gettext as _

register = template.Library()


@register.filter
def is_checkbox(field):
    return isinstance(field.field.widget, forms.CheckboxInput)


@register.filter
def is_multi_checkbox(field):
    return isinstance(field.field.widget, forms.CheckboxSelectMultiple)


@register.filter
def status_badge(status):
    """CSS modifier for a job status badge."""
    return {
        "successful": "ok",
        "failed": "fail",
        "error": "fail",
        "canceled": "warn",
        "running": "run",
        "pending": "",
    }.get(status, "")


@register.filter
def duration(delta):
    """Human readable run time, e.g. '1m 12s'."""
    if delta is None:
        return "-"
    total = int(delta.total_seconds())
    if total < 60:
        return _("%(s)ss") % {"s": total}
    minutes, seconds = divmod(total, 60)
    if minutes < 60:
        return _("%(m)sm %(s)ss") % {"m": minutes, "s": f"{seconds:02d}"}
    hours, minutes = divmod(minutes, 60)
    return _("%(h)sh %(m)sm") % {"h": hours, "m": f"{minutes:02d}"}


@register.filter
def ago(value):
    if not value:
        return "-"
    return _("%(time)s ago") % {"time": timesince(value).split(",")[0]}


@register.filter
def uptime(seconds):
    """Seconds as '12d 4h' or '3h 05m'."""
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return "-"
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    if days:
        return _("%(d)sd %(h)sh") % {"d": days, "h": hours}
    return _("%(h)sh %(m)sm") % {"h": hours, "m": f"{rest // 60:02d}"}


@register.simple_tag(takes_context=True)
def query_string(context, **kwargs):
    """Current query string with some parameters replaced."""
    params = context["request"].GET.copy()
    for key, value in kwargs.items():
        if value in (None, ""):
            params.pop(key, None)
        else:
            params[key] = value
    return ("?" + params.urlencode()) if params else ""


@register.simple_tag
def asset(path):
    """A static URL that changes whenever the file does.

    Browsers hold on to stylesheets and scripts; without a version in the URL
    an update to Loona shows new pages with the old CSS until a hard reload.
    """
    url = static(path)
    found = finders.find(path)
    if not found:
        return url
    return f"{url}?v={int(os.path.getmtime(found))}"



@register.filter
def tr(value):
    """Translate a value made at runtime - a form label Django built from a
    field name, say.  Its English text has to be in the catalogue (see
    core/i18n_labels.py); anything already translated passes through."""
    if value in (None, ""):
        return value
    return _(str(value))
