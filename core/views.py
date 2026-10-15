# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.conf import settings
from django.utils.http import url_has_allowed_host_and_scheme
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from access import policy
from playbooks.models import Playbook
from runs.models import Job

from .models import UserPreference


@login_required
def dashboard(request):
    # The overview is about playbook work; Loona's own key runs live on the
    # host pages and behind the Jobs page filter.
    access = policy.for_user(request.user)
    jobs = access.jobs()
    work = jobs.exclude(kind__in=Job.SYSTEM_KINDS)
    recent = work.select_related("playbook")[:8]
    counts = {
        "hosts": access.hosts().count(),
        "groups": access.groups().count(),
        "credentials": access.credentials(kinds=None).count(),
        "playbooks": Playbook.objects.count(),
        # Matches what "All jobs" opens on, and what "Recent jobs" lists here:
        # Loona's own key runs are not what this number is about.
        "jobs": work.count(),
    }
    running = jobs.filter(status__in=[Job.PENDING, Job.RUNNING]).count()
    by_status = {
        row["status"]: row["n"]
        for row in jobs.order_by().values("status").annotate(n=Count("id"))
    }
    from access import approvals

    return render(
        request,
        "core/dashboard.html",
        {
            "awaiting_me": approvals.waiting_for(request.user, limit=6),
            "drifting": _drifting(request.user),
            "counts": counts,
            "recent_jobs": recent,
            "running": running,
            "by_status": by_status,
            "top_groups": access.groups().annotate(n=Count("hosts")).order_by("-n")[:6],
        },
    )


@login_required
@require_POST
def theme_toggle(request):
    """Flip this account between the dark and light palettes.

    The page has already repainted itself by the time this lands - the button
    flips data-theme locally, and this only makes the choice stick. Anything
    that is not an htmx call still gets sent back where it came from.
    """
    UserPreference.toggle_theme(request.user)
    if request.headers.get("HX-Request"):
        return HttpResponse(status=204)
    return redirect(request.META.get("HTTP_REFERER") or "dashboard")


@login_required
@require_POST
def language_set(request):
    """This person's own interface language; "" goes back to the default."""
    language = request.POST.get("language", "")
    if language not in dict(settings.LANGUAGES):
        language = ""
    UserPreference.set_language(request.user, language)
    back = request.POST.get("next") or request.META.get("HTTP_REFERER") or ""
    if not url_has_allowed_host_and_scheme(back, allowed_hosts={request.get_host()},
                                           require_https=request.is_secure()):
        back = "dashboard"
    return redirect(back)


def _drifting(user):
    from runs.drift_views import _visible
    from runs.models import DriftCheck

    return (
        _visible(user)
        .filter(status__in=(DriftCheck.DRIFTED, DriftCheck.ERROR))
        .distinct()
        .select_related("last_job")[:6]
    )

