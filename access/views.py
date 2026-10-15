# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Teams: who is in them, what they may touch, and which LDAP groups feed them."""
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.models import Group
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _

from .forms import DirectoryLinkForm, GrantForm, MaintenanceWindowForm, MemberForm, TeamForm
from .models import DirectoryAccount, DirectoryGroup, GroupGrant, MaintenanceWindow


def manages_teams(view):
    return login_required(
        permission_required("auth.change_group", raise_exception=True)(view)
    )


@manages_teams
def team_list(request):
    teams = Group.objects.annotate(
        members=Count("user", distinct=True),
        roles=Count("grants", distinct=True),
        ldap=Count("directory_groups", distinct=True),
    ).order_by("name")
    return render(request, "access/team_list.html", {"teams": teams})


@manages_teams
def team_create(request):
    form = TeamForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        team = form.save()
        messages.success(request, _('Team %(team)s created.') % {"team": team})
        return redirect("team_detail", team.pk)
    return render(request, "access/team_form.html", {"form": form})


@manages_teams
def team_rename(request, pk):
    team = get_object_or_404(Group, pk=pk)
    form = TeamForm(request.POST or None, instance=team)
    if request.method == "POST" and form.is_valid():
        form.save()
        return redirect("team_detail", team.pk)
    return render(request, "access/team_form.html", {"form": form, "team": team})


@manages_teams
def team_delete(request, pk):
    team = get_object_or_404(Group, pk=pk)
    if request.method == "POST":
        name = team.name
        # Directory groups that fed it stay known, pointing nowhere.
        team.delete()
        messages.success(request, _('Team %(name)s deleted.') % {"name": name})
        return redirect("team_list")
    return render(request, "core/confirm_delete.html", {"object": team})


@manages_teams
def team_detail(request, pk):
    team = get_object_or_404(Group, pk=pk)
    return render(request, "access/team_detail.html", _detail_context(team))


def _detail_context(team, member_form=None, grant_form=None, link_form=None):
    synced = _synced_members(team)
    members = [
        {"user": user, "synced": user.pk in synced}
        for user in team.user_set.order_by("username")
    ]
    return {
        "team": team,
        "members": members,
        "grants": team.grants.select_related("host_group").order_by("host_group__name"),
        "links": team.directory_groups.order_by("name"),
        "member_form": member_form or MemberForm(team=team),
        "grant_form": grant_form or GrantForm(),
        "link_form": link_form or DirectoryLinkForm(team=team),
    }


def _synced_members(team):
    """Members the directory put here, and will put back if removed."""
    # Filtered in Python: JSON containment lookups differ between SQLite and
    # PostgreSQL, and a team's membership is small.
    accounts = DirectoryAccount.objects.filter(user__groups=team)
    return {a.user_id for a in accounts if team.pk in a.granted_team_ids}


def _rerender(request, team, **forms):
    return render(request, "access/team_detail.html", _detail_context(team, **forms))


@manages_teams
@require_POST
def member_add(request, pk):
    team = get_object_or_404(Group, pk=pk)
    form = MemberForm(request.POST, team=team)
    if not form.is_valid():
        return _rerender(request, team, member_form=form)
    team.user_set.add(form.cleaned_data["user"])
    return redirect("team_detail", team.pk)


@manages_teams
@require_POST
def member_remove(request, pk, user_pk):
    team = get_object_or_404(Group, pk=pk)
    user = get_object_or_404(get_user_model(), pk=user_pk)
    account = DirectoryAccount.objects.filter(user=user).first()
    if account and team.pk in account.granted_team_ids:
        messages.error(
            request,
            _('%(user)s is in %(team)s through LDAP and would be back at the next sign-in. Take them out of the LDAP group instead.') % {"user": user, "team": team},
        )
    else:
        team.user_set.remove(user)
    return redirect("team_detail", team.pk)


@manages_teams
@require_POST
def grant_add(request, pk):
    team = get_object_or_404(Group, pk=pk)
    form = GrantForm(request.POST)
    if not form.is_valid():
        return _rerender(request, team, grant_form=form)
    # One role per team and group: picking a group again changes its role.
    GroupGrant.objects.update_or_create(
        team=team,
        host_group=form.cleaned_data["host_group"],
        defaults={"role": form.cleaned_data["role"]},
    )
    return redirect("team_detail", team.pk)


@manages_teams
@require_POST
def grant_remove(request, pk, grant_pk):
    get_object_or_404(GroupGrant, pk=grant_pk, team_id=pk).delete()
    return redirect("team_detail", pk)


@manages_teams
@require_POST
def directory_link(request, pk):
    team = get_object_or_404(Group, pk=pk)
    form = DirectoryLinkForm(request.POST, team=team)
    if not form.is_valid():
        return _rerender(request, team, link_form=form)
    link = form.cleaned_data["directory_group"]
    link.team = team
    link.save()
    messages.info(request, _("Members move over the next time each of them signs in."))
    return redirect("team_detail", team.pk)


@manages_teams
@require_POST
def directory_unlink(request, pk, link_pk):
    link = get_object_or_404(DirectoryGroup, pk=link_pk, team_id=pk)
    link.team = None
    link.save()
    messages.info(request, _("Members leave the team the next time each of them signs in."))
    return redirect("team_detail", pk)


# -- maintenance windows ---------------------------------------------------------
# Superusers only, like a group's approval rule: removing a window would let a
# group's own admins change production whenever they like.


def superuser_only(view):
    from functools import wraps

    from django.core.exceptions import PermissionDenied

    @login_required
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_superuser:
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapped


@superuser_only
def window_add(request, group_pk):
    from inventory.models import HostGroup
    from zoneinfo import available_timezones

    group = get_object_or_404(HostGroup, pk=group_pk)
    form = MaintenanceWindowForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        window = form.save(commit=False)
        window.host_group = group
        window.save()
        messages.success(request, f"Maintenance window added to {group}: {window.days_label} "
                                  f"{window.start:%H:%M}-{window.end:%H:%M} {window.timezone}.")
        return redirect(group)
    return render(request, "access/window_form.html",
                  {"form": form, "group": group, "timezones": sorted(available_timezones())})


@superuser_only
@require_POST
def window_delete(request, pk):
    window = get_object_or_404(MaintenanceWindow, pk=pk)
    group = window.host_group
    window.delete()
    messages.success(request, _('Maintenance window removed from %(group)s.') % {"group": group})
    return redirect(group)
