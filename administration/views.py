# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Administration: settings, sign-in, directory mapping, users, audit.

Superusers only. Every save is written to the audit log, secrets masked.
"""
from __future__ import annotations

import platform
import shutil
import subprocess
from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.db import connection
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _
from ldap3.core.exceptions import LDAPException

from access.ldap import LdapBackend
from access.models import DirectoryAccount, DirectoryGroup, dn_key
from core.version import __version__

from . import system
from .forms import GeneralForm, LdapForm, MappingForm, SsoForm, UserCreateForm, UserEditForm, VaultForm
from .models import AuditEntry

# Never written to the audit log in the clear.  Every form field holding a
# secret belongs here - the notifications tests check this.
SECRET_FIELDS = {
    "ldap_bind_password_encrypted", "bind_password", "password", "new_password",
    "smtp_password", "bot_token", "secret",
    "hcv_token_encrypted", "hcv_secret_id_encrypted", "token", "secret_id",
    "client_secret", "oidc_client_secret_encrypted",
}


def superuser_only(view):
    @login_required
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not (request.user.is_active and request.user.is_superuser):
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapped


def audit(user, section, summary, form=None, extra=None):
    changes = {}
    if form is not None:
        for name in form.changed_data:
            if name in ("test_username",):
                continue
            if name in SECRET_FIELDS:
                changes[name] = ["", "(changed)"]
            else:
                before = form.initial.get(name)
                after = form.cleaned_data.get(name)
                changes[name] = [_plain(before), _plain(after)]
    changes.update(extra or {})
    AuditEntry.objects.create(user=user, section=section, summary=summary[:255], changes=changes)


def _plain(value):
    if hasattr(value, "all"):
        return sorted(str(v) for v in value.all())
    if isinstance(value, (list, tuple, set)):
        return sorted(str(getattr(v, "name", v)) for v in value)
    if value is None or isinstance(value, (bool, int, str)):
        return value
    return str(value)


# -- overview ------------------------------------------------------------------


@superuser_only
def overview(request):
    row = system.get()
    return render(
        request,
        "administration/overview.html",
        {
            "section": "overview",
            "row": row,
            "versions": _versions(),
            "worker": _worker_status(),
            "ldap": system.ldap_conf(),
            "users": get_user_model().objects.count(),
            "recent": AuditEntry.objects.select_related("user")[:8],
        },
    )


def _versions() -> list[tuple[str, str]]:
    found = [("Loona", __version__), ("Python", platform.python_version())]
    with connection.cursor() as cursor:
        cursor.execute("SHOW server_version")
        found.append(("PostgreSQL", cursor.fetchone()[0]))
    for label, command in (
        ("Ansible", ["ansible", "--version"]),
        ("OpenTofu", [settings.LOONA_TOFU_BINARY, "version"]),
    ):
        found.append((label, _first_line(command)))
    return found


def _first_line(command) -> str:
    if not shutil.which(command[0]):
        return "not installed"
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=10,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return "did not answer"
    return (done.stdout or done.stderr).strip().splitlines()[0] if (done.stdout or done.stderr) else "?"


def _worker_status() -> str:
    if settings.LOONA_RUNNER_MODE != "celery":
        return "Runs execute inside the web process (thread mode)."
    try:
        from loona.celery import app

        answers = app.control.ping(timeout=1.0)
    except Exception as exc:  # noqa: BLE001
        return f"Could not reach the broker: {exc}"
    if not answers:
        return "No worker answered - runs will queue until one starts."
    return _("%(count)s worker(s) answering.") % {"count": len(answers)}


# -- general ---------------------------------------------------------------------


@superuser_only
def general(request):
    row = system.for_editing()
    form = GeneralForm(request.POST or None, instance=row)
    if request.method == "POST" and form.is_valid():
        saved = form.save(commit=False)
        saved.updated_by = request.user
        saved.save()
        system.invalidate()
        if form.changed_data:
            audit(request.user, "general", "Changed general settings", form)
        messages.success(request, _("Saved. Every Loona process picks this up within seconds."))
        return redirect("admin_general")
    return render(request, "administration/general.html", {"section": "general", "form": form})


@superuser_only
@require_POST
def refresh_modules(request):
    from playbooks import docs

    try:
        count = docs.refresh_index()
    except docs.DocsUnavailable as exc:
        messages.error(request, _('ansible-doc is not usable: %(exc)s') % {"exc": exc})
    else:
        audit(request.user, "general", f"Refreshed the module index ({count} modules)")
        messages.success(request, _('%(count)s modules indexed.') % {"count": count})
    return redirect("admin_general")


# -- authentication -------------------------------------------------------------------


@superuser_only
def ldap(request):
    row = system.for_editing()
    form = LdapForm(request.POST or None, instance=row)
    result = None
    if request.method == "POST" and form.is_valid():
        if "test" in request.POST:
            result = _test_ldap(form.conf(row.ldap_bind_password), form.cleaned_data["test_username"])
        else:
            saved = form.save(commit=False)
            saved.updated_by = request.user
            saved.save()
            system.invalidate()
            if form.changed_data:
                audit(request.user, "ldap", "Changed LDAP settings", form)
            messages.success(request, _("LDAP settings saved."))
            return redirect("admin_ldap")
    env_configured = bool(settings.LOONA_LDAP["SERVER_URI"])
    return render(
        request,
        "administration/ldap.html",
        {
            "section": "ldap",
            "form": form,
            "result": result,
            "env_configured": env_configured and not row.ldap_enabled,
            "has_password": bool(row.ldap_bind_password_encrypted),
        },
    )


# -- single sign-on --------------------------------------------------------------------


@superuser_only
def sso(request):
    from django.urls import reverse

    row = system.for_editing()
    form = SsoForm(request.POST or None, instance=row)
    result = None
    if request.method == "POST" and form.is_valid():
        if "test" in request.POST:
            result = _test_sso(form)
        else:
            saved = form.save(commit=False)
            saved.updated_by = request.user
            saved.save()
            system.invalidate()
            if form.changed_data:
                audit(request.user, "sso", "Changed single sign-on settings", form)
            messages.success(request, _("Single sign-on settings saved."))
            return redirect("admin_sso")
    base = row.public_url.rstrip("/") or request.build_absolute_uri("/").rstrip("/")
    return render(request, "administration/sso.html", {
        "section": "sso", "form": form, "result": result,
        "has_secret": bool(row.oidc_client_secret_encrypted),
        "redirect_uri": base + reverse("sso_oidc_callback"),
        "sp_entity": base + reverse("sso_saml_metadata"),
        "acs_url": base + reverse("sso_saml_acs"),
        "no_public_url": not row.public_url,
    })


def _test_sso(form) -> dict:
    data = form.cleaned_data
    try:
        if data["sso_protocol"] == "oidc":
            from signin import oidc

            return {"ok": True, "message": oidc.check_settings(data["oidc_issuer"])}
        if data["sso_protocol"] == "saml":
            from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

            idp = OneLogin_Saml2_IdPMetadataParser.parse(data["saml_idp_metadata"])["idp"]
            return {"ok": True, "message": _("Metadata of %(entity)s; sign-in at %(url)s.") % {
                "entity": idp.get("entityId"), "url": idp.get("singleSignOnService", {}).get("url")}}
    except Exception as exc:  # noqa: BLE001 - shown to the admin
        return {"ok": False, "message": str(exc)}
    return {"ok": False, "message": _("Pick OpenID Connect or SAML first.")}


# -- HashiCorp Vault ----------------------------------------------------------------


@superuser_only
def vault(request):
    row = system.for_editing()
    form = VaultForm(request.POST or None, instance=row)
    result = None
    if request.method == "POST" and form.is_valid():
        if "test" in request.POST:
            result = _test_vault(form.conf(row), form.cleaned_data["test_ref"])
        else:
            saved = form.save(commit=False)
            saved.updated_by = request.user
            saved.save()
            system.invalidate()
            if form.changed_data:
                audit(request.user, "vault", "Changed HashiCorp Vault settings", form)
            messages.success(request, _("HashiCorp Vault settings saved."))
            return redirect("admin_vault")
    return render(request, "administration/vault.html", {
        "section": "vault",
        "form": form,
        "result": result,
        "has_token": bool(row.hcv_token_encrypted),
        "has_secret_id": bool(row.hcv_secret_id_encrypted),
    })


def _test_vault(conf, ref) -> dict:
    """Sign in; with a reference, read it too - without showing the value."""
    from secretstore import hashicorp

    if not conf.address:
        return {"ok": False, "message": "Fill in the address first."}
    client = hashicorp.Client(conf)
    try:
        me = client.whoami()
        message = f"Signed in. Policies: {', '.join(me.get('policies') or []) or 'none'}."
        if me.get("ttl"):
            message += f" Token valid for {me['ttl']} s more."
        if ref:
            value = client.get(ref)
            message += f" Read {ref}: {len(value)} characters."
    except hashicorp.VaultError as exc:
        return {"ok": False, "message": str(exc)}
    return {"ok": True, "message": message}


def _test_ldap(conf, username) -> dict:
    """Bind with the service account; with a login, look that user up too."""
    if not conf["SERVER_URI"]:
        return {"ok": False, "message": "Fill in the server first."}
    directory = LdapBackend.directory_factory(conf)
    try:
        if not username:
            conn = directory._connect(conf["BIND_DN"] or None, conf["BIND_PASSWORD"] or None)
            try:
                bound = conn.bind()
                message = "" if bound else str(conn.result.get("description") or conn.result)
            finally:
                conn.unbind()
            if not bound:
                return {"ok": False, "message": f"The service account could not bind: {message}"}
            return {"ok": True, "message": "Connected, and the service account signed in."}
        found = directory.lookup(username)
    except LDAPException as exc:
        return {"ok": False, "message": f"{type(exc).__name__}: {exc}"}
    if found is None:
        return {"ok": False, "message": f"Connected, but found no user {username!r} with the user filter."}
    teams = []
    for key, (dn, name) in sorted(found.groups.items(), key=lambda item: item[1][1]):
        link = DirectoryGroup.objects.filter(dn_key=key).select_related("team").first()
        if link and link.team:
            team = link.team.name
        elif conf["MIRROR_GROUPS"] == "mapped":
            team = None
        else:
            team = f"{name} (created at first sign-in)"
        teams.append({"dn": dn, "name": name, "team": team})
    flags = []
    if conf["SUPERUSER_GROUP"] and found.in_group(conf["SUPERUSER_GROUP"]):
        flags.append("superuser")
    if conf["REQUIRE_GROUP"] and not found.in_group(conf["REQUIRE_GROUP"]):
        flags.append("NOT in the required group - would be refused")
    return {
        "ok": True,
        "message": f"Found {found.dn}",
        "user": found,
        "groups": teams,
        "flags": flags,
    }


# -- directory group mapping ----------------------------------------------------------


@superuser_only
def directory_groups(request):
    form = MappingForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        if DirectoryGroup.objects.filter(dn_key=dn_key(form.cleaned_data["dn"])).exists():
            form.add_error("dn", _("This group is already known; change its team in the table."))
        else:
            link = form.save(commit=False)
            link.name = form.cleaned_data["name"]
            link.save()
            audit(request.user, "directory", f"Mapped {link.dn} to {link.team or 'no team'}")
            messages.success(request, _("Mapping added. Members join at their next sign-in or re-check."))
            return redirect("admin_directory")
    links = DirectoryGroup.objects.select_related("team").order_by("name")
    return render(
        request,
        "administration/directory.html",
        {
            "section": "directory",
            "links": links,
            "form": form,
            "teams": Group.objects.order_by("name"),
        },
    )


@superuser_only
@require_POST
def directory_group_update(request, pk):
    link = get_object_or_404(DirectoryGroup, pk=pk)
    if "delete" in request.POST:
        audit(request.user, "directory", f"Forgot directory group {link.dn}")
        link.delete()
        return redirect("admin_directory")
    team_pk = request.POST.get("team")
    team = Group.objects.filter(pk=team_pk).first() if team_pk else None
    if team != link.team:
        audit(request.user, "directory", f"Mapped {link.dn} to {team or 'no team'}",
              extra={"team": [str(link.team or ""), str(team or "")]})
        link.team = team
        link.save()
    return redirect("admin_directory")


# -- users -----------------------------------------------------------------------------


@superuser_only
def users(request):
    User = get_user_model()
    people = (
        User.objects.select_related("directory_account")
        .prefetch_related("groups")
        .order_by("username")
    )
    return render(request, "administration/users.html", {"section": "users", "people": people})


@superuser_only
def user_create(request):
    form = UserCreateForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        audit(request.user, "users", f"Created local user {user.username}",
              extra={"is_superuser": [None, user.is_superuser]})
        messages.success(request, _('User %(username)s created.') % {"username": user.username})
        return redirect("admin_users")
    return render(request, "administration/user_form.html", {"section": "users", "form": form})


@superuser_only
def user_edit(request, pk):
    User = get_user_model()
    person = get_object_or_404(User, pk=pk)
    account = DirectoryAccount.objects.filter(user=person).first()
    directory_teams = account.granted_team_ids if account else []
    form = UserEditForm(request.POST or None, instance=person, acting_user=request.user,
                        directory_teams=directory_teams)
    if request.method == "POST" and form.is_valid():
        form.save()
        if form.changed_data:
            audit(request.user, "users", f"Changed user {person.username}", form)
        messages.success(request, _('%(username)s saved.') % {"username": person.username})
        return redirect("admin_users")
    return render(
        request,
        "administration/user_form.html",
        {"section": "users", "form": form, "person": person, "account": account,
         "identity": getattr(person, "sso_identity", None), "codes_on": _codes_on(person)},
    )


def _codes_on(person) -> bool:
    from signin.mfa import has_codes

    return has_codes(person)


@superuser_only
@require_POST
def user_codes_reset(request, pk):
    """For a lost phone: the person sets codes up again at the next sign-in."""
    from signin.mfa import turn_off

    person = get_object_or_404(get_user_model(), pk=pk)
    turn_off(person)
    audit(request.user, "users", f"Reset one-time codes of {person.username}")
    messages.success(request, _("One-time codes of %(username)s reset.") % {"username": person.username})
    return redirect("admin_user_edit", pk)


# -- audit -----------------------------------------------------------------------------


@superuser_only
def audit_log(request):
    entries = AuditEntry.objects.select_related("user")[:300]
    return render(request, "administration/audit.html", {"section": "audit", "entries": entries})
