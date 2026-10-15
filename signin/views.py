# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Signing in: password (with a one-time code where needed) or an identity
provider; and the page where people manage their own one-time codes."""
from __future__ import annotations

import logging

from django import forms
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy, ngettext
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from core.forms import style

from . import mfa, throttle, totp
from .sso import Refused, conf, user_for

log = logging.getLogger("loona.signin")


class CodeForm(forms.Form):
    code = forms.CharField(
        label=gettext_lazy("Code"), max_length=20,
        widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "inputmode": "numeric",
                                      "autofocus": True}),
    )


def _next(request, value: str = "") -> str:
    target = value or request.POST.get("next") or request.GET.get("next") or ""
    if url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()},
                                       require_https=request.is_secure()):
        return target
    return ""


def _try_later(seconds: int) -> str:
    minutes = max(1, (seconds + 59) // 60)
    return ngettext("Too many failed attempts. Try again in %(minutes)s minute.",
                    "Too many failed attempts. Try again in %(minutes)s minutes.",
                    minutes) % {"minutes": minutes}


class LoginForm(AuthenticationForm):
    """The password form, refusing to even check a password while throttled."""

    def clean(self):
        keys = throttle.password_keys(self.request, self.cleaned_data.get("username", ""))
        seconds = throttle.wait(keys)
        if seconds:
            raise forms.ValidationError(_try_later(seconds), code="throttled")
        try:
            cleaned = super().clean()
        except forms.ValidationError:
            throttle.failed(keys)
            raise
        throttle.succeeded(keys)
        return cleaned


def _sso_offered() -> bool:
    row = conf()
    if row.sso_protocol == "oidc":
        return bool(row.oidc_issuer and row.oidc_client_id)
    if row.sso_protocol == "saml":
        return bool(row.saml_idp_metadata.strip())
    return False


# -- password sign-in ------------------------------------------------------------------


def login_view(request):
    if request.user.is_authenticated:
        return redirect(_next(request) or "dashboard")
    form = LoginForm(request, data=request.POST or None)
    style(form)
    if request.method == "POST" and form.is_valid():
        user = form.get_user()
        next_url = _next(request)
        if mfa.has_codes(user):
            mfa.start_pending(request, user, enroll=False, next_url=next_url)
            return redirect("signin_code")
        if mfa.required_for(user):
            mfa.start_pending(request, user, enroll=True, next_url=next_url)
            return redirect("signin_setup")
        login(request, user)
        request.session[mfa.METHOD] = "password"
        return redirect(next_url or "dashboard")
    return render(request, "registration/login.html", {
        "form": form, "next": _next(request), "sso": _sso_offered(), "sso_label": conf().sso_label,
    })


def code_view(request):
    user, state = mfa.pending(request)
    if user is None or state["enroll"]:
        messages.error(request, _("Sign in again."))
        return redirect("login")
    form = CodeForm(request.POST or None)
    style(form)
    if request.method == "POST" and form.is_valid():
        keys = throttle.code_keys(user)
        seconds = throttle.wait(keys)
        if seconds:
            request.session.pop(mfa.PENDING, None)
            messages.error(request, _try_later(seconds))
            return redirect("login")
        used = mfa.check(user, form.cleaned_data["code"])
        if not used:
            throttle.failed(keys)
        if used:
            throttle.succeeded(keys)
            mfa.finish(request, user, state)
            if used == "recovery":
                messages.warning(request, _("You used a recovery code; %(left)s left. Set up your "
                                            "authenticator again if the phone is gone.") % {
                                     "left": mfa.recovery_left(user)})
            return redirect(state["next"] or "dashboard")
        left = mfa.count_try(request)
        if left <= 0:
            messages.error(request, _("Too many wrong codes. Sign in again."))
            return redirect("login")
        form.add_error("code", _("That code is not right (or was used already)."))
    return render(request, "signin/code.html", {"form": form, "who": user})


def setup_view(request):
    """Required codes, not set up yet: set them up before getting in."""
    user, state = mfa.pending(request)
    if user is None or not state["enroll"]:
        messages.error(request, _("Sign in again."))
        return redirect("login")
    return _setup(request, user, done=lambda codes: _setup_done_pending(request, user, state, codes))


def _setup_done_pending(request, user, state, codes):
    mfa.finish(request, user, state)
    request.session["_loona_fresh_codes"] = codes
    return redirect("account_security")


def _setup(request, user, done):
    form = CodeForm(request.POST or None)
    style(form)
    from .models import TotpDevice

    device = TotpDevice.objects.filter(user=user, confirmed_at__isnull=True).first()
    if request.method == "GET" or device is None:
        device = mfa.begin_setup(user)
    elif form.is_valid():
        codes = mfa.confirm_setup(user, form.cleaned_data["code"])
        if codes:
            messages.success(request, _("One-time codes are on."))
            return done(codes)
        if request.session.get(mfa.PENDING) and mfa.count_try(request) <= 0:
            messages.error(request, _("Too many wrong codes. Sign in again."))
            return redirect("login")
        form.add_error("code", _("That code is not right. Check the phone's clock, too."))
    issuer = conf().instance_name or "Loona"
    uri = totp.provisioning_uri(device.secret, user.get_username(), f"Loona {issuer}".strip()
                                if issuer != "Loona" else "Loona")
    return render(request, "signin/setup.html", {
        "form": form, "secret": device.secret, "qr": totp.qr_svg(uri),
        "required": mfa.required_for(user), "who": user,
    })


# -- the person's own page -------------------------------------------------------------


@login_required
def security_view(request):
    user = request.user
    fresh = request.session.pop("_loona_fresh_codes", None)
    return render(request, "signin/security.html", {
        "on": mfa.has_codes(user), "required": mfa.required_for(user), "fresh": fresh,
        "left": mfa.recovery_left(user), "sso": hasattr(user, "sso_identity"),
        "method": request.session.get(mfa.METHOD, "password"), "form": style(CodeForm()),
    })


@login_required
def security_setup(request):
    def done(codes):
        request.session["_loona_fresh_codes"] = codes
        request.session[mfa.METHOD] = "password"
        return redirect("account_security")

    return _setup(request, request.user, done)


@login_required
@require_POST
def security_off(request):
    if mfa.required_for(request.user):
        messages.error(request, _("One-time codes are required for your account."))
        return redirect("account_security")
    if not mfa.check(request.user, request.POST.get("code", "")):
        messages.error(request, _("That code is not right."))
        return redirect("account_security")
    mfa.turn_off(request.user)
    messages.success(request, _("One-time codes are off."))
    return redirect("account_security")


@login_required
@require_POST
def security_new_codes(request):
    if not mfa.check(request.user, request.POST.get("code", "")):
        messages.error(request, _("That code is not right."))
        return redirect("account_security")
    request.session["_loona_fresh_codes"] = mfa.new_recovery_codes(request.user)
    return redirect("account_security")


# -- identity providers -------------------------------------------------------------------


def _protocol():
    from . import oidc, saml

    return {"oidc": oidc, "saml": saml}.get(conf().sso_protocol)


def sso_start(request):
    module = _protocol()
    if module is None or not _sso_offered():
        messages.error(request, _("Single sign-on is not set up."))
        return redirect("login")
    try:
        return redirect(module.begin(request, _next(request)))
    except Refused as exc:
        messages.error(request, str(exc))
        return redirect("login")


def _finish_sso(request, protocol):
    module = _protocol()
    if module is None or conf().sso_protocol != protocol:
        messages.error(request, _("Single sign-on is not set up."))
        return redirect("login")
    try:
        claims, next_url = module.complete(request)
        user = user_for(claims)
    except Refused as exc:
        log.warning("SSO sign-in refused: %s", exc)
        messages.error(request, str(exc))
        return redirect("login")
    # Any backend in AUTHENTICATION_BACKENDS that loads users by id will do.
    login(request, user, backend="administration.auth.LocalBackend")
    request.session[mfa.METHOD] = protocol
    return redirect(_next(request, next_url) or "dashboard")


def oidc_callback(request):
    return _finish_sso(request, "oidc")


@csrf_exempt
@require_POST
def saml_acs(request):
    # The IdP posts here from its own page: no CSRF token, the signed and
    # solicited (InResponseTo) assertion is what is checked instead.
    return _finish_sso(request, "saml")


def saml_metadata(request):
    from . import saml

    return HttpResponse(saml.metadata(request), content_type="application/samlmetadata+xml")


def admin_login(request, extra_context=None):
    """Django admin's own sign-in form would skip one-time codes."""
    from django.contrib.auth.views import redirect_to_login

    if request.user.is_authenticated:
        # Signed in, but not staff: Django admin is not for them.
        from django.core.exceptions import PermissionDenied

        raise PermissionDenied
    return redirect_to_login(_next(request) or "/admin/")
