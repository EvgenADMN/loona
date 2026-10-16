# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""SAML 2.0 sign-in, Loona as the service provider (python3-saml).

Loona trusts the signing certificate in the IdP metadata an administrator
pasted, insists on signed assertions, and only takes answers to requests it
sent itself (no IdP-initiated sign-in): an assertion replayed from another
service cannot open a session here.

The answer must also come back to the browser that asked.  The IdP posts it
from its own site, so the session cookie (SameSite=Lax) does not come along:
the ACS checks the answer and keeps it, then redirects the browser to
/login/sso/saml/finish/, and that request does carry the cookie.  Only the
session that started the sign-in can collect the answer, so one issued for
somebody's own account cannot be planted in another person's browser.
"""
from __future__ import annotations

import dataclasses
from datetime import timedelta
from urllib.parse import urlsplit

from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _

from .sso import Claims, Refused, as_list, conf, group_names

MAX_AGE = timedelta(minutes=10)
SESSION_KEY = "loona_saml_request"


def _base(request) -> str:
    return conf().public_url.rstrip("/") or request.build_absolute_uri("/").rstrip("/")


def settings_for(request, with_idp: bool = True) -> dict:
    from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

    row = conf()
    idp = {"idp": {}}
    if with_idp:
        if not row.saml_idp_metadata.strip():
            raise Refused(_("Single sign-on is not set up yet."))
        try:
            idp = OneLogin_Saml2_IdPMetadataParser.parse(row.saml_idp_metadata)
        except Exception as exc:  # noqa: BLE001 - a broken paste
            raise Refused(_("The identity provider metadata cannot be read: %(error)s") % {"error": exc}) from exc
        if not idp.get("idp", {}).get("x509cert") and not idp.get("idp", {}).get("x509certMulti"):
            raise Refused(_("The identity provider metadata has no signing certificate."))
    base = _base(request)
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": base + reverse("sso_saml_metadata"),
            "assertionConsumerService": {
                "url": base + reverse("sso_saml_acs"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "x509cert": "",
            "privateKey": "",
        },
        "idp": idp["idp"],
        "security": {
            "authnRequestsSigned": False,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": True,
            "wantNameId": True,
            "requestedAuthnContext": False,
            "rejectDeprecatedAlgorithm": True,
            # Keycloak sends one Attribute element per group, all named "groups".
            "allowRepeatAttributeName": True,
            # Identity providers inside a network are often http://adfs/ or
            # http://keycloak:8080/ - names without a dot are fine there.
            "allowSingleLabelDomains": True,
        },
    }


def _request_data(request) -> dict:
    # Behind a proxy, the address people use (Loona's address in
    # Administration) is what the IdP posts to and what must be checked.
    public = urlsplit(conf().public_url) if conf().public_url else None
    https = (public.scheme == "https") if public else request.is_secure()
    host = public.netloc if public else request.get_host()
    return {
        "https": "on" if https else "off",
        "http_host": host,
        "script_name": request.path,
        "get_data": request.GET.copy(),
        "post_data": request.POST.copy(),
    }


def _auth(request):
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.errors import OneLogin_Saml2_Error

    try:
        return OneLogin_Saml2_Auth(_request_data(request), old_settings=settings_for(request))
    except OneLogin_Saml2_Error as exc:
        raise Refused(_("The single sign-on settings cannot be used: %(error)s") % {"error": exc}) from exc


def begin(request, next_url: str) -> str:
    from .models import SamlRequest

    auth = _auth(request)
    url = auth.login(return_to="")
    SamlRequest.objects.filter(created_at__lt=timezone.now() - MAX_AGE).delete()
    request_id = auth.get_last_request_id()
    SamlRequest.objects.create(request_id=request_id, next_url=next_url[:500])
    request.session[SESSION_KEY] = request_id
    return url


def _answered_request(request):
    """The request this answer is to - taken, so it cannot be answered twice."""
    from onelogin.saml2.response import OneLogin_Saml2_Response
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    from .models import SamlRequest

    raw = request.POST.get("SAMLResponse", "")
    if not raw:
        raise Refused(_("The identity provider sent no answer."))
    try:
        answer = OneLogin_Saml2_Response(OneLogin_Saml2_Settings(settings_for(request)), raw)
        in_response_to = answer.document.get("InResponseTo") or ""
    except Exception as exc:  # noqa: BLE001 - malformed input from outside
        raise Refused(_("The identity provider's answer cannot be read: %(error)s") % {"error": exc}) from exc
    found = SamlRequest.objects.filter(request_id=in_response_to, claims__isnull=True,
                                       created_at__gte=timezone.now() - MAX_AGE).first()
    if not in_response_to or found is None:
        raise Refused(_("This sign-in was not started here, or took too long. Try again."))
    return found


def receive(request) -> str:
    """The ACS: check the IdP's answer and keep it for the browser that asked.
    Returns the request it answers."""
    from .models import SamlRequest

    started = _answered_request(request)
    claims = _verified(request, started)
    kept = SamlRequest.objects.filter(pk=started.pk, claims__isnull=True).update(claims=dataclasses.asdict(claims))
    if not kept:
        raise Refused(_("This sign-in was not started here, or took too long. Try again."))
    return started.request_id


def complete(request) -> tuple[Claims, str]:
    """The answer kept by receive(), for the session that started the sign-in only."""
    from .models import SamlRequest

    request_id = request.GET.get("request", "")
    mine = request.session.pop(SESSION_KEY, None)
    found = SamlRequest.objects.filter(request_id=request_id, claims__isnull=False,
                                       created_at__gte=timezone.now() - MAX_AGE).first()
    if not request_id or mine != request_id or found is None \
            or not SamlRequest.objects.filter(pk=found.pk).delete()[0]:
        raise Refused(_("This sign-in was not started in this browser, or took too long. Try again."))
    return Claims(**found.claims), found.next_url


def _verified(request, started) -> Claims:
    row = conf()
    auth = _auth(request)
    try:
        auth.process_response(request_id=started.request_id)
    except Exception as exc:  # noqa: BLE001 - malformed input from outside
        raise Refused(_("The identity provider's answer cannot be read: %(error)s") % {"error": exc}) from exc
    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        reason = auth.get_last_error_reason() or ", ".join(errors) or "not authenticated"
        raise Refused(_("The identity provider's answer does not check out: %(error)s") % {"error": reason})
    attributes = auth.get_attributes()

    def first(name):
        values = as_list(attributes.get(name)) if name else []
        return values[0] if values else ""

    settings = auth.get_settings()
    return Claims(
        protocol="saml",
        issuer=settings.get_idp_data()["entityId"],
        subject=auth.get_nameid(),
        username=first(row.sso_username_attr) if row.sso_username_attr else auth.get_nameid(),
        email=first(row.sso_email_attr),
        first_name=first(row.sso_first_name_attr),
        last_name=first(row.sso_last_name_attr),
        groups=group_names(attributes.get(row.sso_groups_attr)) if row.sso_groups_attr else [],
    )


def metadata(request) -> str:
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    settings = OneLogin_Saml2_Settings(settings_for(request, with_idp=False), sp_validation_only=True)
    return settings.get_sp_metadata()
