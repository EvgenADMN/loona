# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""OpenID Connect sign-in: the authorization code flow with PKCE.

Keycloak, Authentik, Azure AD / Entra ID, Okta, Google, Dex, GitLab - any
provider with a discovery document.  The ID token is checked against the
provider's published keys (signature, issuer, audience, expiry, nonce);
claims from the userinfo endpoint are added when the provider has one.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt
from django.urls import reverse
from django.utils.translation import gettext as _

from .sso import Claims, Refused, as_list, conf, group_names

SESSION = "_loona_oidc"
TIMEOUT = 10
# Asymmetric only: a symmetric algorithm would let anyone holding the
# client secret mint tokens.
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]
_discovery: dict = {}
_jwks: dict = {}


def _get_json(url: str, headers=None) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise Refused(_("The identity provider could not be reached: %(error)s") % {"error": exc}) from exc


def _post_form(url: str, data: dict, auth: tuple[str, str]) -> dict:
    basic = base64.b64encode(
        f"{urllib.parse.quote(auth[0], safe='')}:{urllib.parse.quote(auth[1], safe='')}".encode()).decode()
    request = urllib.request.Request(
        url, data=urllib.parse.urlencode(data).encode(), method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
                 "Authorization": f"Basic {basic}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:300].decode(errors="replace")
        raise Refused(_("The identity provider turned the sign-in down: %(error)s") % {"error": detail}) from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise Refused(_("The identity provider could not be reached: %(error)s") % {"error": exc}) from exc


def discovery(issuer: str) -> dict:
    issuer = issuer.rstrip("/")
    cached = _discovery.get(issuer)
    if cached and time.time() - cached[0] < 3600:
        return cached[1]
    doc = _get_json(f"{issuer}/.well-known/openid-configuration")
    if str(doc.get("issuer", "")).rstrip("/") != issuer:
        raise Refused(_("The discovery document names another issuer: %(issuer)s") % {"issuer": doc.get("issuer")})
    _discovery[issuer] = (time.time(), doc)
    return doc


def _signing_key(doc: dict, token: str):
    uri = doc["jwks_uri"]
    client = _jwks.get(uri)
    if client is None:
        client = _jwks[uri] = jwt.PyJWKClient(uri, cache_keys=True, lifespan=3600, timeout=TIMEOUT)
    try:
        return client.get_signing_key_from_jwt(token).key
    except jwt.PyJWKClientError as exc:
        raise Refused(_("The ID token is not signed with a key the provider publishes.")) from exc


def redirect_uri(request) -> str:
    base = conf().public_url.rstrip("/") or request.build_absolute_uri("/").rstrip("/")
    return base + reverse("sso_oidc_callback")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def begin(request, next_url: str) -> str:
    """Where to send the browser to sign in."""
    row = conf()
    doc = discovery(row.oidc_issuer)
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    request.session[SESSION] = {"state": state, "nonce": nonce, "verifier": verifier, "next": next_url,
                                "at": time.time()}
    query = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": row.oidc_client_id,
        "redirect_uri": redirect_uri(request),
        "scope": row.oidc_scopes or "openid",
        "state": state,
        "nonce": nonce,
        "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256",
    })
    return f"{doc['authorization_endpoint']}?{query}"


def complete(request) -> tuple[Claims, str]:
    """Check the provider's answer. Returns the claims and where to go next."""
    row = conf()
    started = request.session.pop(SESSION, None)
    if not started or time.time() - started["at"] > 600:
        raise Refused(_("This sign-in was not started here, or took too long. Try again."))
    if request.GET.get("error"):
        raise Refused(_("The identity provider said: %(error)s") % {
            "error": request.GET.get("error_description") or request.GET["error"]})
    if not secrets.compare_digest(request.GET.get("state", ""), started["state"]):
        raise Refused(_("This sign-in was not started here. Try again."))
    doc = discovery(row.oidc_issuer)
    tokens = _post_form(doc["token_endpoint"], {
        "grant_type": "authorization_code",
        "code": request.GET.get("code", ""),
        "redirect_uri": redirect_uri(request),
        "code_verifier": started["verifier"],
    }, (row.oidc_client_id, row.oidc_client_secret))
    id_token = tokens.get("id_token")
    if not id_token:
        raise Refused(_("The identity provider sent no ID token. Is the openid scope requested?"))
    allowed = [a for a in doc.get("id_token_signing_alg_values_supported") or ["RS256"] if a in ALGORITHMS]
    try:
        claims = jwt.decode(
            id_token, _signing_key(doc, id_token), algorithms=allowed or ["RS256"],
            audience=row.oidc_client_id, issuer=doc["issuer"], leeway=60,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise Refused(_("The ID token does not check out: %(error)s") % {"error": exc}) from exc
    if not secrets.compare_digest(str(claims.get("nonce", "")), started["nonce"]):
        raise Refused(_("The ID token was not issued for this sign-in."))
    if doc.get("userinfo_endpoint") and tokens.get("access_token"):
        info = _get_json(doc["userinfo_endpoint"], {"Authorization": f"Bearer {tokens['access_token']}"})
        if info.get("sub") == claims["sub"]:
            # Same person; the userinfo answer is the fuller and fresher one.
            claims = {**claims, **info}
    username_attr = row.sso_username_attr or "preferred_username"
    return Claims(
        protocol="oidc",
        issuer=doc["issuer"],
        subject=str(claims["sub"]),
        username=str(claims.get(username_attr) or claims.get("email") or ""),
        email=str(claims.get(row.sso_email_attr) or ""),
        first_name=str(claims.get(row.sso_first_name_attr) or ""),
        last_name=str(claims.get(row.sso_last_name_attr) or ""),
        groups=group_names(claims.get(row.sso_groups_attr)) if row.sso_groups_attr else [],
    ), started.get("next") or ""


def check_settings(issuer: str) -> str:
    """For the Administration page: can the provider be found?"""
    _discovery.pop(issuer.rstrip("/"), None)
    doc = discovery(issuer)
    return _("Found %(issuer)s; signs ID tokens with %(algs)s.") % {
        "issuer": doc["issuer"], "algs": ", ".join(as_list(doc.get("id_token_signing_alg_values_supported")))}
