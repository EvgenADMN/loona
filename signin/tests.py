# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
import base64
import re
import time
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse

from access.models import DirectoryAccount, DirectoryGroup
from administration import system
from administration.models import SystemSettings

from . import mfa, oidc, totp
from .models import RecoveryCode, SsoIdentity, Throttle, TotpDevice

User = get_user_model()
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


def settings(**fields):
    SystemSettings.objects.update_or_create(pk=1, defaults=fields)
    system.invalidate()


class TotpTests(TestCase):
    def test_rfc_6238_vectors(self):
        # RFC 6238 appendix B, SHA-1, cut to six digits.
        self.assertEqual(totp.code_at(RFC_SECRET, 59 // 30), "287082")
        self.assertEqual(totp.code_at(RFC_SECRET, 1111111109 // 30), "081804")
        self.assertEqual(totp.code_at(RFC_SECRET, 2000000000 // 30), "279037")

    def test_a_step_either_side_and_never_twice(self):
        now = 1111111109
        step = totp.current_step(now)
        self.assertEqual(totp.matching_step(RFC_SECRET, totp.code_at(RFC_SECRET, step - 1), now=now), step - 1)
        self.assertIsNone(totp.matching_step(RFC_SECRET, totp.code_at(RFC_SECRET, step - 2), now=now))
        code = totp.code_at(RFC_SECRET, step)
        self.assertIsNone(totp.matching_step(RFC_SECRET, code, after_step=step, now=now))
        self.assertIsNone(totp.matching_step(RFC_SECRET, "12345", now=now))

    def test_qr_and_uri(self):
        uri = totp.provisioning_uri(RFC_SECRET, "alice", "Loona")
        self.assertTrue(uri.startswith("otpauth://totp/Loona%3Aalice?secret="))
        self.assertIn("<svg", totp.qr_svg(uri))


def now_code(user):
    device = TotpDevice.objects.get(user=user)
    return totp.code_at(device.secret, totp.current_step())


def with_codes(user) -> list[str]:
    device = mfa.begin_setup(user)
    return mfa.confirm_setup(user, totp.code_at(device.secret, totp.current_step()))


class PasswordSignInTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user("alice", password="Alice-pass-123")

    def sign_in(self, username="alice", password="Alice-pass-123", **extra):
        return self.client.post(reverse("login"), {"username": username, "password": password, **extra})

    def signed_in(self) -> bool:
        return self.client.get("/").status_code == 200

    def test_without_codes_a_password_is_enough(self):
        self.assertRedirects(self.sign_in(), "/", fetch_redirect_response=False)
        self.assertTrue(self.signed_in())

    def test_with_codes_the_password_alone_does_not_sign_in(self):
        codes = with_codes(self.alice)
        TotpDevice.objects.filter(user=self.alice).update(last_step=0)
        self.assertRedirects(self.sign_in(next="/runs/"), reverse("signin_code"), fetch_redirect_response=False)
        self.assertFalse(self.signed_in())
        self.assertContains(self.client.post(reverse("signin_code"), {"code": "000000"}), "not right")
        response = self.client.post(reverse("signin_code"), {"code": now_code(self.alice)})
        self.assertRedirects(response, "/runs/", fetch_redirect_response=False)
        self.assertTrue(self.signed_in())
        # The same code a second time - from someone who saw it - does not work.
        self.client.logout()
        self.sign_in()
        self.assertContains(self.client.post(reverse("signin_code"), {"code": now_code(self.alice)}), "not right")
        # A recovery code does, once.
        self.client.post(reverse("signin_code"), {"code": codes[0].upper()})
        self.assertTrue(self.signed_in())
        self.client.logout()
        self.sign_in()
        self.assertContains(self.client.post(reverse("signin_code"), {"code": codes[0]}), "not right")

    def test_five_wrong_codes_and_the_password_is_asked_again(self):
        with_codes(self.alice)
        self.sign_in()
        for _ in range(4):
            self.client.post(reverse("signin_code"), {"code": "000000"})
        self.assertRedirects(self.client.post(reverse("signin_code"), {"code": "000000"}), reverse("login"),
                             fetch_redirect_response=False)
        self.assertRedirects(self.client.get(reverse("signin_code")), reverse("login"), fetch_redirect_response=False)

    def test_guessing_passwords_is_slowed_down(self):
        for _ in range(5):
            self.assertContains(self.sign_in(password="guess"), "Please enter a correct")
        # Locked now: even the right password is not checked.
        self.assertContains(self.sign_in(), "Too many failed attempts")
        self.assertFalse(self.signed_in())
        # Someone else signing in from the same address is not held up.
        User.objects.create_user("bob", password="Bob-pass-123")
        self.assertRedirects(self.sign_in("bob", "Bob-pass-123"), "/", fetch_redirect_response=False)
        # The lock runs out, and a good password then clears the count.
        Throttle.objects.update(locked_until=None)
        self.client.logout()
        self.assertRedirects(self.sign_in(), "/", fetch_redirect_response=False)
        self.assertFalse(Throttle.objects.filter(key__startswith="pair:alice").exists())

    def test_the_lock_grows_with_each_further_failure(self):
        for _ in range(5):
            self.sign_in(password="guess")
        first = Throttle.objects.get(key__startswith="pair:alice").locked_until
        Throttle.objects.update(locked_until=None)
        self.sign_in(password="guess")
        second = Throttle.objects.get(key__startswith="pair:alice").locked_until
        self.assertGreater(second - first, timedelta(seconds=50))

    def test_one_address_trying_many_accounts_is_stopped(self):
        for number in range(20):
            self.sign_in(f"nobody{number}", "guess")
        self.assertContains(self.sign_in(), "Too many failed attempts")

    def test_a_new_sign_in_does_not_buy_more_codes(self):
        with_codes(self.alice)
        for _ in range(2):
            self.sign_in()
            for _ in range(3):
                self.client.post(reverse("signin_code"), {"code": "000000"})
        # Six wrong codes over two sign-ins: the next, right one is refused.
        self.sign_in()
        response = self.client.post(reverse("signin_code"), {"code": now_code(self.alice)})
        self.assertRedirects(response, reverse("login"), fetch_redirect_response=False)
        self.assertFalse(self.signed_in())

    def test_a_wrong_password_never_gets_to_the_code(self):
        with_codes(self.alice)
        self.sign_in(password="nope")
        self.assertRedirects(self.client.get(reverse("signin_code")), reverse("login"), fetch_redirect_response=False)

    def test_required_codes_are_set_up_on_the_way_in(self):
        settings(mfa_policy="everyone")
        self.assertRedirects(self.sign_in(), reverse("signin_setup"), fetch_redirect_response=False)
        page = self.client.get(reverse("signin_setup"))
        self.assertContains(page, "<svg")
        secret = page.context["secret"]
        response = self.client.post(reverse("signin_setup"), {"code": totp.code_at(secret, totp.current_step())})
        self.assertRedirects(response, reverse("account_security"), fetch_redirect_response=False)
        page = self.client.get(reverse("account_security"))
        self.assertEqual(len(page.context["fresh"]), 10)
        self.assertEqual(RecoveryCode.objects.filter(user=self.alice).count(), 10)
        self.assertNotContains(self.client.get(reverse("account_security")), page.context["fresh"][0])

    def test_superusers_only(self):
        settings(mfa_policy="superusers")
        self.assertRedirects(self.sign_in(), "/", fetch_redirect_response=False)
        User.objects.create_superuser("root", password="Root-pass-123")
        self.client.logout()
        self.assertRedirects(self.sign_in("root", "Root-pass-123"), reverse("signin_setup"),
                             fetch_redirect_response=False)

    def test_an_open_session_is_sent_to_set_codes_up_once_they_are_required(self):
        self.sign_in()
        settings(mfa_policy="everyone")
        self.assertRedirects(self.client.get("/"), reverse("account_security"), fetch_redirect_response=False)
        self.assertEqual(self.client.get("/api/v1/me/").status_code, 403)
        self.assertEqual(self.client.get(reverse("account_security")).status_code, 200)
        self.client.get(reverse("account_security_setup"))
        secret = TotpDevice.objects.get(user=self.alice).secret
        self.client.post(reverse("account_security_setup"), {"code": totp.code_at(secret, totp.current_step())})
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/api/v1/me/").status_code, 200)

    def test_turning_codes_off_takes_a_code_and_is_refused_when_required(self):
        with_codes(self.alice)
        self.client.force_login(self.alice)
        TotpDevice.objects.filter(user=self.alice).update(last_step=0)
        self.client.post(reverse("account_security_off"), {"code": "000000"})
        self.assertTrue(mfa.has_codes(self.alice))
        self.client.post(reverse("account_security_off"), {"code": now_code(self.alice)})
        self.assertFalse(mfa.has_codes(self.alice))
        with_codes(self.alice)
        TotpDevice.objects.filter(user=self.alice).update(last_step=0)
        settings(mfa_policy="everyone")
        self.client.post(reverse("account_security_off"), {"code": now_code(self.alice)})
        self.assertTrue(mfa.has_codes(self.alice))

    def test_django_admin_signs_in_here(self):
        response = self.client.get("/admin/")
        self.assertRedirects(self.client.get(response["Location"]), "/login/?next=/admin/",
                             fetch_redirect_response=False)

    def test_an_administrator_resets_codes(self):
        with_codes(self.alice)
        root = User.objects.create_superuser("root", password="x")
        self.client.force_login(root)
        self.assertContains(self.client.get(reverse("admin_user_edit", args=[self.alice.pk])), "Reset one-time codes")
        self.client.post(reverse("admin_user_codes_reset", args=[self.alice.pk]))
        self.assertFalse(mfa.has_codes(self.alice))


# -- OpenID Connect, against a provider made up here ------------------------------------------

ISSUER = "https://idp.example.com/realms/main"


class FakeProvider:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.claims = {}
        self.userinfo = {}
        self.token_calls = []
        self.alg = "RS256"
        self.sign_with = None

    def discovery(self):
        return {"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/auth",
                "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/certs",
                "userinfo_endpoint": f"{ISSUER}/userinfo",
                "id_token_signing_alg_values_supported": ["RS256", "HS256"]}

    def get_json(self, url, headers=None):
        if url.endswith("openid-configuration"):
            return self.discovery()
        return self.userinfo

    def post_form(self, url, data, auth):
        self.token_calls.append((data, auth))
        claims = {"iss": ISSUER, "aud": "loona", "iat": int(time.time()), "exp": int(time.time()) + 300,
                  "nonce": self.nonce, **self.claims}
        key = self.sign_with if self.sign_with is not None else self.key
        return {"id_token": jwt.encode(claims, key, algorithm=self.alg), "access_token": "at"}


class OidcTests(TestCase):
    def setUp(self):
        oidc._discovery.clear()
        settings(sso_protocol="oidc", oidc_issuer=ISSUER, oidc_client_id="loona", sso_groups_attr="groups",
                 sso_mirror_groups="all", public_url="https://loona.example.com", sso_label="Sign in with Keycloak")
        row = SystemSettings.objects.get(pk=1)
        row.oidc_client_secret = "s3cret"
        row.save()
        system.invalidate()
        self.idp = FakeProvider()
        for name, value in (("_get_json", self.idp.get_json), ("_post_form", self.idp.post_form),
                            ("_signing_key", lambda doc, token: self.idp.key.public_key())):
            patcher = patch.object(oidc, name, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def go(self, claims, userinfo=None, next_url="/runs/"):
        self.idp.claims = {"sub": "u-1", "preferred_username": "alice", "email": "alice@example.com",
                           "given_name": "Alice", "groups": ["/devops", "readers"], **claims}
        self.idp.userinfo = userinfo or {}
        response = self.client.get(reverse("sso_start") + f"?next={next_url}")
        query = parse_qs(urlsplit(response["Location"]).query)
        self.idp.nonce = query["nonce"][0]
        self.assertEqual(query["redirect_uri"], ["https://loona.example.com/login/sso/oidc/callback/"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        return self.client.get(reverse("sso_oidc_callback"), {"state": query["state"][0], "code": "c"})

    def test_the_login_page_offers_it(self):
        self.assertContains(self.client.get(reverse("login")), "Sign in with Keycloak")

    def test_a_first_sign_in_makes_the_user_and_the_teams(self):
        response = self.go({})
        self.assertRedirects(response, "/runs/", fetch_redirect_response=False)
        user = User.objects.get(username="alice")
        self.assertEqual((user.email, user.first_name, user.has_usable_password()), ("alice@example.com", "Alice", False))
        self.assertEqual(sorted(user.groups.values_list("name", flat=True)), ["devops", "readers"])
        self.assertTrue(DirectoryGroup.objects.filter(dn="oidc:devops").exists())
        self.assertEqual(SsoIdentity.objects.get(user=user).subject, "u-1")
        verifier = self.idp.token_calls[0][0]["code_verifier"]
        self.assertTrue(len(verifier) > 40)
        self.assertEqual(self.idp.token_calls[0][1], ("loona", "s3cret"))
        self.assertEqual(self.client.get("/").status_code, 200)
        # No one-time code asked: the provider decides about that.
        settings(mfa_policy="everyone")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_the_subject_is_what_counts(self):
        self.go({})
        self.client.logout()
        self.go({"preferred_username": "alice.renamed"})
        self.assertEqual(User.objects.count(), 1)
        self.assertFalse(User.objects.filter(username="alice.renamed").exists())

    def test_groups_from_userinfo_and_the_superuser_group(self):
        settings(sso_superuser_group="admins")
        self.go({"groups": []}, userinfo={"sub": "u-1", "groups": ["admins"]})
        self.assertTrue(User.objects.get(username="alice").is_superuser)

    def test_a_local_account_is_not_taken_over(self):
        User.objects.create_superuser("alice", password="x")
        response = self.go({})
        self.assertRedirects(response, reverse("login"), fetch_redirect_response=False)
        self.assertFalse(SsoIdentity.objects.exists())
        self.assertIn("already exists", str(list(response.wsgi_request._messages)))
        # Not even when taking over is on: it signs in on its own.
        settings(sso_link_existing=True)
        self.go({})
        self.assertFalse(SsoIdentity.objects.exists())

    def test_only_accounts_without_their_own_sign_in_are_taken_over(self):
        settings(sso_link_existing=True)
        for make in (lambda: User.objects.create_user("alice", password="Alice-pass-123"),
                     lambda: User.objects.create_superuser("alice")):
            user = make()
            self.go({})
            self.assertFalse(SsoIdentity.objects.exists())
            user.delete()
        user = User.objects.create_user("alice")
        with_codes(user)
        self.go({})
        self.assertFalse(SsoIdentity.objects.exists())
        user.delete()
        User.objects.create_user("alice")  # made ready for single sign-on, no password
        self.go({})
        self.assertTrue(SsoIdentity.objects.filter(user__username="alice").exists())

    def test_ldap_accounts_are_taken_over_only_when_allowed(self):
        user = User.objects.create_user("alice")
        DirectoryAccount.objects.create(user=user, dn="uid=alice,dc=x")
        self.go({})
        self.assertFalse(SsoIdentity.objects.exists())
        settings(sso_link_existing=True)
        self.go({})
        self.assertFalse(DirectoryAccount.objects.filter(user=user).exists())

    def test_required_group(self):
        settings(sso_require_group="loona-users")
        self.go({})
        self.assertFalse(User.objects.filter(username="alice").exists())
        self.go({"groups": ["loona-users"]})
        self.assertTrue(User.objects.filter(username="alice").exists())

    def test_tokens_that_do_not_check_out(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.idp.sign_with = other
        self.go({})
        self.idp.sign_with = None
        self.go({"aud": "someone-else"})
        self.go({"nonce": "replayed"})
        self.go({"exp": int(time.time()) - 3600})
        self.idp.alg, self.idp.sign_with = "HS256", "s3cret"
        self.go({})
        self.assertFalse(User.objects.exists())

    def test_a_callback_nobody_started(self):
        response = self.client.get(reverse("sso_oidc_callback"), {"state": "x", "code": "c"})
        self.assertRedirects(response, reverse("login"), fetch_redirect_response=False)

    def test_another_state(self):
        self.client.get(reverse("sso_start"))
        response = self.client.get(reverse("sso_oidc_callback"), {"state": "forged", "code": "c"})
        self.assertRedirects(response, reverse("login"), fetch_redirect_response=False)
        self.assertFalse(User.objects.exists())

    def test_an_inactive_account_stays_out(self):
        self.go({})
        User.objects.filter(username="alice").update(is_active=False)
        self.client.logout()
        self.go({})
        self.assertNotEqual(self.client.get("/").status_code, 200)

    def test_the_admin_page(self):
        root = User.objects.create_superuser("root", password="x")
        self.client.force_login(root)
        page = self.client.get(reverse("admin_sso"))
        self.assertContains(page, "https://loona.example.com/login/sso/oidc/callback/")
        response = self.client.post(reverse("admin_sso"), {
            "sso_protocol": "oidc", "sso_label": "SSO", "oidc_issuer": ISSUER, "oidc_client_id": "loona",
            "oidc_scopes": "openid email", "saml_idp_metadata": "", "sso_username_attr": "",
            "sso_email_attr": "email", "sso_first_name_attr": "given_name", "sso_last_name_attr": "family_name",
            "sso_groups_attr": "groups", "sso_mirror_groups": "mapped", "sso_require_group": "",
            "sso_superuser_group": "", "client_secret": "new-secret", "test": "1"})
        self.assertContains(response, "Found https://idp.example.com/realms/main")
        self.client.post(reverse("admin_sso"), {
            "sso_protocol": "oidc", "sso_label": "SSO", "oidc_issuer": ISSUER, "oidc_client_id": "loona",
            "oidc_scopes": "openid email", "saml_idp_metadata": "", "sso_username_attr": "",
            "sso_email_attr": "email", "sso_first_name_attr": "given_name", "sso_last_name_attr": "family_name",
            "sso_groups_attr": "groups", "sso_mirror_groups": "mapped", "sso_require_group": "",
            "sso_superuser_group": "", "client_secret": "new-secret", "save": "1"})
        self.assertEqual(system.get().oidc_client_secret, "new-secret")
        from administration.models import AuditEntry

        self.assertNotIn("new-secret", str(AuditEntry.objects.get(section="sso").changes))


class SamlTests(TestCase):
    def setUp(self):
        settings(sso_protocol="saml", saml_idp_metadata="", public_url="https://loona.example.com")

    def test_sp_metadata(self):
        response = self.client.get(reverse("sso_saml_metadata"))
        self.assertContains(response, 'entityID="https://loona.example.com/login/sso/saml/metadata/"')
        self.assertContains(response, "https://loona.example.com/login/sso/saml/acs/")

    def test_an_answer_to_nothing_is_refused(self):
        settings(saml_idp_metadata=IDP_METADATA)
        response = self.client.post(reverse("sso_saml_acs"), {"SAMLResponse": base64.b64encode(
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="x" Version="2.0" '
            b'IssueInstant="2026-01-01T00:00:00Z"/>').decode()})
        self.assertRedirects(response, reverse("login"), fetch_redirect_response=False)
        self.assertFalse(User.objects.exists())

    def test_metadata_without_a_certificate_is_refused_by_the_form(self):
        from administration.forms import SsoForm

        form = SsoForm({"sso_protocol": "saml", "sso_label": "x", "oidc_scopes": "openid",
                        "saml_idp_metadata": re.sub(r"<md:KeyDescriptor.*?</md:KeyDescriptor>", "", IDP_METADATA), "sso_email_attr": "email",
                        "sso_first_name_attr": "a", "sso_last_name_attr": "b", "sso_mirror_groups": "mapped"},
                       instance=SystemSettings.objects.get(pk=1))
        self.assertFalse(form.is_valid())
        self.assertIn("signing certificate", str(form.errors))

    def test_an_idp_with_a_one_word_host_name(self):
        """Inside a network the IdP is often http://keycloak:8080/ - no dot in the name."""
        settings(saml_idp_metadata=IDP_METADATA.replace("https://idp.example.com/sso", "http://keycloak:8181/sso"))
        response = self.client.get(reverse("sso_start"))
        self.assertTrue(response["Location"].startswith("http://keycloak:8181/sso?SAMLRequest="), response)

    def test_unusable_settings_are_explained_not_a_server_error(self):
        settings(saml_idp_metadata=IDP_METADATA.replace("https://idp.example.com/sso", "not-a-url"))
        response = self.client.get(reverse("sso_start"), follow=True)
        self.assertContains(response, "cannot be used")

    def test_sign_in_starts_at_the_idp(self):
        settings(saml_idp_metadata=IDP_METADATA)
        response = self.client.get(reverse("sso_start"))
        self.assertTrue(response["Location"].startswith("https://idp.example.com/sso?SAMLRequest="))
        from .models import SamlRequest

        self.assertEqual(SamlRequest.objects.count(), 1)

    def test_an_answer_only_signs_in_the_browser_that_asked(self):
        from django.test import Client

        from . import saml
        from .models import SamlRequest
        from .sso import Claims

        settings(saml_idp_metadata=IDP_METADATA)
        self.client.get(reverse("sso_start"))
        request_id = SamlRequest.objects.get().request_id
        answer = base64.b64encode(
            f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="x" Version="2.0" '
            f'IssueInstant="2026-01-01T00:00:00Z" InResponseTo="{request_id}"/>'.encode()).decode()
        claims = Claims(protocol="saml", issuer="https://idp.example.com/meta", subject="mallory", username="mallory")
        # Someone else's browser is handed the (valid) answer to this request.
        other = Client()
        with patch.object(saml, "_verified", return_value=claims):
            response = other.post(reverse("sso_saml_acs"), {"SAMLResponse": answer})
            self.assertEqual(other.post(reverse("sso_saml_acs"), {"SAMLResponse": answer})["Location"],
                             reverse("login"), "one answer per request")
        finish = response["Location"]
        self.assertTrue(finish.startswith(reverse("sso_saml_finish")))
        self.assertRedirects(other.get(finish), reverse("login"), fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", other.session)
        # The browser that started it collects it, once.
        self.client.get(finish)
        self.assertEqual(User.objects.get(pk=self.client.session["_auth_user_id"]).username, "mallory")
        self.assertFalse(SamlRequest.objects.exists())


CERT = ("MIIBrTCCAVOgAwIBAgIUQ9F0VqvDT3P0gQf0pFOxkx4p1ZEwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAwwHdGVzdC1p"
        "ZHAwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjASMRAwDgYDVQQDDAd0ZXN0LWlkcDBZMBMGByqGSM49"
        "AgEGCCqGSM49AwEHA0IABPq2Yd0xBzYwY1u0d9Gv6Ow3hQfQmF9x9dJbqLqEmV8w0mJ3C7o7x0O4y1d8m9f6W1oS"
        "x4cS4b7vX6m2hjv2cFqjUzBRMB0GA1UdDgQWBBQ5mY8kKZ5mY8kKZ5mY8kKZ5mY8kDAfBgNVHSMEGDAWgBQ5mY8k"
        "KZ5mY8kKZ5mY8kKZ5mY8kDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDf")
IDP_METADATA = f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com/meta">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{CERT}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


# -- against a real Keycloak --------------------------------------------------------------------
#
#   docker run -d --name loona-keycloak-test -p 8081:8081 \
#     -v $PWD/signin/testdata:/opt/keycloak/data/import:ro \
#     -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
#     quay.io/keycloak/keycloak:26.0 start-dev --http-port=8081 --import-realm
#   LOONA_KEYCLOAK_TEST_URL=http://localhost:8081 python manage.py test signin

import html.parser  # noqa: E402
import http.cookiejar  # noqa: E402
import os  # noqa: E402
import unittest  # noqa: E402
import urllib.parse  # noqa: E402
import urllib.request  # noqa: E402

from django.test import LiveServerTestCase  # noqa: E402

KEYCLOAK = os.environ.get("LOONA_KEYCLOAK_TEST_URL", "")


class _Forms(html.parser.HTMLParser):
    """The forms of a page: [(action, {name: value})]."""

    def __init__(self):
        super().__init__()
        self.forms = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.forms.append([attrs.get("action", ""), {}])
        elif tag == "input" and self.forms and attrs.get("name"):
            self.forms[-1][1][attrs["name"]] = attrs.get("value") or ""


class _LocalhostPolicy(http.cookiejar.DefaultCookiePolicy):
    # Keycloak marks its cookies Secure even over http; browsers still send
    # them to localhost, so this does too.
    def return_ok_secure(self, cookie, request):
        return True


class Browser:
    def __init__(self):
        jar = http.cookiejar.CookieJar(policy=_LocalhostPolicy())
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def open(self, url, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        with self.opener.open(url, data=body, timeout=30) as response:
            return response.geturl(), response.read().decode()

    def submit(self, page_url, page, **fields):
        parser = _Forms()
        parser.feed(page)
        action, values = parser.forms[0]
        return self.open(urllib.parse.urljoin(page_url, action.replace("&amp;", "&")), {**values, **fields})


@unittest.skipUnless(KEYCLOAK, "set LOONA_KEYCLOAK_TEST_URL to a Keycloak with signin/testdata imported")
class KeycloakTests(LiveServerTestCase):
    # Keycloak's test clients know Loona at this port.
    port = 8765

    @classmethod
    def setUpClass(cls):
        import socket

        # A previous run's connections may hold the port a little longer.
        for _attempt in range(120):
            with socket.socket() as probe:
                try:
                    probe.bind(("127.0.0.1", cls.port))
                    break
                except OSError:
                    time.sleep(1)
        super().setUpClass()

    def setUp(self):
        oidc._discovery.clear()
        oidc._jwks.clear()
        settings(public_url="http://localhost:8765", sso_groups_attr="groups", sso_mirror_groups="all",
                 sso_superuser_group="loona-admins", mfa_policy="everyone")

    def sign_in(self):
        browser = Browser()
        url, page = browser.open(f"{self.live_server_url}/login/sso/?next=/runs/")
        self.assertIn("/realms/loona/", url)
        url, page = browser.submit(url, page, username="alice", password="alice-pass")
        self.answer = (url, page)
        if "SAMLResponse" in page:
            url, page = browser.submit(url, page)
        return browser, url, page

    def check_alice(self, protocol):
        user = User.objects.get(username="alice")
        self.assertEqual((user.email, user.first_name, user.is_superuser), ("alice@example.com", "Alice", True))
        self.assertEqual(sorted(user.groups.values_list("name", flat=True)), ["devops", "loona-admins"])
        self.assertEqual(SsoIdentity.objects.get(user=user).protocol, protocol)

    def test_openid_connect(self):
        settings(sso_protocol="oidc", oidc_issuer=f"{KEYCLOAK}/realms/loona", oidc_client_id="loona",
                 oidc_scopes="openid email profile", sso_username_attr="", sso_email_attr="email",
                 sso_first_name_attr="given_name", sso_last_name_attr="family_name")
        row = SystemSettings.objects.get(pk=1)
        row.oidc_client_secret = "loona-secret"
        row.save()
        system.invalidate()
        browser, url, page = self.sign_in()
        self.assertEqual(url, f"{self.live_server_url}/runs/", page[:500])
        self.check_alice("oidc")

    def test_saml(self):
        metadata = Browser().open(f"{KEYCLOAK}/realms/loona/protocol/saml/descriptor")[1]
        settings(sso_protocol="saml", saml_idp_metadata=metadata, sso_username_attr="",
                 sso_email_attr="email", sso_first_name_attr="given_name", sso_last_name_attr="")
        browser, url, page = self.sign_in()
        self.assertEqual(url, f"{self.live_server_url}/runs/", page[:500])
        self.check_alice("saml")
        # The same answer posted again - by someone who copied it - opens nothing.
        url, page = Browser().submit(*self.answer)
        self.assertEqual(urllib.parse.urlsplit(url).path, "/login/")
