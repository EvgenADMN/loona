# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("login/code/", views.code_view, name="signin_code"),
    path("login/setup/", views.setup_view, name="signin_setup"),
    path("login/sso/", views.sso_start, name="sso_start"),
    path("login/sso/oidc/callback/", views.oidc_callback, name="sso_oidc_callback"),
    path("login/sso/saml/acs/", views.saml_acs, name="sso_saml_acs"),
    path("login/sso/saml/metadata/", views.saml_metadata, name="sso_saml_metadata"),
    path("account/security/", views.security_view, name="account_security"),
    path("account/security/setup/", views.security_setup, name="account_security_setup"),
    path("account/security/off/", views.security_off, name="account_security_off"),
    path("account/security/codes/", views.security_new_codes, name="account_security_codes"),
]
