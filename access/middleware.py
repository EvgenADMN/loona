# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Keep directory users' sessions in step with the directory.

A session outlives the sign-in that started it.  Without this, someone
removed from LDAP - or moved out of a group - keeps what they had until their
session expires, which by Django's default is two weeks away.
"""
import logging
import time

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.shortcuts import redirect
from django.utils.translation import gettext as _
from ldap3.core.exceptions import LDAPException

from administration import system

from .ldap import LdapBackend, sync_user
from .models import DirectoryAccount

log = logging.getLogger("loona.ldap")

SESSION_KEY = "_loona_directory_checked"
# After a failed attempt to reach the directory, try again this much sooner.
RETRY_SECONDS = 60


@receiver(user_logged_in)
def _signed_in_counts_as_checked(sender, request, user, **kwargs):
    # A sign-in against the directory has just synced everything.
    if request is not None and hasattr(request, "session"):
        request.session[SESSION_KEY] = time.time()


class DirectoryRecheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        conf = system.ldap_conf()
        user = getattr(request, "user", None)
        if (
            conf["SERVER_URI"]
            and user is not None
            and user.is_authenticated
            and DirectoryAccount.objects.filter(user=user).exists()
        ):
            response = self._recheck(request, user, conf)
            if response is not None:
                return response
        return self.get_response(request)

    def _recheck(self, request, user, conf):
        now = time.time()
        interval = conf["RECHECK_MINUTES"] * 60
        if now - request.session.get(SESSION_KEY, 0) < interval:
            return None
        try:
            found = LdapBackend.directory_factory(conf).lookup(user.get_username())
        except LDAPException:
            # The directory being down must not sign everybody out; keep the
            # session and ask again shortly.
            log.warning("Could not re-check %s against LDAP", user, exc_info=True)
            request.session[SESSION_KEY] = now - interval + RETRY_SECONDS
            return None

        refreshed = sync_user(found, conf) if found is not None else None
        if refreshed is None or not refreshed.is_active:
            log.info("Signing %s out: no longer allowed in by the directory", user)
            logout(request)
            messages.warning(request, _("Your directory account no longer gives access to Loona."))
            return redirect(settings.LOGIN_URL)
        request.session[SESSION_KEY] = now
        reload_user(request.user)
        return None


def reload_user(user):
    """Re-read the user and drop the permission caches built from the old row:
    is_superuser, teams or permissions may have changed during this request."""
    user.refresh_from_db()
    real = getattr(user, "_wrapped", user)  # request.user is a SimpleLazyObject
    for cache in ("_perm_cache", "_user_perm_cache", "_group_perm_cache", "_loona_access"):
        real.__dict__.pop(cache, None)


def directory_still_allows(user) -> bool:
    """For token-authenticated requests, which have no session to mark.

    The directory account's last sync stands in for the session's mark: if it
    is older than the re-check interval, the directory is asked again. As for
    sessions, an unreachable directory lets the request through.
    """
    from django.utils import timezone

    conf = system.ldap_conf()
    account = DirectoryAccount.objects.filter(user=user).first()
    if not conf["SERVER_URI"] or account is None:
        return True
    age = (timezone.now() - account.synced_at).total_seconds()
    if age < conf["RECHECK_MINUTES"] * 60:
        return True
    try:
        found = LdapBackend.directory_factory(conf).lookup(user.get_username())
    except LDAPException:
        log.warning("Could not re-check %s against LDAP", user, exc_info=True)
        return True
    refreshed = sync_user(found, conf) if found is not None else None
    return refreshed is not None and refreshed.is_active


def may_still_act(user) -> bool:
    """For a run started on a user's behalf outside a request (a trigger, a
    schedule): the account is active and the directory still lets it in."""
    if not user.is_active or not directory_still_allows(user):
        return False
    reload_user(user)
    return user.is_active
