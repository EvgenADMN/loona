# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Per-user settings that outlive a session."""
from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


class UserPreference(models.Model):
    """Interface choices tied to the account, not to the browser.

    Kept as its own model rather than a column on the user so that later
    preferences have an obvious home, and so Loona never has to swap in a
    custom user model to add one.
    """

    DARK = "dark"
    LIGHT = "light"
    THEME_CHOICES = [(DARK, _("Dark")), (LIGHT, _("Light"))]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="preference"
    )
    theme = models.CharField(max_length=8, choices=THEME_CHOICES, default=DARK)
    # "" follows the default set in Administration.
    language = models.CharField(max_length=10, blank=True, default="", choices=settings.LANGUAGES)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user}: {self.theme}"

    @classmethod
    def theme_for(cls, user) -> str:
        """The theme to render for this user, or "" to follow the browser.

        Signed out there is no account to read, so the operating system's own
        light/dark setting decides - that is what the empty string means.
        """
        if not getattr(user, "is_authenticated", False):
            return ""
        preference = cls.objects.filter(user=user).values_list("theme", flat=True).first()
        return preference or cls.DARK

    @classmethod
    def toggle_theme(cls, user) -> str:
        preference, _created = cls.objects.get_or_create(user=user)
        preference.theme = cls.LIGHT if preference.theme == cls.DARK else cls.DARK
        preference.save(update_fields=["theme", "updated_at"])
        return preference.theme

    @classmethod
    def language_for(cls, user) -> str:
        """The person's own choice of language, or "" for the default."""
        if not getattr(user, "is_authenticated", False):
            return ""
        return cls.objects.filter(user=user).values_list("language", flat=True).first() or ""

    @classmethod
    def set_language(cls, user, language: str):
        preference, _created = cls.objects.get_or_create(user=user)
        preference.language = language
        preference.save(update_fields=["language", "updated_at"])
