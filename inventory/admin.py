# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib import admin

from .models import Credential, Host, HostGroup, HostKey


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("name", "address", "port", "credential", "enabled")
    list_filter = ("enabled", "groups", "credential")
    search_fields = ("name", "address", "description")
    filter_horizontal = ("groups",)


@admin.register(HostGroup)
class HostGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "description")
    search_fields = ("name", "description")
    filter_horizontal = ("parents",)


@admin.register(Credential)
class CredentialAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "username", "become_method")
    filter_horizontal = ("teams",)
    list_filter = ("kind", "become_method")
    search_fields = ("name", "username")
    # Secrets are encrypted blobs; editing them belongs in the Loona UI.
    exclude = ("secret_encrypted", "become_secret_encrypted")


@admin.register(HostKey)
class HostKeyAdmin(admin.ModelAdmin):
    list_display = ("host", "username", "status", "fingerprint", "installed_at")
    list_filter = ("status",)
    search_fields = ("host__name", "username", "fingerprint")
    # The private half is an encrypted blob, and installing or revoking a key is
    # a job rather than a field edit - both belong in the Loona UI.
    readonly_fields = ("public_key", "fingerprint", "created_at", "installed_at", "verified_at")
    exclude = ("private_key_encrypted",)
