# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib import admin
from django.contrib.auth.admin import GroupAdmin
from django.contrib.auth.models import Group

from .models import DirectoryGroup, GroupGrant


class GroupGrantInline(admin.TabularInline):
    model = GroupGrant
    extra = 1
    autocomplete_fields = ("host_group",)
    verbose_name = "role on a host group"
    verbose_name_plural = "Roles on host groups"


# Teams are Django groups; their host-group roles are edited on the same page
# as their members and global permissions.
admin.site.unregister(Group)


class DirectoryGroupInline(admin.TabularInline):
    model = DirectoryGroup
    fk_name = "team"
    extra = 0
    fields = ("dn", "name", "last_seen")
    readonly_fields = ("dn", "name", "last_seen")
    can_delete = False
    verbose_name = "LDAP group mapped here"
    verbose_name_plural = "LDAP groups mapped here (their members join this team at sign-in)"

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Group)
class TeamAdmin(GroupAdmin):
    inlines = [GroupGrantInline, DirectoryGroupInline]


@admin.register(DirectoryGroup)
class DirectoryGroupAdmin(admin.ModelAdmin):
    """Where a directory group is pointed at a different team, or at none."""

    list_display = ("name", "dn", "team", "last_seen")
    list_editable = ("team",)
    list_filter = (("team", admin.EmptyFieldListFilter),)
    search_fields = ("name", "dn", "team__name")
    fields = ("dn", "name", "team", "last_seen")

    def get_readonly_fields(self, request, obj=None):
        # Rows usually arrive from the directory at a member's first sign-in;
        # adding one by hand is how a group is mapped ahead of that.
        return ("dn", "last_seen") if obj else ("last_seen",)


@admin.register(GroupGrant)
class GroupGrantAdmin(admin.ModelAdmin):
    list_display = ("host_group", "team", "role")
    list_filter = ("role", "team")
    search_fields = ("host_group__name", "team__name")
    autocomplete_fields = ("host_group", "team")
