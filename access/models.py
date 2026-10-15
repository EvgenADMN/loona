# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Who may do what, scoped to host groups.

A team is a plain Django group, so membership and global permissions (editing
playbooks, managing credentials) are managed the way Django already manages
them.  What Django has no notion of is a role *on a slice of the inventory* -
that is a :class:`GroupGrant`.
"""
import re

from django.contrib.auth.models import Group
from django.db import models
from django.utils.translation import gettext_lazy as _

from inventory.models import HostGroup


class Role(models.IntegerChoices):
    """Ordered: every role can do everything the ones below it can."""

    VIEWER = 10, "Viewer"
    OPERATOR = 20, "Operator"
    ADMIN = 30, "Admin"


class GroupGrant(models.Model):
    """A team's role on a host group and on every group nested under it."""

    team = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="grants")
    host_group = models.ForeignKey(
        HostGroup, on_delete=models.CASCADE, related_name="grants"
    )
    role = models.PositiveSmallIntegerField(choices=Role.choices, default=Role.VIEWER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["host_group__name", "team__name"]
        constraints = [
            models.UniqueConstraint(
                fields=["team", "host_group"], name="access_one_grant_per_team_group"
            )
        ]

    def __str__(self):
        return f"{self.team} is {self.get_role_display()} on {self.host_group}"


class DirectoryAccount(models.Model):
    """Marks a user as coming from LDAP.

    Only marked users are ever signed in or updated by the directory, so an
    LDAP entry that happens to share a name with a local account - the
    break-glass admin, say - cannot take that account over.
    """

    user = models.OneToOneField(
        "auth.User", on_delete=models.CASCADE, related_name="directory_account"
    )
    dn = models.CharField(_("DN"), max_length=1024)
    # Team ids the directory put this user in at the last sign-in.  Needed to
    # take them out again after a group is remapped to another team, when
    # nothing points at the old team any more.
    granted_team_ids = models.JSONField(default=list, blank=True)
    synced_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.dn


class DirectoryGroup(models.Model):
    """One LDAP group and the Loona team it maps onto.

    Rows appear the first time a member signs in.  Several directory groups
    may point at one team; a group with no team is known but grants nothing.
    Membership of every team that some directory group points at is owned by
    the directory: it is rewritten on each sign-in, for directory users only.
    """

    dn_key = models.CharField(
        max_length=1024, unique=True, editable=False, help_text=_("Lower-cased DN.")
    )
    dn = models.CharField(_("DN"), max_length=1024)
    name = models.CharField(max_length=255)
    team = models.ForeignKey(
        Group,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="directory_groups",
        help_text=_("Members of this directory group join this team."),
    )
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.dn

    def save(self, *args, **kwargs):
        self.dn_key = dn_key(self.dn)
        super().save(*args, **kwargs)


def dn_key(dn: str) -> str:
    """DNs compare case-insensitively and ignore spaces around separators.

    Only unescaped commas separate: in "cn=Doe\\, John" the comma is part of
    the name, and the space after it is kept.
    """
    parts = re.split(r"(?<!\\),", dn)
    return ",".join(part.strip() for part in parts).lower()


class Approval(models.Model):
    """A second person's decision on a preview before it is applied."""

    APPROVED = "approved"
    REJECTED = "rejected"
    DECISIONS = [(APPROVED, "Approved"), (REJECTED, "Rejected")]

    plan = models.OneToOneField("runs.Job", on_delete=models.CASCADE, related_name="approval")
    decision = models.CharField(max_length=8, choices=DECISIONS)
    decided_by = models.ForeignKey(
        "auth.User", on_delete=models.SET_NULL, null=True, related_name="approvals"
    )
    comment = models.TextField(blank=True, default="")
    decided_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.get_decision_display()} by {self.decided_by} for #{self.plan_id}"

    @property
    def approved(self):
        return self.decision == self.APPROVED



WEEKDAYS = [(0, _("Mon")), (1, _("Tue")), (2, _("Wed")), (3, _("Thu")), (4, _("Fri")), (5, _("Sat")), (6, _("Sun"))]


def _default_zone():
    from django.conf import settings

    return settings.TIME_ZONE


class MaintenanceWindow(models.Model):
    """When changes to a host group may go ahead without a second person.

    A group with windows - its own or a parent's - takes changes inside
    them under its usual approval rule; outside every one of them, applying
    anything needs approval and "Run now" is off.  A group without windows
    has no such restriction.  See access.approvals.
    """

    host_group = models.ForeignKey(HostGroup, on_delete=models.CASCADE, related_name="maintenance_windows")
    weekdays = models.JSONField(default=list, help_text=_("0 = Monday ... 6 = Sunday."))
    start = models.TimeField()
    end = models.TimeField(help_text=_("At or before the start: the window runs past midnight into the next day."))
    timezone = models.CharField(max_length=64, default=_default_zone)
    description = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        ordering = ["host_group__name", "start"]

    def __str__(self):
        return f"{self.host_group}: {self.days_label} {self.start:%H:%M}-{self.end:%H:%M} {self.timezone}"

    @property
    def days_label(self) -> str:
        names = dict(WEEKDAYS)
        days = sorted(self.weekdays)
        if days == list(range(7)):
            return "Every day"
        if days == list(range(5)):
            return "Mon-Fri"
        return ", ".join(str(names[d]) for d in days)

    def contains(self, moment) -> bool:
        from zoneinfo import ZoneInfo

        local = moment.astimezone(ZoneInfo(self.timezone))
        now, day = local.time(), local.weekday()
        if self.start < self.end:
            return day in self.weekdays and self.start <= now < self.end
        # Past midnight (or, when start == end, a whole day from start on).
        return (day in self.weekdays and now >= self.start) or (
            (day - 1) % 7 in self.weekdays and now < self.end
        )
