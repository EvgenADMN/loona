# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""The self-service catalog: things people may ask for, and their requests.

An item is an OpenTofu project plus a form.  Every request of the item adds
an entry to ``var.loona_requests``, the project creates a machine for each
entry and lists it in ``loona_hosts``, and Loona takes it from there as for
any machine the project creates.  See catalog.services.
"""
from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from inventory.models import HostGroup


class CatalogItem(models.Model):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True, default="")
    tofu_project = models.ForeignKey(
        "infra.TofuProject", on_delete=models.PROTECT, related_name="catalog_items",
        verbose_name=_("OpenTofu project"),
        help_text=_("Creates a machine for every entry of var.loona_requests."),
    )
    host_group = models.ForeignKey(
        HostGroup, on_delete=models.PROTECT, related_name="catalog_items",
        verbose_name=_("New hosts join"),
        help_text=_("The project's group or one under it. Roles there decide what requesters "
                  "may do with their machines."),
    )
    teams = models.ManyToManyField(
        "auth.Group", blank=True, related_name="catalog_items",
        help_text=_("Teams that may request this. Operators of the project's group always may."),
    )
    # Survey questions, as on a launch template (runs.surveys), passwords excepted.
    fields = models.JSONField(default=list, blank=True)
    approval_required = models.BooleanField(
        default=True,
        help_text=_("An Admin of the project's group looks at each request's plan before it is "
                  "applied. Off: plans that create only are applied at once."),
    )
    max_per_user = models.PositiveIntegerField(
        _("Per person"), default=0, help_text=_("How many each person may have at once. 0: no limit.")
    )
    enabled = models.BooleanField(default=True, help_text=_("Off: no new requests."))
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("catalog_request_new", args=[self.pk])


class CatalogRequest(models.Model):
    PLANNING = "planning"
    WAITING = "waiting"
    APPLYING = "applying"
    ACTIVE = "active"
    FAILED = "failed"
    REJECTED = "rejected"
    RETIRED = "retired"
    STATUS_CHOICES = [
        (PLANNING, _("Planning")),
        (WAITING, _("Waiting for approval")),
        (APPLYING, _("Being applied")),
        (ACTIVE, _("Active")),
        (FAILED, _("Failed")),
        (REJECTED, _("Rejected")),
        (RETIRED, _("Retired")),
    ]
    # Statuses in which the request is still going somewhere.
    BUSY = {PLANNING, WAITING, APPLYING}

    item = models.ForeignKey(CatalogItem, on_delete=models.PROTECT, related_name="requests")
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="catalog_requests"
    )
    # The host name the machine will have, and the key of its loona_requests entry.
    name = models.CharField(max_length=120)
    values = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=PLANNING, db_index=True)
    # Set while the request is on its way out: its plan leaves the machine out.
    retiring = models.BooleanField(default=False)
    error = models.TextField(blank=True, default="")
    # The run moving it right now (or last): a plan, then its apply.
    job = models.ForeignKey(
        "runs.Job", on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    host = models.ForeignKey(
        "inventory.Host", on_delete=models.SET_NULL, null=True, blank=True, related_name="catalog_requests"
    )
    # Kept for the requester, who may not see the host itself.
    address = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-pk"]

    def __str__(self):
        return f"{self.item}: {self.name}"

    def get_absolute_url(self):
        return reverse("catalog_request_detail", args=[self.pk])

    @property
    def machine_exists(self) -> bool:
        """Whether the machine is (or is about to be) there, for every plan
        of the project other than this request's own."""
        if self.retiring:
            # Until the retiring apply runs, the machine is still there.
            return self.status in (self.PLANNING, self.WAITING, self.FAILED)
        return self.status in (self.APPLYING, self.ACTIVE)

    @property
    def is_open(self) -> bool:
        """Holds its name and counts against the quota."""
        return self.status not in (self.REJECTED, self.RETIRED) and not (
            self.status == self.FAILED and not self.retiring
        )

    @property
    def stage(self) -> str:
        label = self.get_status_display()
        if self.retiring and self.status in self.BUSY | {self.FAILED}:
            return f"Retiring: {label.lower()}"
        return label

    @property
    def badge(self) -> str:
        if self.status in (self.FAILED, self.REJECTED):
            return "fail"
        if self.status in self.BUSY:
            return "warn" if self.status == self.WAITING else "run"
        return "ok" if self.status == self.ACTIVE else ""
