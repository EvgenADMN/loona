# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.utils.translation import gettext as _

from administration import system
from administration.views import audit, superuser_only

from . import dispatch
from .forms import ChannelForm, SmtpForm
from .models import TEST, Channel, Delivery


@superuser_only
def overview(request):
    row = system.for_editing()
    smtp = SmtpForm(request.POST or None, instance=row, prefix="smtp")
    if request.method == "POST" and smtp.is_valid():
        smtp.save()
        system.invalidate()
        if smtp.changed_data:
            audit(request.user, "notifications", "Changed the SMTP settings", smtp)
        messages.success(request, _("Mail settings saved."))
        return redirect("admin_notifications")
    return render(request, "notifications/overview.html", {
        "section": "notifications",
        "smtp": smtp,
        "has_smtp_password": bool(row.smtp_password_encrypted),
        "channels": Channel.objects.prefetch_related("host_groups"),
        "deliveries": Delivery.objects.select_related("channel")[:40],
        "public_url": row.public_url,
    })


@superuser_only
def channel_edit(request, pk=None):
    channel = get_object_or_404(Channel, pk=pk) if pk else Channel()
    form = ChannelForm(request.POST or None, instance=channel)
    if request.method == "POST" and form.is_valid():
        saved = form.save()
        audit(request.user, "notifications", f"{'Changed' if pk else 'Added'} channel {saved.name}", form)
        messages.success(request, _('Channel %(name)s saved. Send a test to check it.') % {"name": saved.name})
        return redirect("admin_notifications")
    return render(request, "notifications/channel_form.html",
                  {"section": "notifications", "form": form, "channel": channel})


@superuser_only
@require_POST
def channel_delete(request, pk):
    channel = get_object_or_404(Channel, pk=pk)
    audit(request.user, "notifications", f"Removed channel {channel.name}")
    channel.delete()
    return redirect("admin_notifications")


@superuser_only
@require_POST
def channel_test(request, pk):
    channel = get_object_or_404(Channel, pk=pk)
    [delivery] = dispatch.emit(
        TEST, "Test message",
        f"{request.user} sent this from Loona to check the channel {channel.name}. It works.",
        "/", channels=[channel],
    ) or [None]
    if delivery is None:
        messages.error(request, _("Could not queue the test."))
        return redirect("admin_notifications")
    # Sent right here rather than in the background: the answer is the point.
    status = dispatch.deliver(delivery.pk)
    delivery.refresh_from_db()
    if status == Delivery.SENT:
        messages.success(request, _('Test sent to %(name)s.') % {"name": channel.name})
    else:
        messages.error(request, f"{channel.name}: {delivery.error}")
    return redirect("admin_notifications")
