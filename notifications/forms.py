# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django import forms
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _

from administration.models import SystemSettings
from core.forms import style
from inventory.models import HostGroup

from .models import EVENTS, Channel

KEEP = _("Leave empty to keep the stored one.")


class SmtpForm(forms.ModelForm):
    smtp_password = forms.CharField(label=_("SMTP password"), required=False,
                                    widget=forms.PasswordInput(render_value=False), help_text=KEEP)

    class Meta:
        model = SystemSettings
        fields = ["smtp_host", "smtp_port", "smtp_security", "smtp_username", "smtp_from"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style(self)

    def save(self, commit=True):
        row = super().save(commit=False)
        if self.cleaned_data.get("smtp_password"):
            row.smtp_password = self.cleaned_data["smtp_password"]
        if commit:
            row.save()
        return row


class ChannelForm(forms.ModelForm):
    events = forms.MultipleChoiceField(choices=EVENTS, widget=forms.CheckboxSelectMultiple,
                                       required=False, label=_("Tell about"))
    recipients = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 3}),
                                 help_text=_("Email: one address per line."))
    bot_token = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False),
                                help_text="Telegram: from @BotFather. " + KEEP)
    chat_id = forms.CharField(required=False, help_text=_("Telegram: the chat, group or channel id."))
    url = forms.CharField(required=False, label=_("URL"),
                          help_text=_("Webhook: where to POST. A Slack or Mattermost incoming webhook works."))
    secret = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False),
                             help_text="Webhook, optional: signs each body as X-Loona-Signature "
                                       "(HMAC-SHA256). " + KEEP)

    class Meta:
        model = Channel
        fields = ["name", "kind", "enabled", "events", "host_groups"]
        widgets = {"host_groups": forms.CheckboxSelectMultiple}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["kind"].choices = Channel.KINDS
        if not self.instance.pk:
            self.fields["kind"].initial = Channel.EMAIL
        self.fields["host_groups"].queryset = HostGroup.objects.order_by("name")
        self.fields["host_groups"].label = _("Only for these groups")
        config = self.instance.config if self.instance.pk else {}
        self.fields["recipients"].initial = "\n".join(config.get("recipients", []))
        self.fields["chat_id"].initial = config.get("chat_id", "")
        self.fields["url"].initial = config.get("url", "")
        self.stored = config
        style(self)

    def clean(self):
        cleaned = super().clean()
        kind = cleaned.get("kind")
        if kind == Channel.EMAIL:
            addresses = [a.strip() for a in cleaned.get("recipients", "").splitlines() if a.strip()]
            if not addresses:
                self.add_error("recipients", _("At least one address."))
            for address in addresses:
                try:
                    validate_email(address)
                except forms.ValidationError:
                    self.add_error("recipients", _('Not an address: %(address)s') % {"address": address})
            cleaned["_config"] = {"recipients": addresses}
        elif kind == Channel.TELEGRAM:
            token = cleaned.get("bot_token") or self.stored.get("bot_token", "")
            if not token:
                self.add_error("bot_token", _("Needed."))
            if not cleaned.get("chat_id"):
                self.add_error("chat_id", _("Needed."))
            cleaned["_config"] = {"bot_token": token, "chat_id": cleaned.get("chat_id", "").strip()}
        elif kind == Channel.WEBHOOK:
            url = cleaned.get("url", "").strip()
            if not url.startswith(("http://", "https://")):
                self.add_error("url", _("An http:// or https:// address."))
            secret = cleaned.get("secret") or self.stored.get("secret", "")
            cleaned["_config"] = {"url": url, "secret": secret}
        return cleaned

    def save(self, commit=True):
        channel = super().save(commit=False)
        channel.events = self.cleaned_data["events"]
        channel.config = self.cleaned_data["_config"]
        channel.save()
        self.save_m2m()
        return channel
