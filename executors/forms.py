# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django import forms
from django.utils.translation import gettext_lazy as _

from inventory.models import HostGroup

from .models import Executor


class ExecutorForm(forms.ModelForm):
    groups = forms.ModelMultipleChoiceField(
        queryset=HostGroup.objects.all(),
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 8}),
        help_text=_("Runs on the hosts of these groups, and of the groups nested under them, go through "
                  "this executor. A group nested deeper that names another executor keeps its own."),
    )

    class Meta:
        model = Executor
        fields = ["name", "description", "enabled"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["groups"].initial = list(self.instance.groups.all())
        self.fields["groups"].label_from_instance = self._label

    def _label(self, group):
        if group.executor_id and group.executor_id != self.instance.pk:
            return f"{group.name} (now: {group.executor.name})"
        return group.name

    def save(self, commit=True):
        executor = super().save(commit=commit)
        wanted = {group.pk for group in self.cleaned_data["groups"]}
        HostGroup.objects.filter(executor=executor).exclude(pk__in=wanted).update(executor=None)
        HostGroup.objects.filter(pk__in=wanted).update(executor=executor)
        return executor
