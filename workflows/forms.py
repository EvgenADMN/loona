# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
from django import forms
from django.utils.translation import gettext_lazy as _

from access import policy
from core.forms import VariablesField, style
from infra.models import TofuProject
from notifications.models import Channel
from playbooks.models import Playbook

from . import engine
from .models import Edge, Step, Workflow

AFTER_CHOICES = [("", "-")] + Edge.CONDITION_CHOICES


class WorkflowForm(forms.ModelForm):
    extra_vars = VariablesField(label=_("Variables for every playbook step"))

    class Meta:
        model = Workflow
        fields = ["name", "description", "host_group", "extra_vars"]
        widgets = {"description": forms.Textarea(attrs={"rows": 2})}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["host_group"].queryset = policy.for_user(user).groups(policy.ADMIN)
        style(self)


class StepForm(forms.ModelForm):
    extra_vars = VariablesField(label=_("Extra variables"))

    class Meta:
        model = Step
        fields = ["name", "kind", "playbook", "host_group", "limit", "extra_vars", "tofu_project",
                  "message", "channels"]
        widgets = {"message": forms.Textarea(attrs={"rows": 3}),
                   "channels": forms.CheckboxSelectMultiple,
                   "limit": forms.TextInput(attrs={"placeholder": "web*:!web03"})}

    def __init__(self, *args, user, workflow, **kwargs):
        super().__init__(*args, **kwargs)
        self.workflow = workflow
        access = policy.for_user(user)
        operate = access.groups(policy.OPERATOR)
        self.fields["playbook"].queryset = Playbook.objects.all()
        self.fields["host_group"].queryset = operate
        self.fields["tofu_project"].queryset = TofuProject.objects.filter(host_group__in=operate)
        self.fields["channels"].queryset = Channel.objects.filter(enabled=True)
        self.fields["message"].help_text = (
            _("For a message: what it says; {workflow}, {run}, {step}, {started_by} and {failed_steps} "
            "are filled in. For an approval: what the approver is asked."))
        others = workflow.steps.exclude(pk=self.instance.pk) if self.instance.pk else workflow.steps.all()
        current = {}
        if self.instance.pk:
            current = dict(self.instance.in_edges.values_list("parent_id", "condition"))
        self.parents = []
        for step in others:
            name = f"after_{step.pk}"
            self.fields[name] = forms.ChoiceField(choices=AFTER_CHOICES, required=False, label=step.name,
                                                  initial=current.get(step.pk, ""))
            self.parents.append((step, name))
        style(self)

    def parent_fields(self):
        return [self[name] for _, name in self.parents]

    def clean(self):
        cleaned = super().clean()
        kind = cleaned.get("kind")
        needs = {Step.PLAYBOOK: ["playbook", "host_group"], Step.TOFU: ["tofu_project"],
                 Step.MESSAGE: ["message"]}.get(kind, [])
        for field in needs:
            if not cleaned.get(field):
                self.add_error(field, _("Needed for this kind of step."))
        if kind == Step.MESSAGE:
            unknown = engine.unknown_placeholders(cleaned.get("message") or "")
            if unknown:
                self.add_error("message", _("Unknown placeholder: %(name)s.") % {"name": unknown[0]})
        name = cleaned.get("name")
        if name and self.workflow.steps.filter(name=name).exclude(pk=self.instance.pk or 0).exists():
            self.add_error("name", _("Another step has this name."))
        me = self.instance.pk or 0
        pairs = [(p, c) for p, c in Edge.objects.filter(workflow=self.workflow).exclude(child_id=me)
                 .values_list("parent_id", "child_id")]
        pairs += [(step.pk, me) for step, field in self.parents if cleaned.get(field)]
        if me and engine.has_cycle(pairs):
            raise forms.ValidationError(_("These arrows would go round in a circle."))
        return cleaned

    def save(self, commit=True):
        step = super().save(commit=False)
        step.workflow = self.workflow
        # Keep only what the kind uses, so a step does not run something it no longer shows.
        if step.kind != Step.PLAYBOOK:
            step.playbook, step.host_group, step.limit, step.extra_vars = None, None, "", {}
        if step.kind != Step.TOFU:
            step.tofu_project = None
        step.save()
        self.save_m2m()
        if step.kind != Step.MESSAGE:
            step.channels.clear()
        Edge.objects.filter(child=step).delete()
        for parent, field in self.parents:
            if self.cleaned_data.get(field):
                Edge.objects.create(workflow=self.workflow, parent=parent, child=step,
                                    condition=self.cleaned_data[field])
        return step
