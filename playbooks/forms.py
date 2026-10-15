# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
import yaml
from django import forms
from django.utils.translation import gettext_lazy as _

from core.forms import TextFileField, VariablesField, style

from . import modules as module_catalog
from . import yaml_io
from .models import Playbook, PlaybookTask


def vault_choices(user, instance):
    """Vault passwords this user may attach, plus those already attached."""
    from access import policy
    from inventory.models import Credential

    choices = policy.for_user(user).credentials(kinds=[Credential.KIND_VAULT])
    if instance.pk:
        choices = choices | instance.vault_credentials.all()
    return choices.distinct()


class PlaybookForm(forms.ModelForm):
    extra_vars = VariablesField(label=_("Play variables"))

    class Meta:
        model = Playbook
        fields = [
            "name",
            "description",
            "mode",
            "project",
            "file_path",
            "vault_credentials",
            "become",
            "gather_facts",
            "serial",
            "any_errors_fatal",
            "extra_vars",
        ]
        widgets = {"description": forms.Textarea(attrs={"rows": 3}),
                   "vault_credentials": forms.CheckboxSelectMultiple}
        help_texts = {"project": _("Roles, templates and files for this playbook, and in file mode the playbook itself.")}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["project"].required = False
        self.fields["vault_credentials"].queryset = vault_choices(user, self.instance)
        style(self)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("mode") == Playbook.MODE_FILE:
            project, path = cleaned.get("project"), (cleaned.get("file_path") or "").strip()
            if not project:
                self.add_error("project", _("A playbook file lives in a project."))
            if not path:
                self.add_error("file_path", _("Which file in the project, e.g. site.yml."))
            elif project and not project.is_git and not project.files.filter(path=path).exists():
                self.add_error("file_path", _('%(name)s has no file %(path)s.') % {"name": project.name, "path": path})
            cleaned["file_path"] = path
        return cleaned


class PlaybookTextForm(forms.ModelForm):
    """Raw YAML editing. The content is parsed so broken plays never save."""

    text_content = TextFileField(
        strip=True,
        widget=forms.Textarea(attrs={"rows": 26, "class": "code editor", "spellcheck": "false"}),
    )

    class Meta:
        model = Playbook
        fields = ["text_content"]

    def clean_text_content(self):
        text = self.cleaned_data["text_content"]
        if text.strip():
            try:
                # Any number of plays; only the graphical editor needs just one.
                yaml_io.validate_playbook(text)
            except yaml_io.ConversionError as exc:
                raise forms.ValidationError(str(exc)) from exc
        return text


class TaskForm(forms.ModelForm):
    """Task editor: fixed task options plus the selected module's arguments.

    Module arguments are built at runtime from :func:`modules.resolve` and
    namespaced with ``arg__`` so they cannot collide with the model's own
    fields.  Arguments no field covers live in ``extra_args``, so a task
    imported from YAML survives an edit with nothing dropped.
    """

    module = forms.CharField(widget=forms.HiddenInput)
    extra_args = VariablesField(
        label=_("Other arguments"),
        help_text=_("Arguments without a field above, as YAML. Kept exactly as written."),
    )

    class Meta:
        model = PlaybookTask
        fields = [
            "name",
            "module",
            "when",
            "loop",
            "tags",
            "become",
            "ignore_errors",
            "register",
            "enabled",
        ]
        widgets = {
            "loop": forms.Textarea(attrs={"rows": 3, "class": "code", "spellcheck": "false"}),
            "when": forms.TextInput(attrs={"placeholder": _("ansible_os_family == 'Debian'")}),
        }

    def __init__(self, *args, module_name=None, **kwargs):
        super().__init__(*args, **kwargs)
        submitted = self.data.get("module", "").strip() if self.is_bound else ""
        self.module_name = module_name or submitted or self.instance.module
        self.fields["module"].initial = self.module_name
        self.fields["name"].widget.attrs["placeholder"] = _("Describe what this task does")
        self.spec = module_catalog.resolve(self.module_name)
        self.featured_names, self.more_names = [], []
        self.more_open = False
        self._build_arg_fields(self.spec, dict(self.instance.args or {}))
        style(self)

    def _build_arg_fields(self, spec, values):
        featured = set(spec.get("featured", []))
        for field in spec["fields"]:
            key = f"arg__{field['name']}"
            given = _take(values, field)
            if given is not _MISSING:
                initial = given
            elif field.get("prefill") or field["type"] == "bool":
                initial = field.get("default")
            else:
                initial = None
            self.fields[key] = self._make_field(field, initial)
            if field["name"] in featured:
                self.featured_names.append(key)
            else:
                self.more_names.append(key)
                # Unfold "all options" when one of them is actually set.
                self.more_open |= given is not _MISSING
        # Whatever is left matched no field.
        self.fields["extra_args"].initial = values

    @staticmethod
    def _make_field(field, initial):
        common = {
            "label": field["label"],
            "required": False,  # required args are checked in clean() for better messages
            "initial": initial,
            "help_text": field.get("help", ""),
        }
        ftype = field["type"]
        code = {"class": "code", "spellcheck": "false"}
        made = TaskForm._make_widget_field(field, ftype, code, common, initial)
        if field.get("description") and field["description"] != field.get("help"):
            made.widget.attrs["title"] = field["description"]
        return made

    @staticmethod
    def _make_widget_field(field, ftype, code, common, initial):
        if ftype == "bool":
            return forms.BooleanField(**common)
        if ftype == "int":
            return forms.IntegerField(**common)
        if ftype == "choice":
            choices = [(c, c or "(default)") for c in field["choices"]]
            if "" not in field["choices"] and not field.get("prefill"):
                choices.insert(0, ("", "(not set)"))
            return forms.ChoiceField(choices=choices, **common)
        if ftype == "textarea":
            # File content, a script: kept as typed, final line break included.
            return TextFileField(widget=forms.Textarea(attrs={"rows": 4, **code}), **common)
        if ftype == "keyvalue":
            return VariablesField(**common)
        if ftype == "list":
            if isinstance(initial, list):
                common["initial"] = "\n".join(str(item) for item in initial)
            common["help_text"] = f"{common['help_text']} One per line.".strip()
            return forms.CharField(widget=forms.Textarea(attrs={"rows": 3, **code}), **common)
        if ftype == "yaml":
            if initial is not None and not isinstance(initial, str):
                common["initial"] = yaml.safe_dump(
                    initial, sort_keys=False, allow_unicode=True
                ).strip()
            common["help_text"] = f"{common['help_text']} Written as YAML.".strip()
            return forms.CharField(widget=forms.Textarea(attrs={"rows": 3, **code}), **common)
        return forms.CharField(**common)

    @property
    def arg_fields(self):
        return [self[name] for name in self.featured_names]

    @property
    def more_fields(self):
        return [self[name] for name in self.more_names]

    def clean_module(self):
        name = self.cleaned_data["module"].strip()
        canonical = module_catalog.canonical_name(name)
        if canonical is None:
            raise forms.ValidationError(_("Unknown module '%(name)s'.") % {"name": name})
        return canonical

    def clean(self):
        cleaned = super().clean()
        args = {}
        for field in self.spec["fields"]:
            key = f"arg__{field['name']}"
            raw = cleaned.get(key)
            value = module_catalog.coerce_value(field, raw)
            if value is None and field["type"] in ("yaml", "keyvalue") and str(raw or "").strip():
                self.add_error(key, _("This is not valid YAML."))
                continue
            if value is None or value == "":
                if field["required"]:
                    self.add_error(key, _("This argument is required."))
                continue
            if field["type"] == "bool" and value == bool(field.get("default")):
                continue
            args[field["name"]] = value

        extra = cleaned.get("extra_args") or {}
        clash = sorted(set(extra) & {f["name"] for f in self.spec["fields"]})
        if clash:
            self.add_error(
                "extra_args", _('Set %(join)s in its own field instead.') % {"join": ', '.join(clash)}
            )
        args.update({k: v for k, v in extra.items() if k not in args})
        cleaned["_args"] = args

        loop = cleaned.get("loop", "")
        if loop.strip():
            try:
                yaml_io.parse_loop(loop)
            except Exception as exc:  # noqa: BLE001
                self.add_error("loop", _('Could not parse the loop: %(exc)s') % {"exc": exc})
        return cleaned

    def save(self, commit=True):
        task = super().save(commit=False)
        task.args = self.cleaned_data.get("_args", {})
        if commit:
            task.save()
        return task


_MISSING = object()


def _take(values: dict, field: dict):
    """Pop a field's value out of the task args, under its name or an alias."""
    for key in (field["name"], *field.get("aliases", [])):
        if key in values:
            return values.pop(key)
    return _MISSING


class ImportYamlForm(forms.Form):
    """Paste YAML and turn it into graphical tasks."""

    text_content = forms.CharField(
        label=_("Playbook YAML"),
        widget=forms.Textarea(attrs={"rows": 20, "class": "code editor", "spellcheck": "false"}),
    )
    replace = forms.BooleanField(
        label=_("Replace existing tasks"), required=False, initial=True
    )

    def clean_text_content(self):
        text = self.cleaned_data["text_content"]
        try:
            self.imported = yaml_io.import_yaml(text)
        except yaml_io.ConversionError as exc:
            raise forms.ValidationError(str(exc)) from exc
        return text
