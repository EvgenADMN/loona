# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""What the API returns. Writes go through the UI's own forms (see views)."""
from django.urls import reverse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from infra.models import TofuProject
from inventory.models import Host, HostFacts, HostGroup
from playbooks import yaml_io
from playbooks.models import Playbook
from access.models import MaintenanceWindow
from runs.models import DriftCheck, Job, JobEvent, LaunchTemplate, Schedule
from secretstore.models import Secret


class HostFactsSummarySerializer(serializers.ModelSerializer):
    addresses = serializers.ListField(source="address_list", child=serializers.CharField(), read_only=True)

    class Meta:
        model = HostFacts
        fields = ["gathered_at", "job", "os", "os_family", "kernel", "architecture", "cpu_count",
                  "cpu_model", "memory_mb", "fqdn", "default_ipv4", "addresses", "virtualization"]


class HostFactsSerializer(HostFactsSummarySerializer):
    class Meta(HostFactsSummarySerializer.Meta):
        fields = HostFactsSummarySerializer.Meta.fields + ["facts"]


class HostSerializer(serializers.ModelSerializer):
    groups = serializers.SlugRelatedField(many=True, read_only=True, slug_field="name")
    credential = serializers.SlugRelatedField(read_only=True, slug_field="name")
    ssh_host_keys = serializers.ListField(source="host_key_fingerprints", read_only=True)
    facts = HostFactsSummarySerializer(read_only=True, allow_null=True,
                                       help_text="The latest facts in short; null until a run gathers them.")

    class Meta:
        model = Host
        fields = ["id", "name", "address", "port", "enabled", "description", "variables",
                  "groups", "credential", "tofu_project", "ssh_host_keys", "facts", "created_at", "updated_at"]


class MaintenanceWindowSerializer(serializers.ModelSerializer):
    class Meta:
        model = MaintenanceWindow
        fields = ["weekdays", "start", "end", "timezone", "description"]


class HostGroupSerializer(serializers.ModelSerializer):
    parents = serializers.SlugRelatedField(many=True, read_only=True, slug_field="name")
    hosts = serializers.SlugRelatedField(many=True, read_only=True, slug_field="name")
    maintenance_windows = MaintenanceWindowSerializer(many=True, read_only=True)

    class Meta:
        model = HostGroup
        fields = ["id", "name", "description", "parents", "variables", "approval_policy",
                  "maintenance_windows", "hosts"]


class PlaybookSerializer(serializers.ModelSerializer):
    yaml = serializers.SerializerMethodField()

    class Meta:
        model = Playbook
        fields = ["id", "name", "description", "mode", "yaml", "updated_at"]

    def get_yaml(self, playbook) -> str:
        try:
            return yaml_io.playbook_yaml(playbook)
        except Exception:  # noqa: BLE001 - a broken playbook still lists
            return ""


class JobSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source="playbook_name")
    created_by = serializers.StringRelatedField()
    is_plan = serializers.BooleanField(read_only=True)
    can_be_applied = serializers.BooleanField(read_only=True)
    hosts = serializers.ListField(source="resolved_hosts", read_only=True)
    host_stats = serializers.ListField(read_only=True)
    opentofu = serializers.SerializerMethodField()
    approval = serializers.SerializerMethodField()
    applied_as = serializers.SerializerMethodField()
    web_url = serializers.SerializerMethodField()

    class Meta:
        model = Job
        fields = ["id", "name", "kind", "status", "is_plan", "can_be_applied", "check_mode",
                  "plan", "applied_as", "approval", "created_by", "created_at", "started_at",
                  "finished_at", "hosts", "host_stats", "opentofu", "error_message",
                  "tofu_project", "drift_check", "schedule", "launch_template", "secret_names",
                  "adhoc_module", "adhoc_args", "adhoc_become", "web_url"]

    @extend_schema_field(OpenApiTypes.OBJECT)
    def get_opentofu(self, job):
        return (job.stats or {}).get("tofu")

    @extend_schema_field(OpenApiTypes.OBJECT)
    def get_approval(self, job):
        approval = getattr(job, "approval", None)
        if approval is None:
            return None
        return {"decision": approval.decision, "by": str(approval.decided_by or ""),
                "comment": approval.comment, "at": approval.decided_at}

    @extend_schema_field(OpenApiTypes.INT)
    def get_applied_as(self, job):
        applied = job.applications.first()
        return applied.pk if applied else None

    def get_web_url(self, job) -> str:
        return reverse("job_detail", args=[job.pk])


class JobEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobEvent
        fields = ["id", "counter", "event", "host", "task", "stdout", "failed", "changed", "created_at"]


class TofuProjectSerializer(serializers.ModelSerializer):
    host_group = serializers.SlugRelatedField(read_only=True, slug_field="name")
    resources = serializers.ListField(source="managed_resources", read_only=True)

    class Meta:
        model = TofuProject
        fields = ["id", "name", "description", "host_group", "source", "git_url", "git_ref",
                  "git_path", "resources"]


class DriftCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = DriftCheck
        fields = ["id", "name", "playbook", "host_group", "tofu_project", "interval_minutes",
                  "enabled", "status", "status_since", "drifted", "last_job", "last_run_at"]


# -- input ---------------------------------------------------------------------

NameOrId = serializers.CharField


class LaunchSerializer(serializers.Serializer):
    groups = serializers.ListField(child=NameOrId(), required=False, default=list)
    hosts = serializers.ListField(child=NameOrId(), required=False, default=list)
    limit = serializers.CharField(required=False, allow_blank=True, default="")
    extra_vars = serializers.DictField(required=False, default=dict)
    tags = serializers.CharField(required=False, allow_blank=True, default="")
    skip_tags = serializers.CharField(required=False, allow_blank=True, default="")
    forks = serializers.IntegerField(required=False, default=5, min_value=1, max_value=200)
    verbosity = serializers.IntegerField(required=False, default=0, min_value=0, max_value=4)
    diff = serializers.BooleanField(required=False, default=False)
    preview = serializers.BooleanField(
        required=False, default=True,
        help_text="true: a check-mode preview to apply later. false: run now "
                  "(refused where every change needs approval).",
    )


class WorkflowStepSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    kind = serializers.CharField()
    target = serializers.CharField()
    after = serializers.SerializerMethodField()

    @extend_schema_field(OpenApiTypes.OBJECT)
    def get_after(self, step):
        return [{"step": e.parent.name, "when": e.condition} for e in step.in_edges.select_related("parent")]


class WorkflowSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    description = serializers.CharField()
    host_group = serializers.CharField(source="host_group.name")
    steps = WorkflowStepSerializer(many=True)


class WorkflowNodeSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    step = serializers.CharField(source="step.name")
    kind = serializers.CharField(source="step.kind")
    status = serializers.CharField()
    job = serializers.PrimaryKeyRelatedField(read_only=True)
    note = serializers.CharField()


class WorkflowRunSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    workflow = serializers.CharField(source="workflow.name")
    status = serializers.CharField()
    created_by = serializers.StringRelatedField()
    created_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField()
    nodes = WorkflowNodeSerializer(many=True)
    web_url = serializers.SerializerMethodField()

    def get_web_url(self, run) -> str:
        return run.get_absolute_url()


class WorkflowStartSerializer(serializers.Serializer):
    extra_vars = serializers.DictField(required=False, default=dict)


class NodeDecisionSerializer(serializers.Serializer):
    node = serializers.IntegerField(help_text="The id of the waiting approval step's node.")
    approve = serializers.BooleanField()
    comment = serializers.CharField(required=False, allow_blank=True, default="")


class CatalogItemSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    name = serializers.CharField()
    description = serializers.CharField()
    fields = serializers.ListField(child=serializers.DictField(),
                                   help_text="What to answer besides name; survey questions.")
    approval_required = serializers.BooleanField()
    max_per_user = serializers.IntegerField()


class CatalogRequestSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    item = serializers.CharField(source="item.name")
    name = serializers.CharField()
    values = serializers.DictField()
    status = serializers.CharField()
    retiring = serializers.BooleanField()
    stage = serializers.CharField()
    error = serializers.CharField()
    requested_by = serializers.StringRelatedField()
    job = serializers.PrimaryKeyRelatedField(read_only=True)
    host = serializers.PrimaryKeyRelatedField(read_only=True)
    address = serializers.CharField()
    created_at = serializers.DateTimeField()


class CatalogOrderSerializer(serializers.Serializer):
    name = serializers.CharField(help_text="The machine's host name.")
    values = serializers.DictField(required=False, default=dict,
                                   help_text="Answers, keyed by the item's field variables.")


class AdhocSerializer(serializers.Serializer):
    module = serializers.CharField(help_text="An allowed module: shell, command, service, ...")
    args = serializers.CharField(required=False, allow_blank=True, default="",
                                 help_text="The command line, or key=value pairs.")
    become = serializers.BooleanField(required=False, default=False)
    groups = serializers.ListField(child=NameOrId(), required=False, default=list)
    hosts = serializers.ListField(child=NameOrId(), required=False, default=list)
    limit = serializers.CharField(required=False, allow_blank=True, default="")
    forks = serializers.IntegerField(required=False, default=5, min_value=1, max_value=200)
    verbosity = serializers.IntegerField(required=False, default=0, min_value=0, max_value=4)
    diff = serializers.BooleanField(required=False, default=False)
    preview = serializers.BooleanField(
        required=False, default=False,
        help_text="true: a check-mode preview to apply later. false (default): run now "
                  "(refused where every change needs approval).",
    )


class HostWriteSerializer(serializers.Serializer):
    name = serializers.CharField(required=False)
    address = serializers.CharField(required=False, allow_blank=True)
    port = serializers.IntegerField(required=False)
    credential = NameOrId(required=False, allow_blank=True, allow_null=True)
    groups = serializers.ListField(child=NameOrId(), required=False)
    enabled = serializers.BooleanField(required=False)
    description = serializers.CharField(required=False, allow_blank=True)
    variables = serializers.DictField(required=False)


class CommentSerializer(serializers.Serializer):
    comment = serializers.CharField(required=False, allow_blank=True, default="")


class PlanRequestSerializer(serializers.Serializer):
    destroy = serializers.BooleanField(required=False, default=False)


class SecretSerializer(serializers.ModelSerializer):
    """A secret's name and where it applies. The value is write-only, here as everywhere."""

    scope = serializers.CharField(read_only=True)
    group = serializers.SlugRelatedField(source="host_group", read_only=True, slug_field="name")
    project = serializers.SlugRelatedField(read_only=True, slug_field="name")

    class Meta:
        model = Secret
        fields = ["id", "name", "description", "scope", "group", "project", "vault_ref", "created_at", "updated_at"]


class SecretWriteSerializer(serializers.Serializer):
    name = serializers.CharField(required=False)
    description = serializers.CharField(required=False, allow_blank=True)
    scope = serializers.ChoiceField(choices=[c[0] for c in Secret.SCOPES], required=False)
    group = serializers.CharField(required=False, help_text="Host group id or name, for scope=group.")
    project = serializers.CharField(required=False, help_text="Ansible project id or name, for scope=project.")
    value = serializers.CharField(required=False, trim_whitespace=False, write_only=True,
                                  help_text="Required when creating, unless vault_ref is given; never returned.")
    vault_ref = serializers.CharField(required=False, allow_blank=True,
                                      help_text="path#key in HashiCorp Vault, read at every run instead of a stored value. "
                                                "Send \"\" together with a value to store it in Loona again.")


class ScheduleSerializer(serializers.ModelSerializer):
    playbook = serializers.SlugRelatedField(read_only=True, slug_field="name")
    group = serializers.SlugRelatedField(source="host_group", read_only=True, slug_field="name")
    workflow = serializers.SlugRelatedField(read_only=True, slug_field="name")
    run_as = serializers.SlugRelatedField(read_only=True, slug_field="username")

    class Meta:
        model = Schedule
        fields = ["id", "name", "playbook", "workflow", "group", "action", "cron", "timezone", "limit",
                  "tags", "skip_tags", "extra_vars", "enabled", "run_as", "next_run_at", "last_run_at",
                  "last_job", "last_workflow_run", "last_note"]


class ScheduleWriteSerializer(serializers.Serializer):
    name = serializers.CharField(required=False)
    playbook = serializers.CharField(required=False, help_text="Playbook id or name.")
    group = serializers.CharField(required=False, help_text="Host group id or name.")
    workflow = serializers.CharField(required=False, help_text="Workflow id or name, instead of playbook and group.")
    action = serializers.ChoiceField(choices=[c[0] for c in Schedule.ACTIONS], required=False)
    cron = serializers.CharField(required=False, help_text="e.g. 0 3 * * mon-fri, or @daily.")
    timezone = serializers.CharField(required=False)
    limit = serializers.CharField(required=False, allow_blank=True)
    tags = serializers.CharField(required=False, allow_blank=True)
    skip_tags = serializers.CharField(required=False, allow_blank=True)
    extra_vars = serializers.DictField(required=False)
    enabled = serializers.BooleanField(required=False)


class LaunchTemplateSerializer(serializers.ModelSerializer):
    playbook = serializers.SlugRelatedField(read_only=True, slug_field="name")
    group = serializers.SlugRelatedField(source="host_group", read_only=True, slug_field="name")

    class Meta:
        model = LaunchTemplate
        fields = ["id", "name", "description", "playbook", "group", "limit", "ask_limit", "tags",
                  "skip_tags", "extra_vars", "survey", "updated_at"]


class TemplateLaunchSerializer(serializers.Serializer):
    answers = serializers.DictField(required=False, default=dict,
                                    help_text="Survey answers by variable name.")
    limit = serializers.CharField(required=False, allow_blank=True, default="",
                                  help_text="Only if the template lets the launcher narrow the hosts.")
    preview = serializers.BooleanField(required=False, default=True,
                                       help_text="True (default): a preview to apply later. False: run now.")
