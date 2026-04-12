from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from rest_framework import serializers

from accounts.serializers import UserSerializer
from integrations.models import IntegrationDefinition, IntegrationSecretRef
from incidents.models import (
    Artifact,
    CommunicationLog,
    Incident,
    IncidentRelation,
    IncidentTask,
    TimelineEntry,
)
from incidents.services import (
    add_artifact_link,
    create_task,
    SENTINEL,
    update_artifact,
    update_artifact_attributes,
)
from playbooks.dsl import ParseError, parse_playbook
from playbooks.models import Execution, ExecutionLog, ExecutionStepResult, Playbook
from playbooks.services import get_manual_playbooks_for_incident
from playbooks.validation import validate_playbook_semantics

User = get_user_model()


def _build_model_validation_instance(serializer: serializers.ModelSerializer, attrs: dict):
    model_class = serializer.Meta.model
    instance = model_class()

    if serializer.instance is not None:
        instance.pk = serializer.instance.pk
        instance._state.adding = False
        for field in serializer.instance._meta.concrete_fields:
            if field.primary_key:
                continue
            setattr(instance, field.name, getattr(serializer.instance, field.name))

    for field_name, value in attrs.items():
        setattr(instance, field_name, value)

    return instance


class ModelFullCleanValidationMixin:
    def validate(self, attrs):
        attrs = super().validate(attrs)
        instance = _build_model_validation_instance(self, attrs)
        try:
            instance.full_clean()
        except DjangoValidationError as exc:
            if hasattr(exc, "message_dict"):
                raise serializers.ValidationError(exc.message_dict) from exc
            raise serializers.ValidationError(exc.messages) from exc
        return attrs


class HttpConnectorSecretSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    rotated_by = UserSerializer(read_only=True)
    has_credential = serializers.BooleanField(read_only=True)
    token_value = serializers.CharField(write_only=True, required=False, allow_blank=False, trim_whitespace=False)
    basic_auth_username = serializers.CharField(write_only=True, required=False, allow_blank=False)
    basic_auth_password = serializers.CharField(write_only=True, required=False, allow_blank=False, trim_whitespace=False)

    class Meta:
        model = IntegrationSecretRef
        fields = [
            "id",
            "name",
            "description",
            "enabled",
            "credential_kind",
            "has_credential",
            "token_value",
            "basic_auth_username",
            "basic_auth_password",
            "created_by",
            "rotated_by",
            "rotated_at",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "has_credential",
            "created_by",
            "rotated_by",
            "rotated_at",
            "created_at",
            "updated_at",
        ]

    def validate(self, attrs):
        attrs = serializers.ModelSerializer.validate(self, attrs)
        kind = attrs.get("credential_kind") or getattr(self.instance, "credential_kind", IntegrationSecretRef.CredentialKind.TOKEN)
        token_value = attrs.get("token_value")
        basic_username = attrs.get("basic_auth_username")
        basic_password = attrs.get("basic_auth_password")
        instance = _build_model_validation_instance(self, attrs)
        previous_kind = self.instance.credential_kind if self.instance is not None else None
        instance.credential_kind = kind
        if kind == IntegrationSecretRef.CredentialKind.TOKEN:
            if token_value:
                instance.set_token_credential(token_value)
            elif self.instance is not None and previous_kind == kind:
                instance.credential_payload_encrypted = self.instance.credential_payload_encrypted
            else:
                instance.credential_payload_encrypted = ""
        elif kind == IntegrationSecretRef.CredentialKind.BASIC_AUTH:
            current_username = ""
            if self.instance is not None and self.instance.has_credential:
                current_username = self.instance.get_credential().get("username", "")
            if basic_password:
                instance.set_basic_auth_credential(basic_username or current_username, basic_password)
            elif self.instance is not None and previous_kind == kind:
                instance.credential_payload_encrypted = self.instance.credential_payload_encrypted
            else:
                instance.credential_payload_encrypted = ""
        try:
            instance.full_clean()
        except DjangoValidationError as exc:
            if hasattr(exc, "message_dict"):
                raise serializers.ValidationError(exc.message_dict) from exc
            raise serializers.ValidationError(exc.messages) from exc
        return attrs

    def create(self, validated_data):
        token_value = validated_data.pop("token_value", "")
        basic_username = validated_data.pop("basic_auth_username", "")
        basic_password = validated_data.pop("basic_auth_password", "")
        request = self.context.get("request")
        actor = getattr(request, "user", None) if request else None
        instance = IntegrationSecretRef(**validated_data)
        if actor and actor.is_authenticated:
            instance.created_by = actor
        if instance.credential_kind == IntegrationSecretRef.CredentialKind.TOKEN:
            instance.set_token_credential(token_value)
        else:
            instance.set_basic_auth_credential(basic_username, basic_password)
        if actor and actor.is_authenticated:
            instance.rotated_by = actor
        instance.rotated_at = timezone.now()
        instance.save()
        return instance

    def update(self, instance, validated_data):
        token_value = validated_data.pop("token_value", None)
        basic_username = validated_data.pop("basic_auth_username", None)
        basic_password = validated_data.pop("basic_auth_password", None)
        for field, value in validated_data.items():
            setattr(instance, field, value)
        request = self.context.get("request")
        actor = getattr(request, "user", None) if request else None
        if instance.credential_kind == IntegrationSecretRef.CredentialKind.TOKEN and token_value:
            instance.set_token_credential(token_value)
            if actor and actor.is_authenticated:
                instance.rotated_by = actor
            instance.rotated_at = timezone.now()
        elif instance.credential_kind == IntegrationSecretRef.CredentialKind.BASIC_AUTH and basic_password:
            current_username = instance.get_credential().get("username", "") if instance.has_credential else ""
            instance.set_basic_auth_credential(basic_username or current_username, basic_password)
            if actor and actor.is_authenticated:
                instance.rotated_by = actor
            instance.rotated_at = timezone.now()
        instance.save()
        return instance


class HttpConnectorSerializer(ModelFullCleanValidationMixin, serializers.ModelSerializer):
    secret_ref = serializers.PrimaryKeyRelatedField(
        queryset=IntegrationSecretRef.objects.all(),
        required=True,
    )

    class Meta:
        model = IntegrationDefinition
        fields = [
            "id",
            "name",
            "description",
            "action_name",
            "enabled",
            "method",
            "secret_ref",
            "auth_strategy",
            "auth_header_name",
            "auth_prefix",
            "auth_query_param",
            "request_template",
            "output_template",
            "expected_params",
            "timeout_seconds",
            "revision",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate(self, attrs):
        attrs = super().validate(attrs)
        instance = _build_model_validation_instance(self, attrs)
        instance.full_clean()
        attrs["expected_params"] = list(instance.expected_params or [])
        return attrs


class HttpConnectorValidateSerializer(HttpConnectorSerializer):
    pass


class ArtifactSerializer(serializers.ModelSerializer):
    incidents = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    incident_id = serializers.IntegerField(write_only=True, required=False)
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = Artifact
        fields = [
            "id",
            "incident_id",
            "type",
            "value",
            "file_url",
            "size",
            "sha256",
            "content_type",
            "attributes",
            "created_at",
            "incidents",
        ]
        read_only_fields = [
            "id",
            "file_url",
            "size",
            "sha256",
            "content_type",
            "created_at",
            "incidents",
        ]

    def get_file_url(self, obj: Artifact):
        if not obj.file:
            return None
        request = self.context.get("request")
        if request:
            return request.build_absolute_uri(obj.file.url)
        return obj.file.url

    def create(self, validated_data):
        incident_id = validated_data.pop("incident_id", None)
        if incident_id is None:
            raise serializers.ValidationError({"incident_id": "Informe o incidente associado"})
        value = (validated_data.get("value") or "").strip()
        if not value:
            raise serializers.ValidationError({"value": "Valor do artefato obrigatorio"})
        type_code = validated_data.get("type") or Artifact.Type.OTHER
        request = self.context.get("request")
        actor = getattr(request, "user", None) if request else None
        incident = Incident.objects.get(pk=incident_id)
        artifact = add_artifact_link(
            incident=incident,
            value=value,
            type_code=type_code,
            actor=actor,
        )
        attributes = validated_data.get("attributes")
        if attributes:
            update_artifact_attributes(
                artifact=artifact,
                incident=incident,
                attributes=attributes,
                merge=True,
                actor=actor,
            )
        return artifact

    def update(self, instance: Artifact, validated_data):
        request = self.context.get("request")
        actor = getattr(request, "user", None) if request else None
        incident_id = validated_data.pop("incident_id", None)
        incident = None
        if incident_id is not None:
            incident = Incident.objects.get(pk=incident_id)
            if not instance.value:
                raise serializers.ValidationError(
                    {"incident_id": "Associação via API não disponível para artefatos de arquivo"}
                )
            add_artifact_link(incident=incident, value=instance.value, type_code=instance.type, actor=actor)
        type_code = validated_data.pop("type", None)
        value = validated_data.pop("value", SENTINEL)
        if type_code is not None or value is not SENTINEL:
            update_artifact(
                artifact=instance,
                incident=incident or instance.primary_incident(),
                type_code=type_code,
                value=value,
                actor=actor,
            )
        if "attributes" in validated_data:
            update_artifact_attributes(
                artifact=instance,
                incident=incident or instance.primary_incident(),
                attributes=validated_data["attributes"],
                merge=True,
                actor=actor,
            )
        instance.refresh_from_db()
        return instance


class TimelineEntrySerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)

    class Meta:
        model = TimelineEntry
        fields = ["id", "entry_type", "message", "created_by", "created_at", "meta"]


class IncidentTaskSerializer(serializers.ModelSerializer):
    owner = UserSerializer(read_only=True)
    created_by = UserSerializer(read_only=True)

    class Meta:
        model = IncidentTask
        fields = ["id", "title", "owner", "eta", "done", "created_by", "created_at", "updated_at"]


class IncidentTaskWriteSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=255)
    owner_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), allow_null=True, required=False
    )
    eta = serializers.DateTimeField(required=False, allow_null=True)


class IncidentTaskUpdateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=255, required=False)
    owner_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), allow_null=True, required=False
    )
    eta = serializers.DateTimeField(required=False, allow_null=True)
    done = serializers.BooleanField(required=False)


class CommunicationLogSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    recipient_user = UserSerializer(read_only=True)

    class Meta:
        model = CommunicationLog
        fields = [
            "id",
            "incident",
            "channel",
            "recipient_team",
            "recipient_user",
            "message",
            "created_by",
            "created_at",
        ]
        read_only_fields = ["id", "incident", "created_by", "created_at", "recipient_user"]


class CommunicationCreateSerializer(serializers.Serializer):
    channel = serializers.CharField(max_length=32, required=False, default="internal")
    recipient_team = serializers.CharField(max_length=128, required=False, allow_blank=True)
    recipient_user_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), allow_null=True, required=False
    )
    message = serializers.CharField()


class IncidentRelationSerializer(serializers.ModelSerializer):
    to_incident_title = serializers.CharField(source="to_incident.title", read_only=True)

    class Meta:
        model = IncidentRelation
        fields = ["id", "relation_type", "to_incident", "to_incident_title", "created_by", "created_at"]
        read_only_fields = ["id", "created_by", "created_at", "to_incident_title"]


class IncidentRelationCreateSerializer(serializers.Serializer):
    to_incident_id = serializers.PrimaryKeyRelatedField(queryset=Incident.objects.all())
    relation_type = serializers.ChoiceField(choices=IncidentRelation.RelationType.choices)


class IncidentArtifactUploadSerializer(serializers.Serializer):
    file = serializers.FileField()


class IncidentArtifactLinkSerializer(serializers.Serializer):
    value = serializers.CharField()
    type = serializers.ChoiceField(
        choices=Artifact.Type.choices, required=False, default=Artifact.Type.URL
    )


class TimelineEntryCreateSerializer(serializers.Serializer):
    entry_type = serializers.ChoiceField(
        choices=TimelineEntry.EntryType.choices,
        required=False,
        default=TimelineEntry.EntryType.NOTE,
    )
    message = serializers.CharField()
    meta = serializers.DictField(required=False)


class IncidentSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    assignee = UserSerializer(read_only=True)
    artifacts = ArtifactSerializer(many=True, read_only=True)
    tasks = IncidentTaskSerializer(many=True, read_only=True)
    communications = CommunicationLogSerializer(many=True, read_only=True)
    relations = IncidentRelationSerializer(source="relations_from", many=True, read_only=True)
    timeline = TimelineEntrySerializer(many=True, read_only=True)

    class Meta:
        model = Incident
        fields = [
            "id",
            "title",
            "description",
            "severity",
            "status",
            "risk_score",
            "labels",
            "mitre_tactics",
            "mitre_techniques",
            "kill_chain_phase",
            "impact_systems",
            "estimated_cost",
            "business_unit",
            "data_classification",
            "escalation_level",
            "escalation_targets",
            "occurred_at",
            "detected_at",
            "responded_at",
            "resolved_at",
            "closed_at",
            "created_by",
            "assignee",
            "created_at",
            "updated_at",
            "artifacts",
            "tasks",
            "communications",
            "relations",
            "timeline",
        ]


class IncidentWriteSerializer(serializers.ModelSerializer):
    assignee = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), allow_null=True, required=False
    )
    artifacts = IncidentArtifactLinkSerializer(many=True, required=False, write_only=True)
    timeline_entries = TimelineEntryCreateSerializer(many=True, required=False, write_only=True)
    tasks = IncidentTaskWriteSerializer(many=True, required=False, write_only=True)

    class Meta:
        model = Incident
        fields = [
            "title",
            "description",
            "severity",
            "status",
            "labels",
            "assignee",
            "mitre_tactics",
            "mitre_techniques",
            "kill_chain_phase",
            "impact_systems",
            "risk_score",
            "estimated_cost",
            "business_unit",
            "data_classification",
            "escalation_level",
            "escalation_targets",
            "occurred_at",
            "detected_at",
            "responded_at",
            "resolved_at",
            "closed_at",
            "artifacts",
            "timeline_entries",
            "tasks",
        ]

    def _get_actor(self):
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            return request.user
        return None

    def create(self, validated_data):
        artifacts_data = validated_data.pop("artifacts", [])
        timeline_data = validated_data.pop("timeline_entries", [])
        tasks_data = validated_data.pop("tasks", [])
        incident = Incident.objects.create(**validated_data)
        actor = self._get_actor()
        for artifact in artifacts_data:
            add_artifact_link(
                incident=incident,
                value=artifact["value"],
                type_code=artifact.get("type", Artifact.Type.OTHER),
                actor=actor,
            )
        for entry in timeline_data:
            incident.log_timeline(
                entry_type=entry.get("entry_type", TimelineEntry.EntryType.NOTE),
                message=entry["message"],
                actor=actor,
                extra=entry.get("meta") or {},
            )
        for task in tasks_data:
            owner = task.get("owner_id")
            create_task(
                incident=incident,
                title=task["title"],
                owner=owner,
                eta=task.get("eta"),
                actor=actor,
            )
        return incident

    def update(self, instance, validated_data):
        validated_data.pop("artifacts", None)
        validated_data.pop("timeline_entries", None)
        validated_data.pop("tasks", None)
        return super().update(instance, validated_data)


class IncidentStatusSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Incident.Status.choices)
    reason = serializers.CharField(required=False, allow_blank=True)


class IncidentAssigneeSerializer(serializers.Serializer):
    assignee_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(), allow_null=True, required=False
    )


class IncidentLabelsSerializer(serializers.Serializer):
    add = serializers.ListField(
        child=serializers.CharField(max_length=64), required=False, allow_empty=True
    )
    remove = serializers.ListField(
        child=serializers.CharField(max_length=64), required=False, allow_empty=True
    )


class IncidentMitreSerializer(serializers.Serializer):
    tactics = serializers.ListField(
        child=serializers.CharField(max_length=64), required=False, allow_empty=True
    )
    techniques = serializers.ListField(
        child=serializers.CharField(max_length=64), required=False, allow_empty=True
    )
    kill_chain_phase = serializers.CharField(required=False, allow_blank=True)


class IncidentImpactSerializer(serializers.Serializer):
    impact_systems = serializers.ListField(
        child=serializers.CharField(max_length=128), required=False, allow_empty=True
    )
    risk_score = serializers.IntegerField(min_value=0, max_value=100, required=False)
    severity = serializers.ChoiceField(
        choices=Incident.Severity.choices, required=False, allow_null=True
    )
    estimated_cost = serializers.DecimalField(
        max_digits=12, decimal_places=2, required=False, allow_null=True
    )
    business_unit = serializers.CharField(max_length=128, required=False, allow_blank=True)
    data_classification = serializers.ChoiceField(
        choices=Incident.DataClassification.choices, required=False
    )


class IncidentEscalationSerializer(serializers.Serializer):
    level = serializers.CharField(max_length=32, required=False, allow_blank=True)
    targets = serializers.ListField(
        child=serializers.CharField(max_length=128), allow_empty=True, required=False
    )


class TimelineQuerySerializer(serializers.Serializer):
    type = serializers.CharField(required=False)
    limit = serializers.IntegerField(required=False, min_value=1, max_value=500)
    after = serializers.DateTimeField(required=False)


class TimelineExportSerializer(serializers.Serializer):
    format = serializers.ChoiceField(choices=[("csv", "csv"), ("pdf", "pdf")])


class ExecutionLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExecutionLog
        fields = ["id", "ts", "level", "message", "step_name"]


class ExecutionStepResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExecutionStepResult
        fields = [
            "id",
            "step_name",
            "step_order",
            "status",
            "started_at",
            "finished_at",
            "duration_ms",
            "resolved_input",
            "result",
            "error_class",
            "error_message",
            "skipped_reason",
        ]


class ExecutionSerializer(serializers.ModelSerializer):
    playbook = serializers.PrimaryKeyRelatedField(read_only=True)
    incident = serializers.PrimaryKeyRelatedField(read_only=True)
    created_by = UserSerializer(read_only=True)
    step_results = ExecutionStepResultSerializer(many=True, read_only=True)

    class Meta:
        model = Execution
        fields = [
            "id",
            "playbook",
            "incident",
            "status",
            "started_at",
            "finished_at",
            "created_by",
            "step_results",
        ]
        read_only_fields = [
            "id",
            "started_at",
            "finished_at",
            "status",
            "playbook",
            "incident",
            "created_by",
            "step_results",
        ]


class PlaybookSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    updated_by = UserSerializer(read_only=True)
    triggers = serializers.SerializerMethodField()
    filters = serializers.SerializerMethodField()

    class Meta:
        model = Playbook
        fields = [
            "id",
            "name",
            "category",
            "description",
            "enabled",
            "type",
            "mode",
            "dsl",
            "triggers",
            "filters",
            "created_by",
            "updated_by",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_by", "updated_by", "created_at", "updated_at", "type", "mode", "triggers", "filters"]

    def get_triggers(self, obj):
        return obj.triggers

    def get_filters(self, obj):
        return obj.filters

    def validate_dsl(self, value):
        try:
            parsed = parse_playbook(value)
            validate_playbook_semantics(value, parsed_playbook=parsed)
        except ParseError as exc:
            raise serializers.ValidationError(str(exc))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return value


class PlaybookRunSerializer(serializers.Serializer):
    incident_id = serializers.IntegerField(required=False)


class PlaybookValidateSerializer(serializers.Serializer):
    dsl = serializers.JSONField()

    def validate_dsl(self, value):
        try:
            parsed = parse_playbook(value)
            validate_playbook_semantics(value, parsed_playbook=parsed)
        except ParseError as exc:
            raise serializers.ValidationError(str(exc))
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        return value


class RunPlaybookOnIncidentSerializer(serializers.Serializer):
    playbook_id = serializers.PrimaryKeyRelatedField(
        queryset=Playbook.objects.none(), source="playbook"
    )

    def __init__(self, *args, **kwargs):
        incident = kwargs.get("context", {}).get("incident")
        super().__init__(*args, **kwargs)
        field = self.fields["playbook_id"]
        if incident is None:
            field.queryset = Playbook.objects.none()
            return
        manual_ids = [playbook.id for playbook in get_manual_playbooks_for_incident(incident)]
        if not manual_ids:
            field.queryset = Playbook.objects.none()
            return
        field.queryset = Playbook.objects.filter(id__in=manual_ids)


class IncidentPlaybookOverviewSerializer(serializers.Serializer):
    available = PlaybookSerializer(many=True)
    executions = ExecutionSerializer(many=True)


class IncidentLabelsResponseSerializer(serializers.Serializer):
    labels = serializers.ListField(child=serializers.CharField())


class IncidentImpactResponseSerializer(serializers.Serializer):
    impact_systems = serializers.ListField(child=serializers.CharField(), required=False)
    risk_score = serializers.IntegerField()
    severity = serializers.ChoiceField(choices=Incident.Severity.choices)
    estimated_cost = serializers.DecimalField(max_digits=12, decimal_places=2)
    business_unit = serializers.CharField(allow_blank=True)
    data_classification = serializers.ChoiceField(choices=Incident.DataClassification.choices)


class LabelSuggestionResponseSerializer(serializers.Serializer):
    results = serializers.ListField(child=serializers.CharField(), help_text="Suggested labels")
