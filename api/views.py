from __future__ import annotations

import csv
import io
import json
import time
from typing import Iterator

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.http import HttpResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.utils.dateparse import parse_datetime
from django.utils.timezone import now
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsSOCLeadOrAbove, ReadOnlyOrSOCAnalyst
from accounts.serializers import UserSerializer
from audit.utils import log_action
from integrations.models import IntegrationDefinition, IntegrationSecretRef
from incidents.analytics import lifecycle_metrics_snapshot, serialize_duration
from incidents.models import Artifact, Incident, IncidentRelation, IncidentTask, TimelineEntry
from incidents.services import (
    add_artifact_from_upload,
    add_artifact_link,
    create_communication,
    create_task,
    escalate_incident,
    link_incident,
    unlink_incident,
    update_incident_assignee,
    update_incident_impact,
    update_incident_labels,
    update_incident_mitre,
    update_incident_status,
    update_task,
)
from playbooks.models import Execution, Playbook
from playbooks.services import (
    get_manual_playbooks_for_incident,
    is_manual_playbook_available_for_incident,
    start_playbook_execution,
)

from .filters import IncidentFilter
from .serializers import (
    ArtifactSerializer,
    CommunicationCreateSerializer,
    CommunicationLogSerializer,
    ExecutionSerializer,
    IntegrationDefinitionSerializer,
    IntegrationDefinitionValidateSerializer,
    IntegrationSecretRefSerializer,
    IncidentArtifactLinkSerializer,
    IncidentArtifactUploadSerializer,
    IncidentAssigneeSerializer,
    IncidentEscalationSerializer,
    IncidentImpactSerializer,
    IncidentLabelsSerializer,
    IncidentLabelsResponseSerializer,
    IncidentMitreSerializer,
    IncidentRelationCreateSerializer,
    IncidentRelationSerializer,
    IncidentSerializer,
    IncidentStatusSerializer,
    IncidentTaskSerializer,
    IncidentTaskUpdateSerializer,
    IncidentTaskWriteSerializer,
    IncidentWriteSerializer,
    IncidentImpactResponseSerializer,
    IncidentPlaybookOverviewSerializer,
    LabelSuggestionResponseSerializer,
    PlaybookRunSerializer,
    PlaybookSerializer,
    PlaybookValidateSerializer,
    RunPlaybookOnIncidentSerializer,
    TimelineEntrySerializer,
    TimelineExportSerializer,
    TimelineQuerySerializer,
)

User = get_user_model()


@extend_schema_view(
    list=extend_schema(summary="List integration secret refs", tags=["Integrations"]),
    retrieve=extend_schema(summary="Retrieve integration secret ref", tags=["Integrations"]),
    create=extend_schema(summary="Create integration secret ref", tags=["Integrations"]),
    partial_update=extend_schema(summary="Update integration secret ref", tags=["Integrations"]),
    update=extend_schema(summary="Replace integration secret ref", tags=["Integrations"]),
)
class IntegrationSecretRefViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    queryset = IntegrationSecretRef.objects.all()
    serializer_class = IntegrationSecretRefSerializer

    def get_permissions(self):
        if self.action in {"create", "update", "partial_update"}:
            permission_classes = [IsSOCLeadOrAbove]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]


@extend_schema_view(
    list=extend_schema(summary="List configured integrations", tags=["Integrations"]),
    retrieve=extend_schema(summary="Retrieve configured integration", tags=["Integrations"]),
    create=extend_schema(summary="Create configured integration", tags=["Integrations"]),
    partial_update=extend_schema(summary="Update configured integration", tags=["Integrations"]),
    update=extend_schema(summary="Replace configured integration", tags=["Integrations"]),
)
class IntegrationDefinitionViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.CreateModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    queryset = IntegrationDefinition.objects.select_related("secret_ref").all()
    serializer_class = IntegrationDefinitionSerializer

    def get_permissions(self):
        if self.action in {"create", "update", "partial_update", "validate_definition"}:
            permission_classes = [IsSOCLeadOrAbove]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    @extend_schema(
        summary="Validate a configured integration definition",
        request=IntegrationDefinitionValidateSerializer,
        responses={200: OpenApiResponse(description="Integration definition is valid")},
        tags=["Integrations"],
    )
    @action(detail=False, methods=["post"], url_path="validate", permission_classes=[IsSOCLeadOrAbove])
    def validate_definition(self, request):
        serializer = IntegrationDefinitionValidateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"valid": True})


@extend_schema_view(
    list=extend_schema(summary="List incidents", tags=["Incidents"]),
    retrieve=extend_schema(summary="Retrieve incident", tags=["Incidents"]),
    create=extend_schema(summary="Create incident", tags=["Incidents"]),
    update=extend_schema(summary="Update incident", tags=["Incidents"]),
    partial_update=extend_schema(summary="Partially update incident", tags=["Incidents"]),
    destroy=extend_schema(summary="Delete incident", tags=["Incidents"]),
)
class IncidentViewSet(viewsets.ModelViewSet):
    queryset = (
        Incident.objects.select_related("created_by", "assignee")
        .prefetch_related(
            "artifacts",
            "timeline__created_by",
            "tasks__owner",
            "tasks__created_by",
            "communications__created_by",
            "communications__recipient_user",
            "relations_from__to_incident",
        )
        .all()
    )
    permission_classes = [ReadOnlyOrSOCAnalyst]
    filter_backends = [DjangoFilterBackend]
    filterset_class = IncidentFilter

    def get_serializer_class(self):
        if self.action in {"create", "update", "partial_update"}:
            return IncidentWriteSerializer
        return IncidentSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save()

    @extend_schema(
        summary="Start a playbook execution for this incident",
        request=RunPlaybookOnIncidentSerializer,
        responses={202: ExecutionSerializer},
        tags=["Incidents", "Playbooks"],
    )
    @action(detail=True, methods=["post"], permission_classes=[IsSOCLeadOrAbove])
    def run_playbook(self, request, pk=None):
        incident = self.get_object()
        serializer = RunPlaybookOnIncidentSerializer(
            data=request.data,
            context={"incident": incident},
        )
        serializer.is_valid(raise_exception=True)
        playbook = serializer.validated_data["playbook"]
        if not is_manual_playbook_available_for_incident(playbook, incident):
            raise ValidationError({"detail": "Playbook manual indisponivel para este incidente"})
        try:
            execution = start_playbook_execution(
                playbook,
                incident,
                actor=request.user,
                context={"event": "manual.incident", "source": "api"},
            )
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)})
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.PLAYBOOK_EXECUTION,
            message=f"Playbook '{playbook.name}' iniciado",
            actor=request.user,
            extra={"execution_id": execution.id},
        )
        log_action(
            actor=request.user,
            verb="incident.playbook_started",
            target=incident,
            meta={"execution_id": execution.id, "playbook_id": playbook.id},
        )
        return Response(
            ExecutionSerializer(execution, context=self.get_serializer_context()).data,
            status=status.HTTP_202_ACCEPTED,
        )

    @extend_schema(
        summary="Update the status of an incident",
        request=IncidentStatusSerializer,
        responses={200: IncidentSerializer},
        tags=["Incidents"],
    )
    @action(detail=True, methods=["patch"], url_path="status")
    def set_status(self, request, pk=None):
        incident = self.get_object()
        serializer = IncidentStatusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        update_incident_status(
            incident=incident,
            status=data["status"],
            reason=data.get("reason"),
            actor=request.user,
        )
        return Response(IncidentSerializer(incident, context=self.get_serializer_context()).data)

    @extend_schema(
        summary="Assign or unassign an incident",
        request=IncidentAssigneeSerializer,
        responses={200: IncidentSerializer},
        tags=["Incidents"],
    )
    @action(detail=True, methods=["patch"], url_path="assignee")
    def set_assignee(self, request, pk=None):
        incident = self.get_object()
        serializer = IncidentAssigneeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        assignee = serializer.validated_data.get("assignee_id")
        update_incident_assignee(incident=incident, assignee=assignee, actor=request.user)
        return Response(IncidentSerializer(incident, context=self.get_serializer_context()).data)

    @extend_schema(
        summary="Add or remove labels from an incident",
        request=IncidentLabelsSerializer,
        responses={200: IncidentLabelsResponseSerializer},
        tags=["Incidents"],
    )
    @action(detail=True, methods=["patch"], url_path="labels")
    def update_labels(self, request, pk=None):
        incident = self.get_object()
        serializer = IncidentLabelsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        update_incident_labels(
            incident=incident,
            add=data.get("add"),
            remove=data.get("remove"),
            actor=request.user,
        )
        response_data = IncidentLabelsResponseSerializer({"labels": incident.labels}).data
        return Response(response_data)

    @extend_schema(
        summary="Update MITRE ATT&CK context for an incident",
        request=IncidentMitreSerializer,
        responses={200: IncidentMitreSerializer},
        tags=["Incidents"],
    )
    @action(detail=True, methods=["patch"], url_path="mitre")
    def update_mitre(self, request, pk=None):
        incident = self.get_object()
        serializer = IncidentMitreSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        update_incident_mitre(
            incident=incident,
            tactics=data.get("tactics"),
            techniques=data.get("techniques"),
            kill_chain_phase=data.get("kill_chain_phase"),
            actor=request.user,
        )
        return Response(
            {
                "mitre_tactics": incident.mitre_tactics,
                "mitre_techniques": incident.mitre_techniques,
                "kill_chain_phase": incident.kill_chain_phase,
            }
        )

    @extend_schema(
        summary="Update impact details for an incident",
        request=IncidentImpactSerializer,
        responses={200: IncidentImpactResponseSerializer},
        tags=["Incidents"],
    )
    @action(detail=True, methods=["patch"], url_path="impact")
    def update_impact(self, request, pk=None):
        incident = self.get_object()
        serializer = IncidentImpactSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        update_incident_impact(
            incident=incident,
            impact_systems=data.get("impact_systems"),
            risk_score=data.get("risk_score"),
            severity=data.get("severity"),
            estimated_cost=data.get("estimated_cost"),
            business_unit=data.get("business_unit"),
            data_classification=data.get("data_classification"),
            actor=request.user,
        )
        payload = {
            "impact_systems": incident.impact_systems,
            "risk_score": incident.risk_score,
            "severity": incident.severity,
            "estimated_cost": incident.estimated_cost,
            "business_unit": incident.business_unit,
            "data_classification": incident.data_classification,
        }
        return Response(IncidentImpactResponseSerializer(payload).data)

    @extend_schema(
        methods=["get"],
        summary="List tasks for an incident",
        responses=IncidentTaskSerializer(many=True),
        tags=["Incident Tasks"],
    )
    @extend_schema(
        methods=["post"],
        summary="Create a new task for an incident",
        request=IncidentTaskWriteSerializer,
        responses={201: IncidentTaskSerializer},
        tags=["Incident Tasks"],
    )
    @action(detail=True, methods=["get", "post"], url_path="tasks")
    def tasks(self, request, pk=None):
        incident = self.get_object()
        context = self.get_serializer_context()
        if request.method.lower() == "get":
            serializer = IncidentTaskSerializer(incident.tasks.all(), many=True, context=context)
            return Response(serializer.data)
        serializer = IncidentTaskWriteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        task = create_task(
            incident=incident,
            title=data["title"],
            owner=data.get("owner_id"),
            eta=data.get("eta"),
            actor=request.user,
        )
        return Response(
            IncidentTaskSerializer(task, context=context).data,
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        methods=["patch"],
        summary="Update a task",
        request=IncidentTaskUpdateSerializer,
        responses=IncidentTaskSerializer,
        tags=["Incident Tasks"],
    )
    @extend_schema(
        methods=["delete"],
        summary="Delete a task",
        responses={204: OpenApiResponse(description="Task deleted")},
        tags=["Incident Tasks"],
    )
    @action(detail=True, methods=["patch", "delete"], url_path="tasks/(?P<task_id>[^/.]+)")
    def task_detail(self, request, pk=None, task_id=None):
        incident = self.get_object()
        task = get_object_or_404(IncidentTask, pk=task_id, incident=incident)
        if request.method.lower() == "delete":
            title = task.title
            task_id_value = task.id
            task.delete()
            incident.log_timeline(
                entry_type=TimelineEntry.EntryType.TASK_UPDATE,
                message=f"Tarefa '{title}' removida",
                actor=request.user,
                extra={"task_id": task_id_value},
            )
            log_action(
                actor=request.user,
                verb="incident.task_deleted",
                target=incident,
                meta={"task_id": task_id_value},
            )
            return Response(status=status.HTTP_204_NO_CONTENT)
        serializer = IncidentTaskUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        kwargs = {"task": task, "actor": request.user}
        if "title" in data:
            kwargs["title"] = data["title"]
        if "owner_id" in data:
            kwargs["owner"] = data["owner_id"]
        if "eta" in data:
            kwargs["eta"] = data["eta"]
        if "done" in data:
            kwargs["done"] = data["done"]
        updated_task = update_task(**kwargs)
        return Response(IncidentTaskSerializer(updated_task, context=self.get_serializer_context()).data)

    @extend_schema(
        summary="Upload a file artifact",
        request=IncidentArtifactUploadSerializer,
        responses={201: ArtifactSerializer},
        tags=["Artifacts"],
    )
    @action(
        detail=True,
        methods=["post"],
        url_path="artifacts/upload",
        parser_classes=[MultiPartParser, FormParser],
    )
    def artifacts_upload(self, request, pk=None):
        incident = self.get_object()
        serializer = IncidentArtifactUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        artifact = add_artifact_from_upload(
            incident=incident,
            upload=data["file"],
            type_code=Artifact.Type.FILE,
            actor=request.user,
        )
        return Response(
            ArtifactSerializer(artifact, context=self.get_serializer_context()).data,
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        summary="Register an artifact via link/value",
        request=IncidentArtifactLinkSerializer,
        responses={201: ArtifactSerializer},
        tags=["Artifacts"],
    )
    @action(detail=True, methods=["post"], url_path="artifacts/link")
    def artifacts_link(self, request, pk=None):
        incident = self.get_object()
        serializer = IncidentArtifactLinkSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        artifact = add_artifact_link(
            incident=incident,
            value=data["value"],
            type_code=data.get("type"),
            actor=request.user,
        )
        return Response(
            ArtifactSerializer(artifact, context=self.get_serializer_context()).data,
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        summary="Retrieve timeline entries",
        parameters=[
            OpenApiParameter(name="type", type=str, location=OpenApiParameter.QUERY, description="Filter by entry type", required=False),
            OpenApiParameter(name="after", type=str, location=OpenApiParameter.QUERY, description="Return entries after ISO timestamp", required=False),
            OpenApiParameter(
                name="limit",
                type=int,
                location=OpenApiParameter.QUERY,
                description="Max entries to return (default 100, max 500)",
                required=False,
            ),
        ],
        responses=TimelineEntrySerializer(many=True),
        tags=["Timeline"],
    )
    @action(detail=True, methods=["get"], url_path="timeline")
    def timeline(self, request, pk=None):
        incident = self.get_object()
        params = TimelineQuerySerializer(data=request.query_params)
        params.is_valid(raise_exception=True)
        data = params.validated_data
        entries = incident.timeline.select_related("created_by").order_by("created_at")
        entry_type = data.get("type")
        if entry_type:
            entries = entries.filter(entry_type=entry_type)
        after = data.get("after")
        if after:
            entries = entries.filter(created_at__gt=after)
        limit = data.get("limit") or 100
        entries = entries[:limit]
        serializer = TimelineEntrySerializer(entries, many=True, context=self.get_serializer_context())
        return Response(serializer.data)

    @extend_schema(
        summary="Export timeline entries",
        parameters=[
            OpenApiParameter(name="format", type=str, location=OpenApiParameter.QUERY, description="Export format (csv or pdf)", required=True),
        ],
        responses={200: OpenApiResponse(description="Timeline export file")},
        tags=["Timeline"],
    )
    @action(detail=True, methods=["get"], url_path="timeline/export")
    def timeline_export(self, request, pk=None):
        incident = self.get_object()
        params = TimelineExportSerializer(data=request.query_params)
        params.is_valid(raise_exception=True)
        fmt = params.validated_data["format"]
        entries = incident.timeline.select_related("created_by").order_by("created_at")
        if fmt == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(["timestamp", "type", "actor", "message", "meta"])
            for entry in entries:
                actor = (
                    entry.created_by.get_full_name() or entry.created_by.get_username()
                    if entry.created_by
                    else ""
                )
                writer.writerow(
                    [
                        entry.created_at.isoformat(),
                        entry.entry_type,
                        actor,
                        entry.message.replace("\r", " ").replace("\n", " "),
                        json.dumps(entry.meta, ensure_ascii=False),
                    ]
                )
            response = HttpResponse(buffer.getvalue(), content_type="text/csv; charset=utf-8")
            response[
                "Content-Disposition"
            ] = f'attachment; filename="incident_{incident.id}_timeline.csv"'
            return response
        return Response({"detail": "Formato ainda nao suportado."}, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        summary="Register an escalation",
        request=IncidentEscalationSerializer,
        responses=IncidentEscalationSerializer,
        tags=["Escalation"],
    )
    @action(detail=True, methods=["post"], url_path="escalate")
    def escalate(self, request, pk=None):
        incident = self.get_object()
        serializer = IncidentEscalationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        targets = data.get("targets") if "targets" in data else incident.escalation_targets
        escalate_incident(
            incident=incident,
            level=data.get("level"),
            targets=targets,
            actor=request.user,
        )
        return Response(
            {
                "escalation_level": incident.escalation_level,
                "escalation_targets": incident.escalation_targets,
            }
        )

    @extend_schema(
        methods=["get"],
        summary="List communication log entries",
        responses=CommunicationLogSerializer(many=True),
        tags=["Communications"],
    )
    @extend_schema(
        methods=["post"],
        summary="Create a communication log entry",
        request=CommunicationCreateSerializer,
        responses={201: CommunicationLogSerializer},
        tags=["Communications"],
    )
    @action(detail=True, methods=["get", "post"], url_path="communications")
    def communications(self, request, pk=None):
        incident = self.get_object()
        context = self.get_serializer_context()
        if request.method.lower() == "get":
            serializer = CommunicationLogSerializer(incident.communications.all(), many=True, context=context)
            return Response(serializer.data)
        serializer = CommunicationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        communication = create_communication(
            incident=incident,
            channel=data.get("channel", "internal"),
            recipient_team=data.get("recipient_team"),
            recipient_user=data.get("recipient_user_id"),
            message=data["message"],
            actor=request.user,
        )
        return Response(
            CommunicationLogSerializer(communication, context=context).data,
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        methods=["get"],
        summary="List related incidents",
        responses=IncidentRelationSerializer(many=True),
        tags=["Incident Relations"],
    )
    @extend_schema(
        methods=["post"],
        summary="Create a relation to another incident",
        request=IncidentRelationCreateSerializer,
        responses={201: IncidentRelationSerializer},
        tags=["Incident Relations"],
    )
    @action(detail=True, methods=["get", "post"], url_path="related")
    def related(self, request, pk=None):
        incident = self.get_object()
        context = self.get_serializer_context()
        if request.method.lower() == "get":
            relations = incident.relations_from.select_related("to_incident").all()
            serializer = IncidentRelationSerializer(relations, many=True, context=context)
            return Response(serializer.data)
        serializer = IncidentRelationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            relation = link_incident(
                source=incident,
                target=data["to_incident_id"],
                relation_type=data["relation_type"],
                actor=request.user,
            )
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)})
        return Response(
            IncidentRelationSerializer(relation, context=context).data,
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        summary="Remove a relation to another incident",
        responses={204: OpenApiResponse(description="Relation removed")},
        tags=["Incident Relations"],
    )
    @action(detail=True, methods=["delete"], url_path="related/(?P<relation_id>[^/.]+)")
    def related_delete(self, request, pk=None, relation_id=None):
        incident = self.get_object()
        relation = get_object_or_404(IncidentRelation, pk=relation_id, from_incident=incident)
        unlink_incident(relation=relation, actor=request.user)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        summary="List playbooks and recent executions for an incident",
        responses=IncidentPlaybookOverviewSerializer,
        tags=["Playbooks"],
    )
    @action(detail=True, methods=["get"], url_path="playbooks")
    def playbooks(self, request, pk=None):
        incident = self.get_object()
        context = self.get_serializer_context()
        available = get_manual_playbooks_for_incident(incident)
        executions = (
            Execution.objects.filter(incident=incident)
            .select_related("playbook", "incident", "created_by")
            .prefetch_related("step_results")
            .order_by("-started_at")[:20]
        )
        payload = {
            "available": PlaybookSerializer(available, many=True, context=context).data,
            "executions": ExecutionSerializer(executions, many=True, context=context).data,
        }
        return Response(IncidentPlaybookOverviewSerializer(payload).data)

    @extend_schema(
        summary="Re-run last playbook for an incident",
        responses={202: ExecutionSerializer},
        tags=["Playbooks"],
    )
    @action(detail=True, methods=["post"], url_path="playbooks/rerun-last", permission_classes=[IsSOCLeadOrAbove])
    def playbooks_rerun_last(self, request, pk=None):
        incident = self.get_object()
        last_execution = (
            Execution.objects.filter(incident=incident)
            .select_related("playbook")
            .order_by("-started_at")
            .first()
        )
        if not last_execution or not last_execution.playbook:
            raise NotFound("Nenhuma execucao anterior encontrada para reexecucao.")
        playbook = last_execution.playbook
        try:
            execution = start_playbook_execution(playbook, incident, actor=request.user)
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)})
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.PLAYBOOK_EXECUTION,
            message=f"Playbook '{playbook.name}' reexecutado",
            actor=request.user,
            extra={"execution_id": execution.id},
        )
        log_action(
            actor=request.user,
            verb="incident.playbook_rerun",
            target=incident,
            meta={"execution_id": execution.id, "playbook_id": playbook.id},
        )
        return Response(
            ExecutionSerializer(execution, context=self.get_serializer_context()).data,
            status=status.HTTP_202_ACCEPTED,
        )

    @extend_schema(
        summary="Retrieve status of a playbook execution",
        responses=ExecutionSerializer,
        tags=["Playbooks"],
    )
    @action(detail=True, methods=["get"], url_path="playbooks/(?P<execution_id>[^/.]+)/status")
    def playbook_status(self, request, pk=None, execution_id=None):
        incident = self.get_object()
        execution = get_object_or_404(
            Execution.objects.select_related("playbook", "incident", "created_by").prefetch_related(
                "step_results",
            ),
            pk=execution_id,
            incident=incident,
        )
        return Response(ExecutionSerializer(execution, context=self.get_serializer_context()).data)


@extend_schema_view(
    list=extend_schema(summary="List artifacts", tags=["Artifacts"]),
    retrieve=extend_schema(summary="Retrieve artifact", tags=["Artifacts"]),
    create=extend_schema(summary="Create artifact", tags=["Artifacts"]),
    update=extend_schema(summary="Update artifact", tags=["Artifacts"]),
    partial_update=extend_schema(summary="Partially update artifact", tags=["Artifacts"]),
    destroy=extend_schema(summary="Delete artifact", tags=["Artifacts"]),
)
class ArtifactViewSet(viewsets.ModelViewSet):
    queryset = Artifact.objects.prefetch_related("incidents").all()
    serializer_class = ArtifactSerializer
    permission_classes = [ReadOnlyOrSOCAnalyst]


@extend_schema_view(
    list=extend_schema(summary="List playbooks", tags=["Playbooks"]),
    retrieve=extend_schema(summary="Retrieve playbook", tags=["Playbooks"]),
    create=extend_schema(summary="Create playbook", tags=["Playbooks"]),
    update=extend_schema(summary="Update playbook", tags=["Playbooks"]),
    partial_update=extend_schema(summary="Partially update playbook", tags=["Playbooks"]),
    destroy=extend_schema(summary="Delete playbook", tags=["Playbooks"]),
)
class PlaybookViewSet(viewsets.ModelViewSet):
    queryset = Playbook.objects.select_related("created_by", "updated_by").all()
    serializer_class = PlaybookSerializer

    def get_permissions(self):
        if self.action in {"create", "update", "partial_update", "destroy", "validate_dsl", "run"}:
            permission_classes = [IsSOCLeadOrAbove]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def perform_update(self, serializer):
        serializer.save(updated_by=self.request.user)

    @extend_schema(
        summary="Validate a playbook DSL document",
        request=PlaybookValidateSerializer,
        responses={200: OpenApiResponse(description="DSL is valid")},
        tags=["Playbooks"],
    )
    @action(detail=False, methods=["post"], url_path="validate", permission_classes=[IsSOCLeadOrAbove])
    def validate_dsl(self, request):
        serializer = PlaybookValidateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"valid": True})

    @extend_schema(
        summary="Execute a playbook against an incident",
        request=PlaybookRunSerializer,
        responses={202: ExecutionSerializer},
        tags=["Playbooks"],
    )
    @action(detail=True, methods=["post"], permission_classes=[IsSOCLeadOrAbove])
    def run(self, request, pk=None):
        playbook = self.get_object()
        serializer = PlaybookRunSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        incident_id = serializer.validated_data.get("incident_id")
        if not incident_id:
            raise ValidationError({"detail": "incident_id e obrigatorio"})
        try:
            incident = Incident.objects.get(pk=incident_id)
        except Incident.DoesNotExist:
            raise NotFound("Incidente nao encontrado")
        try:
            execution = start_playbook_execution(playbook, incident, actor=request.user)
        except ValueError as exc:
            raise ValidationError({"detail": str(exc)})
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.PLAYBOOK_EXECUTION,
            message=f"Playbook '{playbook.name}' iniciado",
            actor=request.user,
            extra={"execution_id": execution.id},
        )
        log_action(
            actor=request.user,
            verb="incident.playbook_started",
            target=incident,
            meta={"execution_id": execution.id, "playbook_id": playbook.id},
        )
        return Response(
            ExecutionSerializer(execution, context={"request": request}).data,
            status=status.HTTP_202_ACCEPTED,
        )


@extend_schema_view(
    list=extend_schema(summary="List playbook executions", tags=["Playbook Executions"]),
    retrieve=extend_schema(summary="Retrieve playbook execution", tags=["Playbook Executions"]),
)
class ExecutionViewSet(mixins.RetrieveModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    queryset = Execution.objects.select_related("playbook", "incident", "created_by").prefetch_related(
        "step_results",
    )
    serializer_class = ExecutionSerializer
    permission_classes = [IsAuthenticated]


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(summary="Retrieve current user profile", tags=["Users"], responses=UserSerializer)
    def get(self, request):
        return Response(UserSerializer(request.user).data)


class UserSearchView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Search for users",
        parameters=[OpenApiParameter(name="q", description="Case-insensitive search string", required=False, type=str, location=OpenApiParameter.QUERY)],
        responses=UserSerializer(many=True),
        tags=["Users"],
    )
    def get(self, request):
        query = request.query_params.get("q", "").strip()
        users = User.objects.all()
        if query:
            users = users.filter(
                Q(username__icontains=query)
                | Q(first_name__icontains=query)
                | Q(last_name__icontains=query)
                | Q(email__icontains=query)
            )
        users = users.order_by("username")[:20]
        return Response(UserSerializer(users, many=True).data)


class LabelSuggestView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Suggest labels",
        parameters=[
            OpenApiParameter(name="incident_id", description="Incident to exclude existing labels", required=False, type=int, location=OpenApiParameter.QUERY),
            OpenApiParameter(name="q", description="Filter suggestions containing the value", required=False, type=str, location=OpenApiParameter.QUERY),
        ],
        responses=LabelSuggestionResponseSerializer,
        tags=["Incidents"],
    )
    def get(self, request):
        query = request.query_params.get("q", "").strip().lower()
        incident_id = request.query_params.get("incident_id")
        queryset = Incident.objects.all()
        if incident_id:
            queryset = queryset.exclude(pk=incident_id)
        suggestions = set()
        for labels in queryset.values_list("labels", flat=True):
            if not labels:
                continue
            for label in labels:
                if not query or query in label.lower():
                    suggestions.add(label)
        data = {"results": sorted(suggestions)}
        return Response(LabelSuggestionResponseSerializer(data).data)


class IncidentMetricsView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Incident lifecycle metrics",
        tags=["Metrics"],
        responses={200: OpenApiResponse(description="MTTD/MTTR metrics")},
    )
    def get(self, request):
        snapshot = lifecycle_metrics_snapshot()
        payload = {}
        for scope, metrics in snapshot.items():
            payload[scope] = {}
            for key, metric in metrics.items():
                serialized = serialize_duration(metric.get("avg"))
                payload[scope][key] = {
                    "count": metric.get("count", 0),
                    "seconds": serialized["seconds"],
                    "iso": serialized["iso"],
                    "display": serialized["display"],
                }
        return Response(payload)


class IncidentStreamView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Stream incident timeline events via SSE",
        parameters=[OpenApiParameter(name="after", description="Start streaming after ISO datetime", required=False, type=str, location=OpenApiParameter.QUERY)],
        responses={200: OpenApiResponse(description="text/event-stream")},
        tags=["Timeline"],
    )
    def get(self, request, pk):
        incident = get_object_or_404(Incident, pk=pk)
        after_param = request.query_params.get("after")
        cursor = parse_datetime(after_param) if after_param else None
        if cursor is None:
            cursor = now()
        elif cursor.tzinfo is None:
            cursor = cursor.replace(tzinfo=now().tzinfo)
        context = {"request": request}

        def event_stream() -> Iterator[str]:
            nonlocal cursor
            iterations = 0
            while iterations < 30:
                entries = (
                    incident.timeline.select_related("created_by")
                    .filter(created_at__gt=cursor)
                    .order_by("created_at")
                )
                for entry in entries:
                    cursor = entry.created_at
                    payload = TimelineEntrySerializer(entry, context=context).data
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
                iterations += 1
                time.sleep(2)
            yield "event: complete\ndata: {}\n\n"

        response = StreamingHttpResponse(event_stream(), content_type="text/event-stream; charset=utf-8")
        response["Cache-Control"] = "no-cache"
        response["X-Accel-Buffering"] = "no"
        return response
