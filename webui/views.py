from __future__ import annotations

import json
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from django.contrib import messages
from django.contrib.auth import get_user_model, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_POST
from django.views import View
from django.views.generic import DetailView, ListView, TemplateView
from audit.utils import log_action
from integrations.models import IntegrationDefinition, IntegrationSecretRef
from integrations.services.configured_executor import preview_configured_integration
from incidents.analytics import lifecycle_metrics_snapshot
from incidents.custom_fields import (
    CustomFieldPayloadError,
    get_custom_field_definition_map,
    remove_custom_field_from_all_incidents,
    reconcile_custom_field_values,
    validate_custom_field_input,
)
from incidents.models import (
    Artifact,
    CommunicationLog,
    CustomFieldDefinition,
    Incident,
    IncidentRelation,
    IncidentTask,
    TimelineEntry,
)
from incidents.constants import (
    DATA_CLASSIFICATIONS,
    ESCALATION_LEVELS,
    KILL_CHAIN_PHASES,
    MITRE_TACTICS,
    MITRE_TECHNIQUES,
    SEVERITY_BY_RISK,
)
from incidents.services import (
    add_artifact_from_upload,
    add_artifact_link,
    create_communication,
    create_task,
    escalate_incident,
    link_incident,
    unlink_incident,
    update_incident_assignee,
    update_incident_lifecycle,
    update_incident_impact,
    update_incident_labels,
    update_incident_mitre,
    update_incident_secondary_assignees,
    update_incident_status,
    update_task,
    update_artifact,
    remove_artifact_link,
    delete_artifact,
    SENTINEL,
)
from playbooks import docs as playbook_docs
from playbooks.models import Execution, Playbook
from playbooks.services import (
    get_manual_playbooks_for_artifact,
    get_manual_playbooks_for_incident,
    is_manual_playbook_available_for_artifact,
    is_manual_playbook_available_for_incident,
    start_playbook_execution,
)

from .forms import (
    CustomFieldDefinitionForm,
    IncidentFilterForm,
    IncidentLifecycleForm,
    HttpConnectorForm,
    HttpConnectorSecretForm,
    IntegrationTestForm,
    PlaybookForm,
    PlaybookRunForm,
    TailwindAuthenticationForm,
    TimelineEntryForm,
)

User = get_user_model()


def _is_htmx(request) -> bool:
    return request.headers.get("HX-Request", "").lower() == "true"


def _hx_trigger(response: HttpResponse, level: str, text: str, *, clear: bool = True) -> HttpResponse:
    response["HX-Trigger"] = json.dumps({"showMessage": {"level": level, "text": text, "clear": clear}})
    return response


def _format_duration(value):
    if not value:
        return "—"
    total_seconds = int(value.total_seconds())
    sign = "-" if total_seconds < 0 else ""
    total_seconds = abs(total_seconds)
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    if not days and hours == 0:
        parts.append(f"{seconds}s")
    return f"{sign}{' '.join(parts)}"


def _incident_context(incident: Incident) -> dict[str, object]:
    return {
        "incident": incident,
        "status_choices": Incident.Status.choices,
        "severity_choices": Incident.Severity.choices,
        "mitre_tactics": MITRE_TACTICS,
        "mitre_techniques": MITRE_TECHNIQUES,
        "kill_chain_phases": KILL_CHAIN_PHASES,
        "escalation_levels": ESCALATION_LEVELS,
        "data_classifications": DATA_CLASSIFICATIONS,
        "severity_by_risk": SEVERITY_BY_RISK,
    }


def _lifecycle_initial(incident: Incident) -> dict[str, object]:
    tz = timezone.get_current_timezone()

    def normalize(value):
        if not value:
            return None
        localized = timezone.localtime(value, tz)
        return localized.replace(tzinfo=None)

    return {
        "occurred_at": normalize(incident.occurred_at),
        "detected_at": normalize(incident.detected_at),
        "responded_at": normalize(incident.responded_at),
        "resolved_at": normalize(incident.resolved_at),
        "closed_at": normalize(incident.closed_at),
    }


def _incident_lifecycle_context(
    incident: Incident, form: IncidentLifecycleForm | None = None
) -> dict[str, object]:
    metrics = {
        "mttd": incident.detection_delta(),
        "mtta": incident.response_delta(),
        "mttr": incident.resolution_delta(),
    }
    return {
        "lifecycle_form": form or IncidentLifecycleForm(initial=_lifecycle_initial(incident)),
        "lifecycle_metrics": {
            key: {"value": value, "display": _format_duration(value)} for key, value in metrics.items()
        },
    }


def _incident_escalation_context(incident: Incident) -> dict[str, object]:
    selected_secondary_assignees = list(
        incident.secondary_assignees.filter(is_active=True).order_by(
            "first_name",
            "last_name",
            "username",
        )
    )
    selected_secondary_assignee_ids = [user.id for user in selected_secondary_assignees]
    return {
        "selected_secondary_assignees": selected_secondary_assignees,
        "secondary_assignee_ids": set(selected_secondary_assignee_ids),
        "escalation_user_candidates": _search_team_users(query="", limit=20),
    }


def _format_custom_field_value_for_input(*, field_type: str, value: Any) -> str:
    if value is None:
        return ""
    if field_type == CustomFieldDefinition.FieldType.BOOLEAN:
        if value is True:
            return "true"
        if value is False:
            return "false"
        return ""
    if field_type == CustomFieldDefinition.FieldType.JSON:
        try:
            return json.dumps(value, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return ""
    return str(value)


def _format_custom_field_value_for_display(*, field_type: str, value: Any) -> str:
    if value is None:
        return "Sem valor"
    if field_type == CustomFieldDefinition.FieldType.BOOLEAN:
        return "True" if value is True else "False" if value is False else "Sem valor"
    if field_type == CustomFieldDefinition.FieldType.JSON:
        try:
            return json.dumps(value, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return "Valor invalido"
    return str(value)


def _coerce_custom_field_value_from_form(*, field_type: str, raw_value: str | None) -> Any:
    value = (raw_value or "").strip()
    if value == "":
        return None
    if field_type == CustomFieldDefinition.FieldType.TEXT:
        return value
    if field_type == CustomFieldDefinition.FieldType.INTEGER:
        try:
            return int(value)
        except ValueError as exc:
            raise ValueError("Informe um numero inteiro valido.") from exc
    if field_type == CustomFieldDefinition.FieldType.NUMBER:
        try:
            return float(value)
        except ValueError as exc:
            raise ValueError("Informe um numero valido.") from exc
    if field_type == CustomFieldDefinition.FieldType.BOOLEAN:
        normalized = value.lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
        raise ValueError("Informe um valor booleano valido.")
    if field_type in {
        CustomFieldDefinition.FieldType.DATE,
        CustomFieldDefinition.FieldType.DATETIME,
    }:
        return value
    if field_type == CustomFieldDefinition.FieldType.JSON:
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("Informe um JSON valido.") from exc
    return value


def _incident_custom_fields_context(
    incident: Incident,
    *,
    editing_internal_id: str | None = None,
    submitted_values: dict[str, str] | None = None,
    field_errors: dict[str, str] | None = None,
) -> dict[str, object]:
    definitions = list(
        CustomFieldDefinition.objects.filter(is_deleted=False, is_active=True).order_by("display_name", "internal_id")
    )
    definition_map = get_custom_field_definition_map(include_inactive=True)
    reconciled_values, _ = reconcile_custom_field_values(
        incident.custom_fields or {},
        definition_map=definition_map,
    )
    fields: list[dict[str, Any]] = []
    for definition in definitions:
        key = str(definition.internal_id)
        input_name = f"custom_field_{key}"
        if submitted_values is not None and input_name in submitted_values:
            input_value = submitted_values[input_name]
        else:
            input_value = _format_custom_field_value_for_input(
                field_type=definition.field_type,
                value=reconciled_values.get(key),
            )
        fields.append(
            {
                "internal_id": key,
                "display_name": definition.display_name,
                "field_type": definition.field_type,
                "input_value": input_value,
                "display_value": _format_custom_field_value_for_display(
                    field_type=definition.field_type,
                    value=reconciled_values.get(key),
                ),
                "has_value": reconciled_values.get(key) is not None,
                "is_editing": key == editing_internal_id,
                "error": (field_errors or {}).get(key, ""),
            }
        )
    inactive_values_count = 0
    for key, value in reconciled_values.items():
        definition = definition_map.get(key)
        if definition and not definition.is_active and value is not None:
            inactive_values_count += 1
    return {
        "incident_custom_fields": fields,
        "inactive_custom_field_values_count": inactive_values_count,
    }


def _render_incident_partial(
    request,
    incident: Incident,
    template_name: str,
    extra_context: dict | None = None,
    *,
    status: int = 200,
) -> HttpResponse:
    context = _incident_context(incident)
    if extra_context:
        context.update(extra_context)
    return render(request, template_name, context, status=status)


def _team_users():
    return User.objects.filter(is_active=True).order_by("first_name", "last_name", "username")


def _search_team_users(*, query: str, limit: int = 20):
    users = _team_users()
    query = (query or "").strip()
    if query:
        users = users.filter(
            Q(username__icontains=query)
            | Q(first_name__icontains=query)
            | Q(last_name__icontains=query)
            | Q(email__icontains=query)
        )
    return users[:limit]


def _normalize_user_ids(values) -> list[int]:
    normalized: list[int] = []
    for raw in values or []:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value > 0 and value not in normalized:
            normalized.append(value)
    return normalized


def _can_execute_playbooks(user) -> bool:
    if not user or not user.is_authenticated:
        return False
    return user.role in {user.Roles.ADMIN, user.Roles.SOC_LEAD}


def _can_manage_integrations(user) -> bool:
    if not user or not user.is_authenticated:
        return False
    return user.role in {user.Roles.ADMIN, user.Roles.SOC_LEAD}


def _can_manage_incident_settings(user) -> bool:
    if not user or not user.is_authenticated:
        return False
    return user.role in {user.Roles.ADMIN, user.Roles.SOC_LEAD}


def _group_playbooks_by_category(playbooks) -> list[dict[str, object]]:
    grouped: list[dict[str, object]] = []
    current_category = None
    current_items = []
    for playbook in playbooks:
        category = playbook.category_display
        if category != current_category:
            if current_category is not None:
                grouped.append({"category": current_category, "playbooks": current_items})
            current_category = category
            current_items = [playbook]
        else:
            current_items.append(playbook)
    if current_category is not None:
        grouped.append({"category": current_category, "playbooks": current_items})
    return grouped


def _execution_panel_context(incident: Incident, *, limit: int = 20) -> dict[str, object]:
    status_rows = (
        Execution.objects.filter(incident=incident)
        .values("status")
        .annotate(total=Count("id"))
    )
    status_count = {row["status"]: row["total"] for row in status_rows}
    execution_metrics = {
        "total": sum(status_count.values()),
        "running": status_count.get(Execution.Status.RUNNING, 0),
        "succeeded": status_count.get(Execution.Status.SUCCEEDED, 0),
        "failed": status_count.get(Execution.Status.FAILED, 0),
    }
    executions = (
        Execution.objects.filter(incident=incident)
        .select_related("playbook")
        .prefetch_related("step_results")
        .order_by("-started_at")[:limit]
    )
    return {
        "executions": executions,
        "execution_metrics": execution_metrics,
    }


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "webui/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        incidents = Incident.objects.all()
        context["open_counts"] = (
            incidents.filter(status__in=[Incident.Status.NEW, Incident.Status.IN_PROGRESS, Incident.Status.CONTAINED])
            .values("severity")
            .annotate(total=Count("id"))
        )
        context["recent_incidents"] = incidents.select_related("assignee").order_by("-created_at")[:6]
        context["executions"] = (
            Execution.objects.select_related("playbook", "incident")
            .prefetch_related("step_results")
            .order_by("-started_at")[:5]
        )
        snapshot = lifecycle_metrics_snapshot()
        rendered_snapshot = {}
        for scope, metrics in snapshot.items():
            rendered_snapshot[scope] = {}
            for key, metric in metrics.items():
                avg = metric.get("avg")
                rendered_snapshot[scope][key] = {
                    "count": metric.get("count", 0),
                    "avg": avg,
                    "seconds": avg.total_seconds() if avg else None,
                    "display": _format_duration(avg),
                }
        context["lifecycle_snapshot"] = rendered_snapshot
        return context


class AutomationOverviewView(LoginRequiredMixin, TemplateView):
    template_name = "webui/automation_overview.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["automation_section"] = "overview"
        context["playbook_count"] = Playbook.objects.count()
        context["enabled_playbook_count"] = Playbook.objects.filter(enabled=True).count()
        context["connector_count"] = IntegrationDefinition.objects.count()
        context["enabled_connector_count"] = IntegrationDefinition.objects.filter(enabled=True).count()
        context["secret_count"] = IntegrationSecretRef.objects.count()
        context["custom_field_count"] = CustomFieldDefinition.objects.filter(is_deleted=False).count()
        context["active_custom_field_count"] = CustomFieldDefinition.objects.filter(
            is_deleted=False,
            is_active=True,
        ).count()
        context["recent_playbooks"] = Playbook.objects.order_by("-updated_at")[:5]
        context["recent_connectors"] = IntegrationDefinition.objects.order_by("-updated_at")[:5]
        context["recent_secrets"] = IntegrationSecretRef.objects.order_by("-updated_at")[:5]
        context["recent_custom_fields"] = (
            CustomFieldDefinition.objects.filter(is_deleted=False).order_by("-updated_at")[:5]
        )
        return context


class IncidentListView(LoginRequiredMixin, ListView):
    template_name = "webui/incident_list.html"
    context_object_name = "incidents"
    paginate_by = 20

    def get_queryset(self):
        queryset = (
            Incident.objects.select_related("assignee", "created_by")
            .prefetch_related("artifacts", "secondary_assignees")
            .order_by("-created_at")
        )
        self.filter_form = IncidentFilterForm(self.request.GET)
        self.artifact_filter = None
        self.ownership_filter = "all"
        artifact_filter = self.request.GET.get("artifact")
        if self.filter_form.is_valid():
            data = self.filter_form.cleaned_data
            self.ownership_filter = data.get("ownership") or "all"
            if self.ownership_filter == "mine":
                queryset = queryset.assigned_to(self.request.user)
            elif self.ownership_filter == "escalated":
                queryset = queryset.escalated_to(self.request.user)
            if data.get("search"):
                term = data["search"]
                queryset = queryset.filter(Q(title__icontains=term) | Q(description__icontains=term))
            if data.get("status"):
                queryset = queryset.filter(status=data["status"])
            if data.get("severity"):
                queryset = queryset.filter(severity=data["severity"])
        if artifact_filter:
            queryset = queryset.filter(artifacts__id=artifact_filter)
            try:
                self.artifact_filter = Artifact.objects.get(pk=artifact_filter)
            except Artifact.DoesNotExist:
                self.artifact_filter = None
        if artifact_filter or self.ownership_filter == "escalated":
            queryset = queryset.distinct()
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = getattr(self, "filter_form", IncidentFilterForm())
        context["ownership_filter"] = getattr(self, "ownership_filter", "all")
        if getattr(self, "artifact_filter", None):
            context["artifact_filter"] = self.artifact_filter
            context["artifact_filter_id"] = self.artifact_filter.id if self.artifact_filter else None
        return context


@login_required
def artifact_directory(request):
    artifacts_qs = Artifact.objects.annotate(incident_count=Count("incidents")).prefetch_related(
        "incidents", "incidents__assignee"
    )
    artifact_filter = request.GET.get("artifact")
    filter_artifact = None
    if artifact_filter:
        artifacts_qs = artifacts_qs.filter(pk=artifact_filter)
        filter_artifact = artifacts_qs.first()
    artifacts = list(artifacts_qs.order_by("-incident_count", "-created_at"))
    duplicates = [artifact for artifact in artifacts if artifact.incident_count > 1]
    context = {
        "artifacts": artifacts,
        "duplicates": duplicates,
        "filter_artifact": filter_artifact,
    }
    return render(request, "webui/artifact_list.html", context)


@login_required
@require_POST
def artifact_delete(request, artifact_id: int):
    artifact = get_object_or_404(Artifact.objects.prefetch_related("incidents"), pk=artifact_id)
    if request.method != "POST":
        return redirect("webui:artifact_directory")
    delete_artifact(artifact=artifact, actor=request.user)
    messages.success(
        request,
        f"Artefato #{artifact_id} removido. Todas as associações com incidentes foram excluídas.",
    )
    return redirect("webui:artifact_directory")


class IncidentDetailView(LoginRequiredMixin, DetailView):
    model = Incident
    template_name = "webui/incident_detail.html"
    context_object_name = "incident"

    def get_queryset(self):
        return (
            Incident.objects.select_related("assignee", "created_by")
            .prefetch_related(
                "artifacts",
                "artifacts__incidents",
                "timeline__created_by",
                "tasks__owner",
                "communications__created_by",
                "communications__recipient_user",
                "relations_from__to_incident",
                "secondary_assignees",
            )
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        incident: Incident = self.object
        incident_playbooks = list(get_manual_playbooks_for_incident(incident))
        context.update(_incident_context(incident))
        context.update(_incident_lifecycle_context(incident))
        context.update(_incident_escalation_context(incident))
        context.update(_incident_custom_fields_context(incident))
        context["timeline_form"] = TimelineEntryForm()
        context["team_users"] = _team_users()
        context["timeline_entries"] = incident.timeline.select_related("created_by").order_by("-created_at")[:100]
        context["relation_choices"] = IncidentRelation.RelationType.choices
        context["Artifact"] = Artifact
        context["available_playbooks"] = incident_playbooks
        context["available_playbook_groups"] = _group_playbooks_by_category(incident_playbooks)
        context.update(_execution_panel_context(incident))
        context["artifact_playbooks"] = {
            artifact.id: list(get_manual_playbooks_for_artifact(artifact, incident=incident))
            for artifact in incident.artifacts.all()
        }
        context["artifact_playbook_groups"] = {
            artifact_id: _group_playbooks_by_category(playbooks)
            for artifact_id, playbooks in context["artifact_playbooks"].items()
        }
        latest_entry = incident.timeline.order_by("-created_at").first()
        context["latest_timeline_ts"] = latest_entry.created_at.isoformat() if latest_entry else ""
        return context


@login_required
def incident_summary_partial(request, pk: int):
    incident = get_object_or_404(
        Incident.objects.select_related("assignee", "created_by"),
        pk=pk,
    )
    return _render_incident_partial(request, incident, "webui/partials/incident_summary.html")


@login_required
@require_POST
def incident_update_status(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    if request.method != "POST":
        return redirect("webui:incident_detail", pk=pk)
    status_value = request.POST.get("status")
    reason = request.POST.get("reason", "").strip() or None
    valid_statuses = {value for value, _ in Incident.Status.choices}
    if status_value not in valid_statuses:
        response = _render_incident_partial(request, incident, "webui/partials/incident_summary.html")
        if _is_htmx(request):
            return _hx_trigger(response, "error", "Status inv?lido", clear=False)
        messages.error(request, "Status inv?lido")
        return redirect("webui:incident_detail", pk=pk)
    try:
        update_incident_status(incident=incident, status=status_value, reason=reason, actor=request.user)
    except ValueError as exc:
        response = _render_incident_partial(request, incident, "webui/partials/incident_summary.html")
        if _is_htmx(request):
            return _hx_trigger(response, "error", str(exc), clear=False)
        messages.error(request, str(exc))
        return redirect("webui:incident_detail", pk=pk)
    message = "Status atualizado"
    if reason:
        message = f"{message} ({reason})"
    if not _is_htmx(request):
        messages.success(request, message)
        return redirect("webui:incident_detail", pk=pk)
    response = _render_incident_partial(request, incident, "webui/partials/incident_summary.html")
    return _hx_trigger(response, "success", message)


@login_required
@require_POST
def incident_update_assignee(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    if request.method != "POST":
        return redirect("webui:incident_detail", pk=pk)
    assignee_id = request.POST.get("assignee_id")
    assignee = None
    if assignee_id:
        assignee = get_object_or_404(User, pk=assignee_id, is_active=True)
    update_incident_assignee(incident=incident, assignee=assignee, actor=request.user)
    label = assignee.get_full_name() or assignee.get_username() if assignee else "Sem respons?vel"
    if not _is_htmx(request):
        messages.success(request, f"Responsável atualizado para {label}")
        return redirect("webui:incident_detail", pk=pk)
    response = _render_incident_partial(request, incident, "webui/partials/incident_summary.html")
    return _hx_trigger(response, "success", f"Responsável atualizado para {label}")


@login_required
def incident_labels_partial(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    return _render_incident_partial(request, incident, "webui/partials/incident_labels_mitre.html")


@login_required
@require_POST
def incident_label_add(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    label = request.POST.get("label", "").strip()
    if label:
        update_incident_labels(incident=incident, add=[label], actor=request.user)
        if not _is_htmx(request):
            messages.success(request, f"Label '{label}' adicionada")
            return redirect("webui:incident_detail", pk=pk)
        response = _render_incident_partial(request, incident, "webui/partials/incident_labels_mitre.html")
        return _hx_trigger(response, "success", f"Label '{label}' adicionada")
    response = _render_incident_partial(request, incident, "webui/partials/incident_labels_mitre.html")
    if _is_htmx(request):
        return _hx_trigger(response, "error", "Informe um r?tulo v?lido", clear=False)
    messages.error(request, "Informe um r?tulo v?lido")
    return redirect("webui:incident_detail", pk=pk)


@login_required
@require_POST
def incident_label_remove(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    label = request.POST.get("label", "").strip()
    if label:
        update_incident_labels(incident=incident, remove=[label], actor=request.user)
        if not _is_htmx(request):
            messages.success(request, f"Label '{label}' removida")
            return redirect("webui:incident_detail", pk=pk)
        response = _render_incident_partial(request, incident, "webui/partials/incident_labels_mitre.html")
        return _hx_trigger(response, "success", f"Label '{label}' removida")
    response = _render_incident_partial(request, incident, "webui/partials/incident_labels_mitre.html")
    if _is_htmx(request):
        return _hx_trigger(response, "error", "R?tulo inv?lido", clear=False)
    messages.error(request, "R?tulo inv?lido")
    return redirect("webui:incident_detail", pk=pk)


@login_required
def incident_lifecycle_partial(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    extra = _incident_lifecycle_context(incident)
    return _render_incident_partial(
        request,
        incident,
        "webui/partials/incident_lifecycle.html",
        extra_context=extra,
    )


@login_required
@require_POST
def incident_lifecycle_update(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    form = IncidentLifecycleForm(request.POST)
    if form.is_valid():
        result = update_incident_lifecycle(incident=incident, actor=request.user, **form.cleaned_data)
        incident.refresh_from_db()
        extra = _incident_lifecycle_context(incident)
        response = _render_incident_partial(
            request,
            incident,
            "webui/partials/incident_lifecycle.html",
            extra_context=extra,
        )
        level = "success" if result.changed else "info"
        message = "Datas do incidente atualizadas" if result.changed else "Nenhuma alteracao aplicada"
        return _hx_trigger(response, level, message)
    extra = _incident_lifecycle_context(incident, form=form)
    response = _render_incident_partial(
        request,
        incident,
        "webui/partials/incident_lifecycle.html",
        extra_context=extra,
        status=400,
    )
    return _hx_trigger(response, "error", "Corrija os campos destacados", clear=False)


@login_required
@require_POST
def incident_mitre_update(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    tactics = request.POST.getlist("tactics")
    techniques = request.POST.getlist("techniques")
    kill_chain = request.POST.get("kill_chain_phase", "").strip() or None
    update_incident_mitre(
        incident=incident,
        tactics=tactics,
        techniques=techniques,
        kill_chain_phase=kill_chain,
        actor=request.user,
    )
    if not _is_htmx(request):
        messages.success(request, "Contexto MITRE atualizado")
        return redirect("webui:incident_detail", pk=pk)
    response = _render_incident_partial(request, incident, "webui/partials/incident_labels_mitre.html")
    return _hx_trigger(response, "success", "Contexto MITRE atualizado")


@login_required
def incident_tasks_partial(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    extra = {"team_users": _team_users()}
    return _render_incident_partial(request, incident, "webui/partials/incident_tasks.html", extra_context=extra)


@login_required
@require_POST
def incident_task_create(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    title = request.POST.get("title", "").strip()
    owner_id = request.POST.get("owner_id")
    eta_raw = request.POST.get("eta")
    owner = None
    if owner_id:
        owner = get_object_or_404(User, pk=owner_id, is_active=True)
    eta = parse_datetime(eta_raw) if eta_raw else None
    if eta and timezone.is_naive(eta):
        eta = timezone.make_aware(eta, timezone.get_current_timezone())
    if not title:
        response = incident_tasks_partial(request, pk)
        return _hx_trigger(response, "error", "Defina um t?tulo para a tarefa", clear=False)
    create_task(incident=incident, title=title, owner=owner, eta=eta, actor=request.user)
    if not _is_htmx(request):
        messages.success(request, "Tarefa criada")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_tasks_partial(request, pk)
    return _hx_trigger(response, "success", "Tarefa criada")


@login_required
@require_POST
def incident_task_toggle(request, pk: int, task_id: int):
    incident = get_object_or_404(Incident, pk=pk)
    task = get_object_or_404(IncidentTask, pk=task_id, incident=incident)
    done_value = request.POST.get("done", "false").lower() in {"1", "true", "on", "yes"}
    update_task(task=task, done=done_value, actor=request.user)
    if not _is_htmx(request):
        messages.success(request, "Tarefa atualizada")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_tasks_partial(request, pk)
    message = "Tarefa conclu?da" if done_value else "Tarefa marcada como pendente"
    return _hx_trigger(response, "success", message)


@login_required
@require_POST
def incident_task_update(request, pk: int, task_id: int):
    incident = get_object_or_404(Incident, pk=pk)
    task = get_object_or_404(IncidentTask, pk=task_id, incident=incident)
    owner_id = request.POST.get("owner_id")
    eta_raw = request.POST.get("eta")
    title = request.POST.get("title")
    kwargs = {"task": task, "actor": request.user}
    if title is not None:
        title_clean = title.strip()
        if title_clean:
            kwargs["title"] = title_clean
    if owner_id is not None:
        kwargs["owner"] = get_object_or_404(User, pk=owner_id, is_active=True) if owner_id else None
    if eta_raw is not None:
        eta = parse_datetime(eta_raw) if eta_raw else None
        if eta and timezone.is_naive(eta):
            eta = timezone.make_aware(eta, timezone.get_current_timezone())
        kwargs["eta"] = eta
    update_task(**kwargs)
    if not _is_htmx(request):
        messages.success(request, "Tarefa atualizada")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_tasks_partial(request, pk)
    return _hx_trigger(response, "success", "Tarefa atualizada")


@login_required
@require_POST
def incident_task_delete(request, pk: int, task_id: int):
    incident = get_object_or_404(Incident, pk=pk)
    task = get_object_or_404(IncidentTask, pk=task_id, incident=incident)
    title = task.title
    task.delete()
    incident.log_timeline(
        entry_type=TimelineEntry.EntryType.TASK_UPDATE,
        message=f"Tarefa '{title}' removida",
        actor=request.user,
        extra={"task_id": task_id},
    )
    log_action(
        actor=request.user,
        verb="incident.task_deleted",
        target=incident,
        meta={"task_id": task_id},
    )
    if not _is_htmx(request):
        messages.success(request, "Tarefa removida")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_tasks_partial(request, pk)
    return _hx_trigger(response, "success", "Tarefa removida")


@login_required
def incident_artifacts_partial(request, pk: int, *, editing_artifact: Artifact | None = None):
    incident = get_object_or_404(Incident.objects.prefetch_related("artifacts__incidents"), pk=pk)
    artifact_playbooks = {
        artifact.id: get_manual_playbooks_for_artifact(artifact, incident=incident)
        for artifact in incident.artifacts.all()
    }
    extra = {
        "editing_artifact": editing_artifact,
        "artifact_playbooks": artifact_playbooks,
    }
    return _render_incident_partial(
        request,
        incident,
        "webui/partials/incident_artifacts.html",
        extra_context=extra,
    )


@login_required
@require_POST
def incident_artifact_upload(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    upload = request.FILES.get("file")
    if not upload:
        response = incident_artifacts_partial(request, pk)
        return _hx_trigger(response, "error", "Selecione um arquivo para enviar", clear=False)
    add_artifact_from_upload(
        incident=incident,
        upload=upload,
        type_code=Artifact.Type.FILE,
        actor=request.user,
    )
    if not _is_htmx(request):
        messages.success(request, "Artefato anexado")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_artifacts_partial(request, pk)
    return _hx_trigger(response, "success", "Artefato anexado")


@login_required
@require_POST
def incident_artifact_link(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    raw_value = request.POST.get("value", "")
    value = raw_value.strip()
    type_code = request.POST.get("type") or Artifact.Type.URL
    if not value:
        response = incident_artifacts_partial(request, pk)
        return _hx_trigger(response, "error", "Informe o valor do artefato", clear=False)
    already_linked = incident.artifacts.filter(type=type_code, value=value).exists()
    add_artifact_link(incident=incident, value=value, type_code=type_code, actor=request.user)
    if not _is_htmx(request):
        if already_linked:
            messages.info(request, "Artefato ja estava associado a este incidente")
        else:
            messages.success(request, "Artefato registrado")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_artifacts_partial(request, pk)
    if already_linked:
        return _hx_trigger(response, "info", "Artefato ja estava associado a este incidente", clear=False)
    return _hx_trigger(response, "success", "Artefato registrado")


@login_required
def incident_artifact_edit(request, pk: int, artifact_id: int):
    incident = get_object_or_404(Incident, pk=pk)
    artifact = get_object_or_404(incident.artifacts, pk=artifact_id)
    response = incident_artifacts_partial(request, pk, editing_artifact=artifact)
    return response


@login_required
@require_POST
def incident_artifact_update(request, pk: int, artifact_id: int):
    incident = get_object_or_404(Incident, pk=pk)
    artifact = get_object_or_404(incident.artifacts, pk=artifact_id)
    if artifact.file:
        type_code = Artifact.Type.FILE
    else:
        type_code = request.POST.get("type") or artifact.type
    value_param = SENTINEL
    if not artifact.file:
        raw_value = request.POST.get("value")
        if raw_value is None:
            value_param = SENTINEL
        else:
            raw_value = raw_value.strip()
            if not raw_value:
                response = incident_artifacts_partial(request, pk, editing_artifact=artifact)
                return _hx_trigger(response, "error", "Valor do artefato nao pode ser vazio", clear=False)
            value_param = raw_value
    try:
        result = update_artifact(
            artifact=artifact,
            incident=incident,
            type_code=type_code,
            value=value_param,
            actor=request.user,
        )
    except ValueError as exc:
        response = incident_artifacts_partial(request, pk, editing_artifact=artifact)
        return _hx_trigger(response, "error", str(exc), clear=False)
    message = "Artefato atualizado" if result.changed else "Nenhuma alteracao aplicada"
    if not _is_htmx(request):
        level = messages.SUCCESS if result.changed else messages.INFO
        messages.add_message(request, level, message)
        return redirect("webui:incident_detail", pk=pk)
    response = incident_artifacts_partial(request, pk)
    trigger_level = "success" if result.changed else "info"
    return _hx_trigger(response, trigger_level, message)


@login_required
@require_POST
def incident_artifact_action(request, pk: int, artifact_id: int):
    incident = get_object_or_404(Incident, pk=pk)
    artifact = get_object_or_404(incident.artifacts, pk=artifact_id)
    if request.method != "POST":
        return redirect("webui:incident_detail", pk=pk)
    action = (request.POST.get("action") or "").strip()
    if not action:
        response = incident_artifacts_partial(request, pk)
        return _hx_trigger(response, "error", "Selecione uma ação", clear=False)

    if action.startswith("playbook:"):
        if not _can_execute_playbooks(request.user):
            raise PermissionDenied("Apenas SOC Lead ou Admin podem executar playbooks manuais")
        _, _, raw_id = action.partition(":")
        try:
            playbook_id = int(raw_id)
            playbook = Playbook.objects.get(
                pk=playbook_id,
                enabled=True,
                type=Playbook.Type.ARTIFACT,
                mode=Playbook.Mode.MANUAL,
            )
        except (ValueError, TypeError, Playbook.DoesNotExist):
            response = incident_artifacts_partial(request, pk)
            return _hx_trigger(response, "error", "Playbook não encontrado", clear=False)
        if not is_manual_playbook_available_for_artifact(playbook, artifact, incident=incident):
            response = incident_artifacts_partial(request, pk)
            return _hx_trigger(
                response,
                "error",
                "Playbook manual não se aplica a este artefato",
                clear=False,
            )
        context = {
            "event": "manual.artifact",
            "artifact": {
                "id": artifact.id,
                "type": artifact.type,
                "value": artifact.value,
                "attributes": artifact.attributes or {},
            },
            "source": "webui",
            "incident_id": incident.id,
        }
        try:
            execution = start_playbook_execution(playbook, incident, actor=request.user, context=context)
            message = f"Playbook '{playbook.name}' executado (execução #{execution.id})"
            level = "success"
        except ValueError as exc:
            message = str(exc)
            level = "error"
        if not _is_htmx(request):
            if level == "success":
                messages.success(request, message)
            else:
                messages.error(request, message)
            return redirect("webui:incident_detail", pk=pk)
        response = incident_artifacts_partial(request, pk)
        return _hx_trigger(response, level, message, clear=(level == "success"))

    if action == "edit":
        if not _is_htmx(request):
            return redirect("webui:incident_detail", pk=pk)
        return incident_artifacts_partial(request, pk, editing_artifact=artifact)

    if action == "delete":
        result = remove_artifact_link(incident=incident, artifact=artifact, actor=request.user)
        if result.changed:
            message = "Artefato removido do incidente"
            level = messages.SUCCESS
            trigger_level = "success"
        else:
            message = "Artefato não estava associado"
            level = messages.INFO
            trigger_level = "info"
        if not _is_htmx(request):
            messages.add_message(request, level, message)
            return redirect("webui:incident_detail", pk=pk)
        response = incident_artifacts_partial(request, pk)
        return _hx_trigger(response, trigger_level, message)

    response = incident_artifacts_partial(request, pk)
    return _hx_trigger(response, "error", "Ação inválida", clear=False)


@login_required
def incident_impact_partial(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    return _render_incident_partial(request, incident, "webui/partials/incident_impact.html")


@login_required
@require_POST
def incident_impact_update(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    impact_raw = request.POST.get("impact_systems", "")
    impact_systems = [value.strip() for value in impact_raw.replace(",", "\n").splitlines() if value.strip()]
    risk_raw = request.POST.get("risk_score")
    severity = request.POST.get("severity") or None
    estimated_cost_raw = request.POST.get("estimated_cost")
    business_unit = request.POST.get("business_unit", "").strip()
    classification = request.POST.get("data_classification") or None

    risk_score = None
    if risk_raw:
        try:
            risk_score = int(risk_raw)
        except ValueError:
            response = incident_impact_partial(request, pk)
            return _hx_trigger(response, "error", "Informe um risk score v?lido", clear=False)
    estimated_cost = None
    if estimated_cost_raw:
        try:
            estimated_cost = Decimal(estimated_cost_raw)
        except (InvalidOperation, TypeError):
            response = incident_impact_partial(request, pk)
            return _hx_trigger(response, "error", "Valor de custo inv?lido", clear=False)

    update_incident_impact(
        incident=incident,
        impact_systems=impact_systems,
        risk_score=risk_score,
        severity=severity,
        estimated_cost=estimated_cost,
        business_unit=business_unit,
        data_classification=classification,
        actor=request.user,
    )
    if not _is_htmx(request):
        messages.success(request, "Impacto atualizado")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_impact_partial(request, pk)
    return _hx_trigger(response, "success", "Impacto atualizado")


@login_required
def incident_custom_fields_partial(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    editing_internal_id = request.GET.get("edit", "").strip() or None
    extra = _incident_custom_fields_context(
        incident,
        editing_internal_id=editing_internal_id,
    )
    return _render_incident_partial(
        request,
        incident,
        "webui/partials/incident_custom_fields.html",
        extra_context=extra,
    )


@login_required
@require_POST
def incident_custom_fields_update(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    internal_id = request.POST.get("internal_id", "").strip()
    if not internal_id or not internal_id.isdigit():
        response = _render_incident_partial(
            request,
            incident,
            "webui/partials/incident_custom_fields.html",
            extra_context=_incident_custom_fields_context(incident),
            status=400,
        )
        return _hx_trigger(response, "error", "Campo customizado invalido", clear=False)

    definition = (
        CustomFieldDefinition.objects.filter(
            is_deleted=False,
            is_active=True,
            internal_id=internal_id,
        )
        .order_by("internal_id")
        .first()
    )
    if not definition:
        response = _render_incident_partial(
            request,
            incident,
            "webui/partials/incident_custom_fields.html",
            extra_context=_incident_custom_fields_context(incident),
            status=400,
        )
        return _hx_trigger(response, "error", "Campo customizado nao encontrado ou inativo", clear=False)

    raw_value = request.POST.get("value", "")
    try:
        parsed_value = _coerce_custom_field_value_from_form(
            field_type=definition.field_type,
            raw_value=raw_value,
        )
    except ValueError as exc:
        response = _render_incident_partial(
            request,
            incident,
            "webui/partials/incident_custom_fields.html",
            extra_context=_incident_custom_fields_context(
                incident,
                editing_internal_id=internal_id,
                submitted_values={internal_id: raw_value},
                field_errors={internal_id: str(exc)},
            ),
            status=400,
        )
        return _hx_trigger(response, "error", "Corrija o campo customizado", clear=False)

    definition_map = get_custom_field_definition_map(include_inactive=True)
    try:
        validated_payload = validate_custom_field_input(
            {internal_id: parsed_value},
            definition_map=definition_map,
            active_only=True,
        )
    except CustomFieldPayloadError as exc:
        response = _render_incident_partial(
            request,
            incident,
            "webui/partials/incident_custom_fields.html",
            extra_context=_incident_custom_fields_context(
                incident,
                editing_internal_id=internal_id,
                submitted_values={internal_id: raw_value},
                field_errors=exc.errors,
            ),
            status=400,
        )
        return _hx_trigger(response, "error", "Corrija o campo customizado", clear=False)

    current_values, reconciled_changed = reconcile_custom_field_values(
        incident.custom_fields or {},
        definition_map=definition_map,
    )
    new_values = dict(current_values)
    new_values.update(validated_payload)
    changed = reconciled_changed or new_values != current_values
    if changed:
        incident.custom_fields = new_values
        incident.save(update_fields=["custom_fields", "updated_at"])
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.NOTE,
            message=f"Campo customizado '{definition.display_name}' atualizado",
            actor=request.user,
            extra={"custom_field_ids": [internal_id]},
        )

    if not _is_htmx(request):
        level = messages.SUCCESS if changed else messages.INFO
        text = "Campo customizado atualizado" if changed else "Nenhuma alteracao aplicada"
        messages.add_message(request, level, text)
        return redirect("webui:incident_detail", pk=pk)

    response = _render_incident_partial(
        request,
        incident,
        "webui/partials/incident_custom_fields.html",
        extra_context=_incident_custom_fields_context(incident),
    )
    trigger_level = "success" if changed else "info"
    trigger_message = "Campo customizado atualizado" if changed else "Nenhuma alteracao aplicada"
    return _hx_trigger(response, trigger_level, trigger_message)


@login_required
def incident_escalation_partial(request, pk: int):
    incident = get_object_or_404(
        Incident.objects.prefetch_related("secondary_assignees"),
        pk=pk,
    )
    return _render_incident_partial(
        request,
        incident,
        "webui/partials/incident_escalation.html",
        extra_context=_incident_escalation_context(incident),
    )


@login_required
@require_POST
def incident_escalation_update(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    level = request.POST.get("level", "").strip()
    normalized_secondary_ids = _normalize_user_ids(request.POST.getlist("secondary_assignees"))
    selected_users = list(
        User.objects.filter(is_active=True, id__in=normalized_secondary_ids)
    )
    selected_user_map = {user.id: user for user in selected_users}
    resolved_secondary_ids = [
        user_id for user_id in normalized_secondary_ids if user_id in selected_user_map
    ]
    targets = [
        (selected_user_map[user_id].get_full_name() or selected_user_map[user_id].get_username())
        for user_id in resolved_secondary_ids
    ]
    escalation_result = escalate_incident(
        incident=incident,
        level=level,
        targets=targets,
        actor=request.user,
    )
    secondary_result = update_incident_secondary_assignees(
        incident=incident,
        assignee_ids=resolved_secondary_ids,
        actor=request.user,
    )
    changed = escalation_result.changed or secondary_result.changed
    message = "Escalonamento atualizado" if changed else "Nenhuma alteracao aplicada"
    if not _is_htmx(request):
        messages.success(request, message)
        return redirect("webui:incident_detail", pk=pk)
    response = incident_escalation_partial(request, pk)
    level = "success" if changed else "info"
    return _hx_trigger(response, level, message)


@login_required
def incident_escalation_user_search(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    query = request.GET.get("q", "")
    selected_ids = set(_normalize_user_ids(request.GET.getlist("secondary_assignees")))
    users = _search_team_users(query=query, limit=25)
    return render(
        request,
        "webui/partials/incident_escalation_user_results.html",
        {
            "incident_id": incident.id,
            "users": users,
            "selected_ids": selected_ids,
        },
    )


@login_required
def incident_communications_partial(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    extra = {"team_users": _team_users()}
    return _render_incident_partial(
        request,
        incident,
        "webui/partials/incident_communications.html",
        extra_context=extra,
    )


@login_required
@require_POST
def incident_communication_create(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    channel = request.POST.get("channel", "internal").strip() or "internal"
    recipient_team = request.POST.get("recipient_team", "").strip()
    recipient_user_id = request.POST.get("recipient_user_id")
    message_text = request.POST.get("message", "").strip()
    recipient_user = None
    if recipient_user_id:
        recipient_user = get_object_or_404(User, pk=recipient_user_id, is_active=True)
    if not message_text:
        response = incident_communications_partial(request, pk)
        return _hx_trigger(response, "error", "Informe a mensagem", clear=False)
    create_communication(
        incident=incident,
        channel=channel,
        recipient_team=recipient_team,
        recipient_user=recipient_user,
        message=message_text,
        actor=request.user,
    )
    if not _is_htmx(request):
        messages.success(request, "Comunicação registrada")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_communications_partial(request, pk)
    return _hx_trigger(response, "success", "Comunica??o registrada")


@login_required
def incident_relations_partial(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    extra = {"relation_choices": IncidentRelation.RelationType.choices}
    return _render_incident_partial(request, incident, "webui/partials/incident_relations.html", extra_context=extra)


@login_required
@require_POST
def incident_relation_create(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    target_id = request.POST.get("incident_id")
    relation_type = request.POST.get("relation_type")
    if not target_id or not relation_type:
        response = incident_relations_partial(request, pk)
        return _hx_trigger(response, "error", "Informe o incidente e o tipo de rela??o", clear=False)
    try:
        target_incident = Incident.objects.get(pk=target_id)
    except Incident.DoesNotExist:
        response = incident_relations_partial(request, pk)
        return _hx_trigger(response, "error", "Incidente relacionado n?o encontrado", clear=False)
    try:
        link_incident(
            source=incident,
            target=target_incident,
            relation_type=relation_type,
            actor=request.user,
        )
    except ValueError as exc:
        response = incident_relations_partial(request, pk)
        return _hx_trigger(response, "error", str(exc), clear=False)
    if not _is_htmx(request):
        messages.success(request, "Rela??o adicionada")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_relations_partial(request, pk)
    return _hx_trigger(response, "success", "Rela??o adicionada")


@login_required
@require_POST
def incident_relation_delete(request, pk: int, relation_id: int):
    incident = get_object_or_404(Incident, pk=pk)
    relation = get_object_or_404(IncidentRelation, pk=relation_id, from_incident=incident)
    unlink_incident(relation=relation, actor=request.user)
    if not _is_htmx(request):
        messages.success(request, "Rela??o removida")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_relations_partial(request, pk)
    return _hx_trigger(response, "success", "Rela??o removida")


@login_required
def incident_timeline_partial(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    entry_type = request.GET.get("type", "")
    after_param = request.GET.get("after")
    entries = incident.timeline.select_related("created_by").order_by("-created_at")
    if entry_type:
        entries = entries.filter(entry_type=entry_type)
    if after_param:
        after_dt = parse_datetime(after_param)
        if after_dt:
            entries = entries.filter(created_at__gt=after_dt)
    entries = entries[:100]
    latest = entries[0].created_at.isoformat() if entries else (
        incident.timeline.order_by("-created_at").first().created_at.isoformat() if incident.timeline.exists() else ""
    )
    extra = {
        "timeline_entries": list(entries),
        "timeline_form": TimelineEntryForm(),
        "selected_type": entry_type,
        "latest_timeline_ts": latest,
    }
    return _render_incident_partial(request, incident, "webui/partials/incident_timeline.html", extra_context=extra)


@login_required
@require_POST
def incident_timeline_add_note(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    form = TimelineEntryForm(request.POST)
    if form.is_valid():
        note = form.cleaned_data["message"]
        TimelineEntry.objects.create(
            incident=incident,
            entry_type=TimelineEntry.EntryType.NOTE,
            message=note,
            created_by=request.user,
        )
        log_action(actor=request.user, verb="incident.note_added", target=incident, meta={})
        if not _is_htmx(request):
            messages.success(request, "Nota adicionada")
            return redirect("webui:incident_detail", pk=pk)
        response = incident_timeline_partial(request, pk)
        return _hx_trigger(response, "success", "Nota adicionada")
    entries = incident.timeline.select_related("created_by").order_by("-created_at")[:100]
    latest = entries[0].created_at.isoformat() if entries else ""
    extra = {
        "timeline_entries": list(entries),
        "timeline_form": form,
        "selected_type": "",
        "latest_timeline_ts": latest,
    }
    response = _render_incident_partial(request, incident, "webui/partials/incident_timeline.html", extra_context=extra)
    if _is_htmx(request):
        return _hx_trigger(response, "error", "N?o foi poss?vel adicionar a nota", clear=False)
    messages.error(request, "N?o foi poss?vel adicionar a nota")
    return redirect("webui:incident_detail", pk=pk)


@login_required
def incident_playbooks_partial(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    available = list(get_manual_playbooks_for_incident(incident))
    extra = {
        "available_playbooks": available,
        "available_playbook_groups": _group_playbooks_by_category(available),
    }
    extra.update(_execution_panel_context(incident))
    return _render_incident_partial(request, incident, "webui/partials/incident_playbooks.html", extra_context=extra)


@login_required
@require_POST
def incident_playbook_run(request, pk: int):
    if not _can_execute_playbooks(request.user):
        raise PermissionDenied("Apenas SOC Lead ou Admin podem executar playbooks manuais")
    incident = get_object_or_404(Incident, pk=pk)
    playbook_id = request.POST.get("playbook_id")
    if not playbook_id:
        response = incident_playbooks_partial(request, pk)
        return _hx_trigger(response, "error", "Selecione um playbook manual valido", clear=False)
    try:
        playbook_pk = int(playbook_id)
    except (TypeError, ValueError):
        response = incident_playbooks_partial(request, pk)
        return _hx_trigger(response, "error", "Selecione um playbook manual valido", clear=False)
    playbook = get_object_or_404(
        Playbook,
        pk=playbook_pk,
        enabled=True,
        type=Playbook.Type.INCIDENT,
        mode=Playbook.Mode.MANUAL,
    )
    if not is_manual_playbook_available_for_incident(playbook, incident):
        response = incident_playbooks_partial(request, pk)
        return _hx_trigger(response, "error", "Playbook manual nao se aplica a este incidente", clear=False)
    try:
        execution = start_playbook_execution(
            playbook,
            incident,
            actor=request.user,
            context={
                "event": "manual.incident",
                "source": "webui",
                "incident_id": incident.id,
            },
        )
    except ValueError as exc:
        response = incident_playbooks_partial(request, pk)
        return _hx_trigger(response, "error", str(exc), clear=False)
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
    if not _is_htmx(request):
        messages.success(request, f"Playbook '{playbook.name}' iniciado")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_playbooks_partial(request, pk)
    return _hx_trigger(response, "success", f"Playbook '{playbook.name}' iniciado")

@login_required
@require_POST
def incident_playbook_rerun(request, pk: int):
    if not _can_execute_playbooks(request.user):
        raise PermissionDenied("Apenas SOC Lead ou Admin podem executar playbooks manuais")
    incident = get_object_or_404(Incident, pk=pk)
    last_execution = (
        Execution.objects.filter(incident=incident)
        .select_related("playbook")
        .order_by("-started_at")
        .first()
    )
    if not last_execution or not last_execution.playbook:
        response = incident_playbooks_partial(request, pk)
        return _hx_trigger(response, "error", "Nenhuma execu??o anterior encontrada", clear=False)
    playbook = last_execution.playbook
    try:
        execution = start_playbook_execution(playbook, incident, actor=request.user)
    except ValueError as exc:
        response = incident_playbooks_partial(request, pk)
        return _hx_trigger(response, "error", str(exc), clear=False)
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
    if not _is_htmx(request):
        messages.success(request, f"Playbook '{playbook.name}' reexecutado")
        return redirect("webui:incident_detail", pk=pk)
    response = incident_playbooks_partial(request, pk)
    return _hx_trigger(response, "success", f"Playbook '{playbook.name}' reexecutado")


@login_required
def incident_assignee_search(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    query = request.GET.get("q", "")
    users = _search_team_users(query=query, limit=8)
    return render(
        request,
        "webui/partials/incident_assignee_options.html",
        {"incident_id": incident.id, "users": users},
    )


@login_required
def incident_label_suggestions(request, pk: int):
    incident = get_object_or_404(Incident, pk=pk)
    query = request.GET.get("q", "").strip().lower()
    existing = {label.lower() for label in incident.labels}
    suggestions: set[str] = set()
    for labels in Incident.objects.values_list("labels", flat=True):
        if not labels:
            continue
        for label in labels:
            label_lower = label.lower()
            if label_lower in existing:
                continue
            if not query or query in label_lower:
                suggestions.add(label)
    results = sorted(suggestions)[:15]
    return render(
        request,
        "webui/partials/incident_label_suggestions.html",
        {"incident_id": incident.id, "suggestions": results},
    )


@login_required
def incident_export_pdf(request, pk: int):
    queryset = (
        Incident.objects.select_related("assignee", "created_by")
        .prefetch_related(
            "artifacts",
            "tasks__owner",
            "tasks__created_by",
            "communications__created_by",
            "communications__recipient_user",
            "timeline__created_by",
            "relations_from__to_incident",
            "executions__playbook",
        )
    )
    incident = get_object_or_404(queryset, pk=pk)
    context = _incident_context(incident)
    context.update(
        {
            "tasks": incident.tasks.all(),
            "timeline_entries": incident.timeline.all(),
            "artifacts": incident.artifacts.all(),
            "communications": incident.communications.all(),
            "relations": incident.relations_from.select_related("to_incident").all(),
            "executions": incident.executions.select_related("playbook").all(),
            "generated_at": timezone.now(),
            "exported_by": request.user,
            "organization_name": "basilio-soar",
        }
    )
    html = render_to_string("webui/incident_export_pdf.html", context, request=request)
    base_url = request.build_absolute_uri("/")
    from weasyprint import HTML

    pdf_bytes = HTML(string=html, base_url=base_url).write_pdf()
    filename = f"incident-{incident.id}.pdf"
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


class PlaybookListView(LoginRequiredMixin, ListView):
    model = Playbook
    template_name = "webui/playbook_list.html"
    context_object_name = "playbooks"
    paginate_by = 20
    ordering = ["category", "name"]

    def get_queryset(self):
        queryset = Playbook.objects.order_by("category", "name")
        category = (self.request.GET.get("category") or "").strip()
        self.active_category = category
        if category:
            queryset = queryset.filter(category=category)
        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["automation_section"] = "playbooks"
        playbooks = list(context["playbooks"])
        grouped: list[dict[str, object]] = []
        current_category = None
        current_items = []
        for playbook in playbooks:
            category = playbook.category_display
            if category != current_category:
                if current_category is not None:
                    grouped.append({"category": current_category, "playbooks": current_items})
                current_category = category
                current_items = [playbook]
            else:
                current_items.append(playbook)
        if current_category is not None:
            grouped.append({"category": current_category, "playbooks": current_items})
        context["playbook_groups"] = grouped
        context["playbook_categories"] = (
            Playbook.objects.order_by("category").values_list("category", flat=True).distinct()
        )
        context["active_category"] = self.active_category
        return context


class PlaybookDetailView(LoginRequiredMixin, DetailView):
    model = Playbook
    template_name = "webui/playbook_detail.html"
    context_object_name = "playbook"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["automation_section"] = "playbooks"
        context["run_form"] = PlaybookRunForm()
        context["executions"] = (
            self.object.executions.select_related("incident")
            .prefetch_related("step_results")
            .order_by("-started_at")[:10]
        )
        context["dsl_pretty"] = json.dumps(self.object.dsl, indent=2) if self.object.dsl else "{}"
        return context


class PlaybookBaseFormView(LoginRequiredMixin, View):
    form_class = PlaybookForm
    template_name = "webui/playbook_form.html"
    success_message = "Playbook salvo"

    def get_object(self):
        return None

    def get(self, request, pk=None):
        instance = self.get_object() if pk else None
        form = self.form_class(instance=instance)
        return self.render(form)

    def post(self, request, pk=None):
        instance = self.get_object() if pk else None
        form = self.form_class(request.POST, instance=instance)
        if form.is_valid():
            playbook = form.save(commit=False)
            if instance is None:
                playbook.created_by = request.user
            else:
                playbook.updated_by = request.user
            playbook.save()
            messages.success(request, self.success_message)
            return redirect("webui:playbook_detail", pk=playbook.pk)
        messages.error(request, "Corrija os erros do formulario")
        return self.render(form)

    def render(self, form):
        context = {
            "form": form,
            "automation_section": "playbooks",
            "guide_steps": playbook_docs.get_guide_steps(),
            "trigger_examples": playbook_docs.get_trigger_examples(),
            "action_catalog": playbook_docs.get_action_catalog(),
            "dsl_scaffold": playbook_docs.DSL_SCAFFOLD,
            "reference_snippets": playbook_docs.get_reference_snippets(),
        }
        return render(self.request, self.template_name, context)


class PlaybookCreateView(PlaybookBaseFormView):
    success_message = "Playbook criado"


class PlaybookUpdateView(PlaybookBaseFormView):
    success_message = "Playbook atualizado"

    def get_object(self):
        return get_object_or_404(Playbook, pk=self.kwargs["pk"])




@login_required
@require_POST
def incident_artifact_run_playbook(request, pk: int, artifact_id: int, playbook_id: int):
    if not _can_execute_playbooks(request.user):
        raise PermissionDenied("Apenas SOC Lead ou Admin podem executar playbooks manuais")
    incident = get_object_or_404(Incident, pk=pk)
    artifact = get_object_or_404(incident.artifacts, pk=artifact_id)
    playbook = get_object_or_404(
        Playbook,
        pk=playbook_id,
        enabled=True,
        type=Playbook.Type.ARTIFACT,
        mode=Playbook.Mode.MANUAL,
    )
    if not is_manual_playbook_available_for_artifact(playbook, artifact, incident=incident):
        messages.error(request, "Playbook manual nao se aplica a este artefato")
        return redirect("webui:incident_detail", pk=pk)
    context = {
        "event": "manual.artifact",
        "artifact": {
            "id": artifact.id,
            "type": artifact.type,
            "value": artifact.value,
            "attributes": artifact.attributes or {},
        },
        "source": "webui",
        "incident_id": incident.id,
    }
    try:
        execution = start_playbook_execution(playbook, incident, actor=request.user, context=context)
        messages.success(
            request,
            f"Playbook '{playbook.name}' executado para o artefato #{artifact.id} (execucao #{execution.id})",
        )
    except ValueError as exc:
        messages.error(request, str(exc))
    return redirect("webui:incident_detail", pk=pk)


class PlaybookRunView(LoginRequiredMixin, View):
    def post(self, request, pk):
        if not _can_execute_playbooks(request.user):
            raise PermissionDenied("Apenas SOC Lead ou Admin podem executar playbooks manuais")
        playbook = get_object_or_404(
            Playbook,
            pk=pk,
            type=Playbook.Type.INCIDENT,
            mode=Playbook.Mode.MANUAL,
        )
        form = PlaybookRunForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Selecione um incidente valido")
            return redirect("webui:playbook_detail", pk=pk)
        incident = form.cleaned_data["incident"]
        if not is_manual_playbook_available_for_incident(playbook, incident):
            messages.error(request, "Playbook manual nao se aplica a este incidente")
            return redirect("webui:playbook_detail", pk=pk)
        try:
            execution = start_playbook_execution(
                playbook,
                incident,
                actor=request.user,
                context={
                    "event": "manual.incident",
                    "source": "webui",
                    "incident_id": incident.id,
                },
            )
            messages.success(
                request,
                f"Playbook executado para incidente #{incident.id} (execucao #{execution.id})",
            )
        except ValueError as exc:
            messages.error(request, str(exc))
        return redirect("webui:playbook_detail", pk=pk)


class AutomationAdminAccessMixin(LoginRequiredMixin):
    permission_message = "Apenas SOC Lead ou Admin podem gerenciar automacoes."

    def has_access(self, user) -> bool:
        return _can_manage_integrations(user)

    def dispatch(self, request, *args, **kwargs):
        if not self.has_access(request.user):
            raise PermissionDenied(self.permission_message)
        return super().dispatch(request, *args, **kwargs)


class IntegrationAccessMixin(AutomationAdminAccessMixin):
    permission_message = "Apenas SOC Lead ou Admin podem gerenciar conectores HTTP"

    def has_access(self, user) -> bool:
        return _can_manage_integrations(user)


class IncidentSettingsAccessMixin(AutomationAdminAccessMixin):
    permission_message = "Apenas SOC Lead ou Admin podem gerenciar configuracoes de incidentes"

    def has_access(self, user) -> bool:
        return _can_manage_incident_settings(user)


class HttpConnectorListView(IntegrationAccessMixin, TemplateView):
    template_name = "webui/integration_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["automation_section"] = "connectors"
        context["connectors"] = IntegrationDefinition.objects.select_related("secret_ref").order_by("action_name")
        context["connector_secrets"] = IntegrationSecretRef.objects.select_related(
            "created_by",
            "rotated_by",
        ).order_by("name")
        return context


class HttpConnectorSecretListView(IntegrationAccessMixin, TemplateView):
    template_name = "webui/integration_secret_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["automation_section"] = "secrets"
        context["connector_secrets"] = IntegrationSecretRef.objects.select_related(
            "created_by",
            "rotated_by",
        ).order_by("name")
        return context


class HttpConnectorSecretDetailView(IntegrationAccessMixin, DetailView):
    model = IntegrationSecretRef
    template_name = "webui/integration_secret_detail.html"
    context_object_name = "secret_ref"

    def get_queryset(self):
        return IntegrationSecretRef.objects.select_related("created_by", "rotated_by")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["automation_section"] = "secrets"
        return context


class HttpConnectorBaseFormView(IntegrationAccessMixin, View):
    form_class = HttpConnectorForm
    template_name = "webui/integration_form.html"
    success_message = "Conector HTTP salvo"

    def get_object(self):
        return None

    def get(self, request, pk=None):
        instance = self.get_object() if pk else None
        form = self.form_class(instance=instance)
        test_form = IntegrationTestForm() if instance else None
        return self.render(form, instance, test_form=test_form)

    def post(self, request, pk=None):
        instance = self.get_object() if pk else None
        form = self.form_class(request.POST, instance=instance)
        if form.is_valid():
            form.save()
            messages.success(request, self.success_message)
            return redirect("webui:http_connector_list")
        messages.error(request, "Corrija os erros do formulario")
        test_form = IntegrationTestForm() if instance else None
        return self.render(form, instance, test_form=test_form)

    def render(self, form, instance, *, test_form=None, test_result=None, test_error=None):
        return render(
            self.request,
            self.template_name,
            {
                "form": form,
                "object": instance,
                "automation_section": "connectors",
                "test_form": test_form,
                "test_result": test_result,
                "test_error": test_error,
            },
        )


class HttpConnectorCreateView(HttpConnectorBaseFormView):
    success_message = "Conector HTTP criado"


class HttpConnectorUpdateView(HttpConnectorBaseFormView):
    success_message = "Conector HTTP atualizado"

    def get_object(self):
        return get_object_or_404(IntegrationDefinition, pk=self.kwargs["pk"])


def _default_http_connector_test_context() -> dict[str, object]:
    return {
        "incident": {},
        "artifact": {},
        "results": {},
        "trigger_context": {},
        "execution": {},
    }


class HttpConnectorTestView(IntegrationAccessMixin, View):
    def post(self, request, pk):
        connector = get_object_or_404(
            IntegrationDefinition.objects.select_related("secret_ref"),
            pk=pk,
        )
        form = HttpConnectorForm(instance=connector)
        test_form = IntegrationTestForm(request.POST)
        if not test_form.is_valid():
            messages.error(request, "Corrija os erros do teste")
            return render(
                request,
                "webui/integration_form.html",
                {
                    "form": form,
                    "object": connector,
                    "automation_section": "connectors",
                    "test_form": test_form,
                },
            )

        try:
            preview = preview_configured_integration(
                integration=connector,
                params=test_form.cleaned_data["params_text"],
                runtime_context=_default_http_connector_test_context(),
                execute_http=test_form.cleaned_data["execute_request"],
            )
        except ValueError as exc:
            messages.error(request, str(exc))
            return render(
                request,
                "webui/integration_form.html",
                {
                    "form": form,
                    "object": connector,
                    "automation_section": "connectors",
                    "test_form": test_form,
                    "test_error": str(exc),
                },
            )

        messages.success(request, "Teste executado")
        return render(
            request,
            "webui/integration_form.html",
            {
                "form": form,
                "object": connector,
                "automation_section": "connectors",
                "test_form": test_form,
                "test_result": json.dumps(preview, indent=2, ensure_ascii=False),
            },
        )


class HttpConnectorSecretBaseFormView(IntegrationAccessMixin, View):
    form_class = HttpConnectorSecretForm
    template_name = "webui/integration_secret_form.html"
    success_message = "Secret do conector salvo"

    def get_object(self):
        return None

    def get(self, request, pk=None):
        instance = self.get_object() if pk else None
        form = self.form_class(instance=instance)
        return self.render(form, instance)

    def post(self, request, pk=None):
        instance = self.get_object() if pk else None
        form = self.form_class(request.POST, instance=instance)
        if form.is_valid():
            form.save(actor=request.user)
            messages.success(request, self.success_message)
            return redirect("webui:http_connector_secret_detail", pk=form.instance.pk)
        messages.error(request, "Corrija os erros do formulario")
        return self.render(form, instance)

    def render(self, form, instance):
        return render(
            self.request,
            self.template_name,
            {
                "form": form,
                "object": instance,
                "automation_section": "secrets",
            },
        )


class HttpConnectorSecretCreateView(HttpConnectorSecretBaseFormView):
    success_message = "Secret do conector criado"


class HttpConnectorSecretUpdateView(HttpConnectorSecretBaseFormView):
    success_message = "Secret do conector atualizado"

    def get_object(self):
        return get_object_or_404(
            IntegrationSecretRef.objects.select_related("created_by", "rotated_by"),
            pk=self.kwargs["pk"],
        )


class CustomFieldDefinitionListView(IncidentSettingsAccessMixin, TemplateView):
    template_name = "webui/custom_field_list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        queryset = (
            CustomFieldDefinition.objects.filter(is_deleted=False)
            .select_related("created_by", "updated_by")
            .order_by("display_name", "internal_id")
        )
        context["automation_section"] = "custom_fields"
        context["custom_fields"] = queryset
        context["active_count"] = queryset.filter(is_active=True).count()
        context["inactive_count"] = queryset.filter(is_active=False).count()
        return context


class CustomFieldDefinitionBaseFormView(IncidentSettingsAccessMixin, View):
    form_class = CustomFieldDefinitionForm
    template_name = "webui/custom_field_form.html"
    success_message = "Campo customizado salvo"

    def get_object(self):
        return None

    def get(self, request, pk=None):
        instance = self.get_object() if pk else None
        form = self.form_class(instance=instance)
        return self.render(form, instance)

    def post(self, request, pk=None):
        instance = self.get_object() if pk else None
        form = self.form_class(request.POST, instance=instance)
        if form.is_valid():
            custom_field = form.save(commit=False)
            if not custom_field.created_by_id:
                custom_field.created_by = request.user
            custom_field.updated_by = request.user
            custom_field.save()
            messages.success(request, self.success_message)
            return redirect("webui:custom_field_list")
        messages.error(request, "Corrija os erros do formulario")
        return self.render(form, instance)

    def render(self, form, instance):
        return render(
            self.request,
            self.template_name,
            {
                "form": form,
                "object": instance,
                "automation_section": "custom_fields",
            },
        )


class CustomFieldDefinitionCreateView(CustomFieldDefinitionBaseFormView):
    success_message = "Campo customizado criado"


class CustomFieldDefinitionUpdateView(CustomFieldDefinitionBaseFormView):
    success_message = "Campo customizado atualizado"

    def get_object(self):
        return get_object_or_404(
            CustomFieldDefinition.objects.filter(is_deleted=False).select_related("created_by", "updated_by"),
            pk=self.kwargs["pk"],
        )


@login_required
@require_POST
def custom_field_delete(request, pk: int):
    if not _can_manage_incident_settings(request.user):
        raise PermissionDenied("Apenas SOC Lead ou Admin podem gerenciar configuracoes de incidentes")
    custom_field = get_object_or_404(CustomFieldDefinition.objects.filter(is_deleted=False), pk=pk)
    internal_id = custom_field.internal_id
    custom_field.is_deleted = True
    custom_field.is_active = False
    custom_field.updated_by = request.user
    custom_field.save(update_fields=["is_deleted", "is_active", "updated_by", "updated_at"])
    remove_custom_field_from_all_incidents(internal_id=internal_id)
    messages.success(request, f"Campo customizado '{custom_field.display_name}' removido")
    return redirect("webui:custom_field_list")


class CustomLoginView(LoginView):
    template_name = "webui/login.html"
    form_class = TailwindAuthenticationForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        response = super().form_valid(form)
        if _is_htmx(self.request):
            response["HX-Redirect"] = self.get_success_url()
        return response

    def form_invalid(self, form):
        if _is_htmx(self.request):
            response = render(self.request, "webui/login.html", {"form": form})
            return _hx_trigger(response, "error", "Credenciais invalidas")
        return super().form_invalid(form)

    def get_success_url(self):
        return self.get_redirect_url() or reverse("webui:dashboard")


class CustomLogoutView(LogoutView):
    template_name = "registration/logged_out.html"
    http_method_names = ["get", "post", "options"]

    def get(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        auth_logout(request)
        return render(request, self.template_name, {})

    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        if _is_htmx(request):
            response["HX-Redirect"] = reverse("webui:login")
        return response
