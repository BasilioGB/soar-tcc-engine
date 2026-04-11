from __future__ import annotations

from typing import Any, Dict

from django.contrib.auth import get_user_model
from django.utils.dateparse import parse_datetime

from audit.utils import log_action
from incidents.models import IncidentTask, TimelineEntry
from incidents.services import (
    add_artifact_link,
    create_communication,
    create_task,
    escalate_incident,
    update_incident_assignee,
    update_incident_impact,
    update_incident_labels,
    update_incident_status,
    update_task,
)

from ..registry import register

User = get_user_model()


def _require_incident(context: Dict[str, Any]):
    incident = context.get("incident")
    if incident is None:
        raise ValueError("Contexto sem incidente")
    return incident


def _resolve_user(identifier):
    if not identifier:
        return None
    if isinstance(identifier, User):
        return identifier
    try:
        return User.objects.get(pk=int(identifier))
    except (User.DoesNotExist, ValueError, TypeError):
        try:
            return User.objects.get(username=str(identifier))
        except User.DoesNotExist:
            raise ValueError(f"Usuario '{identifier}' nao encontrado")


@register("incident.add_label")
def add_label(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    label = step.input.get("label")
    if not label:
        raise ValueError("Label obrigatorio")
    actor = context.get("actor")
    incident.add_label(label, actor=actor)
    return {"label": label, "labels": incident.labels}


@register("incident.add_labels")
def add_labels(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    labels = step.input.get("labels") or []
    if not isinstance(labels, (list, tuple)):
        raise ValueError("labels deve ser uma lista")
    actor = context.get("actor")
    update_incident_labels(incident=incident, add=list(labels), actor=actor)
    return {"labels": incident.labels}


@register("incident.add_note")
def add_note(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    message = step.input.get("message")
    if not message:
        raise ValueError("Mensagem obrigatoria")
    entry_type = step.input.get("entry_type", TimelineEntry.EntryType.NOTE)
    meta = step.input.get("meta", {})
    actor = context.get("actor")
    incident.log_timeline(entry_type=entry_type, message=message, actor=actor, extra=meta)
    return {"message": message, "entry_type": entry_type, "meta": meta}


@register("incident.update_status")
def update_status(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    status = step.input.get("status")
    if not status:
        raise ValueError("Status obrigatorio")
    reason = step.input.get("reason")
    actor = context.get("actor")
    result = update_incident_status(incident=incident, status=status, reason=reason, actor=actor)
    return {"status": incident.status, "changed": result.changed, "reason": reason}


@register("incident.assign")
def assign_incident(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    identifier = step.input.get("assignee") or step.input.get("assignee_id")
    assignee = _resolve_user(identifier) if identifier else None
    actor = context.get("actor")
    result = update_incident_assignee(incident=incident, assignee=assignee, actor=actor)
    return {
        "assignee": getattr(assignee, "username", None),
        "changed": result.changed,
    }


@register("incident.update_impact")
def update_impact(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    data = {
        "impact_systems": step.input.get("impact_systems"),
        "risk_score": step.input.get("risk_score"),
        "severity": step.input.get("severity"),
        "estimated_cost": step.input.get("estimated_cost"),
        "business_unit": step.input.get("business_unit"),
        "data_classification": step.input.get("data_classification"),
    }
    actor = context.get("actor")
    result = update_incident_impact(incident=incident, actor=actor, **data)
    payload = {
        "impact_systems": incident.impact_systems,
        "risk_score": incident.risk_score,
        "severity": incident.severity,
        "estimated_cost": incident.estimated_cost,
        "business_unit": incident.business_unit,
        "data_classification": incident.data_classification,
        "changed": result.changed,
    }
    return payload


@register("incident.escalate")
def escalate(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    level = step.input.get("level")
    targets = step.input.get("targets") or []
    if level is None and not targets:
        raise ValueError("Informe level ou targets")
    actor = context.get("actor")
    result = escalate_incident(incident=incident, level=level, targets=targets, actor=actor)
    return {
        "level": incident.escalation_level,
        "targets": incident.escalation_targets,
        "changed": result.changed,
    }


@register("incident.log_action")
def log_audit_action(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    verb = step.input.get("verb")
    if not verb:
        raise ValueError("Verbo obrigatorio")
    meta = step.input.get("meta", {})
    actor = context.get("actor")
    entry = log_action(actor=actor, verb=verb, target=incident, meta=meta)
    return {"verb": entry.verb, "meta": entry.meta}


@register("task.create")
def create_followup_task(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    title = step.input.get("title")
    if not title:
        raise ValueError("Titulo obrigatorio")
    owner_identifier = step.input.get("owner") or step.input.get("owner_id")
    owner = _resolve_user(owner_identifier) if owner_identifier else None
    eta_raw = step.input.get("eta")
    eta = parse_datetime(eta_raw) if eta_raw else None
    actor = context.get("actor")
    task = create_task(incident=incident, title=title, owner=owner, eta=eta, actor=actor)
    return {
        "task_id": task.id,
        "title": task.title,
        "owner": getattr(task.owner, "username", None),
        "eta": task.eta.isoformat() if task.eta else None,
    }


@register("task.complete")
def complete_task(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    task_id = step.input.get("task_id")
    title = step.input.get("title")
    if not task_id and not title:
        raise ValueError("Informe task_id ou title")
    try:
        if task_id:
            task = IncidentTask.objects.get(pk=task_id, incident=incident)
        else:
            task = IncidentTask.objects.filter(incident=incident, title=title).latest("created_at")
    except IncidentTask.DoesNotExist:
        raise ValueError("Tarefa nao encontrada")
    done = step.input.get("done", True)
    actor = context.get("actor")
    update_task(task=task, done=done, actor=actor)
    return {"task_id": task.id, "done": task.done}


@register("communication.log")
def log_communication(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    message = step.input.get("message")
    if not message:
        raise ValueError("Mensagem obrigatoria")
    recipient_user = step.input.get("recipient_user") or step.input.get("recipient_user_id")
    recipient_user = _resolve_user(recipient_user) if recipient_user else None
    actor = context.get("actor")
    communication = create_communication(
        incident=incident,
        channel=step.input.get("channel", "internal"),
        recipient_team=step.input.get("recipient_team"),
        recipient_user=recipient_user,
        message=message,
        actor=actor,
    )
    return {
        "communication_id": communication.id,
        "channel": communication.channel,
        "recipient_team": communication.recipient_team,
        "recipient_user": getattr(communication.recipient_user, "username", None),
    }


@register("artifact.create")
def create_artifact(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    value = step.input.get("value")
    if not value:
        raise ValueError("value obrigatorio")
    type_code = step.input.get("type", "OTHER")
    actor = context.get("actor")
    artifact = add_artifact_link(
        incident=incident,
        value=value,
        type_code=type_code,
        actor=actor,
    )
    return {"artifact_id": artifact.id, "type": artifact.type, "value": artifact.value}


@register("artifact.extract_domain_from_email")
def extract_domain_from_email(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    email = step.input.get("email")
    if not email:
        source_artifact_id = step.input.get("artifact_id")
        if source_artifact_id:
            try:
                artifact = incident.artifacts.get(pk=source_artifact_id)
                email = artifact.value
            except incident.artifacts.model.DoesNotExist:
                raise ValueError("Artefato de email nao encontrado")
    if not email or "@" not in email:
        raise ValueError("Email invalido para extrair dominio")
    domain = email.split("@", 1)[1].strip().lower()
    actor = context.get("actor")
    artifact = add_artifact_link(
        incident=incident,
        value=domain,
        type_code="DOMAIN",
        actor=actor,
    )
    incident.add_label("domain-extracted", actor=actor)
    return {"domain": domain, "artifact_id": artifact.id}
