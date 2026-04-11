from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction

from audit.utils import log_action
from core.realtime import broadcast_incident_update
from .models import (
    Artifact,
    CommunicationLog,
    Incident,
    IncidentArtifact,
    IncidentRelation,
    IncidentTask,
    TimelineEntry,
)

SENTINEL = object()

User = get_user_model()


@dataclass
class OperationResult:
    changed: bool
    incident: Incident | None = None


def update_incident_status(*, incident: Incident, status: str, actor, reason: str | None = None) -> OperationResult:
    with transaction.atomic():
        changed = incident.set_status(status=status, actor=actor, reason=reason)
        if changed:
            log_action(
                actor=actor,
                verb="incident.status_changed",
                target=incident,
                meta={"to": status, "reason": reason},
            )
            broadcast_incident_update(
                incident.id,
                sections=["summary", "lifecycle"],
                payload={"message": "Status do incidente atualizado", "status": status},
            )
    return OperationResult(changed=changed, incident=incident)


def update_incident_assignee(*, incident: Incident, assignee, actor) -> OperationResult:
    with transaction.atomic():
        changed = incident.set_assignee(assignee=assignee, actor=actor)
        if changed:
            log_action(
                actor=actor,
                verb="incident.assignee_changed",
                target=incident,
                meta={"assignee_id": getattr(assignee, "id", None)},
            )
            broadcast_incident_update(
                incident.id,
                sections=["summary"],
                payload={"message": "Responsavel atualizado"},
            )
    return OperationResult(changed=changed, incident=incident)


def update_incident_lifecycle(
    *,
    incident: Incident,
    actor,
    occurred_at=None,
    detected_at=None,
    responded_at=None,
    resolved_at=None,
    closed_at=None,
) -> OperationResult:
    fields = {
        "occurred_at": occurred_at,
        "detected_at": detected_at,
        "responded_at": responded_at,
        "resolved_at": resolved_at,
        "closed_at": closed_at,
    }
    changed = {}
    with transaction.atomic():
        for field, value in fields.items():
            current = getattr(incident, field)
            if value == "":
                value = None
            if value == current:
                continue
            setattr(incident, field, value)
            changed[field] = value
        if not changed:
            return OperationResult(changed=False, incident=incident)
        update_fields = list(changed.keys()) + ["updated_at"]
        incident._save_with_skip_signals(update_fields=update_fields)
        timeline_meta = {}
        for field in changed.keys():
            field_value = getattr(incident, field)
            if hasattr(field_value, "isoformat") and field_value is not None:
                timeline_meta[field] = field_value.isoformat()
            else:
                timeline_meta[field] = field_value
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.NOTE,
            message="Metadados de lifecycle atualizados",
            actor=actor,
            extra=timeline_meta,
        )
        log_action(
            actor=actor,
            verb="incident.lifecycle_updated",
            target=incident,
            meta={field: (value.isoformat() if hasattr(value, "isoformat") else value) for field, value in changed.items()},
        )
        broadcast_incident_update(
            incident.id,
            sections=["summary", "lifecycle"],
            payload={"message": "Datas do incidente atualizadas"},
        )
    return OperationResult(changed=True, incident=incident)


def update_incident_labels(
    *,
    incident: Incident,
    add: Iterable[str] | None = None,
    remove: Iterable[str] | None = None,
    actor,
) -> OperationResult:
    with transaction.atomic():
        changed = incident.set_labels(add=list(add or []), remove=list(remove or []), actor=actor)
        if changed:
            log_action(
                actor=actor,
                verb="incident.labels_changed",
                target=incident,
                meta={"labels": incident.labels},
            )
            broadcast_incident_update(
                incident.id,
                sections=["summary", "taxonomy", "playbooks"],
                payload={"message": "Labels do incidente atualizadas"},
            )
    return OperationResult(changed=changed, incident=incident)


def update_incident_mitre(
    *,
    incident: Incident,
    tactics: list[str] | None = None,
    techniques: list[str] | None = None,
    kill_chain_phase: str | None = None,
    actor,
) -> OperationResult:
    with transaction.atomic():
        changed = incident.update_mitre(
            tactics=tactics, techniques=techniques, kill_chain_phase=kill_chain_phase, actor=actor
        )
        if changed:
            log_action(
                actor=actor,
                verb="incident.mitre_updated",
                target=incident,
                meta={
                    "tactics": incident.mitre_tactics,
                    "techniques": incident.mitre_techniques,
                    "kill_chain": incident.kill_chain_phase,
                },
            )
            broadcast_incident_update(
                incident.id,
                sections=["taxonomy"],
                payload={"message": "Taxonomia MITRE atualizada"},
            )
    return OperationResult(changed=changed, incident=incident)


def update_incident_impact(
    *,
    incident: Incident,
    impact_systems=None,
    risk_score: int | None = None,
    severity: str | None = None,
    estimated_cost=None,
    business_unit: str | None = None,
    data_classification: str | None = None,
    actor,
) -> OperationResult:
    with transaction.atomic():
        changed = incident.update_impact(
            impact_systems=impact_systems,
            risk_score=risk_score,
            severity=severity,
            estimated_cost=estimated_cost,
            business_unit=business_unit,
            data_classification=data_classification,
            actor=actor,
        )
        if changed:
            log_action(
                actor=actor,
                verb="incident.impact_updated",
                target=incident,
                meta={
                    "risk_score": incident.risk_score,
                    "severity": incident.severity,
                    "estimated_cost": str(incident.estimated_cost),
                },
            )
            broadcast_incident_update(
                incident.id,
                sections=["summary", "impact"],
                payload={"message": "Impacto do incidente atualizado"},
            )
    return OperationResult(changed=changed, incident=incident)


def escalate_incident(*, incident: Incident, level: str | None, targets: list[str], actor) -> OperationResult:
    with transaction.atomic():
        changed = incident.update_escalation(level=level, targets=targets, actor=actor)
        if changed:
            log_action(
                actor=actor,
                verb="incident.escalated",
                target=incident,
                meta={"level": level, "targets": targets},
            )
            broadcast_incident_update(
                incident.id,
                sections=["escalation", "timeline"],
                payload={"message": "Escalonamento atualizado"},
            )
    return OperationResult(changed=changed, incident=incident)


def create_communication(
    *,
    incident: Incident,
    channel: str,
    recipient_team: str | None,
    recipient_user,
    message: str,
    actor,
) -> CommunicationLog:
    with transaction.atomic():
        comm = CommunicationLog.objects.create(
            incident=incident,
            channel=channel,
            recipient_team=recipient_team or "",
            recipient_user=recipient_user,
            message=message,
            created_by=actor,
        )
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.COMMUNICATION,
            message=f"Comunicacao registrada via {channel}",
            actor=actor,
            extra={
                "recipient_team": comm.recipient_team,
                "recipient_user": getattr(comm.recipient_user, "id", None),
            },
        )
        log_action(
            actor=actor,
            verb="incident.communication_created",
            target=incident,
            meta={"communication_id": comm.id},
        )
        broadcast_incident_update(
            incident.id,
            sections=["communications", "timeline"],
            payload={"message": "Nova comunicacao registrada"},
        )
        return comm


def create_task(
    *,
    incident: Incident,
    title: str,
    owner,
    eta,
    actor,
) -> IncidentTask:
    with transaction.atomic():
        task = IncidentTask.objects.create(
            incident=incident,
            title=title,
            owner=owner,
            eta=eta,
            created_by=actor,
        )
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.TASK_UPDATE,
            message=f"Tarefa '{title}' criada",
            actor=actor,
            extra={"task_id": task.id, "owner": getattr(owner, "id", None)},
        )
        log_action(
            actor=actor,
            verb="incident.task_created",
            target=incident,
            meta={"task_id": task.id},
        )
        broadcast_incident_update(
            incident.id,
            sections=["tasks", "timeline"],
            payload={"message": f"Tarefa '{title}' criada"},
        )
        return task


def update_task(
    *,
    task: IncidentTask,
    title: str | None = None,
    owner=SENTINEL,
    eta=SENTINEL,
    done=SENTINEL,
    actor,
) -> IncidentTask:
    with transaction.atomic():
        fields: list[str] = []
        changed = False
        if title is not None and title != task.title:
            task.title = title
            fields.append("title")
        if owner is not SENTINEL and owner != task.owner:
            task.owner = owner
            fields.append("owner")
        if eta is not SENTINEL and eta != task.eta:
            task.eta = eta
            fields.append("eta")
        if fields:
            task.save(update_fields=fields + ["updated_at"])
            task.incident.log_timeline(
                entry_type=TimelineEntry.EntryType.TASK_UPDATE,
                message=f"Tarefa '{task.title}' atualizada",
                actor=actor,
                extra={"task_id": task.id},
            )
            changed = True
        if done is not SENTINEL and done != task.done:
            task.toggle(done=done, actor=actor)
            changed = True
        if changed:
            log_action(
                actor=actor,
                verb="incident.task_updated",
                target=task.incident,
                meta={"task_id": task.id},
            )
            broadcast_incident_update(
                task.incident_id,
                sections=["tasks", "timeline"],
                payload={"message": "Dados da tarefa atualizados"},
            )
        return task


def _calculate_sha256(upload: UploadedFile) -> str:
    hasher = hashlib.sha256()
    for chunk in upload.chunks():
        hasher.update(chunk)
    upload.seek(0)
    return hasher.hexdigest()


def add_artifact_from_upload(
    *,
    incident: Incident,
    upload: UploadedFile,
    type_code: str | None = None,
    actor,
) -> Artifact:
    size = upload.size
    content_type = getattr(upload, "content_type", "") or ""
    sha256 = _calculate_sha256(upload)
    artifact_type = type_code or Artifact.Type.FILE
    with transaction.atomic():
        artifact = Artifact.objects.create(
            type=artifact_type,
            file=upload,
            size=size,
            sha256=sha256,
            content_type=content_type,
        )
        IncidentArtifact.objects.create(
            incident=incident,
            artifact=artifact,
            created_by=actor,
        )
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.ARTIFACT_ADDED,
            message=f"Artefato de tipo {artifact.type} anexado",
            actor=actor,
            extra={
                "artifact_id": artifact.id,
                "sha256": artifact.sha256,
                "size": artifact.size,
            },
        )
        log_action(
            actor=actor,
            verb="incident.artifact_uploaded",
            target=incident,
            meta={"artifact_id": artifact.id},
        )
        broadcast_incident_update(
            incident.id,
            sections=["artifacts", "timeline", "summary"],
            payload={"message": "Novo artefato anexado", "artifact_id": artifact.id},
        )
        return artifact


def add_artifact_link(
    *,
    incident: Incident,
    value: str,
    type_code: str,
    actor,
) -> Artifact:
    normalized_value = (value or "").strip()
    if not normalized_value:
        raise ValueError("Valor do artefato nao pode ser vazio")
    with transaction.atomic():
        artifact, created = Artifact.objects.get_or_create(
            type=type_code,
            value=normalized_value,
        )
        membership, membership_created = IncidentArtifact.objects.get_or_create(
            incident=incident,
            artifact=artifact,
            defaults={"created_by": actor},
        )
        if not membership_created:
            return artifact
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.ARTIFACT_ADDED,
            message=f"Artefato de tipo {artifact.type} {'criado' if created else 'associado'}",
            actor=actor,
            extra={"artifact_id": artifact.id},
        )
        log_action(
            actor=actor,
            verb="incident.artifact_linked",
            target=incident,
            meta={"artifact_id": artifact.id},
        )
        broadcast_incident_update(
            incident.id,
            sections=["artifacts", "timeline", "summary"],
            payload={"message": "Artefato vinculado ao incidente", "artifact_id": artifact.id},
        )
        return artifact


def remove_artifact_link(
    *,
    incident: Incident,
    artifact: Artifact,
    actor,
) -> OperationResult:
    with transaction.atomic():
        try:
            membership = IncidentArtifact.objects.get(incident=incident, artifact=artifact)
        except IncidentArtifact.DoesNotExist:
            return OperationResult(changed=False, incident=incident)
        membership.delete()
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.NOTE,
            message=f"Artefato #{artifact.id} removido do incidente",
            actor=actor,
            extra={"artifact_id": artifact.id},
        )
        log_action(
            actor=actor,
            verb="incident.artifact_unlinked",
            target=incident,
            meta={"artifact_id": artifact.id},
        )
    broadcast_incident_update(
        incident.id,
        sections=["artifacts", "timeline", "summary"],
        payload={"message": "Artefato removido do incidente", "artifact_id": artifact.id},
    )
    return OperationResult(changed=True, incident=incident)


def delete_artifact(
    *,
    artifact: Artifact,
    actor,
) -> None:
    with transaction.atomic():
        related_incidents = list(artifact.incidents.all())
        artifact_id = artifact.id
        for incident in related_incidents:
            incident.log_timeline(
                entry_type=TimelineEntry.EntryType.NOTE,
                message=f"Artefato #{artifact_id} removido do incidente (exclusão global)",
                actor=actor,
                extra={"artifact_id": artifact_id},
            )
            log_action(
                actor=actor,
                verb="incident.artifact_unlinked",
                target=incident,
                meta={"artifact_id": artifact_id, "global_delete": True},
            )
            broadcast_incident_update(
                incident.id,
                sections=["artifacts", "timeline", "summary"],
                payload={"message": "Artefato removido globalmente", "artifact_id": artifact_id},
            )
        artifact.delete()


def update_artifact(
    *,
    artifact: Artifact,
    incident: Incident | None = None,
    value=SENTINEL,
    type_code: str | None = None,
    actor,
) -> OperationResult:
    with transaction.atomic():
        updates: dict[str, str] = {}
        if type_code and type_code != artifact.type:
            if artifact.incidents.exclude(pk=getattr(incident, "pk", None)).exists():
                raise ValueError("Nao e possivel alterar o tipo de um artefato compartilhado com outros incidentes")
            artifact.type = type_code
            updates["type"] = type_code
        if value is not SENTINEL:
            if artifact.file:
                raise ValueError("Nao e possivel alterar o valor de um artefato de arquivo")
            new_value = (value or "").strip()
            if not new_value:
                raise ValueError("Valor do artefato nao pode ser vazio")
            if new_value != artifact.value:
                if artifact.incidents.exclude(pk=getattr(incident, "pk", None)).exists():
                    raise ValueError("Nao e possivel alterar o valor de um artefato compartilhado com outros incidentes")
                artifact.value = new_value
                updates["value"] = new_value
        if not updates:
            return OperationResult(changed=False, incident=incident or artifact.primary_incident())
        artifact.save(update_fields=list(updates.keys()))
        affected_incidents = list(artifact.incidents.all())
        for related_incident in affected_incidents:
            related_incident.log_timeline(
                entry_type=TimelineEntry.EntryType.NOTE,
                message=f"Artefato #{artifact.id} atualizado",
                actor=actor,
                extra={"artifact_id": artifact.id, "updates": updates},
            )
            log_action(
                actor=actor,
                verb="incident.artifact_updated",
                target=related_incident,
                meta={"artifact_id": artifact.id, "updates": updates},
            )
            broadcast_incident_update(
                related_incident.id,
                sections=["artifacts", "timeline", "summary"],
                payload={"message": "Artefato atualizado", "artifact_id": artifact.id},
            )
    return OperationResult(changed=True, incident=incident or artifact.primary_incident())


def update_artifact_attributes(
    *,
    artifact: Artifact,
    incident: Incident | None = None,
    attributes: dict[str, Any],
    merge: bool = True,
    actor=None,
) -> OperationResult:
    if not isinstance(attributes, dict):
        raise ValueError("attributes deve ser um objeto")
    with transaction.atomic():
        changed = artifact.set_attributes(attributes=attributes, merge=merge)
        if not changed:
            return OperationResult(changed=False, incident=incident or artifact.primary_incident())
        related_incidents = list(artifact.incidents.all())
        for related_incident in related_incidents:
            related_incident.log_timeline(
                entry_type=TimelineEntry.EntryType.NOTE,
                message=f"Atributos do artefato #{artifact.id} atualizados",
                actor=actor,
                extra={"artifact_id": artifact.id, "attributes": attributes, "merge": merge},
            )
            log_action(
                actor=actor,
                verb="incident.artifact_attributes_updated",
                target=related_incident,
                meta={
                    "artifact_id": artifact.id,
                    "attributes": attributes,
                    "merge": merge,
                },
            )
            broadcast_incident_update(
                related_incident.id,
                sections=["artifacts", "timeline"],
                payload={"message": "Atributos do artefato atualizados", "artifact_id": artifact.id},
            )
    return OperationResult(changed=True, incident=incident or artifact.primary_incident())


def link_incident(
    *,
    source: Incident,
    target: Incident,
    relation_type: str,
    actor,
) -> IncidentRelation:
    if source.pk == target.pk:
        raise ValueError("Nao e possivel relacionar o incidente consigo mesmo.")
    with transaction.atomic():
        relation, created = IncidentRelation.objects.get_or_create(
            from_incident=source,
            to_incident=target,
            relation_type=relation_type,
            defaults={"created_by": actor},
        )
        if not created:
            return relation
        source.log_timeline(
            entry_type=TimelineEntry.EntryType.NOTE,
            message=f"Incidente relacionado ({relation_type}) com #{target.pk}",
            actor=actor,
            extra={"relation_id": relation.id, "to": target.pk},
        )
        log_action(
            actor=actor,
            verb="incident.related",
            target=source,
            meta={"relation_id": relation.id, "to": target.pk, "type": relation_type},
        )
        broadcast_incident_update(
            source.id,
            sections=["relations", "timeline"],
            payload={"message": "Relacao de incidente criada", "relation_id": relation.id},
        )
        return relation


def unlink_incident(*, relation: IncidentRelation, actor) -> None:
    with transaction.atomic():
        source = relation.from_incident
        target_id = relation.to_incident_id
        relation_type = relation.relation_type
        relation.delete()
        source.log_timeline(
            entry_type=TimelineEntry.EntryType.NOTE,
            message=f"Relacao {relation_type} com #{target_id} removida",
            actor=actor,
            extra={"to": target_id, "type": relation_type},
        )
        log_action(
            actor=actor,
            verb="incident.relation_removed",
            target=source,
            meta={"to": target_id, "type": relation_type},
        )
        broadcast_incident_update(
            source.id,
            sections=["relations", "timeline"],
            payload={"message": "Relacao de incidente removida", "relation_type": relation_type, "target_id": target_id},
        )
