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

BRANCH_EXCLUSIVE_LABELS = {
    "credential-compromise",
    "malware-suspected",
    "bec",
    "mailbox-compromise",
}

BRANCH_MINIMUM_CONTAINMENT_TASK_KEYWORDS: dict[str, tuple[str, ...]] = {
    "credential-compromise": (
        "resetar senha e revogar",
        "revisar metodos mfa",
    ),
    "malware-suspected": (
        "isolar o endpoint",
        "bloquear url, hash e dominio",
    ),
    "bec": (
        "acionar financeiro e banco",
        "validar mudanca bancaria",
    ),
    "mailbox-compromise": (
        "resetar a conta e revogar",
        "remover inbox rules",
    ),
}

RECOVERY_MINIMUM_TASK_KEYWORDS: tuple[str, ...] = (
    "validar que conta, mailbox, endpoint e mensagens remanescentes foram limpos",
    "monitorar sign-ins, envio de email e criacao de regras por 7 a 14 dias",
    "comunicar usuario afetado, gestor e registrar resumo executivo final",
    "registrar licoes aprendidas e melhorias obrigatorias pos-incidente",
)


@dataclass
class OperationResult:
    changed: bool
    incident: Incident | None = None


def _normalize_labels_for_branch_exclusivity(
    *,
    add: Iterable[str] | None,
    remove: Iterable[str] | None,
) -> tuple[list[str], list[str]]:
    add_labels: list[str] = []
    remove_labels: list[str] = []

    for raw in add or []:
        label = (raw or "").strip()
        if label:
            add_labels.append(label)

    for raw in remove or []:
        label = (raw or "").strip()
        if label:
            remove_labels.append(label)

    branch_additions = [label for label in add_labels if label in BRANCH_EXCLUSIVE_LABELS]
    if branch_additions:
        selected_branch = branch_additions[-1]
        add_labels = [
            label
            for label in add_labels
            if label not in BRANCH_EXCLUSIVE_LABELS or label == selected_branch
        ]
        remove_labels.extend(BRANCH_EXCLUSIVE_LABELS - {selected_branch})

    deduped_add: list[str] = []
    for label in add_labels:
        if label not in deduped_add:
            deduped_add.append(label)

    deduped_remove: list[str] = []
    for label in remove_labels:
        if label in deduped_add:
            continue
        if label not in deduped_remove:
            deduped_remove.append(label)

    return deduped_add, deduped_remove


def _is_phishing_context(incident: Incident) -> bool:
    labels = set(incident.labels or [])
    return "phishing" in labels or bool(labels & BRANCH_EXCLUSIVE_LABELS)


def _task_matches_keyword(task: IncidentTask, keyword: str) -> bool:
    title = (task.title or "").strip().lower()
    return keyword in title


def _missing_task_keywords(
    *,
    tasks: list[IncidentTask],
    keywords: Iterable[str],
) -> tuple[list[str], list[str]]:
    missing_created: list[str] = []
    missing_done: list[str] = []
    for keyword in keywords:
        matching = [task for task in tasks if _task_matches_keyword(task, keyword)]
        if not matching:
            missing_created.append(keyword)
            missing_done.append(keyword)
            continue
        if not any(task.done for task in matching):
            missing_done.append(keyword)
    return missing_created, missing_done


def _validate_transition_to_contained(*, incident: Incident) -> None:
    if incident.status != Incident.Status.IN_PROGRESS:
        raise ValueError("Transicao para CONTAINED exige status atual IN_PROGRESS.")

    active_branch_labels = sorted(set(incident.labels or []) & BRANCH_EXCLUSIVE_LABELS)
    if len(active_branch_labels) != 1:
        raise ValueError(
            "Transicao para CONTAINED exige exatamente um ramo ativo entre "
            f"{', '.join(sorted(BRANCH_EXCLUSIVE_LABELS))}."
        )

    branch = active_branch_labels[0]
    keywords = BRANCH_MINIMUM_CONTAINMENT_TASK_KEYWORDS.get(branch, ())
    tasks = list(incident.tasks.all())
    missing_created, missing_done = _missing_task_keywords(tasks=tasks, keywords=keywords)
    if missing_created or missing_done:
        chunks: list[str] = []
        if missing_created:
            chunks.append(
                "tarefas minimas nao criadas: " + ", ".join(missing_created)
            )
        if missing_done:
            chunks.append(
                "tarefas minimas nao concluidas: " + ", ".join(missing_done)
            )
        raise ValueError(
            "Transicao para CONTAINED bloqueada para o ramo "
            f"'{branch}'; " + " | ".join(chunks) + "."
        )


def _validate_transition_to_resolved(*, incident: Incident) -> None:
    if incident.status != Incident.Status.CONTAINED:
        raise ValueError("Transicao para RESOLVED exige status atual CONTAINED.")

    tasks = list(incident.tasks.all())
    missing_created, missing_done = _missing_task_keywords(
        tasks=tasks,
        keywords=RECOVERY_MINIMUM_TASK_KEYWORDS,
    )
    if missing_created or missing_done:
        chunks: list[str] = []
        if missing_created:
            chunks.append(
                "itens de recuperacao nao criados: " + ", ".join(missing_created)
            )
        if missing_done:
            chunks.append(
                "itens de recuperacao nao concluidos: " + ", ".join(missing_done)
            )
        raise ValueError(
            "Transicao para RESOLVED bloqueada; " + " | ".join(chunks) + "."
        )


def _validate_status_transition(*, incident: Incident, target_status: str) -> None:
    if not _is_phishing_context(incident):
        return
    if target_status == Incident.Status.CONTAINED:
        _validate_transition_to_contained(incident=incident)
    elif target_status == Incident.Status.RESOLVED:
        _validate_transition_to_resolved(incident=incident)


def update_incident_status(*, incident: Incident, status: str, actor, reason: str | None = None) -> OperationResult:
    with transaction.atomic():
        _validate_status_transition(incident=incident, target_status=status)
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
        normalized_add, normalized_remove = _normalize_labels_for_branch_exclusivity(
            add=add,
            remove=remove,
        )
        changed = incident.set_labels(
            add=normalized_add,
            remove=normalized_remove,
            actor=actor,
        )
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


def update_incident_secondary_assignees(
    *,
    incident: Incident,
    assignee_ids: Iterable[int | str],
    actor,
) -> OperationResult:
    normalized_ids: set[int] = set()
    for raw in assignee_ids:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value > 0:
            normalized_ids.add(value)

    allowed_ids = set(
        User.objects.filter(is_active=True, id__in=normalized_ids).values_list("id", flat=True)
    )
    current_ids = set(incident.secondary_assignees.values_list("id", flat=True))

    if allowed_ids == current_ids:
        return OperationResult(changed=False, incident=incident)

    with transaction.atomic():
        incident.secondary_assignees.set(allowed_ids)
        added_ids = sorted(allowed_ids - current_ids)
        removed_ids = sorted(current_ids - allowed_ids)
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.ESCALATION,
            message="Responsaveis secundarios do escalonamento atualizados",
            actor=actor,
            extra={
                "added_user_ids": added_ids,
                "removed_user_ids": removed_ids,
                "secondary_assignees": sorted(allowed_ids),
            },
        )
        log_action(
            actor=actor,
            verb="incident.secondary_assignees_updated",
            target=incident,
            meta={
                "added_user_ids": added_ids,
                "removed_user_ids": removed_ids,
                "secondary_assignee_ids": sorted(allowed_ids),
            },
        )
        broadcast_incident_update(
            incident.id,
            sections=["summary", "escalation", "timeline"],
            payload={
                "message": "Responsaveis secundarios atualizados",
                "secondary_assignee_ids": sorted(allowed_ids),
            },
        )
    return OperationResult(changed=True, incident=incident)


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


def create_artifact_record(
    *,
    incident: Incident,
    type_code: str,
    value: str = "",
    attributes: dict[str, Any] | None = None,
    actor,
) -> Artifact:
    normalized_value = (value or "").strip()
    with transaction.atomic():
        artifact = Artifact.objects.create(
            type=type_code,
            value=normalized_value,
            attributes=attributes or {},
        )
        IncidentArtifact.objects.create(
            incident=incident,
            artifact=artifact,
            created_by=actor,
        )
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.ARTIFACT_ADDED,
            message=f"Artefato de tipo {artifact.type} criado",
            actor=actor,
            extra={"artifact_id": artifact.id},
        )
        log_action(
            actor=actor,
            verb="incident.artifact_created",
            target=incident,
            meta={"artifact_id": artifact.id},
        )
        broadcast_incident_update(
            incident.id,
            sections=["artifacts", "timeline", "summary"],
            payload={"message": "Novo artefato criado", "artifact_id": artifact.id},
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


def update_artifact_hash(
    *,
    artifact: Artifact,
    incident: Incident | None = None,
    sha256: str,
    actor=None,
) -> OperationResult:
    normalized_hash = (sha256 or "").strip().lower()
    if not normalized_hash:
        raise ValueError("sha256 obrigatorio")
    with transaction.atomic():
        if normalized_hash == artifact.sha256:
            return OperationResult(changed=False, incident=incident or artifact.primary_incident())
        artifact.sha256 = normalized_hash
        artifact.save(update_fields=["sha256"])
        related_incidents = list(artifact.incidents.all())
        for related_incident in related_incidents:
            related_incident.log_timeline(
                entry_type=TimelineEntry.EntryType.NOTE,
                message=f"Hash SHA256 do artefato #{artifact.id} atualizado",
                actor=actor,
                extra={"artifact_id": artifact.id, "sha256": normalized_hash},
            )
            log_action(
                actor=actor,
                verb="incident.artifact_hash_updated",
                target=related_incident,
                meta={"artifact_id": artifact.id, "sha256": normalized_hash},
            )
            broadcast_incident_update(
                related_incident.id,
                sections=["artifacts", "timeline"],
                payload={"message": "Hash do artefato atualizado", "artifact_id": artifact.id},
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
