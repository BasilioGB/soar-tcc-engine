from __future__ import annotations

from django.db.models.signals import post_delete, post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone

from audit.utils import log_action
from automation.events import emit_event
from core.realtime import broadcast_global_notification, broadcast_incident_update
from .models import Incident, IncidentArtifact, TimelineEntry


@receiver(pre_save, sender=Incident)
def capture_previous_state(sender, instance: Incident, **_: object) -> None:
    if not instance.pk:
        instance._previous_state = {}  # type: ignore[attr-defined]
        return
    try:
        previous = Incident.objects.get(pk=instance.pk)
    except Incident.DoesNotExist:
        instance._previous_state = {}  # type: ignore[attr-defined]
        return
    instance._previous_state = {  # type: ignore[attr-defined]
        "status": previous.status,
        "assignee_id": previous.assignee_id,
        "severity": previous.severity,
        "risk_score": previous.risk_score,
        "labels": list(previous.labels),
        "escalation_level": previous.escalation_level,
        "escalation_targets": list(previous.escalation_targets),
    }


@receiver(post_save, sender=Incident)
def incident_post_save(sender, instance: Incident, created: bool, **_: object) -> None:
    previous_state = getattr(instance, "_previous_state", {})  # type: ignore[attr-defined]
    skip_logging = getattr(instance, "_skip_signal_logging", False)  # type: ignore[attr-defined]

    if created:
        updates: list[str] = []
        if not instance.occurred_at:
            instance.occurred_at = instance.created_at or timezone.now()
            updates.append("occurred_at")
        if not instance.detected_at:
            instance.detected_at = instance.created_at or timezone.now()
            updates.append("detected_at")
        if updates:
            instance._save_with_skip_signals(update_fields=updates)
        TimelineEntry.objects.create(
            incident=instance,
            entry_type=TimelineEntry.EntryType.NOTE,
            message="Incidente criado",
            created_by=instance.created_by,
        )
        log_action(
            actor=instance.created_by,
            verb="incident.created",
            target=instance,
            meta={"severity": instance.severity, "status": instance.status},
        )
        emit_event(
            "incident.created",
            {
                "incident_id": instance.id,
                "status": instance.status,
                "severity": instance.severity,
                "labels": list(instance.labels or []),
                "assignee": instance.assignee_id,
            },
        )
        broadcast_incident_update(
            instance.id,
            sections=[
                "summary",
                "lifecycle",
                "timeline",
                "tasks",
                "artifacts",
                "taxonomy",
                "escalation",
                "communications",
                "relations",
            ],
            payload={"message": "Novo incidente registrado"},
        )
        broadcast_global_notification(
            "incident_created",
            {
                "message": f"Incidente #{instance.id} criado",
                "incident_id": instance.id,
                "title": instance.title,
                "severity": instance.severity,
                "status": instance.status,
            },
        )
        return

    if skip_logging or not previous_state:
        return

    change_details: dict[str, object] = {}

    previous_status = previous_state.get("status")
    if previous_status is not None and previous_status != instance.status:
        TimelineEntry.objects.create(
            incident=instance,
            entry_type=TimelineEntry.EntryType.STATUS_CHANGED,
            message=f"Status alterado de {previous_status} para {instance.status}",
            created_by=None,
        )
        log_action(
            actor=None,
            verb="incident.status_changed",
            target=instance,
            meta={"from": previous_status, "to": instance.status},
        )
        change_details["status"] = {"from": previous_status, "to": instance.status}

    previous_assignee_id = previous_state.get("assignee_id")
    if previous_assignee_id != instance.assignee_id:
        if instance.assignee:
            label = instance.assignee.get_full_name() or instance.assignee.get_username()
            message = f"Responsavel alterado para {label}"
        else:
            message = "Responsavel removido"
        TimelineEntry.objects.create(
            incident=instance,
            entry_type=TimelineEntry.EntryType.ASSIGNEE_CHANGED,
            message=message,
            created_by=None,
        )
        log_action(
            actor=None,
            verb="incident.assignee_changed",
            target=instance,
            meta={"from": previous_assignee_id, "to": instance.assignee_id},
        )
        change_details["assignee"] = {"from": previous_assignee_id, "to": instance.assignee_id}

    previous_severity = previous_state.get("severity")
    if previous_severity is not None and previous_severity != instance.severity:
        change_details["severity"] = {"from": previous_severity, "to": instance.severity}

    previous_risk = previous_state.get("risk_score")
    if previous_risk is not None and previous_risk != instance.risk_score:
        change_details["risk_score"] = {"from": previous_risk, "to": instance.risk_score}

    previous_labels = previous_state.get("labels")
    if previous_labels is not None and list(previous_labels) != list(instance.labels):
        change_details["labels"] = {"from": previous_labels, "to": instance.labels}

    prev_level = previous_state.get("escalation_level")
    if prev_level != instance.escalation_level:
        change_details["escalation_level"] = {"from": prev_level, "to": instance.escalation_level}

    prev_targets = previous_state.get("escalation_targets")
    if prev_targets is not None and list(prev_targets) != list(instance.escalation_targets):
        change_details["escalation_targets"] = {"from": prev_targets, "to": instance.escalation_targets}

    if change_details:
        log_action(
            actor=None,
            verb="incident.updated",
            target=instance,
            meta={"changes": change_details},
        )
        emit_event(
            "incident.updated",
            {
                "incident_id": instance.id,
                "status": instance.status,
                "severity": instance.severity,
                "labels": list(instance.labels or []),
                "assignee": instance.assignee_id,
                "changed_fields": list(change_details.keys()),
                "changes": change_details,
            },
        )
        sections = {"summary"}
        if "labels" in change_details:
            sections.update({"taxonomy", "playbooks"})
        if {"risk_score", "severity"} & set(change_details.keys()):
            sections.add("impact")
        if "assignee" in change_details:
            sections.add("tasks")
        if "status" in change_details:
            sections.add("lifecycle")
        broadcast_incident_update(
            instance.id,
            sections=sections,
            payload={"message": "Incidente atualizado", "changed_fields": list(change_details.keys())},
        )
        broadcast_global_notification(
            "incident_updated",
            {
                "message": f"Incidente #{instance.id} atualizado",
                "incident_id": instance.id,
                "changed_fields": list(change_details.keys()),
            },
        )


@receiver(post_save, sender=IncidentArtifact)
def incident_artifact_post_save(sender, instance: IncidentArtifact, created: bool, **_: object) -> None:
    if not created:
        return
    artifact = instance.artifact
    incident = instance.incident
    emit_event(
        "artifact.created",
        {
            "artifact_id": artifact.id,
            "incident_id": incident.id,
            "type": artifact.type,
            "value": artifact.value,
            "attributes": artifact.attributes or {},
            "incident_labels": list(incident.labels or []),
        },
    )
    broadcast_incident_update(
        incident.id,
        sections=["artifacts", "timeline", "summary"],
        payload={"message": "Artefato associado ao incidente", "artifact_id": artifact.id},
    )


@receiver(post_delete, sender=IncidentArtifact)
def incident_artifact_post_delete(sender, instance: IncidentArtifact, **_: object) -> None:
    incident_id = instance.incident_id
    if not incident_id:
        return
    broadcast_incident_update(
        incident_id,
        sections=["artifacts", "timeline", "summary"],
        payload={"message": "Artefato desvinculado do incidente", "artifact_id": instance.artifact_id},
    )


@receiver(post_save, sender=TimelineEntry)
def timeline_entry_post_save(sender, instance: TimelineEntry, created: bool, **_: object) -> None:
    if not created:
        return
    broadcast_incident_update(
        instance.incident_id,
        sections=["timeline"],
        payload={"message": "Linha do tempo atualizada", "entry_id": instance.id, "entry_type": instance.entry_type},
    )
