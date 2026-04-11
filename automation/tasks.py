from __future__ import annotations

import hashlib
import json

from celery import shared_task
from django.conf import settings
from django.core.cache import cache


@shared_task(bind=True, ignore_result=True)
def run_playbook_execution(self, execution_id: int):
    from .runner import run_execution_sync

    run_execution_sync(execution_id)


@shared_task(bind=True, ignore_result=True)
def process_playbook_event(self, event: str, payload: dict):
    from incidents.models import Incident, Artifact
    from automation.filter_resolution import build_event_resolution_context
    from playbooks.models import Playbook
    from playbooks.services import start_playbook_execution
    from playbooks.trigger_cache import get_triggers_for_event
    from automation.trigger_matching import matches

    triggers = get_triggers_for_event(event)
    dedup_ttl = getattr(settings, 'PLAYBOOK_TRIGGER_DEDUP_TTL', 30)

    if not triggers:
        return

    playbook_ids = {trigger["playbook_id"] for trigger in triggers}
    playbooks = Playbook.objects.filter(id__in=playbook_ids, enabled=True)
    playbook_map = {playbook.id: playbook for playbook in playbooks}

    if event.startswith("incident."):
        incident_id = payload.get("incident_id")
        if not incident_id:
            return
        try:
            incident = Incident.objects.get(pk=incident_id)
        except Incident.DoesNotExist:
            return
        for trigger in triggers:
            playbook = playbook_map.get(trigger["playbook_id"])
            if not playbook or playbook.type != Playbook.Type.INCIDENT:
                continue
            if not matches(
                event,
                trigger.get("filters") or {},
                payload,
                resolution_context=build_event_resolution_context(
                    event=event,
                    payload=payload,
                    incident=incident,
                ),
                source=f"trigger do playbook {playbook.id} para evento {event}",
            ):
                continue
            dedup_key = _build_trigger_dedup_key(
                event=event,
                playbook_id=playbook.id,
                incident_id=incident_id,
                payload=payload,
            )
            if not cache.add(dedup_key, True, dedup_ttl):
                continue
            start_playbook_execution(
                playbook,
                incident,
                actor=None,
                context={"event": event, **payload},
            )
    elif event == "artifact.created":
        artifact_id = payload.get("artifact_id")
        incident_id = payload.get("incident_id")
        if not incident_id:
            return
        try:
            incident = Incident.objects.get(pk=incident_id)
        except Incident.DoesNotExist:
            return
        artifact = None
        artifact_data = {}
        if artifact_id:
            try:
                artifact = Artifact.objects.get(pk=artifact_id)
                artifact_data = {
                    "id": artifact.id,
                    "type": artifact.type,
                    "value": artifact.value,
                    "attributes": artifact.attributes or {},
                }
            except Artifact.DoesNotExist:
                artifact_data = {"id": artifact_id}
        for trigger in triggers:
            playbook = playbook_map.get(trigger["playbook_id"])
            if not playbook or playbook.type != Playbook.Type.ARTIFACT:
                continue
            if not matches(
                event,
                trigger.get("filters") or {},
                payload,
                resolution_context=build_event_resolution_context(
                    event=event,
                    payload=payload,
                    incident=incident,
                    artifact=artifact,
                ),
                source=f"trigger do playbook {playbook.id} para evento {event}",
            ):
                continue
            dedup_key = _build_trigger_dedup_key(
                event=event,
                playbook_id=playbook.id,
                incident_id=incident_id,
                artifact_id=artifact_id,
                payload=payload,
            )
            if not cache.add(dedup_key, True, dedup_ttl):
                continue
            context = {"event": event, **payload}
            if artifact_data:
                context.setdefault("artifact", artifact_data)
            start_playbook_execution(
                playbook,
                incident,
                actor=None,
                context=context,
            )


def _build_trigger_dedup_key(
    *,
    event: str,
    playbook_id: int,
    incident_id: int,
    payload: dict,
    artifact_id: int | None = None,
) -> str:
    key_parts = ["playbook-trigger", event, str(playbook_id), str(incident_id)]
    if artifact_id is not None:
        key_parts.append(str(artifact_id))
    key_parts.append(_payload_fingerprint(payload))
    return ":".join(key_parts)


def _payload_fingerprint(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:12]
