from __future__ import annotations

from django.conf import settings
from django.db import transaction

from automation.runner import enqueue_execution, run_execution_sync
from .manual_filters import manual_playbook_matches_artifact, manual_playbook_matches_incident
from .models import Execution, Playbook, PlaybookFilter


def start_playbook_execution(
    playbook: Playbook,
    incident,
    actor=None,
    force_sync: bool | None = None,
    context: dict | None = None,
) -> Execution:
    if not playbook.enabled:
        raise ValueError("Playbook is disabled")

    execution_context = context or {}

    with transaction.atomic():
        execution = Execution.objects.create(
            playbook=playbook,
            incident=incident,
            created_by=actor,
            context=execution_context,
        )

    eager = settings.CELERY_TASK_ALWAYS_EAGER if force_sync is None else force_sync
    if eager:
        run_execution_sync(execution.id)
        execution.refresh_from_db()
    else:
        enqueue_execution(execution.id)
    return execution


def is_manual_playbook_available_for_incident(playbook: Playbook, incident) -> bool:
    if playbook.mode != Playbook.Mode.MANUAL or playbook.type != Playbook.Type.INCIDENT:
        return False
    return manual_playbook_matches_incident(playbook, incident)


def is_manual_playbook_available_for_artifact(playbook: Playbook, artifact, incident=None) -> bool:
    if playbook.mode != Playbook.Mode.MANUAL or playbook.type != Playbook.Type.ARTIFACT:
        return False
    if incident is None:
        incident = artifact.primary_incident()
    if incident is None:
        return False
    return manual_playbook_matches_artifact(playbook, incident, artifact)


def get_manual_playbooks_for_incident(incident) -> list[Playbook]:
    base_qs = (
        Playbook.objects.filter(
            enabled=True,
            type=Playbook.Type.INCIDENT,
            mode=Playbook.Mode.MANUAL,
            filter_entries__target=PlaybookFilter.Target.INCIDENT,
        )
        .distinct()
        .prefetch_related("filter_entries")
        .order_by("name")
    )
    return [
        playbook
        for playbook in base_qs
        if is_manual_playbook_available_for_incident(playbook, incident)
    ]


def get_manual_playbooks_for_artifact(artifact, incident=None) -> list[Playbook]:
    base_qs = (
        Playbook.objects.filter(
            enabled=True,
            type=Playbook.Type.ARTIFACT,
            mode=Playbook.Mode.MANUAL,
            filter_entries__target=PlaybookFilter.Target.ARTIFACT,
        )
        .distinct()
        .prefetch_related("filter_entries")
        .order_by("name")
    )
    return [
        playbook
        for playbook in base_qs
        if is_manual_playbook_available_for_artifact(playbook, artifact, incident=incident)
    ]
