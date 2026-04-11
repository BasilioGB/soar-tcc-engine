from __future__ import annotations

from typing import Any

from automation.filter_resolution import build_manual_filter_context
from automation.matcher import (
    resolve_and_match_artifact_rules,
    resolve_and_match_incident_rules,
)
from incidents.models import Incident, Artifact

def manual_playbook_matches_incident(playbook, incident: Incident) -> bool:
    filters = playbook.filter_entries.filter(target=playbook.filter_entries.model.Target.INCIDENT)
    if not filters.exists():
        return False
    context = build_manual_filter_context(incident=incident)
    return any(
        resolve_and_match_incident_rules(
            filter.conditions or {},
            incident,
            resolution_context=context,
            source=f"manual incident filters do playbook {playbook.id}",
        )
        for filter in filters
    )


def manual_playbook_matches_artifact(playbook, incident: Incident, artifact: Artifact | None) -> bool:
    filters = playbook.filter_entries.filter(target=playbook.filter_entries.model.Target.ARTIFACT)
    if not filters.exists():
        return False
    context = build_manual_filter_context(incident=incident, artifact=artifact)
    return any(
        resolve_and_match_artifact_rules(
            filter.conditions or {},
            artifact,
            incident_source=incident,
            resolution_context=context,
            source=f"manual artifact filters do playbook {playbook.id}",
        )
        for filter in filters
    )
