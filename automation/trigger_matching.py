from __future__ import annotations

from typing import Any, Dict

from .filter_resolution import build_event_resolution_context
from .matcher import (
    resolve_and_match_artifact_rules,
    resolve_and_match_incident_rules,
)


def matches(
    event: str,
    filters: Dict[str, Any],
    payload: Dict[str, Any],
    *,
    resolution_context: Dict[str, Any] | None = None,
    source: str = "trigger filters",
) -> bool:
    filters = filters or {}
    if not filters:
        return True
    context = resolution_context or build_event_resolution_context(event=event, payload=payload)
    if event.startswith("incident."):
        return resolve_and_match_incident_rules(
            filters,
            payload,
            resolution_context=context,
            source=source,
        )
    if event == "artifact.created":
        return resolve_and_match_artifact_rules(
            filters,
            payload,
            incident_source=payload,
            resolution_context=context,
            source=source,
        )
    return False
