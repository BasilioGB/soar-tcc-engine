from __future__ import annotations

from typing import Any

from .input_resolution import resolve_step_input


def resolve_dynamic_mapping(
    mapping: dict[str, Any],
    context: dict[str, Any],
    *,
    source: str,
) -> dict[str, Any]:
    try:
        return resolve_step_input(mapping, context)
    except ValueError as exc:
        raise ValueError(f"Falha ao resolver placeholders em {source}: {exc}") from exc


def build_event_resolution_context(
    *,
    event: str,
    payload: dict[str, Any],
    incident=None,
    artifact=None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "payload": payload,
        "trigger_context": payload,
    }
    if incident is not None:
        context["incident"] = incident
    elif event.startswith("incident."):
        context["incident"] = payload
    if artifact is not None:
        context["artifact"] = artifact
    elif event == "artifact.created":
        context["artifact"] = payload
        context.setdefault(
            "incident",
            {
                "id": payload.get("incident_id"),
                "labels": payload.get("incident_labels") or [],
            },
        )
    return context


def build_manual_filter_context(*, incident, artifact=None) -> dict[str, Any]:
    context: dict[str, Any] = {
        "incident": incident,
        "payload": incident,
    }
    if artifact is not None:
        context["artifact"] = artifact
        context["payload"] = artifact
    return context
