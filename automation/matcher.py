from __future__ import annotations

from typing import Any, Iterable

from .filter_resolution import resolve_dynamic_mapping


def resolve_and_match_incident_rules(
    rules: dict[str, Any],
    incident_source: Any,
    *,
    resolution_context: dict[str, Any],
    source: str,
) -> bool:
    resolved_rules = resolve_dynamic_mapping(rules or {}, resolution_context, source=source)
    return match_incident_rules(resolved_rules, incident_source)


def resolve_and_match_artifact_rules(
    rules: dict[str, Any],
    artifact_source: Any,
    *,
    incident_source: Any = None,
    resolution_context: dict[str, Any],
    source: str,
) -> bool:
    resolved_rules = resolve_dynamic_mapping(rules or {}, resolution_context, source=source)
    return match_artifact_rules(resolved_rules, artifact_source, incident_source=incident_source)


def match_incident_rules(rules: dict[str, Any], incident_source: Any) -> bool:
    if not rules:
        return True

    labels = set(_ensure_iterable(_read_value(incident_source, "labels", [])))
    if "labels" in rules:
        expected = set(_ensure_iterable(rules["labels"]))
        if not expected.issubset(labels):
            return False

    if "any_label" in rules:
        expected = set(_ensure_iterable(rules["any_label"]))
        if labels.isdisjoint(expected):
            return False

    if "status" in rules:
        statuses = set(_ensure_iterable(rules["status"]))
        if _read_value(incident_source, "status") not in statuses:
            return False

    if "severity" in rules:
        severities = set(_ensure_iterable(rules["severity"]))
        if _read_value(incident_source, "severity") not in severities:
            return False

    if "assignee" in rules:
        assignees = set(_ensure_iterable(rules["assignee"]))
        assignee_candidates = _incident_assignee_candidates(incident_source)
        if assignee_candidates.isdisjoint(assignees):
            return False

    if "changed_fields" in rules:
        changed = set(_ensure_iterable(_read_value(incident_source, "changed_fields", [])))
        required = set(_ensure_iterable(rules["changed_fields"]))
        if not required.intersection(changed):
            return False

    return True


def match_artifact_rules(
    rules: dict[str, Any],
    artifact_source: Any,
    *,
    incident_source: Any = None,
) -> bool:
    if not rules:
        return True

    if artifact_source is None:
        return False

    if "incident_labels" in rules:
        incident_labels = set(_ensure_iterable(_incident_labels_for_artifact(artifact_source, incident_source)))
        expected = set(_ensure_iterable(rules["incident_labels"]))
        if not expected.issubset(incident_labels):
            return False

    if "type" in rules:
        types = set(_ensure_iterable(rules["type"]))
        if _read_value(artifact_source, "type") not in types:
            return False

    if "value_contains" in rules:
        needles: Iterable[str] = _ensure_iterable(rules["value_contains"])
        value = str(_read_value(artifact_source, "value", "") or "")
        if not any(str(needle).lower() in value.lower() for needle in needles):
            return False

    if "attribute_equals" in rules:
        expected_map = rules["attribute_equals"] or {}
        attributes = _read_value(artifact_source, "attributes", {}) or {}
        for path, expected in expected_map.items():
            value = _get_attribute_value(attributes, str(path))
            if value != expected:
                return False

    return True


def _incident_assignee_candidates(incident_source: Any) -> set[Any]:
    raw_assignee = _read_value(incident_source, "assignee")
    candidates: set[Any] = set()

    if raw_assignee is not None:
        try:
            candidates.add(raw_assignee)
        except TypeError:
            pass
        username = _read_value(raw_assignee, "username")
        identifier = _read_value(raw_assignee, "id")
        if username is not None:
            candidates.add(username)
        if identifier is not None:
            candidates.add(identifier)

    assignee_id = _read_value(incident_source, "assignee_id")
    if assignee_id is not None:
        candidates.add(assignee_id)

    return candidates


def _incident_labels_for_artifact(artifact_source: Any, incident_source: Any) -> list[Any]:
    if incident_source is not None:
        labels = _read_value(incident_source, "labels")
        if labels is not None:
            return list(_ensure_iterable(labels))
    return list(_ensure_iterable(_read_value(artifact_source, "incident_labels", [])))


def _ensure_iterable(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _read_value(source: Any, field: str, default: Any = None) -> Any:
    if source is None:
        return default
    if isinstance(source, dict):
        return source.get(field, default)
    return getattr(source, field, default)


def _get_attribute_value(attributes: dict[str, Any], path: str) -> Any:
    current: Any = attributes
    for segment in path.split("."):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            return None
    return current
