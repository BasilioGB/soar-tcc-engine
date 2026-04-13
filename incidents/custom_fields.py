from __future__ import annotations

import json
import re
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Mapping

from django.utils.dateparse import parse_date, parse_datetime

from .models import CustomFieldDefinition, Incident


class CustomFieldPayloadError(ValueError):
    def __init__(self, errors: dict[str, str]):
        super().__init__("Custom field payload is invalid")
        self.errors = errors


def get_custom_field_definition_map(*, include_inactive: bool = True) -> dict[str, CustomFieldDefinition]:
    queryset = CustomFieldDefinition.objects.filter(is_deleted=False)
    if not include_inactive:
        queryset = queryset.filter(is_active=True)
    return {str(definition.internal_id): definition for definition in queryset}


def reconcile_custom_field_values(
    stored_values: Any,
    *,
    definition_map: Mapping[str, CustomFieldDefinition] | None = None,
) -> tuple[dict[str, Any], bool]:
    if definition_map is None:
        definition_map = get_custom_field_definition_map(include_inactive=True)
    if not isinstance(stored_values, dict):
        return {}, bool(stored_values)

    reconciled: dict[str, Any] = {}
    changed = False
    for key, value in stored_values.items():
        canonical_key = _normalize_internal_key(key)
        if canonical_key is None or canonical_key not in definition_map:
            changed = True
            continue
        if canonical_key != str(key):
            changed = True
        reconciled[canonical_key] = value
    return reconciled, changed or reconciled != stored_values


def project_active_custom_field_values(
    stored_values: Any,
    *,
    definition_map: Mapping[str, CustomFieldDefinition] | None = None,
) -> dict[str, Any]:
    if definition_map is None:
        definition_map = get_custom_field_definition_map(include_inactive=True)
    reconciled, _ = reconcile_custom_field_values(stored_values, definition_map=definition_map)
    return {
        key: value
        for key, value in reconciled.items()
        if key in definition_map and definition_map[key].is_active
    }


def validate_custom_field_input(
    payload: Any,
    *,
    definition_map: Mapping[str, CustomFieldDefinition] | None = None,
    active_only: bool = True,
) -> dict[str, Any]:
    if definition_map is None:
        definition_map = get_custom_field_definition_map(include_inactive=True)
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise CustomFieldPayloadError({"non_field_errors": "custom_fields deve ser um objeto JSON."})

    errors: dict[str, str] = {}
    normalized: dict[str, Any] = {}
    for raw_key, value in payload.items():
        canonical_key = _normalize_internal_key(raw_key)
        if canonical_key is None:
            errors[str(raw_key)] = "A chave do custom field deve ser um ID interno numerico."
            continue
        definition = definition_map.get(canonical_key)
        if definition is None:
            errors[str(raw_key)] = "Campo customizado nao definido."
            continue
        if active_only and not definition.is_active:
            errors[str(raw_key)] = "Campo customizado inativo."
            continue
        try:
            normalized[str(definition.internal_id)] = _normalize_custom_field_value(
                value=value,
                field_type=definition.field_type,
            )
        except ValueError as exc:
            errors[str(raw_key)] = str(exc)

    if errors:
        raise CustomFieldPayloadError(errors)
    return normalized


def reconcile_incident_custom_fields_storage(
    incident: Incident,
    *,
    definition_map: Mapping[str, CustomFieldDefinition] | None = None,
    persist: bool = False,
) -> dict[str, Any]:
    reconciled, changed = reconcile_custom_field_values(
        incident.custom_fields or {},
        definition_map=definition_map,
    )
    if changed and persist:
        incident.custom_fields = reconciled
        incident._save_with_skip_signals(update_fields=["custom_fields", "updated_at"])
    return reconciled


def remove_custom_field_from_all_incidents(*, internal_id: int | str) -> int:
    normalized = _normalize_internal_key(internal_id)
    if normalized is None:
        return 0

    updated_count = 0
    for incident in Incident.objects.only("id", "custom_fields").iterator():
        stored = incident.custom_fields or {}
        if not isinstance(stored, dict) or normalized not in stored:
            continue
        del stored[normalized]
        incident.custom_fields = stored
        incident._save_with_skip_signals(update_fields=["custom_fields", "updated_at"])
        updated_count += 1
    return updated_count


def find_playbooks_referencing_custom_field(
    *,
    internal_id: int | str,
    api_name: str | None = None,
) -> list[dict[str, Any]]:
    normalized_internal_id = _normalize_internal_key(internal_id)
    normalized_api_name = (api_name or "").strip()
    if not normalized_internal_id and not normalized_api_name:
        return []

    from playbooks.models import Playbook

    referenced: list[dict[str, Any]] = []
    for playbook in Playbook.objects.only("id", "name", "enabled", "dsl").iterator():
        if _dsl_references_custom_field(
            playbook.dsl,
            internal_id=normalized_internal_id,
            api_name=normalized_api_name,
        ):
            referenced.append(
                {
                    "id": playbook.id,
                    "name": playbook.name,
                    "enabled": bool(playbook.enabled),
                }
            )
    return referenced


def _dsl_references_custom_field(
    value: Any,
    *,
    internal_id: str | None,
    api_name: str,
) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if api_name and str(key).strip() == api_name:
                return True
            if internal_id and _normalize_internal_key(key) == internal_id:
                return True
            if key == "api_name" and api_name and str(item).strip() == api_name:
                return True
            if key == "internal_id" and internal_id and _normalize_internal_key(item) == internal_id:
                return True
            if _dsl_references_custom_field(item, internal_id=internal_id, api_name=api_name):
                return True
        return False

    if isinstance(value, (list, tuple, set)):
        return any(
            _dsl_references_custom_field(item, internal_id=internal_id, api_name=api_name)
            for item in value
        )

    if isinstance(value, str):
        if api_name and re.search(rf"\bincident\.custom_fields\.{re.escape(api_name)}\b", value):
            return True
        if internal_id and re.search(rf"\bincident\.custom_fields\.{re.escape(internal_id)}\b", value):
            return True

    return False


def _normalize_custom_field_value(*, value: Any, field_type: str) -> Any:
    if value is None:
        return None
    if field_type == CustomFieldDefinition.FieldType.TEXT:
        if not isinstance(value, str):
            raise ValueError("Valor precisa ser string.")
        return value
    if field_type == CustomFieldDefinition.FieldType.INTEGER:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("Valor precisa ser inteiro.")
        return value
    if field_type == CustomFieldDefinition.FieldType.NUMBER:
        if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
            raise ValueError("Valor precisa ser numerico.")
        return float(value) if isinstance(value, Decimal) else value
    if field_type == CustomFieldDefinition.FieldType.BOOLEAN:
        if not isinstance(value, bool):
            raise ValueError("Valor precisa ser booleano.")
        return value
    if field_type == CustomFieldDefinition.FieldType.DATE:
        if isinstance(value, datetime):
            return value.date().isoformat()
        if isinstance(value, date):
            return value.isoformat()
        if isinstance(value, str):
            parsed_date = parse_date(value)
            if parsed_date:
                return parsed_date.isoformat()
        raise ValueError("Valor precisa ser uma data ISO-8601 (YYYY-MM-DD).")
    if field_type == CustomFieldDefinition.FieldType.DATETIME:
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, str):
            parsed_datetime = parse_datetime(value)
            if parsed_datetime:
                return parsed_datetime.isoformat()
        raise ValueError("Valor precisa ser um datetime ISO-8601.")
    if field_type == CustomFieldDefinition.FieldType.JSON:
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("Valor precisa ser JSON serializavel.") from exc
        return value
    raise ValueError("Tipo de custom field invalido.")


def _normalize_internal_key(raw_key: Any) -> str | None:
    if isinstance(raw_key, bool):
        return None
    if isinstance(raw_key, int):
        return str(raw_key) if raw_key > 0 else None
    if isinstance(raw_key, str):
        key = raw_key.strip()
        if not key.isdigit():
            return None
        numeric_value = int(key)
        return str(numeric_value) if numeric_value > 0 else None
    return None
