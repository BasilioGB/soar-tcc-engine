from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError

from integrations.models import IntegrationDefinition
from integrations.registry import list_actions
from playbooks.dsl import ParsedPlaybook, parse_playbook

def validate_playbook_semantics(
    data: Any,
    *,
    parsed_playbook: ParsedPlaybook | None = None,
) -> ParsedPlaybook:
    parsed = parsed_playbook or parse_playbook(data)
    errors: list[str] = []

    static_actions = set(list_actions())
    configured_actions = {
        item.action_name: item
        for item in IntegrationDefinition.objects.select_related("secret_ref").filter(
            action_name__in={step.action for step in parsed.steps}
        )
    }

    for step in parsed.steps:
        if step.action in static_actions:
            continue

        connector = configured_actions.get(step.action)
        if connector is None:
            errors.append(f"Step '{step.name}': acao '{step.action}' nao encontrada.")
            continue
        if not connector.enabled:
            errors.append(f"Step '{step.name}': conector HTTP '{step.action}' esta desabilitado.")
            continue

        errors.extend(_http_connector_semantic_errors(step.name, connector))
        errors.extend(_missing_param_errors(step.name, connector, step.input))

    if errors:
        raise ValidationError(errors)

    return parsed


def _http_connector_semantic_errors(step_name: str, connector: IntegrationDefinition) -> list[str]:
    errors: list[str] = []
    request_template = connector.request_template or {}

    if not isinstance(request_template, dict):
        errors.append(
            f"Step '{step_name}': conector HTTP '{connector.action_name}' tem request_template invalido."
        )
        return errors

    if request_template.get("payload") is not None and request_template.get("body") is not None:
        errors.append(
            f"Step '{step_name}': conector HTTP '{connector.action_name}' nao pode definir payload e body ao mesmo tempo."
        )

    if connector.secret_ref is None:
        errors.append(
            f"Step '{step_name}': conector HTTP '{connector.action_name}' exige secret_ref."
        )

    return errors


def _missing_param_errors(
    step_name: str,
    connector: IntegrationDefinition,
    step_input: dict[str, Any],
) -> list[str]:
    missing = [
        param
        for param in connector.expected_params
        if step_input.get(param) in (None, "")
    ]
    if not missing:
        return []

    return [
        (
            f"Step '{step_name}': conector HTTP '{connector.action_name}' exige os parametros "
            f"{', '.join(sorted(missing))}."
        )
    ]
