from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError

from integrations.models import IntegrationDefinition
from integrations.registry import list_actions
from playbooks.dsl import ParsedPlaybook, parse_playbook

ALLOWED_POST_RESPONSE_PREFIXES = ("incident.", "task.", "communication.", "artifact.")


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

        integration = configured_actions.get(step.action)
        if integration is None:
            errors.append(f"Step '{step.name}': acao '{step.action}' nao encontrada.")
            continue
        if not integration.enabled:
            errors.append(f"Step '{step.name}': integracao '{step.action}' esta desabilitada.")
            continue

        errors.extend(_integration_semantic_errors(step.name, integration))
        errors.extend(_missing_param_errors(step.name, integration, step.input))

    if errors:
        raise ValidationError(errors)

    return parsed


def _integration_semantic_errors(step_name: str, integration: IntegrationDefinition) -> list[str]:
    errors: list[str] = []
    request_template = integration.request_template or {}

    if not isinstance(request_template, dict):
        errors.append(
            f"Step '{step_name}': integracao '{integration.action_name}' tem request_template invalido."
        )
        return errors

    if request_template.get("payload") is not None and request_template.get("body") is not None:
        errors.append(
            f"Step '{step_name}': integracao '{integration.action_name}' nao pode definir payload e body ao mesmo tempo."
        )

    if (
        integration.auth_type == IntegrationDefinition.AuthType.SECRET_REF
        and integration.secret_ref is None
    ):
        errors.append(
            f"Step '{step_name}': integracao '{integration.action_name}' exige secret_ref."
        )

    static_actions = set(list_actions())
    for action in integration.post_response_actions or []:
        action_name = action.get("action")
        if not isinstance(action_name, str) or not action_name.startswith(ALLOWED_POST_RESPONSE_PREFIXES):
            errors.append(
                f"Step '{step_name}': integracao '{integration.action_name}' possui post_response_action invalida."
            )
            continue
        if action_name not in static_actions:
            errors.append(
                f"Step '{step_name}': integracao '{integration.action_name}' referencia post_response_action inexistente '{action_name}'."
            )

    return errors


def _missing_param_errors(
    step_name: str,
    integration: IntegrationDefinition,
    step_input: dict[str, Any],
) -> list[str]:
    missing = [
        param
        for param in integration.expected_params
        if step_input.get(param) in (None, "")
    ]
    if not missing:
        return []

    return [
        (
            f"Step '{step_name}': integracao '{integration.action_name}' exige os parametros "
            f"{', '.join(sorted(missing))}."
        )
    ]
