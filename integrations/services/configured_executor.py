from __future__ import annotations

import base64
from types import SimpleNamespace
from typing import Any

from integrations.models import IntegrationDefinition
from integrations.registry import get_action_executor
from integrations.services.http_client import execute_request
from integrations.services.secrets import resolve_secret_value
from integrations.services.template_renderer import (
    render_post_response_actions,
    render_request_template,
)

SENSITIVE_HEADER_NAMES = {"authorization", "proxy-authorization", "x-api-key", "api-key"}
ALLOWED_POST_RESPONSE_PREFIXES = ("incident.", "task.", "communication.", "artifact.")


def execute_configured_integration(
    *,
    integration: IntegrationDefinition,
    params: dict[str, Any] | None,
    runtime_context: dict[str, Any] | None,
) -> dict[str, Any]:
    normalized_params = params or {}
    _validate_expected_params(integration, normalized_params)

    rendered_request = render_request_template(
        integration.request_template,
        runtime_context,
        params=normalized_params,
    )
    secret_value = _resolve_secret(integration)
    request_payload = _build_request_payload(
        integration=integration,
        rendered_request=rendered_request,
        secret_value=secret_value,
    )
    response = execute_request(**request_payload)
    mapped_output = map_response_output(integration.response_mapping, response)
    post_response_results = _execute_post_response_actions(
        integration=integration,
        runtime_context=runtime_context,
        params=normalized_params,
        output=mapped_output,
        response=response,
    )
    return {
        "action_name": integration.action_name,
        "integration_revision": integration.revision,
        "response": _sanitize_http_result(response),
        "output": mapped_output,
        "post_response_results": post_response_results,
    }


def map_response_output(response_mapping: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    if not response_mapping:
        return {}

    output: dict[str, Any] = {}
    for key, path in response_mapping.items():
        output[key] = _resolve_path(path, response)
    return output


def _validate_expected_params(integration: IntegrationDefinition, params: dict[str, Any]) -> None:
    missing = [
        name
        for name in integration.expected_params
        if params.get(name) in (None, "")
    ]
    if missing:
        names = ", ".join(sorted(missing))
        raise ValueError(f"Parametros obrigatorios ausentes para '{integration.action_name}': {names}")


def _resolve_secret(integration: IntegrationDefinition) -> str | None:
    if integration.auth_type != IntegrationDefinition.AuthType.SECRET_REF:
        return None
    if integration.secret_ref is None:
        raise ValueError(f"Integration '{integration.action_name}' exige secret_ref")
    return resolve_secret_value(integration.secret_ref)


def _build_request_payload(
    *,
    integration: IntegrationDefinition,
    rendered_request: dict[str, Any],
    secret_value: str | None,
) -> dict[str, Any]:
    headers = dict(rendered_request.get("headers") or {})
    query = rendered_request.get("query")
    request_payload = {
        "method": rendered_request.get("method") or integration.method,
        "url": rendered_request.get("url"),
        "headers": headers,
        "query": query,
        "timeout": rendered_request.get("timeout") or integration.timeout_seconds,
        "payload": rendered_request.get("payload"),
        "raw_body": rendered_request.get("body"),
    }
    _apply_secret_auth(
        rendered_request=rendered_request,
        headers=headers,
        query=query,
        secret_value=secret_value,
    )
    request_payload["headers"] = headers
    request_payload["query"] = rendered_request.get("query")
    return request_payload


def _apply_secret_auth(
    *,
    rendered_request: dict[str, Any],
    headers: dict[str, Any],
    query: Any,
    secret_value: str | None,
) -> None:
    if not secret_value:
        return

    auth_config = rendered_request.get("auth") or {}
    strategy = auth_config.get("strategy", "bearer_header")

    if strategy == "bearer_header":
        header_name = auth_config.get("header_name", "Authorization")
        prefix = auth_config.get("prefix", "Bearer")
        headers[header_name] = f"{prefix} {secret_value}".strip()
        return

    if strategy == "header":
        header_name = auth_config.get("header_name", "Authorization")
        prefix = auth_config.get("prefix", "")
        headers[header_name] = f"{prefix}{secret_value}" if prefix else secret_value
        return

    if strategy == "query_param":
        param_name = auth_config.get("param", "api_key")
        if query is None:
            query = {}
            rendered_request["query"] = query
        if not isinstance(query, dict):
            raise ValueError("Request query deve ser um objeto para auth strategy 'query_param'")
        query[param_name] = secret_value
        return

    if strategy == "basic":
        username = str(auth_config.get("username") or "").strip()
        if not username:
            raise ValueError("Auth strategy 'basic' exige username")
        encoded = base64.b64encode(f"{username}:{secret_value}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
        return

    raise ValueError(f"Auth strategy nao suportada: {strategy}")


def _execute_post_response_actions(
    *,
    integration: IntegrationDefinition,
    runtime_context: dict[str, Any] | None,
    params: dict[str, Any],
    output: dict[str, Any],
    response: dict[str, Any],
) -> list[dict[str, Any]]:
    rendered_actions = render_post_response_actions(
        integration.post_response_actions,
        runtime_context,
        params=params,
        output=output,
        response=response,
    )
    if not rendered_actions:
        return []

    post_context = dict(runtime_context or {})
    post_context["params"] = params
    post_context["output"] = output
    post_context["response"] = response

    results: list[dict[str, Any]] = []
    for index, action_spec in enumerate(rendered_actions, start=1):
        action_name = action_spec.get("action")
        if not _is_allowed_post_response_action(action_name):
            raise ValueError(
                f"Acao '{action_name}' nao permitida em post_response_actions de '{integration.action_name}'"
            )
        executor = get_action_executor(action_name)
        if executor is None:
            raise ValueError(f"Acao '{action_name}' nao encontrada para post_response_actions")
        step = SimpleNamespace(
            name=f"{integration.action_name}.post_response.{index}",
            action=action_name,
            input=action_spec.get("input", {}),
        )
        result = executor(step=step, context=post_context)
        results.append({"action": action_name, "result": result})
    return results


def _is_allowed_post_response_action(action_name: Any) -> bool:
    if not isinstance(action_name, str) or not action_name.strip():
        return False
    return action_name.startswith(ALLOWED_POST_RESPONSE_PREFIXES)


def _sanitize_http_result(result: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(result)
    headers = sanitized.get("headers") or {}
    if isinstance(headers, dict):
        sanitized["headers"] = {
            key: ("***REDACTED***" if str(key).lower() in SENSITIVE_HEADER_NAMES else value)
            for key, value in headers.items()
        }
    return sanitized


def _resolve_path(path: str, data: Any) -> Any:
    current = data
    traversed: list[str] = []

    for segment in path.split("."):
        traversed.append(segment)
        if isinstance(current, dict):
            if segment in current:
                current = current[segment]
                continue
            raise ValueError(_missing_path_message(path, segment, traversed[:-1]))

        if isinstance(current, (list, tuple)):
            if not segment.isdigit():
                raise ValueError(
                    f"Response mapping '{path}' exige indice numerico para acessar listas em '{segment}'"
                )
            index = int(segment)
            if 0 <= index < len(current):
                current = current[index]
                continue
            raise ValueError(_missing_path_message(path, segment, traversed[:-1]))

        if current is not None and hasattr(current, segment):
            current = getattr(current, segment)
            continue

        raise ValueError(_missing_path_message(path, segment, traversed[:-1]))

    return current


def _missing_path_message(path: str, segment: str, traversed: list[str]) -> str:
    if traversed:
        parent = ".".join(traversed)
        return f"Response mapping '{path}' nao encontrado: '{segment}' ausente sob '{parent}'"
    return f"Response mapping '{path}' nao encontrado: chave raiz '{segment}' ausente"
