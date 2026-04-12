from __future__ import annotations

import base64
from typing import Any

from integrations.models import IntegrationDefinition
from integrations.services.http_client import execute_request
from integrations.services.secrets import resolve_secret_credentials
from integrations.services.template_renderer import render_output_template, render_request_template

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-apikey",
    "api-key",
    "apikey",
}
SENSITIVE_QUERY_NAMES = {"api_key", "apikey", "token", "access_token", "x-apikey"}


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
    credentials = _resolve_secret(integration)
    request_payload = _build_request_payload(
        integration=integration,
        rendered_request=rendered_request,
        credentials=credentials,
    )
    response = execute_request(**request_payload)
    output = _build_output(
        integration=integration,
        response=response,
        params=normalized_params,
        runtime_context=runtime_context,
    )
    return {
        "action_name": integration.action_name,
        "connector_revision": integration.revision,
        "response": _sanitize_http_result(response, integration),
        "output": output,
    }


def preview_configured_integration(
    *,
    integration: IntegrationDefinition,
    params: dict[str, Any] | None,
    runtime_context: dict[str, Any] | None,
    execute_http: bool = True,
) -> dict[str, Any]:
    normalized_params = params or {}
    _validate_expected_params(integration, normalized_params)

    rendered_request = render_request_template(
        integration.request_template,
        runtime_context,
        params=normalized_params,
    )
    credentials = _resolve_secret(integration)
    request_payload = _build_request_payload(
        integration=integration,
        rendered_request=rendered_request,
        credentials=credentials,
    )
    preview = {
        "request": _sanitize_request_payload(request_payload, integration),
        "auth_usage": _describe_auth_usage(integration),
    }
    if not execute_http:
        return preview

    response = execute_request(**request_payload)
    preview["response"] = _sanitize_http_result(response, integration)
    preview["output"] = _build_output(
        integration=integration,
        response=response,
        params=normalized_params,
        runtime_context=runtime_context,
    )
    return preview


def _build_output(
    *,
    integration: IntegrationDefinition,
    response: dict[str, Any],
    params: dict[str, Any],
    runtime_context: dict[str, Any] | None,
) -> Any:
    if integration.output_template:
        return render_output_template(
            integration.output_template,
            runtime_context,
            params=params,
            response=response,
        )
    if "body" in response:
        return response.get("body")
    return response


def _validate_expected_params(connector: IntegrationDefinition, params: dict[str, Any]) -> None:
    missing = [
        name
        for name in connector.expected_params
        if params.get(name) in (None, "")
    ]
    if missing:
        names = ", ".join(sorted(missing))
        raise ValueError(f"Parametros obrigatorios ausentes para '{connector.action_name}': {names}")


def _resolve_secret(connector: IntegrationDefinition) -> dict[str, str]:
    if connector.secret_ref is None:
        raise ValueError(f"HTTP connector '{connector.action_name}' exige secret_ref")
    return resolve_secret_credentials(connector.secret_ref)


def _build_request_payload(
    *,
    integration: IntegrationDefinition,
    rendered_request: dict[str, Any],
    credentials: dict[str, str] | None,
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
    query = _apply_secret_auth(
        integration=integration,
        headers=headers,
        query=query,
        credentials=credentials,
    )
    request_payload["headers"] = headers
    request_payload["query"] = query
    return request_payload


def _apply_secret_auth(
    *,
    integration: IntegrationDefinition,
    headers: dict[str, Any],
    query: Any,
    credentials: dict[str, str] | None,
) -> Any:
    if not credentials:
        return query

    strategy = integration.auth_strategy

    if strategy == IntegrationDefinition.AuthStrategy.BEARER_HEADER:
        secret_value = _require_token_credential(integration, credentials)
        header_name = integration.auth_header_name or "Authorization"
        prefix = integration.auth_prefix or "Bearer"
        headers[header_name] = f"{prefix} {secret_value}".strip()
        return query

    if strategy == IntegrationDefinition.AuthStrategy.HEADER:
        secret_value = _require_token_credential(integration, credentials)
        header_name = integration.auth_header_name or "Authorization"
        prefix = integration.auth_prefix or ""
        headers[header_name] = f"{prefix}{secret_value}" if prefix else secret_value
        return query

    if strategy == IntegrationDefinition.AuthStrategy.QUERY_PARAM:
        secret_value = _require_token_credential(integration, credentials)
        param_name = integration.auth_query_param or "api_key"
        if query is None:
            query = {}
        if not isinstance(query, dict):
            raise ValueError("Request query deve ser um objeto para auth strategy 'query_param'")
        query[param_name] = secret_value
        return query

    if strategy == IntegrationDefinition.AuthStrategy.BASIC:
        username, secret_value = _require_basic_auth_credential(integration, credentials)
        encoded = base64.b64encode(f"{username}:{secret_value}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {encoded}"
        return query

    raise ValueError(f"Auth strategy nao suportada: {strategy}")


def _sanitize_http_result(result: dict[str, Any], integration: IntegrationDefinition) -> dict[str, Any]:
    sanitized = dict(result)
    headers = sanitized.get("headers") or {}
    if isinstance(headers, dict):
        sanitized["headers"] = _sanitize_headers(headers, integration)
    query = sanitized.get("query")
    if isinstance(query, dict):
        sanitized["query"] = _sanitize_query(query, integration)
    return sanitized


def _sanitize_request_payload(payload: dict[str, Any], integration: IntegrationDefinition) -> dict[str, Any]:
    sanitized = dict(payload)
    headers = dict(sanitized.get("headers") or {})
    if headers:
        sanitized["headers"] = _sanitize_headers(headers, integration)

    query = sanitized.get("query")
    if isinstance(query, dict):
        sanitized["query"] = _sanitize_query(query, integration)
    return sanitized


def _sanitize_headers(
    headers: dict[str, Any],
    integration: IntegrationDefinition,
) -> dict[str, Any]:
    auth_header_name = (integration.auth_header_name or "Authorization").lower()
    return {
        key: (
            "***REDACTED***"
            if str(key).lower() in SENSITIVE_HEADER_NAMES or str(key).lower() == auth_header_name
            else value
        )
        for key, value in headers.items()
    }


def _sanitize_query(
    query: dict[str, Any],
    integration: IntegrationDefinition,
) -> dict[str, Any]:
    auth_query_param = (integration.auth_query_param or "api_key").lower()
    return {
        key: (
            "***REDACTED***"
            if str(key).lower() in SENSITIVE_QUERY_NAMES or str(key).lower() == auth_query_param
            else value
        )
        for key, value in query.items()
    }


def _describe_auth_usage(connector: IntegrationDefinition) -> str:
    secret_name = connector.secret_ref.name if connector.secret_ref else "secret_ref"
    strategy = connector.auth_strategy
    if strategy == IntegrationDefinition.AuthStrategy.BEARER_HEADER:
        header_name = connector.auth_header_name or "Authorization"
        prefix = connector.auth_prefix or "Bearer"
        return f"Usa o secret '{secret_name}' no header '{header_name}' com prefixo '{prefix}'."
    if strategy == IntegrationDefinition.AuthStrategy.HEADER:
        header_name = connector.auth_header_name or "Authorization"
        prefix = connector.auth_prefix or ""
        if prefix:
            return f"Usa o secret '{secret_name}' no header '{header_name}' com prefixo literal '{prefix}'."
        return f"Usa o secret '{secret_name}' diretamente no header '{header_name}'."
    if strategy == IntegrationDefinition.AuthStrategy.QUERY_PARAM:
        param_name = connector.auth_query_param or "api_key"
        return f"Usa o secret '{secret_name}' no parametro de query '{param_name}'."
    if strategy == IntegrationDefinition.AuthStrategy.BASIC:
        return f"Usa a credencial Basic Auth armazenada em '{secret_name}'."
    return f"Usa o secret '{secret_name}' com strategy '{strategy}'."


def _require_token_credential(
    integration: IntegrationDefinition,
    credentials: dict[str, str],
) -> str:
    token = (credentials.get("token") or "").strip()
    if not token:
        raise ValueError(
            f"HTTP connector '{integration.action_name}' exige um secret do tipo Token/API Key"
        )
    return token


def _require_basic_auth_credential(
    integration: IntegrationDefinition,
    credentials: dict[str, str],
) -> tuple[str, str]:
    username = (credentials.get("username") or "").strip()
    password = (credentials.get("password") or "").strip()
    if not username or not password:
        raise ValueError(
            f"HTTP connector '{integration.action_name}' exige um secret do tipo Basic Auth"
        )
    return username, password
