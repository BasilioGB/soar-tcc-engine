from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import requests

DEFAULT_TIMEOUT_SECONDS = 15
ALLOWED_METHODS = {"POST", "PUT", "PATCH", "DELETE", "GET"}


def parse_timeout(value: Any) -> float:
    if value in (None, ""):
        return float(DEFAULT_TIMEOUT_SECONDS)
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Webhook timeout invalido") from exc
    if timeout <= 0:
        raise ValueError("Webhook timeout deve ser maior que zero")
    return timeout


def normalize_method(value: Any) -> str:
    method = str(value or "POST").strip().upper()
    if method not in ALLOWED_METHODS:
        raise ValueError(f"Metodo HTTP nao suportado para webhook: {method}")
    return method


def parse_response_body(response: requests.Response) -> Any:
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "json" in content_type:
        try:
            return response.json()
        except ValueError:
            return response.text
    return response.text


def execute_request(
    *,
    method: Any,
    url: Any,
    headers: Any = None,
    query: Any = None,
    timeout: Any = None,
    payload: Any = None,
    raw_body: Any = None,
) -> dict[str, Any]:
    normalized_method = normalize_method(method)
    normalized_timeout = parse_timeout(timeout)
    normalized_headers = headers or {}

    if not url:
        raise ValueError("Webhook URL ausente")
    if not isinstance(normalized_headers, dict):
        raise ValueError("Webhook headers devem ser um objeto")
    if payload is not None and raw_body is not None:
        raise ValueError("Use payload ou body no webhook, nao ambos")

    request_kwargs: dict[str, Any] = {
        "method": normalized_method,
        "url": url,
        "headers": normalized_headers,
        "timeout": normalized_timeout,
    }
    if query is not None:
        request_kwargs["params"] = query
    if payload is not None:
        request_kwargs["json"] = payload
    elif raw_body is not None:
        request_kwargs["data"] = raw_body

    try:
        response = requests.request(**request_kwargs)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise ValueError(f"Falha ao enviar webhook HTTP: {exc}") from exc

    return {
        "url": url,
        "method": normalized_method,
        "payload": payload,
        "request_body": raw_body,
        "headers": normalized_headers,
        "timeout": normalized_timeout,
        "sent_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status_code": response.status_code,
        "response_headers": dict(response.headers),
        "body": parse_response_body(response),
    }
