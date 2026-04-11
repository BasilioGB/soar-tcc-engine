from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import requests

from ..registry import register

DEFAULT_TIMEOUT_SECONDS = 15
ALLOWED_METHODS = {"POST", "PUT", "PATCH", "DELETE", "GET"}


def _parse_timeout(value: Any) -> float:
    if value in (None, ""):
        return float(DEFAULT_TIMEOUT_SECONDS)
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Webhook timeout invalido") from exc
    if timeout <= 0:
        raise ValueError("Webhook timeout deve ser maior que zero")
    return timeout


def _normalize_method(value: Any) -> str:
    method = str(value or "POST").strip().upper()
    if method not in ALLOWED_METHODS:
        raise ValueError(f"Metodo HTTP nao suportado para webhook: {method}")
    return method


def _parse_response_body(response: requests.Response) -> Any:
    content_type = (response.headers.get("Content-Type") or "").lower()
    if "json" in content_type:
        try:
            return response.json()
        except ValueError:
            return response.text
    return response.text


@register("http_webhook.post")
def send_webhook(*, step, context: dict[str, Any]):
    url = step.input.get("url")
    payload = step.input.get("payload")
    raw_body = step.input.get("body")
    headers = step.input.get("headers") or {}
    method = _normalize_method(step.input.get("method"))
    timeout = _parse_timeout(step.input.get("timeout"))

    if not url:
        raise ValueError("Webhook URL ausente")
    if not isinstance(headers, dict):
        raise ValueError("Webhook headers devem ser um objeto")
    if payload is not None and raw_body is not None:
        raise ValueError("Use payload ou body no webhook, nao ambos")

    request_kwargs: dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": headers,
        "timeout": timeout,
    }
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
        "method": method,
        "payload": payload,
        "request_body": raw_body,
        "headers": headers,
        "timeout": timeout,
        "sent_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status_code": response.status_code,
        "response_headers": dict(response.headers),
        "body": _parse_response_body(response),
    }
