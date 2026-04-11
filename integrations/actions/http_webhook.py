from __future__ import annotations

from typing import Any

from ..registry import register
from ..services.http_client import execute_request


@register("http_webhook.post")
def send_webhook(*, step, context: dict[str, Any]):
    return execute_request(
        method=step.input.get("method"),
        url=step.input.get("url"),
        headers=step.input.get("headers"),
        timeout=step.input.get("timeout"),
        payload=step.input.get("payload"),
        raw_body=step.input.get("body"),
    )
