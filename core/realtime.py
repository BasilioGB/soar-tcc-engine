from __future__ import annotations

from typing import Iterable, Sequence

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer


def _group_send(group: str, message: dict) -> None:
    channel_layer = get_channel_layer()
    if not channel_layer:
        return
    async_to_sync(channel_layer.group_send)(group, message)


def broadcast_incident_update(
    incident_id: int,
    *,
    sections: Iterable[str] | None = None,
    payload: dict | None = None,
) -> None:
    message_sections: Sequence[str] = tuple(dict.fromkeys(sections or ()))  # preserves order / uniqueness
    _group_send(
        f"incident_{incident_id}",
        {
            "type": "incident.message",
            "sections": list(message_sections),
            "payload": payload or {},
        },
    )


def broadcast_global_notification(kind: str, payload: dict | None = None) -> None:
    _group_send(
        "notify",
        {
            "type": "notify.message",
            "kind": kind,
            "payload": payload or {},
        },
    )
