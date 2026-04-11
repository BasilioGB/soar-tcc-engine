from __future__ import annotations

from typing import Dict, Any

from django.db import transaction

from playbooks.trigger_cache import get_triggers_for_event

from .tasks import process_playbook_event


def emit_event(event: str, payload: Dict[str, Any]) -> None:
    # snapshot payload to avoid later mutation
    data = dict(payload)
    triggers = get_triggers_for_event(event)
    if not triggers:
        return

    def _enqueue():
        process_playbook_event.delay(event, data)

    if transaction.get_connection().in_atomic_block:
        transaction.on_commit(_enqueue)
    else:
        _enqueue()
