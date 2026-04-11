from __future__ import annotations

from typing import Iterable, List, Dict

from django.conf import settings
from django.core.cache import cache

from .models import PlaybookTrigger

CACHE_PREFIX = "playbook_triggers"
CACHE_TIMEOUT = getattr(settings, "PLAYBOOK_TRIGGER_CACHE_TIMEOUT", 60)


def _cache_key(event: str) -> str:
    return f"{CACHE_PREFIX}:{event}"


def get_triggers_for_event(event: str) -> List[Dict]:
    key = _cache_key(event)
    data = cache.get(key)
    if data is not None:
        return data

    triggers = (
        PlaybookTrigger.objects.filter(active=True, event=event, playbook__enabled=True)
        .select_related("playbook")
        .all()
    )
    data = [
        {
            "playbook_id": trigger.playbook_id,
            "playbook_type": trigger.playbook.type,
            "filters": trigger.filters or {},
        }
        for trigger in triggers
    ]
    cache.set(key, data, CACHE_TIMEOUT)
    return data


def invalidate_events(events: Iterable[str]) -> None:
    unique_events = set(events)
    for event in unique_events:
        cache.delete(_cache_key(event))
