from __future__ import annotations

from typing import Any, Optional

from django.contrib.contenttypes.models import ContentType

from .models import ActionLog


def log_action(
    *,
    actor,
    verb: str,
    target=None,
    meta: Optional[dict[str, Any]] = None
) -> ActionLog:
    ct = None
    target_id = None

    if target is not None:
        ct = ContentType.objects.get_for_model(target, for_concrete_model=False)
        target_id = target.pk

    entry = ActionLog.objects.create(
        actor=actor,
        verb=verb,
        target_content_type=ct,
        target_object_id=target_id,
        meta=meta or {},
    )
    return entry
