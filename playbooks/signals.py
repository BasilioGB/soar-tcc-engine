from __future__ import annotations

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from audit.utils import log_action
from .dsl import parse_playbook, ParseError
from .models import Playbook, PlaybookStep


@receiver(post_save, sender=Playbook)
def sync_steps_from_dsl(sender, instance: Playbook, created: bool, **kwargs):
    try:
        parsed = parse_playbook(instance.dsl)
    except ParseError:
        return

    with transaction.atomic():
        seen = set()
        for idx, step in enumerate(parsed.steps):
            obj, _ = PlaybookStep.objects.update_or_create(
                playbook=instance,
                name=step.name,
                defaults={"order": idx, "action": step.action, "config": step.input},
            )
            seen.add(obj.name)
        (PlaybookStep.objects.filter(playbook=instance)
         .exclude(name__in=seen)
         .delete())

    verb = "playbook.created" if created else "playbook.updated"
    log_action(actor=instance.created_by if created else instance.updated_by, verb=verb, target=instance)
