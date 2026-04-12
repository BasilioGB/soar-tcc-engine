from __future__ import annotations

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from incidents.models import Incident
from playbooks.validation import validate_playbook_semantics
from .dsl import (
    ExecutionMode,
    ManualFilterTarget,
    ParseError,
    PlaybookType,
    TriggerEvent,
    parse_playbook,
)


class Playbook(models.Model):
    class Type(models.TextChoices):
        INCIDENT = PlaybookType.INCIDENT.value, "Incidente"
        ARTIFACT = PlaybookType.ARTIFACT.value, "Artefato"

    class Mode(models.TextChoices):
        AUTOMATIC = ExecutionMode.AUTOMATIC.value, "Automatico"
        MANUAL = ExecutionMode.MANUAL.value, "Manual"

    name = models.CharField(max_length=255, unique=True)
    category = models.CharField(max_length=64, default="Geral", db_index=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    dsl = models.JSONField(default=dict)
    type = models.CharField(max_length=32, choices=Type.choices, default=Type.INCIDENT)
    mode = models.CharField(max_length=32, choices=Mode.choices, default=Mode.AUTOMATIC)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="playbooks_created", on_delete=models.SET_NULL, null=True
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="playbooks_updated", on_delete=models.SET_NULL, null=True, blank=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    @property
    def category_display(self) -> str:
        return (self.category or "Geral").strip() or "Geral"

    def clean(self):
        super().clean()
        self.category = self.category_display
        try:
            parsed = parse_playbook(self.dsl)
            validate_playbook_semantics(self.dsl, parsed_playbook=parsed)
        except ParseError as exc:
            raise ValidationError({"dsl": str(exc)})
        except ValidationError as exc:
            raise ValidationError({"dsl": exc.messages})
        self.type = parsed.type.value
        self.mode = parsed.mode.value

    def save(self, *args, **kwargs):
        self.category = self.category_display
        try:
            parsed = parse_playbook(self.dsl)
            validate_playbook_semantics(self.dsl, parsed_playbook=parsed)
        except ParseError as exc:
            raise ValidationError({"dsl": str(exc)}) from exc
        except ValidationError as exc:
            raise ValidationError({"dsl": exc.messages}) from exc
        self.type = parsed.type.value
        self.mode = parsed.mode.value
        if isinstance(self.dsl, dict):
            self.dsl["type"] = self.type
            self.dsl["mode"] = self.mode
        super().save(*args, **kwargs)
        if self.mode == Playbook.Mode.AUTOMATIC:
            self.sync_triggers(parsed)
            self.sync_filters(clear_only=True)
        else:
            self.sync_triggers(clear_only=True)
            self.sync_filters(parsed)

    def sync_triggers(self, parsed_playbook=None, clear_only: bool = False):
        from .trigger_cache import invalidate_events

        parsed = parsed_playbook or parse_playbook(self.dsl)
        existing_events = list(self.trigger_entries.values_list("event", flat=True))
        PlaybookTrigger.objects.filter(playbook=self).delete()
        new_triggers: list[PlaybookTrigger] = []
        if not clear_only:
            new_triggers = [
                PlaybookTrigger(
                    playbook=self,
                    event=trigger.event,
                    filters=trigger.filters or {},
                )
                for trigger in parsed.triggers
            ]
            if new_triggers:
                PlaybookTrigger.objects.bulk_create(new_triggers)
        invalidate_events(existing_events + [trigger.event for trigger in new_triggers])

    def sync_filters(self, parsed_playbook=None, clear_only: bool = False):
        parsed = parsed_playbook or parse_playbook(self.dsl)
        PlaybookFilter.objects.filter(playbook=self).delete()
        if clear_only:
            return
        records = [
            PlaybookFilter(
                playbook=self,
                target=manual_filter.target.value,
                conditions=manual_filter.conditions or {},
            )
            for manual_filter in parsed.filters
        ]
        if records:
            PlaybookFilter.objects.bulk_create(records)

    @property
    def triggers(self) -> list[dict]:
        data = parse_playbook(self.dsl)
        return [{"event": trigger.event, "filters": trigger.filters} for trigger in data.triggers]

    @property
    def filters(self) -> list[dict]:
        data = parse_playbook(self.dsl)
        return [
            {"target": manual_filter.target.value, "conditions": manual_filter.conditions}
            for manual_filter in data.filters
        ]

    @property
    def steps(self):
        return parse_playbook(self.dsl).steps

    @property
    def playbook_type(self) -> PlaybookType:
        return parse_playbook(self.dsl).type


class PlaybookStep(models.Model):
    playbook = models.ForeignKey(Playbook, related_name="step_definitions", on_delete=models.CASCADE)
    name = models.CharField(max_length=128)
    action = models.CharField(max_length=128)
    order = models.PositiveIntegerField(default=0)
    config = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["order"]
        unique_together = ("playbook", "name")

    def __str__(self) -> str:
        return f"{self.playbook.name}::{self.name}"


class PlaybookTrigger(models.Model):
    class Event(models.TextChoices):
        INCIDENT_CREATED = TriggerEvent.INCIDENT_CREATED.value, "Incidente criado"
        INCIDENT_UPDATED = TriggerEvent.INCIDENT_UPDATED.value, "Incidente atualizado"
        ARTIFACT_CREATED = TriggerEvent.ARTIFACT_CREATED.value, "Artefato criado"

    playbook = models.ForeignKey(Playbook, related_name="trigger_entries", on_delete=models.CASCADE)
    event = models.CharField(max_length=64, choices=Event.choices)
    filters = models.JSONField(default=dict, blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["event"]),
            models.Index(fields=["playbook", "event"]),
        ]

    def __str__(self) -> str:
        return f"{self.playbook.name} -> {self.event}"


class PlaybookFilter(models.Model):
    class Target(models.TextChoices):
        INCIDENT = ManualFilterTarget.INCIDENT.value, "Incidente"
        ARTIFACT = ManualFilterTarget.ARTIFACT.value, "Artefato"

    playbook = models.ForeignKey(Playbook, related_name="filter_entries", on_delete=models.CASCADE)
    target = models.CharField(max_length=32, choices=Target.choices)
    conditions = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["target"]),
            models.Index(fields=["playbook", "target"]),
        ]

    def __str__(self) -> str:
        return f"{self.playbook.name} [{self.target}]"


class Execution(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        RUNNING = "RUNNING", "Running"
        SUCCEEDED = "SUCCEEDED", "Succeeded"
        FAILED = "FAILED", "Failed"

    playbook = models.ForeignKey(Playbook, related_name="executions", on_delete=models.CASCADE)
    incident = models.ForeignKey(Incident, related_name="executions", on_delete=models.CASCADE)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="executions_started", on_delete=models.SET_NULL, null=True, blank=True
    )
    context = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-started_at", "-id"]

    def __str__(self) -> str:
        return f"Execution #{self.id} - {self.playbook.name}"


class ExecutionLog(models.Model):
    class Level(models.TextChoices):
        INFO = "INFO", "Info"
        WARNING = "WARNING", "Warning"
        ERROR = "ERROR", "Error"

    execution = models.ForeignKey(Execution, related_name="logs", on_delete=models.CASCADE)
    ts = models.DateTimeField(default=timezone.now)
    level = models.CharField(max_length=16, choices=Level.choices, default=Level.INFO)
    message = models.TextField()
    step_name = models.CharField(max_length=128, blank=True)

    class Meta:
        ordering = ["ts", "id"]

    def __str__(self) -> str:
        return f"[{self.level}] {self.step_name}: {self.message[:50]}"


class ExecutionStepResult(models.Model):
    class Status(models.TextChoices):
        SUCCEEDED = "SUCCEEDED", "Succeeded"
        FAILED = "FAILED", "Failed"
        SKIPPED = "SKIPPED", "Skipped"

    execution = models.ForeignKey(Execution, related_name="step_results", on_delete=models.CASCADE)
    step_name = models.CharField(max_length=128)
    step_order = models.PositiveIntegerField()
    status = models.CharField(max_length=16, choices=Status.choices)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(default=timezone.now)
    duration_ms = models.PositiveIntegerField(default=0)
    resolved_input = models.JSONField(default=dict, blank=True)
    result = models.JSONField(null=True, blank=True)
    error_class = models.CharField(max_length=128, blank=True)
    error_message = models.TextField(blank=True)
    skipped_reason = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["step_order", "id"]
        indexes = [
            models.Index(fields=["execution", "step_order"]),
            models.Index(fields=["execution", "step_name"]),
            models.Index(fields=["status"]),
        ]

    def __str__(self) -> str:
        return f"{self.execution_id}:{self.step_order}:{self.step_name} [{self.status}]"
