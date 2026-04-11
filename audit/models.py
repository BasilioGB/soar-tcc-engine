from __future__ import annotations

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils import timezone


class ActionLog(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name="audit_logs", on_delete=models.SET_NULL, null=True, blank=True
    )
    verb = models.CharField(max_length=128)
    timestamp = models.DateTimeField(default=timezone.now)
    target_content_type = models.ForeignKey(ContentType, on_delete=models.SET_NULL, null=True, blank=True)
    target_object_id = models.CharField(max_length=64, null=True, blank=True)
    target = GenericForeignKey("target_content_type", "target_object_id")
    meta = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["verb"]),
            models.Index(fields=["timestamp"]),
        ]

    def __str__(self) -> str:
        target_repr = f" {self.target}" if self.target else ""
        return f"{self.timestamp:%Y-%m-%d %H:%M} - {self.verb}{target_repr}"
