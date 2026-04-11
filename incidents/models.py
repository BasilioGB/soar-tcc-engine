from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone


class IncidentQuerySet(models.QuerySet):
    def open(self):
        return self.exclude(status=Incident.Status.CLOSED)

    def with_severity(self, severity: str):
        return self.filter(severity=severity)

    def assigned_to(self, user):
        return self.filter(assignee=user)


class Incident(models.Model):
    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    class Status(models.TextChoices):
        NEW = "NEW", "New"
        IN_PROGRESS = "IN_PROGRESS", "In progress"
        CONTAINED = "CONTAINED", "Contained"
        RESOLVED = "RESOLVED", "Resolved"
        CLOSED = "CLOSED", "Closed"

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    labels = models.JSONField(default=list, blank=True)
    mitre_tactics = models.JSONField(default=list, blank=True)
    mitre_techniques = models.JSONField(default=list, blank=True)
    kill_chain_phase = models.CharField(max_length=64, blank=True)
    impact_systems = models.JSONField(default=list, blank=True)
    risk_score = models.PositiveIntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
    )
    estimated_cost = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    business_unit = models.CharField(max_length=128, blank=True)

    class DataClassification(models.TextChoices):
        PUBLIC = "public", "Public"
        INTERNAL = "internal", "Internal"
        CONFIDENTIAL = "confidential", "Confidential"
        RESTRICTED = "restricted", "Restricted"

    data_classification = models.CharField(
        max_length=32,
        choices=DataClassification.choices,
        default=DataClassification.INTERNAL,
    )
    escalation_level = models.CharField(max_length=32, blank=True)
    escalation_targets = models.JSONField(default=list, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="incidents_created",
        on_delete=models.SET_NULL,
        null=True,
    )
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="incidents_assigned",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    occurred_at = models.DateTimeField(null=True, blank=True)
    detected_at = models.DateTimeField(null=True, blank=True, default=timezone.now)
    responded_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = IncidentQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.id} - {self.title}"

    @staticmethod
    def recommended_severity_from_risk(risk_score: int) -> str:
        if risk_score >= 80:
            return Incident.Severity.CRITICAL
        if risk_score >= 60:
            return Incident.Severity.HIGH
        if risk_score >= 40:
            return Incident.Severity.MEDIUM
        return Incident.Severity.LOW

    def _save_with_skip_signals(self, *, update_fields: list[str]):
        setattr(self, "_skip_signal_logging", True)
        try:
            self.save(update_fields=update_fields)
        finally:
            if hasattr(self, "_skip_signal_logging"):
                delattr(self, "_skip_signal_logging")

    def add_label(self, label: str, actor=None):
        label = label.strip()
        if not label:
            return
        if label not in self.labels:
            self.labels.append(label)
            self._save_with_skip_signals(update_fields=["labels", "updated_at"])
            self.log_timeline(
                entry_type=TimelineEntry.EntryType.LABEL_ADDED,
                message=f"Label '{label}' adicionada",
                actor=actor,
            )

    def remove_label(self, label: str, actor=None):
        label = label.strip()
        if label in self.labels:
            self.labels.remove(label)
            self._save_with_skip_signals(update_fields=["labels", "updated_at"])
            self.log_timeline(
                entry_type=TimelineEntry.EntryType.LABEL_REMOVED,
                message=f"Label '{label}' removida",
                actor=actor,
            )

    def set_labels(self, *, add: list[str] | None = None, remove: list[str] | None = None, actor=None) -> bool:
        add = add or []
        remove = remove or []
        changed = False
        for raw_label in add:
            label = raw_label.strip()
            if not label or label in self.labels:
                continue
            self.labels.append(label)
            changed = True
            self.log_timeline(
                entry_type=TimelineEntry.EntryType.LABEL_ADDED,
                message=f"Label '{label}' adicionada",
                actor=actor,
            )
        for raw_label in remove:
            label = raw_label.strip()
            if label in self.labels:
                self.labels.remove(label)
                changed = True
                self.log_timeline(
                    entry_type=TimelineEntry.EntryType.LABEL_REMOVED,
                    message=f"Label '{label}' removida",
                    actor=actor,
                )
        if changed:
            self._save_with_skip_signals(update_fields=["labels", "updated_at"])
        return changed

    def set_status(self, *, status: str, actor=None, reason: str | None = None) -> bool:
        previous = self.status
        if previous == status:
            return False
        now = timezone.now()
        updates = ["status", "updated_at"]
        if previous == Incident.Status.NEW and status != Incident.Status.NEW and not self.responded_at:
            self.responded_at = now
            updates.append("responded_at")
        if status in {
            Incident.Status.IN_PROGRESS,
            Incident.Status.CONTAINED,
            Incident.Status.RESOLVED,
            Incident.Status.CLOSED,
        } and not self.responded_at:
            self.responded_at = now
            updates.append("responded_at")
        if status in {Incident.Status.RESOLVED, Incident.Status.CLOSED} and not self.resolved_at:
            self.resolved_at = now
            updates.append("resolved_at")
        if status == Incident.Status.CLOSED:
            self.closed_at = now
            updates.append("closed_at")
        self.status = status
        self._save_with_skip_signals(update_fields=updates)
        message = f"Status alterado de {previous} para {status}"
        if reason:
            message = f"{message} ({reason})"
        self.log_timeline(
            entry_type=TimelineEntry.EntryType.STATUS_CHANGED,
            message=message,
            actor=actor,
            extra={"from": previous, "to": status, "reason": reason},
        )
        return True

    def set_assignee(self, *, assignee=None, actor=None) -> bool:
        previous = self.assignee
        if previous == assignee:
            return False
        self.assignee = assignee
        self._save_with_skip_signals(update_fields=["assignee", "updated_at"])
        if assignee:
            label = assignee.get_full_name() or assignee.get_username()
            message = f"Responsavel alterado para {label}"
        else:
            message = "Responsavel removido"
        self.log_timeline(
            entry_type=TimelineEntry.EntryType.ASSIGNEE_CHANGED,
            message=message,
            actor=actor,
            extra={
                "from": getattr(previous, "id", None),
                "to": getattr(assignee, "id", None),
            },
        )
        return True

    def update_mitre(self, *, tactics=None, techniques=None, kill_chain_phase=None, actor=None) -> bool:
        changed = False
        if tactics is not None and tactics != self.mitre_tactics:
            self.mitre_tactics = tactics
            changed = True
        if techniques is not None and techniques != self.mitre_techniques:
            self.mitre_techniques = techniques
            changed = True
        if kill_chain_phase is not None and kill_chain_phase != self.kill_chain_phase:
            self.kill_chain_phase = kill_chain_phase
            changed = True
        if changed:
            self._save_with_skip_signals(
                update_fields=["mitre_tactics", "mitre_techniques", "kill_chain_phase", "updated_at"]
            )
            self.log_timeline(
                entry_type=TimelineEntry.EntryType.NOTE,
                message="Contexto MITRE/Kill Chain atualizado",
                actor=actor,
                extra={
                    "tactics": self.mitre_tactics,
                    "techniques": self.mitre_techniques,
                    "kill_chain": self.kill_chain_phase,
                },
            )
        return changed

    def update_impact(
        self,
        *,
        impact_systems=None,
        risk_score=None,
        severity=None,
        estimated_cost=None,
        business_unit=None,
        data_classification=None,
        actor=None,
    ) -> bool:
        fields: list[str] = []
        if impact_systems is not None and impact_systems != self.impact_systems:
            self.impact_systems = impact_systems
            fields.append("impact_systems")
        if risk_score is not None and risk_score != self.risk_score:
            self.risk_score = risk_score
            fields.append("risk_score")
            if severity is None:
                severity = self.recommended_severity_from_risk(risk_score)
        if severity is not None and severity != self.severity:
            previous = self.severity
            self.severity = severity
            fields.append("severity")
            self.log_timeline(
                entry_type=TimelineEntry.EntryType.NOTE,
                message=f"Severidade ajustada de {previous} para {severity}",
                actor=actor,
                extra={"from": previous, "to": severity, "reason": "risk_update"},
            )
        if estimated_cost is not None and estimated_cost != self.estimated_cost:
            self.estimated_cost = estimated_cost
            fields.append("estimated_cost")
        if business_unit is not None and business_unit != self.business_unit:
            self.business_unit = business_unit
            fields.append("business_unit")
        if data_classification is not None and data_classification != self.data_classification:
            self.data_classification = data_classification
            fields.append("data_classification")
        if fields:
            fields.append("updated_at")
            self._save_with_skip_signals(update_fields=fields)
            self.log_timeline(
                entry_type=TimelineEntry.EntryType.NOTE,
                message="Impacto do incidente atualizado",
                actor=actor,
                extra={
                    "impact_systems": self.impact_systems,
                    "risk_score": self.risk_score,
                    "estimated_cost": str(self.estimated_cost),
                    "business_unit": self.business_unit,
                    "data_classification": self.data_classification,
                },
            )
        return bool(fields)

    def update_escalation(self, *, level=None, targets=None, actor=None) -> bool:
        changed = False
        if level is not None and level != self.escalation_level:
            self.escalation_level = level
            changed = True
        if targets is not None and targets != self.escalation_targets:
            self.escalation_targets = targets
            changed = True
        if changed:
            self._save_with_skip_signals(update_fields=["escalation_level", "escalation_targets", "updated_at"])
            self.log_timeline(
                entry_type=TimelineEntry.EntryType.ESCALATION,
                message="Incidente escalonado",
                actor=actor,
                extra={
                    "level": self.escalation_level,
                    "targets": self.escalation_targets,
                },
            )
        return changed

    def log_timeline(self, *, entry_type: str, message: str, actor=None, extra: dict | None = None):
        TimelineEntry.objects.create(
            incident=self,
            entry_type=entry_type,
            message=message,
            created_by=actor,
            meta=extra or {},
        )

    def detection_delta(self):
        if self.occurred_at and self.detected_at:
            return self.detected_at - self.occurred_at
        return None

    def response_delta(self):
        if self.detected_at and self.responded_at:
            return self.responded_at - self.detected_at
        return None

    def resolution_delta(self):
        resolved = self.resolved_at or self.closed_at
        if self.detected_at and resolved:
            return resolved - self.detected_at
        return None


class Artifact(models.Model):
    class Type(models.TextChoices):
        IP = "IP", "IP"
        DOMAIN = "DOMAIN", "Domain"
        URL = "URL", "URL"
        EMAIL = "EMAIL", "Email"
        HASH = "HASH", "Hash"
        FILE = "FILE", "File"
        OTHER = "OTHER", "Other"

    type = models.CharField(max_length=16, choices=Type.choices, default=Type.OTHER)
    value = models.CharField(max_length=512, blank=True)
    file = models.FileField(upload_to="artifacts/%Y/%m/%d/", blank=True, null=True)
    size = models.BigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True)
    content_type = models.CharField(max_length=128, blank=True)
    attributes = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    incidents = models.ManyToManyField(
        Incident,
        through="IncidentArtifact",
        related_name="artifacts",
        blank=True,
    )

    class Meta:
        ordering = ["created_at"]

    def __str__(self) -> str:
        label = self.value or (self.file.name if self.file else "")
        return f"{self.type}: {label}"

    def set_attributes(self, *, attributes: dict[str, Any], merge: bool = True) -> bool:
        if not isinstance(attributes, dict):
            raise ValueError("Attributes devem ser um objeto")
        current = self.attributes or {}
        if merge:
            new_value = {**current, **attributes}
        else:
            new_value = attributes
        if new_value == current:
            return False
        self.attributes = new_value
        self.save(update_fields=["attributes"])
        return True

    def primary_incident(self) -> Incident | None:
        return (
            self.incidents.order_by("incidentartifact__created_at").first()
        )


class IncidentArtifact(models.Model):
    incident = models.ForeignKey(
        Incident,
        related_name="artifact_memberships",
        on_delete=models.CASCADE,
    )
    artifact = models.ForeignKey(
        Artifact,
        related_name="incident_memberships",
        on_delete=models.CASCADE,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("incident", "artifact")
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Artifact {self.artifact_id} -> Incident {self.incident_id}"


class TimelineEntry(models.Model):
    class EntryType(models.TextChoices):
        NOTE = "NOTE", "Note"
        STATUS_CHANGED = "STATUS_CHANGED", "Status Changed"
        ASSIGNEE_CHANGED = "ASSIGNEE_CHANGED", "Assignee Changed"
        LABEL_ADDED = "LABEL_ADDED", "Label Added"
        LABEL_REMOVED = "LABEL_REMOVED", "Label Removed"
        ARTIFACT_ADDED = "ARTIFACT_ADDED", "Artifact Added"
        TASK_UPDATE = "TASK_UPDATE", "Task Update"
        ESCALATION = "ESCALATION", "Escalation"
        COMMUNICATION = "COMMUNICATION", "Communication"
        PLAYBOOK_EXECUTION = "PLAYBOOK_EXECUTION", "Playbook Execution"

    incident = models.ForeignKey(Incident, related_name="timeline", on_delete=models.CASCADE)
    entry_type = models.CharField(max_length=32, choices=EntryType.choices, default=EntryType.NOTE)
    message = models.TextField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="timeline_entries",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(default=timezone.now)
    meta = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self) -> str:
        return f"{self.get_entry_type_display()} - {self.created_at:%Y-%m-%d %H:%M}"


class IncidentTask(models.Model):
    incident = models.ForeignKey(Incident, related_name="tasks", on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="incident_tasks",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    eta = models.DateTimeField(null=True, blank=True)
    done = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="incident_tasks_created",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["done", "eta", "-created_at"]

    def __str__(self) -> str:
        return self.title

    def toggle(self, *, done: bool, actor=None):
        if self.done == done:
            return False
        self.done = done
        self.save(update_fields=["done", "updated_at"])
        self.incident.log_timeline(
            entry_type=TimelineEntry.EntryType.TASK_UPDATE,
            message=f"Tarefa '{self.title}' marcada como {'concluida' if done else 'pendente'}",
            actor=actor,
            extra={"task_id": self.pk, "done": done},
        )
        return True


class IncidentRelation(models.Model):
    class RelationType(models.TextChoices):
        RELATED = "related", "Related"
        DUPLICATE = "duplicate", "Duplicate"
        PARENT = "parent", "Parent"
        CHILD = "child", "Child"

    from_incident = models.ForeignKey(
        Incident,
        related_name="relations_from",
        on_delete=models.CASCADE,
    )
    to_incident = models.ForeignKey(
        Incident,
        related_name="relations_to",
        on_delete=models.CASCADE,
    )
    relation_type = models.CharField(max_length=16, choices=RelationType.choices)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="incident_relations_created",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("from_incident", "to_incident", "relation_type"),
                name="unique_incident_relation",
            )
        ]

    def __str__(self) -> str:
        return f"{self.from_incident_id} -> {self.to_incident_id} ({self.relation_type})"


class CommunicationLog(models.Model):
    incident = models.ForeignKey(Incident, related_name="communications", on_delete=models.CASCADE)
    channel = models.CharField(max_length=32, default="internal")
    recipient_team = models.CharField(max_length=128, blank=True)
    recipient_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="incident_communications",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    message = models.TextField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="communication_logs_created",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Communication for incident {self.incident_id} via {self.channel}"
