from django.contrib.auth import get_user_model
from django.test import TestCase

from incidents.models import Incident, IncidentRelation, TimelineEntry
from incidents.services import (
    BRANCH_MINIMUM_CONTAINMENT_TASK_KEYWORDS,
    RECOVERY_MINIMUM_TASK_KEYWORDS,
    create_communication,
    create_task,
    escalate_incident,
    link_incident,
    update_incident_secondary_assignees,
    update_incident_impact,
    update_incident_labels,
    update_incident_status,
    update_task,
)


class IncidentServiceTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="analyst", password="pass", email="analyst@example.com")
        self.other_user = User.objects.create_user(username="lead", password="pass", email="lead@example.com")
        self.incident = Incident.objects.create(title="Phishing", description="Email suspeito", created_by=self.user)

    def test_recommended_severity_from_risk(self):
        self.assertEqual(Incident.recommended_severity_from_risk(10), Incident.Severity.LOW)
        self.assertEqual(Incident.recommended_severity_from_risk(55), Incident.Severity.MEDIUM)
        self.assertEqual(Incident.recommended_severity_from_risk(70), Incident.Severity.HIGH)
        self.assertEqual(Incident.recommended_severity_from_risk(95), Incident.Severity.CRITICAL)

    def test_incident_uses_default_classification(self):
        self.assertEqual(
            self.incident.classification,
            Incident.Classification.UNDETERMINED,
        )

    def test_update_labels_and_timeline(self):
        update_incident_labels(incident=self.incident, add=["phishing"], actor=self.user)
        self.assertIn("phishing", self.incident.labels)
        self.assertTrue(
            TimelineEntry.objects.filter(incident=self.incident, entry_type=TimelineEntry.EntryType.LABEL_ADDED).exists()
        )
        update_incident_labels(incident=self.incident, remove=["phishing"], actor=self.user)
        self.assertNotIn("phishing", self.incident.labels)

    def test_update_status_records_timeline(self):
        update_incident_status(incident=self.incident, status=Incident.Status.IN_PROGRESS, actor=self.user, reason="triagem")
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, Incident.Status.IN_PROGRESS)
        self.assertTrue(
            TimelineEntry.objects.filter(incident=self.incident, entry_type=TimelineEntry.EntryType.STATUS_CHANGED).exists()
        )

    def test_task_lifecycle(self):
        task = create_task(incident=self.incident, title="Verificar header", owner=self.user, eta=None, actor=self.user)
        update_task(task=task, done=True, actor=self.user)
        task.refresh_from_db()
        self.assertTrue(task.done)
        self.assertTrue(
            TimelineEntry.objects.filter(incident=self.incident, entry_type=TimelineEntry.EntryType.TASK_UPDATE).exists()
        )

    def test_escalation_and_communication(self):
        escalate_incident(incident=self.incident, level="tier2", targets=["lead"], actor=self.user)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.escalation_level, "tier2")
        create_communication(
            incident=self.incident,
            channel="internal",
            recipient_team="NOC",
            recipient_user=self.other_user,
            message="Chamado aberto",
            actor=self.user,
        )
        self.assertEqual(self.incident.communications.count(), 1)

    def test_secondary_assignees_update(self):
        result = update_incident_secondary_assignees(
            incident=self.incident,
            assignee_ids=[self.user.id, self.other_user.id],
            actor=self.user,
        )
        self.assertTrue(result.changed)
        self.assertEqual(
            set(self.incident.secondary_assignees.values_list("id", flat=True)),
            {self.user.id, self.other_user.id},
        )
        no_change_result = update_incident_secondary_assignees(
            incident=self.incident,
            assignee_ids=[self.user.id, self.other_user.id],
            actor=self.user,
        )
        self.assertFalse(no_change_result.changed)

    def test_link_incident(self):
        related = Incident.objects.create(title="Duplicado", created_by=self.user)
        link_incident(source=self.incident, target=related, relation_type=IncidentRelation.RelationType.RELATED, actor=self.user)
        self.assertEqual(self.incident.relations_from.count(), 1)
        with self.assertRaises(ValueError):
            link_incident(source=self.incident, target=self.incident, relation_type=IncidentRelation.RelationType.RELATED, actor=self.user)

    def test_update_impact_adjusts_severity(self):
        update_incident_impact(
            incident=self.incident,
            impact_systems=["mail"],
            risk_score=85,
            severity=None,
            estimated_cost=1000,
            business_unit="SOC",
            data_classification="internal",
            actor=self.user,
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.severity, Incident.Severity.CRITICAL)
        self.assertEqual(self.incident.impact_systems, ["mail"])

    def _create_and_finish_tasks(self, *, keywords: tuple[str, ...]):
        for keyword in keywords:
            task = create_task(
                incident=self.incident,
                title=f"Checklist: {keyword}",
                owner=self.user,
                eta=None,
                actor=self.user,
            )
            update_task(task=task, done=True, actor=self.user)

    def test_update_labels_enforces_single_branch_label(self):
        self.incident.labels = ["phishing", "bec"]
        self.incident.save(update_fields=["labels", "updated_at"])

        update_incident_labels(
            incident=self.incident,
            add=["mailbox-compromise"],
            actor=self.user,
        )
        self.incident.refresh_from_db()

        active_branches = {
            label
            for label in self.incident.labels
            if label in BRANCH_MINIMUM_CONTAINMENT_TASK_KEYWORDS
        }
        self.assertEqual(active_branches, {"mailbox-compromise"})

    def test_contained_requires_single_active_branch(self):
        update_incident_labels(
            incident=self.incident,
            add=["phishing"],
            actor=self.user,
        )
        update_incident_status(
            incident=self.incident,
            status=Incident.Status.IN_PROGRESS,
            actor=self.user,
            reason="triagem",
        )

        with self.assertRaises(ValueError):
            update_incident_status(
                incident=self.incident,
                status=Incident.Status.CONTAINED,
                actor=self.user,
                reason="contencao",
            )

    def test_contained_requires_branch_tasks_created_and_done(self):
        update_incident_labels(
            incident=self.incident,
            add=["phishing", "bec"],
            actor=self.user,
        )
        update_incident_status(
            incident=self.incident,
            status=Incident.Status.IN_PROGRESS,
            actor=self.user,
            reason="triagem",
        )

        with self.assertRaises(ValueError):
            update_incident_status(
                incident=self.incident,
                status=Incident.Status.CONTAINED,
                actor=self.user,
                reason="contencao",
            )

        self._create_and_finish_tasks(
            keywords=BRANCH_MINIMUM_CONTAINMENT_TASK_KEYWORDS["bec"],
        )
        update_incident_status(
            incident=self.incident,
            status=Incident.Status.CONTAINED,
            actor=self.user,
            reason="contencao concluida",
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, Incident.Status.CONTAINED)

    def test_resolved_requires_recovery_tasks_done(self):
        update_incident_labels(
            incident=self.incident,
            add=["phishing", "credential-compromise"],
            actor=self.user,
        )
        update_incident_status(
            incident=self.incident,
            status=Incident.Status.IN_PROGRESS,
            actor=self.user,
            reason="triagem",
        )
        self._create_and_finish_tasks(
            keywords=BRANCH_MINIMUM_CONTAINMENT_TASK_KEYWORDS["credential-compromise"],
        )
        update_incident_status(
            incident=self.incident,
            status=Incident.Status.CONTAINED,
            actor=self.user,
            reason="contencao concluida",
        )

        with self.assertRaises(ValueError):
            update_incident_status(
                incident=self.incident,
                status=Incident.Status.RESOLVED,
                actor=self.user,
                reason="encerramento",
            )

        self._create_and_finish_tasks(keywords=RECOVERY_MINIMUM_TASK_KEYWORDS)
        update_incident_status(
            incident=self.incident,
            status=Incident.Status.RESOLVED,
            actor=self.user,
            reason="encerramento concluido",
        )
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, Incident.Status.RESOLVED)
