from django.contrib.auth import get_user_model
from django.test import TestCase

from incidents.models import Incident, IncidentRelation, TimelineEntry
from incidents.services import (
    create_communication,
    create_task,
    escalate_incident,
    link_incident,
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
