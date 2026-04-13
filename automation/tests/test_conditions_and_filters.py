from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings

from automation.tasks import _build_trigger_dedup_key
from automation.trigger_matching import matches
from incidents.models import Artifact, Incident, TimelineEntry
from incidents.services import add_artifact_link
from playbooks.models import Execution, ExecutionStepResult, Playbook
from playbooks.services import (
    get_manual_playbooks_for_artifact,
    start_playbook_execution,
)


class TriggerAndManualFilterPlaceholderTests(TestCase):
    def test_incident_trigger_filters_resolve_placeholders_against_incident_context(self):
        User = get_user_model()
        user = User.objects.create_user(username="lead", password="pass")
        incident = Incident.objects.create(
            title="Credential reset",
            description="incident payload context",
            created_by=user,
            severity=Incident.Severity.MEDIUM,
        )

        payload = {
            "incident_id": incident.id,
            "severity": incident.severity,
            "status": incident.status,
            "labels": incident.labels,
        }

        self.assertTrue(
            matches(
                "incident.updated",
                {"severity": ["{{incident.severity}}"]},
                payload,
                resolution_context={"incident": incident, "payload": payload, "trigger_context": payload},
            )
        )

    def test_trigger_filters_raise_when_placeholder_cannot_be_resolved(self):
        payload = {
            "incident_id": 9,
            "severity": "MEDIUM",
            "status": "NEW",
            "labels": [],
        }

        with self.assertRaisesMessage(ValueError, "trigger filters"):
            matches(
                "incident.updated",
                {"severity": ["{{incident.owner.id}}"]},
                payload,
                resolution_context={"incident": payload, "payload": payload, "trigger_context": payload},
            )

    def test_trigger_filters_resolve_placeholders_against_event_payload(self):
        payload = {
            "artifact_id": 10,
            "incident_id": 5,
            "type": "IP",
            "value": "203.0.113.7",
            "incident_labels": ["credential"],
            "attributes": {"expected_type": "IP"},
        }

        self.assertTrue(
            matches(
                "artifact.created",
                {"attribute_equals": {"expected_type": "{{artifact.type}}"}},
                payload,
            )
        )

    def test_incident_updated_filters_require_changed_fields_overlap(self):
        payload = {
            "incident_id": 11,
            "severity": "HIGH",
            "status": "IN_PROGRESS",
            "labels": ["phishing", "bec"],
            "changed_fields": ["severity"],
        }

        self.assertFalse(
            matches(
                "incident.updated",
                {"labels": ["phishing", "bec"], "changed_fields": ["labels"]},
                payload,
            )
        )
        self.assertTrue(
            matches(
                "incident.updated",
                {"labels": ["phishing", "bec"], "changed_fields": ["severity", "labels"]},
                payload,
            )
        )

    def test_incident_trigger_filters_support_exclude_labels(self):
        payload_blocked = {
            "incident_id": 21,
            "severity": "HIGH",
            "status": "IN_PROGRESS",
            "labels": ["phishing", "manual-treatment"],
        }
        payload_allowed = {
            "incident_id": 22,
            "severity": "HIGH",
            "status": "IN_PROGRESS",
            "labels": ["phishing"],
        }

        self.assertFalse(
            matches(
                "incident.created",
                {"labels": ["phishing"], "exclude_labels": ["manual-treatment"]},
                payload_blocked,
            )
        )
        self.assertTrue(
            matches(
                "incident.created",
                {"labels": ["phishing"], "exclude_labels": ["manual-treatment"]},
                payload_allowed,
            )
        )

    def test_artifact_trigger_filters_support_exclude_labels(self):
        payload_blocked = {
            "artifact_id": 31,
            "incident_id": 9,
            "type": "URL",
            "value": "https://bad.example",
            "incident_labels": ["phishing", "manual-treatment"],
        }
        payload_allowed = {
            "artifact_id": 32,
            "incident_id": 9,
            "type": "URL",
            "value": "https://good.example",
            "incident_labels": ["phishing"],
        }

        self.assertFalse(
            matches(
                "artifact.created",
                {"type": ["URL"], "exclude_labels": ["manual-treatment"]},
                payload_blocked,
            )
        )
        self.assertTrue(
            matches(
                "artifact.created",
                {"type": ["URL"], "exclude_labels": ["manual-treatment"]},
                payload_allowed,
            )
        )

    def test_manual_artifact_filters_resolve_placeholders_against_artifact(self):
        User = get_user_model()
        user = User.objects.create_user(username="lead", password="pass")
        incident = Incident.objects.create(
            title="IOC triage",
            description="artifact review",
            created_by=user,
        )
        artifact = add_artifact_link(
            incident=incident,
            value="203.0.113.7",
            type_code=Artifact.Type.IP,
            actor=user,
        )
        artifact.attributes = {"expected_type": "IP"}
        artifact.save(update_fields=["attributes"])

        playbook = Playbook.objects.create(
            name="Dynamic artifact filter",
            dsl={
                "name": "Dynamic artifact filter",
                "type": "artifact",
                "mode": "manual",
                "filters": [
                    {
                        "target": "artifact",
                        "conditions": {
                            "attribute_equals": {"expected_type": "{{artifact.type}}"}
                        },
                    }
                ],
                "steps": [
                    {
                        "name": "note",
                        "action": "incident.add_note",
                        "input": {"message": "artifact filter matched"},
                    }
                ],
            },
            enabled=True,
            created_by=user,
        )

        available = get_manual_playbooks_for_artifact(artifact, incident=incident)
        self.assertIn(playbook.id, [item.id for item in available])

    def test_manual_filters_raise_when_placeholder_cannot_be_resolved(self):
        User = get_user_model()
        user = User.objects.create_user(username="lead_strict", password="pass")
        incident = Incident.objects.create(
            title="Strict manual filter",
            description="invalid placeholder should fail",
            created_by=user,
        )
        artifact = add_artifact_link(
            incident=incident,
            value="strict.example",
            type_code=Artifact.Type.DOMAIN,
            actor=user,
        )
        playbook = Playbook.objects.create(
            name="Invalid strict artifact filter",
            dsl={
                "name": "Invalid strict artifact filter",
                "type": "artifact",
                "mode": "manual",
                "filters": [
                    {
                        "target": "artifact",
                        "conditions": {
                            "attribute_equals": {"expected_type": "{{artifact.owner.id}}"}
                        },
                    }
                ],
                "steps": [
                    {
                        "name": "note",
                        "action": "incident.add_note",
                        "input": {"message": "never runs"},
                    }
                ],
            },
            enabled=True,
            created_by=user,
        )

        with self.assertRaisesMessage(ValueError, f"manual artifact filters do playbook {playbook.id}"):
            get_manual_playbooks_for_artifact(artifact, incident=incident)


@override_settings(
    CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}},
    CELERY_TASK_ALWAYS_EAGER=True,
)
class RuntimeConditionTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="lead", password="pass")
        self.incident = Incident.objects.create(
            title="Conditional incident",
            description="condition execution",
            created_by=self.user,
            labels=["phishing"],
        )

    def test_when_can_skip_step_and_enable_followup_logic(self):
        playbook = Playbook.objects.create(
            name="Conditional runtime flow",
            dsl={
                "name": "Conditional runtime flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "critical_only_note",
                        "action": "incident.add_note",
                        "when": {"left": "{{incident.severity}}", "equals": "CRITICAL"},
                        "input": {"message": "critical path"},
                    },
                    {
                        "name": "skip_audit_note",
                        "action": "incident.add_note",
                        "when": {"left": "{{results.critical_only_note.skipped}}", "equals": True},
                        "input": {"message": "optional step skipped"},
                    },
                    {
                        "name": "complex_condition_note",
                        "action": "incident.add_note",
                        "when": {
                            "all": [
                                {"left": "{{incident.severity}}", "in": ["MEDIUM", "HIGH"]},
                                {"left": "{{incident.labels}}", "contains": "phishing"},
                                {"not": {"left": "{{incident.labels}}", "contains": "ignored"}},
                            ]
                        },
                        "input": {"message": "complex condition matched"},
                    },
                ],
            },
            enabled=True,
            created_by=self.user,
        )

        execution = start_playbook_execution(
            playbook,
            self.incident,
            actor=self.user,
            force_sync=True,
            context={"event": "manual.incident"},
        )

        execution.refresh_from_db()
        self.assertEqual(execution.status, Execution.Status.SUCCEEDED)
        self.assertFalse(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="critical path",
            ).exists()
        )
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="optional step skipped",
            ).exists()
        )
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="complex condition matched",
            ).exists()
        )
        self.assertTrue(
            execution.logs.filter(
                step_name="critical_only_note",
                message__contains="status=SKIPPED step=critical_only_note",
            ).exists()
        )
        self.assertTrue(
            execution.step_results.filter(
                step_name="critical_only_note",
                status=ExecutionStepResult.Status.SKIPPED,
                skipped_reason="when",
            ).exists()
        )


class TriggerDedupKeyTests(SimpleTestCase):
    def test_dedup_key_changes_when_payload_changes(self):
        base_payload = {
            "incident_id": 15,
            "status": "OPEN",
            "changed_fields": ["severity"],
        }
        changed_payload = {
            "incident_id": 15,
            "status": "OPEN",
            "changed_fields": ["labels"],
        }

        first_key = _build_trigger_dedup_key(
            event="incident.updated",
            playbook_id=7,
            incident_id=15,
            payload=base_payload,
        )
        second_key = _build_trigger_dedup_key(
            event="incident.updated",
            playbook_id=7,
            incident_id=15,
            payload=changed_payload,
        )

        self.assertNotEqual(first_key, second_key)
