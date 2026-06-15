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

    def test_control_branch_executes_first_matching_branch(self):
        playbook = Playbook.objects.create(
            name="Branch runtime flow",
            dsl={
                "name": "Branch runtime flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "decidir_veredito",
                        "action": "control.branch",
                        "branches": [
                            {
                                "name": "critical",
                                "when": {"left": "{{incident.severity}}", "equals": "CRITICAL"},
                                "steps": [
                                    {
                                        "name": "critical_note",
                                        "action": "incident.add_note",
                                        "input": {"message": "critical branch"},
                                    }
                                ],
                            },
                            {
                                "name": "medium",
                                "when": {"left": "{{incident.severity}}", "equals": "MEDIUM"},
                                "steps": [
                                    {
                                        "name": "medium_note",
                                        "action": "incident.add_note",
                                        "input": {"message": "medium branch"},
                                    }
                                ],
                            },
                        ],
                        "default": [
                            {
                                "name": "default_note",
                                "action": "incident.add_note",
                                "input": {"message": "default branch"},
                            }
                        ],
                    },
                    {
                        "name": "after_branch",
                        "action": "incident.add_note",
                        "input": {
                            "message": "selected={{results.decidir_veredito.selected_branch}}"
                        },
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
        self.assertFalse(TimelineEntry.objects.filter(incident=self.incident, message="critical branch").exists())
        self.assertTrue(TimelineEntry.objects.filter(incident=self.incident, message="medium branch").exists())
        self.assertFalse(TimelineEntry.objects.filter(incident=self.incident, message="default branch").exists())
        self.assertTrue(TimelineEntry.objects.filter(incident=self.incident, message="selected=medium").exists())
        branch_result = execution.step_results.get(step_name="decidir_veredito")
        self.assertEqual(branch_result.status, ExecutionStepResult.Status.SUCCEEDED)
        self.assertEqual(branch_result.result["selected_branch"], "medium")
        self.assertTrue(branch_result.result["matched"])
        self.assertFalse(branch_result.result["used_default"])
        self.assertEqual(branch_result.result["evaluated_branches"], ["critical", "medium"])
        self.assertEqual(branch_result.result["executed_steps"], ["medium_note"])
        self.assertTrue(
            execution.logs.filter(
                step_name="decidir_veredito",
                message__contains="selecionou 'medium' matched=True used_default=False",
            ).exists()
        )
        self.assertEqual(
            list(execution.step_results.order_by("step_order").values_list("step_name", flat=True)),
            ["decidir_veredito", "medium_note", "after_branch"],
        )

    def test_control_branch_executes_default_when_no_branch_matches(self):
        playbook = Playbook.objects.create(
            name="Branch default runtime flow",
            dsl={
                "name": "Branch default runtime flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "decidir_veredito",
                        "action": "control.branch",
                        "branches": [
                            {
                                "name": "critical",
                                "when": {"left": "{{incident.severity}}", "equals": "CRITICAL"},
                                "steps": [
                                    {
                                        "name": "critical_note",
                                        "action": "incident.add_note",
                                        "input": {"message": "critical branch"},
                                    }
                                ],
                            }
                        ],
                        "default": [
                            {
                                "name": "default_note",
                                "action": "incident.add_note",
                                "input": {"message": "default branch"},
                            }
                        ],
                    }
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
        self.assertFalse(TimelineEntry.objects.filter(incident=self.incident, message="critical branch").exists())
        self.assertTrue(TimelineEntry.objects.filter(incident=self.incident, message="default branch").exists())
        branch_result = execution.step_results.get(step_name="decidir_veredito")
        self.assertEqual(branch_result.result["selected_branch"], "default")
        self.assertFalse(branch_result.result["matched"])
        self.assertTrue(branch_result.result["used_default"])
        self.assertEqual(branch_result.result["evaluated_branches"], ["critical"])
        self.assertEqual(branch_result.result["executed_steps"], ["default_note"])
        self.assertTrue(
            execution.logs.filter(
                step_name="decidir_veredito",
                message__contains="selecionou 'default' matched=False used_default=True",
            ).exists()
        )

    def test_control_branch_respects_on_error_stop_inside_selected_branch(self):
        playbook = Playbook.objects.create(
            name="Branch stop on error flow",
            dsl={
                "name": "Branch stop on error flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "decidir_veredito",
                        "action": "control.branch",
                        "branches": [
                            {
                                "name": "medium",
                                "when": {"left": "{{incident.severity}}", "equals": "MEDIUM"},
                                "steps": [
                                    {
                                        "name": "broken_branch_note",
                                        "action": "incident.add_note",
                                        "input": {"message": "{{incident.owner.id}}"},
                                    },
                                    {
                                        "name": "branch_followup",
                                        "action": "incident.add_note",
                                        "input": {"message": "branch followup should not run"},
                                    },
                                ],
                            }
                        ],
                    },
                    {
                        "name": "after_branch",
                        "action": "incident.add_note",
                        "input": {"message": "after branch should not run"},
                    },
                ],
                "on_error": "stop",
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
        self.assertEqual(execution.status, Execution.Status.FAILED)
        self.assertTrue(
            execution.step_results.filter(
                step_name="broken_branch_note",
                status=ExecutionStepResult.Status.FAILED,
                error_message__contains="Placeholder 'incident.owner.id'",
            ).exists()
        )
        self.assertFalse(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="branch followup should not run",
            ).exists()
        )
        self.assertFalse(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="after branch should not run",
            ).exists()
        )
        self.assertEqual(
            list(execution.step_results.order_by("step_order").values_list("step_name", flat=True)),
            ["decidir_veredito", "broken_branch_note"],
        )

    def test_control_branch_respects_on_error_continue_inside_selected_branch(self):
        playbook = Playbook.objects.create(
            name="Branch continue on error flow",
            dsl={
                "name": "Branch continue on error flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "decidir_veredito",
                        "action": "control.branch",
                        "branches": [
                            {
                                "name": "medium",
                                "when": {"left": "{{incident.severity}}", "equals": "MEDIUM"},
                                "steps": [
                                    {
                                        "name": "broken_branch_note",
                                        "action": "incident.add_note",
                                        "input": {"message": "{{incident.owner.id}}"},
                                    },
                                    {
                                        "name": "branch_followup",
                                        "action": "incident.add_note",
                                        "input": {"message": "branch followup ran"},
                                    },
                                ],
                            }
                        ],
                    },
                    {
                        "name": "after_branch",
                        "action": "incident.add_note",
                        "input": {"message": "after branch ran"},
                    },
                ],
                "on_error": "continue",
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
        self.assertEqual(execution.status, Execution.Status.FAILED)
        self.assertTrue(
            execution.step_results.filter(
                step_name="broken_branch_note",
                status=ExecutionStepResult.Status.FAILED,
                error_message__contains="Placeholder 'incident.owner.id'",
            ).exists()
        )
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="branch followup ran",
            ).exists()
        )
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="after branch ran",
            ).exists()
        )
        self.assertEqual(
            list(execution.step_results.order_by("step_order").values_list("step_name", flat=True)),
            ["decidir_veredito", "broken_branch_note", "branch_followup", "after_branch"],
        )

    def test_control_branch_without_match_or_default_does_not_break_execution(self):
        playbook = Playbook.objects.create(
            name="Branch no match no default flow",
            dsl={
                "name": "Branch no match no default flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "decidir_veredito",
                        "action": "control.branch",
                        "branches": [
                            {
                                "name": "critical",
                                "when": {"left": "{{incident.severity}}", "equals": "CRITICAL"},
                                "steps": [
                                    {
                                        "name": "critical_note",
                                        "action": "incident.add_note",
                                        "input": {"message": "critical branch"},
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "name": "after_branch",
                        "action": "incident.add_note",
                        "input": {"message": "after branch without selected path"},
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
        self.assertFalse(TimelineEntry.objects.filter(incident=self.incident, message="critical branch").exists())
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="after branch without selected path",
            ).exists()
        )
        branch_result = execution.step_results.get(step_name="decidir_veredito")
        self.assertIsNone(branch_result.result["selected_branch"])
        self.assertFalse(branch_result.result["matched"])
        self.assertFalse(branch_result.result["used_default"])
        self.assertEqual(branch_result.result["evaluated_branches"], ["critical"])
        self.assertEqual(branch_result.result["executed_steps"], [])
        self.assertEqual(
            list(execution.step_results.order_by("step_order").values_list("step_name", flat=True)),
            ["decidir_veredito", "after_branch"],
        )

    def test_control_branch_when_false_skips_without_evaluating_paths(self):
        playbook = Playbook.objects.create(
            name="Branch skipped by own when flow",
            dsl={
                "name": "Branch skipped by own when flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "decidir_veredito",
                        "action": "control.branch",
                        "when": {"left": "{{incident.severity}}", "equals": "CRITICAL"},
                        "branches": [
                            {
                                "name": "critical",
                                "when": {"left": "{{incident.severity}}", "equals": "CRITICAL"},
                                "steps": [
                                    {
                                        "name": "critical_note",
                                        "action": "incident.add_note",
                                        "input": {"message": "critical branch"},
                                    }
                                ],
                            }
                        ],
                        "default": [
                            {
                                "name": "default_note",
                                "action": "incident.add_note",
                                "input": {"message": "default branch"},
                            }
                        ],
                    },
                    {
                        "name": "after_branch",
                        "action": "incident.add_note",
                        "when": {"left": "{{results.decidir_veredito.skipped}}", "equals": True},
                        "input": {"message": "branch skipped"},
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
        self.assertFalse(TimelineEntry.objects.filter(incident=self.incident, message="critical branch").exists())
        self.assertFalse(TimelineEntry.objects.filter(incident=self.incident, message="default branch").exists())
        self.assertTrue(TimelineEntry.objects.filter(incident=self.incident, message="branch skipped").exists())
        self.assertTrue(
            execution.step_results.filter(
                step_name="decidir_veredito",
                status=ExecutionStepResult.Status.SKIPPED,
                skipped_reason="when",
            ).exists()
        )
        self.assertEqual(
            list(execution.step_results.order_by("step_order").values_list("step_name", flat=True)),
            ["decidir_veredito", "after_branch"],
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
