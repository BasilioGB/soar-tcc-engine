from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings

from automation.input_resolution import resolve_step_input
from incidents.models import Artifact, Incident, TimelineEntry
from incidents.services import add_artifact_link
from playbooks.models import Execution, ExecutionLog, ExecutionStepResult, Playbook
from playbooks.services import start_playbook_execution


class InputResolutionTests(SimpleTestCase):
    def test_resolves_placeholders_in_nested_structures(self):
        context = {
            "incident": SimpleNamespace(id=42, title="Phishing"),
            "artifact": {"id": 7, "value": "malicious.example"},
            "trigger_context": {"event": "artifact.created"},
            "results": {
                "fetch_context": {
                    "payload": {
                        "incident_id": 42,
                        "artifact_value": "malicious.example",
                    }
                }
            },
        }

        resolved = resolve_step_input(
            {
                "incident_id": "{{incident.id}}",
                "payload": "{{results.fetch_context.payload}}",
                "message": "Incident {{incident.id}} -> {{artifact.value}}",
                "items": [
                    "{{trigger_context.event}}",
                    "{{results.fetch_context.payload.incident_id}}",
                ],
            },
            context,
        )

        self.assertEqual(resolved["incident_id"], 42)
        self.assertEqual(
            resolved["payload"],
            {"incident_id": 42, "artifact_value": "malicious.example"},
        )
        self.assertEqual(resolved["message"], "Incident 42 -> malicious.example")
        self.assertEqual(resolved["items"], ["artifact.created", 42])

    def test_raises_clear_error_when_placeholder_path_is_missing(self):
        with self.assertRaisesMessage(ValueError, "Placeholder 'incident.owner.id'"):
            resolve_step_input("{{incident.owner.id}}", {"incident": SimpleNamespace(id=1)})

    def test_supports_default_and_simple_filters(self):
        context = {
            "incident": SimpleNamespace(
                id=8,
                title="  phishing em massa  ",
                assignee=None,
                labels=["phishing", "vip"],
            ),
            "results": {"capture": {"items": ["one", "two"]}},
        }

        resolved = resolve_step_input(
            {
                "assignee": '{{incident.assignee.username|default:"unassigned"|upper}}',
                "title": "{{incident.title|strip|upper}}",
                "label_count": "{{incident.labels|length}}",
                "labels": '{{incident.labels|join:", "}}',
                "payload": "{{results.capture|json}}",
            },
            context,
        )

        self.assertEqual(resolved["assignee"], "UNASSIGNED")
        self.assertEqual(resolved["title"], "PHISHING EM MASSA")
        self.assertEqual(resolved["label_count"], 2)
        self.assertEqual(resolved["labels"], "phishing, vip")
        self.assertEqual(resolved["payload"], '{"items": ["one", "two"]}')

    def test_default_can_be_used_inside_interpolated_string(self):
        resolved = resolve_step_input(
            "owner={{incident.assignee.username|default:'n/a'}}",
            {"incident": SimpleNamespace(assignee=None)},
        )
        self.assertEqual(resolved, "owner=n/a")


@override_settings(
    CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}},
    CELERY_TASK_ALWAYS_EAGER=True,
)
class RunnerPlaceholderExecutionTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="lead", password="pass")
        self.incident = Incident.objects.create(
            title="Suspicious domain",
            description="IOC reported by user",
            created_by=self.user,
        )
        self.artifact = add_artifact_link(
            incident=self.incident,
            value="malicious.example",
            type_code=Artifact.Type.DOMAIN,
            actor=self.user,
        )

    @patch("integrations.services.http_client.requests.request")
    def test_execution_resolves_incident_artifact_trigger_and_results_placeholders(self, request_mock):
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {"ok": True}
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        playbook = Playbook.objects.create(
            name="Placeholder artifact flow",
            dsl={
                "name": "Placeholder artifact flow",
                "type": "artifact",
                "mode": "manual",
                "filters": [{"target": "artifact", "conditions": {"type": ["DOMAIN"]}}],
                "steps": [
                    {
                        "name": "fetch_context",
                        "action": "http_webhook.post",
                        "input": {
                            "url": "https://hooks.local/incidents/{{incident.id}}",
                            "payload": {
                                "incident_id": "{{incident.id}}",
                                "artifact_value": "{{artifact.value}}",
                                "event": "{{trigger_context.event}}",
                            },
                        },
                    },
                    {
                        "name": "create_followup",
                        "action": "task.create",
                        "input": {
                            "title": (
                                "Review {{results.fetch_context.payload.artifact_value}} "
                                "for incident {{results.fetch_context.payload.incident_id}}"
                            )
                        },
                    },
                    {
                        "name": "record_outcome",
                        "action": "incident.add_note",
                        "input": {
                            "message": (
                                "Task {{results.create_followup.task_id}} created from "
                                "{{results.fetch_context.payload.event}}"
                            )
                        },
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
            context={
                "event": "manual.artifact",
                "artifact": {
                    "id": self.artifact.id,
                    "type": self.artifact.type,
                    "value": self.artifact.value,
                    "attributes": self.artifact.attributes or {},
                },
            },
        )

        execution.refresh_from_db()
        self.assertEqual(execution.status, Execution.Status.SUCCEEDED)
        self.assertEqual(self.incident.tasks.count(), 1)
        self.assertEqual(
            self.incident.tasks.get().title,
            f"Review {self.artifact.value} for incident {self.incident.id}",
        )
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message__contains="created from manual.artifact",
            ).exists()
        )
        self.assertEqual(execution.step_results.count(), 3)
        fetch_context_result = execution.step_results.get(step_name="fetch_context")
        self.assertEqual(fetch_context_result.status, ExecutionStepResult.Status.SUCCEEDED)
        self.assertEqual(fetch_context_result.result["payload"]["incident_id"], self.incident.id)
        create_followup_result = execution.step_results.get(step_name="create_followup")
        self.assertEqual(create_followup_result.status, ExecutionStepResult.Status.SUCCEEDED)
        self.assertEqual(
            create_followup_result.resolved_input["title"],
            f"Review {self.artifact.value} for incident {self.incident.id}",
        )

    def test_start_playbook_execution_returns_updated_execution_in_sync_mode(self):
        playbook = Playbook.objects.create(
            name="Sync execution contract",
            dsl={
                "name": "Sync execution contract",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "record_note",
                        "action": "incident.add_note",
                        "input": {"message": "sync contract ok"},
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

        self.assertEqual(execution.status, Execution.Status.SUCCEEDED)
        self.assertIsNotNone(execution.started_at)
        self.assertIsNotNone(execution.finished_at)
        self.assertGreaterEqual(execution.logs.count(), 2)
        self.assertTrue(
            execution.logs.filter(
                step_name="record_note",
                message__contains="status=SUCCEEDED step=record_note",
            ).exists()
        )

    def test_placeholder_error_respects_on_error_continue(self):
        playbook = Playbook.objects.create(
            name="Placeholder continue flow",
            dsl={
                "name": "Placeholder continue flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "broken_note",
                        "action": "incident.add_note",
                        "input": {"message": "{{incident.owner.id}}"},
                    },
                    {
                        "name": "fallback_note",
                        "action": "incident.add_note",
                        "input": {"message": "placeholder failure handled"},
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
            execution.logs.filter(
                step_name="broken_note",
                level=ExecutionLog.Level.ERROR,
                message__contains="error_class=StepExecutionError",
            ).exists()
        )
        self.assertTrue(
            execution.step_results.filter(
                step_name="broken_note",
                status=ExecutionStepResult.Status.FAILED,
                error_class="StepExecutionError",
                error_message__contains="Placeholder 'incident.owner.id'",
            ).exists()
        )
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="placeholder failure handled",
            ).exists()
        )

    def test_execution_supports_default_and_filters_at_runtime(self):
        playbook = Playbook.objects.create(
            name="Placeholder filter flow",
            dsl={
                "name": "Placeholder filter flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "record_filtered_note",
                        "action": "incident.add_note",
                        "input": {
                            "message": (
                                "{{incident.title|strip|upper}} / "
                                "{{incident.assignee.username|default:'unassigned'|upper}}"
                            )
                        },
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
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="SUSPICIOUS DOMAIN / UNASSIGNED",
            ).exists()
        )
