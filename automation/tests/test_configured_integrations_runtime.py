from __future__ import annotations

import os
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings

from incidents.models import Incident, TimelineEntry
from integrations.models import IntegrationDefinition, IntegrationSecretRef
from playbooks.models import Execution, ExecutionStepResult, Playbook
from playbooks.services import start_playbook_execution


@override_settings(
    CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}},
    CELERY_TASK_ALWAYS_EAGER=True,
)
class ConfiguredIntegrationRuntimeTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="lead_runtime", password="pass")
        self.incident = Incident.objects.create(
            title="Credential theft",
            description="Conta comprometida",
            created_by=self.user,
        )
        self.secret = IntegrationSecretRef.objects.create(
            name="jira.default",
            reference="TEST_JIRA_TOKEN",
        )
        os.environ["TEST_JIRA_TOKEN"] = "super-secret-token"

    def tearDown(self):
        os.environ.pop("TEST_JIRA_TOKEN", None)
        super().tearDown()

    @patch("integrations.services.http_client.requests.request")
    def test_runtime_executes_configured_integration_and_exposes_output_in_results(self, request_mock):
        response = Mock()
        response.status_code = 201
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {
            "key": "INFRA-123",
            "self": "https://jira.local/browse/INFRA-123",
        }
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            auth_type=IntegrationDefinition.AuthType.SECRET_REF,
            secret_ref=self.secret,
            request_template={
                "url": "https://jira.local/rest/api/3/issue",
                "headers": {"Content-Type": "application/json"},
                "auth": {"strategy": "bearer_header"},
                "body": {
                    "fields": {
                        "summary": "{{params.summary}}",
                        "description": "{{params.description}}",
                    }
                },
            },
            expected_params=["summary", "description"],
            response_mapping={
                "issue_key": "body.key",
                "issue_url": "body.self",
            },
            post_response_actions=[
                {
                    "action": "incident.add_note",
                    "input": {
                        "message": "Ticket {{output.issue_key}} criado automaticamente",
                    },
                }
            ],
        )

        playbook = Playbook.objects.create(
            name="Configured integration flow",
            dsl={
                "name": "Configured integration flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "open_jira",
                        "action": "jira.create_issue",
                        "input": {
                            "summary": "Bloquear credencial {{incident.id}}",
                            "description": "Incidente {{incident.title}}",
                        },
                    },
                    {
                        "name": "record_ticket_key",
                        "action": "incident.add_note",
                        "input": {
                            "message": "Ticket result {{results.open_jira.issue_key}}",
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
            context={"event": "manual.incident"},
        )

        execution.refresh_from_db()
        self.assertEqual(execution.status, Execution.Status.SUCCEEDED)
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="Ticket INFRA-123 criado automaticamente",
            ).exists()
        )
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message="Ticket result INFRA-123",
            ).exists()
        )
        open_jira_result = execution.step_results.get(step_name="open_jira")
        self.assertEqual(open_jira_result.status, ExecutionStepResult.Status.SUCCEEDED)
        self.assertEqual(open_jira_result.result["output"]["issue_key"], "INFRA-123")
        record_ticket_key_result = execution.step_results.get(step_name="record_ticket_key")
        self.assertEqual(
            record_ticket_key_result.resolved_input["message"],
            "Ticket result INFRA-123",
        )

    def test_playbook_creation_fails_when_configured_action_is_disabled(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            enabled=False,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
        )

        with self.assertRaisesMessage(
            ValidationError,
            "integracao 'jira.create_issue' esta desabilitada",
        ):
            Playbook.objects.create(
                name="Disabled configured integration flow",
                dsl={
                    "name": "Disabled configured integration flow",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "open_jira",
                            "action": "jira.create_issue",
                            "input": {
                                "summary": "Bloquear credencial {{incident.id}}",
                            },
                        }
                    ],
                    "on_error": "stop",
                },
                enabled=True,
                created_by=self.user,
            )
