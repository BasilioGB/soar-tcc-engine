from __future__ import annotations

import os
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from incidents.models import Incident, TimelineEntry
from integrations.models import IntegrationDefinition, IntegrationSecretRef
from integrations.services.configured_executor import execute_configured_integration


class ConfiguredExecutorTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="lead", password="pass")
        self.incident = Incident.objects.create(
            title="Phishing",
            description="IOC reportado",
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

    def _runtime_context(self) -> dict:
        return {
            "incident": self.incident,
            "actor": self.user,
            "execution": {"id": 10},
            "results": {},
            "trigger_context": {"event": "manual.incident"},
        }

    @patch("integrations.services.http_client.requests.request")
    def test_executes_configured_integration_with_auth_mapping_and_post_response(self, request_mock):
        response = Mock()
        response.status_code = 201
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {
            "key": "INFRA-123",
            "self": "https://jira.local/browse/INFRA-123",
        }
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        integration = IntegrationDefinition.objects.create(
            name="Criar issue no Jira",
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
                        "message": "Ticket {{output.issue_key}} criado: {{output.issue_url}}",
                    },
                }
            ],
        )

        result = execute_configured_integration(
            integration=integration,
            params={
                "summary": "Bloquear credencial",
                "description": "Credencial comprometida",
            },
            runtime_context=self._runtime_context(),
        )

        request_mock.assert_called_once_with(
            method="POST",
            url="https://jira.local/rest/api/3/issue",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer super-secret-token",
            },
            timeout=15.0,
            data={
                "fields": {
                    "summary": "Bloquear credencial",
                    "description": "Credencial comprometida",
                }
            },
        )
        self.assertEqual(result["output"]["issue_key"], "INFRA-123")
        self.assertEqual(result["output"]["issue_url"], "https://jira.local/browse/INFRA-123")
        self.assertEqual(result["response"]["headers"]["Authorization"], "***REDACTED***")
        self.assertEqual(result["post_response_results"][0]["action"], "incident.add_note")
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=self.incident,
                message__contains="Ticket INFRA-123 criado",
            ).exists()
        )

    def test_requires_expected_params(self):
        integration = IntegrationDefinition.objects.create(
            name="Criar issue no Jira",
            action_name="jira.create_issue",
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary", "description"],
        )

        with self.assertRaisesMessage(ValueError, "Parametros obrigatorios ausentes"):
            execute_configured_integration(
                integration=integration,
                params={"summary": "Bloquear credencial"},
                runtime_context=self._runtime_context(),
            )

    @patch("integrations.services.http_client.requests.request")
    def test_rejects_payload_and_body_together(self, request_mock):
        integration = IntegrationDefinition.objects.create(
            name="Criar issue no Jira",
            action_name="jira.create_issue",
            request_template={
                "url": "https://jira.local/rest/api/3/issue",
                "payload": {"a": 1},
                "body": "raw",
            },
        )

        with self.assertRaisesMessage(ValueError, "Use payload ou body no webhook, nao ambos"):
            execute_configured_integration(
                integration=integration,
                params={},
                runtime_context=self._runtime_context(),
            )

        request_mock.assert_not_called()

    @patch("integrations.services.http_client.requests.request")
    def test_supports_query_param_secret_auth(self, request_mock):
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {"ok": True}
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        integration = IntegrationDefinition.objects.create(
            name="Buscar IOC",
            action_name="ti.lookup_ioc",
            auth_type=IntegrationDefinition.AuthType.SECRET_REF,
            secret_ref=self.secret,
            method=IntegrationDefinition.Method.GET,
            request_template={
                "url": "https://ti.local/ioc",
                "query": {"value": "{{params.value}}"},
                "auth": {"strategy": "query_param", "param": "token"},
            },
            expected_params=["value"],
        )

        execute_configured_integration(
            integration=integration,
            params={"value": "malicious.example"},
            runtime_context=self._runtime_context(),
        )

        request_mock.assert_called_once_with(
            method="GET",
            url="https://ti.local/ioc",
            headers={},
            params={"value": "malicious.example", "token": "super-secret-token"},
            timeout=15.0,
        )

    @patch("integrations.services.http_client.requests.request")
    def test_rejects_post_response_actions_outside_allowed_prefixes(self, request_mock):
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {"ok": True}
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        integration = IntegrationDefinition.objects.create(
            name="Criar issue no Jira",
            action_name="jira.create_issue",
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            post_response_actions=[
                {
                    "action": "http_webhook.post",
                    "input": {"url": "https://hooks.local"},
                }
            ],
        )

        with self.assertRaisesMessage(ValueError, "nao permitida em post_response_actions"):
            execute_configured_integration(
                integration=integration,
                params={},
                runtime_context=self._runtime_context(),
            )
