from __future__ import annotations

from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from incidents.models import Incident
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
        self.secret = IntegrationSecretRef(
            name="jira.default",
        )
        self.secret.set_token_credential("super-secret-token")
        self.secret.full_clean()
        self.secret.save()

    def _runtime_context(self) -> dict:
        return {
            "incident": self.incident,
            "actor": self.user,
            "execution": {"id": 10},
            "results": {},
            "trigger_context": {"event": "manual.incident"},
        }

    @patch("integrations.services.http_client.requests.request")
    def test_executes_configured_integration_and_returns_response_body_as_output(self, request_mock):
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
            secret_ref=self.secret,
            auth_strategy=IntegrationDefinition.AuthStrategy.BEARER_HEADER,
            request_template={
                "url": "https://jira.local/rest/api/3/issue",
                "headers": {"Content-Type": "application/json"},
                "body": {
                    "fields": {
                        "summary": "{{params.summary}}",
                        "description": "{{params.description}}",
                    }
                },
            },
            expected_params=["summary", "description"],
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
        self.assertEqual(result["output"]["key"], "INFRA-123")
        self.assertEqual(result["output"]["self"], "https://jira.local/browse/INFRA-123")
        self.assertEqual(result["response"]["headers"]["Authorization"], "***REDACTED***")

    @patch("integrations.services.http_client.requests.request")
    def test_executes_configured_integration_with_output_template(self, request_mock):
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {
            "data": {
                "id": "primeup.com",
                "attributes": {
                    "reputation": 0,
                    "last_analysis_stats": {"malicious": 0, "harmless": 10},
                },
            }
        }
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        integration = IntegrationDefinition.objects.create(
            name="VT Domain",
            action_name="virustotal.domain_lookup",
            method=IntegrationDefinition.Method.GET,
            secret_ref=self.secret,
            auth_strategy=IntegrationDefinition.AuthStrategy.HEADER,
            auth_header_name="x-apikey",
            request_template={
                "url": "https://www.virustotal.com/api/v3/domains/{{params.domain}}",
            },
            output_template={
                "domain": "{{response.body.data.id}}",
                "reputation": "{{response.body.data.attributes.reputation}}",
                "stats": "{{response.body.data.attributes.last_analysis_stats}}",
            },
            expected_params=["domain"],
        )

        result = execute_configured_integration(
            integration=integration,
            params={"domain": "primeup.com"},
            runtime_context=self._runtime_context(),
        )

        self.assertEqual(
            result["output"],
            {
                "domain": "primeup.com",
                "reputation": 0,
                "stats": {"malicious": 0, "harmless": 10},
            },
        )
        self.assertEqual(result["response"]["headers"]["x-apikey"], "***REDACTED***")

    def test_requires_expected_params(self):
        integration = IntegrationDefinition.objects.create(
            name="Criar issue no Jira",
            action_name="jira.create_issue",
            secret_ref=self.secret,
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
            secret_ref=self.secret,
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
            secret_ref=self.secret,
            method=IntegrationDefinition.Method.GET,
            auth_strategy=IntegrationDefinition.AuthStrategy.QUERY_PARAM,
            auth_query_param="token",
            request_template={
                "url": "https://ti.local/ioc",
                "query": {"value": "{{params.value}}"},
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

    def test_rejects_missing_stored_secret_credential(self):
        broken_secret = IntegrationSecretRef.objects.create(
            name="broken.secret",
            credential_payload_encrypted="",
        )
        integration = IntegrationDefinition.objects.create(
            name="Buscar IOC",
            action_name="ti.lookup_ioc",
            secret_ref=broken_secret,
            method=IntegrationDefinition.Method.GET,
            auth_strategy=IntegrationDefinition.AuthStrategy.BEARER_HEADER,
            request_template={"url": "https://ti.local/ioc"},
        )

        with self.assertRaisesMessage(ValueError, "nao possui credencial armazenada"):
            execute_configured_integration(
                integration=integration,
                params={},
                runtime_context=self._runtime_context(),
            )

    @patch("integrations.services.http_client.requests.request")
    def test_supports_basic_auth_credentials_from_secret(self, request_mock):
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {"ok": True}
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        secret = IntegrationSecretRef(name="snow.basic")
        secret.set_basic_auth_credential("svc-user", "svc-pass")
        secret.full_clean()
        secret.save()
        integration = IntegrationDefinition.objects.create(
            name="Buscar ticket",
            action_name="snow.get_ticket",
            secret_ref=secret,
            method=IntegrationDefinition.Method.GET,
            auth_strategy=IntegrationDefinition.AuthStrategy.BASIC,
            request_template={"url": "https://snow.local/api/tickets/{{params.number}}"},
            expected_params=["number"],
        )

        execute_configured_integration(
            integration=integration,
            params={"number": "INC001"},
            runtime_context=self._runtime_context(),
        )

        request_mock.assert_called_once()
        self.assertIn("Authorization", request_mock.call_args.kwargs["headers"])
