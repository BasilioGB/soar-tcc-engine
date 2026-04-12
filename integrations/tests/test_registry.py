from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import TestCase

from integrations.models import IntegrationDefinition, IntegrationSecretRef
from integrations.registry import get_action_executor


class ActionRegistryResolutionTests(TestCase):
    def setUp(self):
        self.secret = IntegrationSecretRef(
            name="jira.default",
        )
        self.secret.set_token_credential("super-secret-token")
        self.secret.full_clean()
        self.secret.save()

    def test_static_action_has_priority_over_configured_action_with_same_name(self):
        IntegrationDefinition.objects.create(
            name="Colisao proposital",
            action_name="incident.add_note",
            secret_ref=self.secret,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
        )

        executor = get_action_executor("incident.add_note")

        self.assertIsNotNone(executor)
        self.assertEqual(executor.__module__, "integrations.actions.incident_actions")

    @patch("integrations.services.http_client.requests.request")
    def test_returns_executor_for_enabled_configured_action(self, request_mock):
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {"key": "INFRA-7"}
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            secret_ref=self.secret,
            auth_strategy=IntegrationDefinition.AuthStrategy.BEARER_HEADER,
            request_template={
                "url": "https://jira.local/rest/api/3/issue",
                "body": {"summary": "{{params.summary}}"},
            },
            expected_params=["summary"],
        )

        executor = get_action_executor("jira.create_issue")

        self.assertIsNotNone(executor)
        result = executor(
            step=SimpleNamespace(input={"summary": "IOC detected"}),
            context={},
        )
        self.assertEqual(result["output"]["key"], "INFRA-7")

    def test_returns_none_for_disabled_configured_action(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            enabled=False,
            secret_ref=self.secret,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
        )

        self.assertIsNone(get_action_executor("jira.create_issue"))
