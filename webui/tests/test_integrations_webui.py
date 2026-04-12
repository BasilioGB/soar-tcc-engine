from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from integrations.models import IntegrationDefinition, IntegrationSecretRef


class WebUIIntegrationsTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(
            username="analyst_integrations_ui",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        self.lead = User.objects.create_user(
            username="lead_integrations_ui",
            password="pass",
            role=User.Roles.SOC_LEAD,
        )

    def test_soc_lead_can_access_list_and_create_records(self):
        self.client.force_login(self.lead)

        list_response = self.client.get(reverse("webui:integration_list"))
        self.assertEqual(list_response.status_code, 200)

        secret_response = self.client.post(
            reverse("webui:integration_secret_create"),
            {
                "name": "jira.default",
                "provider": "env",
                "reference": "JIRA_API_TOKEN",
                "description": "Token do Jira",
                "enabled": True,
            },
        )
        self.assertEqual(secret_response.status_code, 302)
        secret_ref = IntegrationSecretRef.objects.get(name="jira.default")

        integration_response = self.client.post(
            reverse("webui:integration_create"),
            {
                "name": "Criar issue Jira",
                "description": "Abre ticket automaticamente",
                "action_name": "jira.create_issue",
                "enabled": True,
                "method": "POST",
                "auth_type": "secret_ref",
                "secret_ref": secret_ref.pk,
                "timeout_seconds": 15,
                "revision": 1,
                "request_template_text": '{"url": "https://jira.local/rest/api/3/issue", "body": {"summary": "{{params.summary}}"}}',
                "expected_params_text": '["summary"]',
                "response_mapping_text": '{"issue_key": "body.key"}',
                "post_response_actions_text": '[{"action": "incident.add_note", "input": {"message": "ok"}}]',
            },
        )
        self.assertEqual(integration_response.status_code, 302)
        self.assertTrue(
            IntegrationDefinition.objects.filter(action_name="jira.create_issue").exists()
        )

    def test_soc_analyst_cannot_access_integration_management(self):
        self.client.force_login(self.analyst)

        responses = [
            self.client.get(reverse("webui:integration_list")),
            self.client.get(reverse("webui:integration_create")),
            self.client.get(reverse("webui:integration_secret_create")),
        ]

        for response in responses:
            self.assertEqual(response.status_code, 403)

    def test_invalid_json_is_rejected_in_integration_form(self):
        self.client.force_login(self.lead)
        secret_ref = IntegrationSecretRef.objects.create(
            name="jira.default",
            reference="JIRA_API_TOKEN",
        )

        response = self.client.post(
            reverse("webui:integration_create"),
            {
                "name": "Criar issue Jira",
                "description": "Abre ticket automaticamente",
                "action_name": "jira.create_issue",
                "enabled": True,
                "method": "POST",
                "auth_type": "secret_ref",
                "secret_ref": secret_ref.pk,
                "timeout_seconds": 15,
                "revision": 1,
                "request_template_text": '{"url": "https://jira.local/rest/api/3/issue"',
                "expected_params_text": '["summary"]',
                "response_mapping_text": '{"issue_key": "body.key"}',
                "post_response_actions_text": '[]',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "JSON invalido em request_template")
        self.assertFalse(
            IntegrationDefinition.objects.filter(action_name="jira.create_issue").exists()
        )
