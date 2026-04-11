from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from integrations.models import IntegrationDefinition


class PlaybookValidationEndpointTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.lead = User.objects.create_user(
            username="lead_validate",
            password="pass",
            role=User.Roles.SOC_LEAD,
        )
        self.url = "/api/v1/playbooks/validate/"
        self.client.force_authenticate(self.lead)

    def test_validate_endpoint_accepts_valid_configured_action(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary"],
            post_response_actions=[
                {"action": "incident.add_note", "input": {"message": "ok"}}
            ],
        )

        response = self.client.post(
            self.url,
            {
                "dsl": {
                    "name": "Configured integration flow",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "open_jira",
                            "action": "jira.create_issue",
                            "input": {"summary": "Bloquear credencial"},
                        }
                    ],
                }
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"valid": True})

    def test_validate_endpoint_rejects_missing_params_for_configured_action(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary", "description"],
            post_response_actions=[
                {"action": "incident.add_note", "input": {"message": "ok"}}
            ],
        )

        response = self.client.post(
            self.url,
            {
                "dsl": {
                    "name": "Configured integration flow",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "open_jira",
                            "action": "jira.create_issue",
                            "input": {"summary": "Bloquear credencial"},
                        }
                    ],
                }
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("description", str(response.data))
