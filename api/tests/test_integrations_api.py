from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from integrations.models import IntegrationDefinition, IntegrationSecretRef


class ConfiguredIntegrationsAPITests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(
            username="analyst_integrations_api",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        self.lead = User.objects.create_user(
            username="lead_integrations_api",
            password="pass",
            role=User.Roles.SOC_LEAD,
        )
        self.secret = IntegrationSecretRef.objects.create(
            name="jira.default",
            reference="JIRA_API_TOKEN",
            description="Token padrao",
        )
        self.integration = IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            auth_type=IntegrationDefinition.AuthType.SECRET_REF,
            secret_ref=self.secret,
            request_template={
                "url": "https://jira.local/rest/api/3/issue",
                "body": {"fields": {"summary": "{{params.summary}}"}},
            },
            expected_params=["summary"],
            response_mapping={"issue_key": "body.key"},
            post_response_actions=[
                {
                    "action": "incident.add_note",
                    "input": {"message": "Ticket {{output.issue_key}} criado"},
                }
            ],
        )
        self.secret_list_url = "/api/v1/integration-secrets/"
        self.secret_detail_url = f"/api/v1/integration-secrets/{self.secret.pk}/"
        self.integration_list_url = "/api/v1/integrations/"
        self.integration_detail_url = f"/api/v1/integrations/{self.integration.pk}/"
        self.integration_validate_url = "/api/v1/integrations/validate/"

    def test_authenticated_user_can_list_and_retrieve_integrations(self):
        self.client.force_authenticate(self.analyst)

        list_response = self.client.get(self.integration_list_url)
        detail_response = self.client.get(self.integration_detail_url)
        secrets_response = self.client.get(self.secret_list_url)

        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(detail_response.status_code, status.HTTP_200_OK)
        self.assertEqual(secrets_response.status_code, status.HTTP_200_OK)
        self.assertEqual(list_response.data[0]["action_name"], "jira.create_issue")
        self.assertEqual(detail_response.data["secret_ref"], self.secret.pk)
        self.assertEqual(secrets_response.data[0]["name"], "jira.default")

    def test_soc_lead_can_create_secret_ref(self):
        self.client.force_authenticate(self.lead)

        response = self.client.post(
            self.secret_list_url,
            {
                "name": "slack.default",
                "provider": "env",
                "reference": "SLACK_API_TOKEN",
                "description": "Token do Slack",
                "enabled": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(
            IntegrationSecretRef.objects.filter(name="slack.default").exists()
        )

    def test_soc_lead_can_create_and_update_integration(self):
        self.client.force_authenticate(self.lead)

        create_response = self.client.post(
            self.integration_list_url,
            {
                "name": "Buscar IOC",
                "description": "Consulta reputacao externa",
                "action_name": "ti.lookup_ioc",
                "enabled": True,
                "method": "GET",
                "auth_type": "secret_ref",
                "secret_ref": self.secret.pk,
                "request_template": {
                    "url": "https://ti.local/ioc",
                    "query": {"value": "{{params.value}}"},
                    "auth": {"strategy": "query_param", "param": "token"},
                },
                "expected_params": ["value"],
                "response_mapping": {"verdict": "body.data.verdict"},
                "post_response_actions": [],
                "timeout_seconds": 10,
                "revision": 2,
            },
            format="json",
        )

        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        created_id = create_response.data["id"]

        update_response = self.client.patch(
            f"{self.integration_list_url}{created_id}/",
            {
                "description": "Consulta reputacao externa atualizada",
                "enabled": False,
                "revision": 3,
            },
            format="json",
        )

        self.assertEqual(update_response.status_code, status.HTTP_200_OK)
        self.assertEqual(update_response.data["revision"], 3)
        self.assertFalse(update_response.data["enabled"])

    def test_validate_endpoint_accepts_valid_integration(self):
        self.client.force_authenticate(self.lead)

        response = self.client.post(
            self.integration_validate_url,
            {
                "name": "Criar ticket ServiceNow",
                "description": "Abre chamado automaticamente",
                "action_name": "servicenow.create_ticket",
                "enabled": True,
                "method": "POST",
                "auth_type": "none",
                "request_template": {
                    "url": "https://snow.local/api/tickets",
                    "body": {"short_description": "{{params.summary}}"},
                },
                "expected_params": ["summary"],
                "response_mapping": {"ticket_id": "body.result.number"},
                "post_response_actions": [],
                "timeout_seconds": 15,
                "revision": 1,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"valid": True})

    def test_invalid_integration_is_rejected_by_validate_endpoint(self):
        self.client.force_authenticate(self.lead)

        response = self.client.post(
            self.integration_validate_url,
            {
                "name": "Integracao invalida",
                "description": "Usa payload e body juntos",
                "action_name": "ti.invalid_lookup",
                "enabled": True,
                "method": "POST",
                "auth_type": "none",
                "request_template": {
                    "url": "https://ti.local/ioc",
                    "payload": {"value": "{{params.value}}"},
                    "body": "raw",
                },
                "expected_params": ["value"],
                "response_mapping": {"verdict": "body.verdict"},
                "post_response_actions": [],
                "timeout_seconds": 15,
                "revision": 1,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("request_template", response.data)

    def test_soc_analyst_is_forbidden_to_create_update_or_validate_integrations(self):
        self.client.force_authenticate(self.analyst)

        create_secret_response = self.client.post(
            self.secret_list_url,
            {
                "name": "slack.default",
                "provider": "env",
                "reference": "SLACK_API_TOKEN",
            },
            format="json",
        )
        create_integration_response = self.client.post(
            self.integration_list_url,
            {
                "name": "Buscar IOC",
                "action_name": "ti.lookup_ioc",
                "request_template": {"url": "https://ti.local/ioc"},
            },
            format="json",
        )
        update_integration_response = self.client.patch(
            self.integration_detail_url,
            {"enabled": False},
            format="json",
        )
        validate_response = self.client.post(
            self.integration_validate_url,
            {
                "name": "Validar IOC",
                "action_name": "ti.validate_ioc",
                "request_template": {"url": "https://ti.local/ioc"},
            },
            format="json",
        )

        self.assertEqual(create_secret_response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(create_integration_response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(update_integration_response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(validate_response.status_code, status.HTTP_403_FORBIDDEN)
