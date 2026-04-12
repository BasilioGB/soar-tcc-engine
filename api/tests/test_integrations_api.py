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
        self.secret = IntegrationSecretRef(
            name="jira.default",
            description="Token padrao",
        )
        self.secret.set_token_credential("super-secret-token")
        self.secret.full_clean()
        self.secret.created_by = self.lead
        self.secret.rotated_by = self.lead
        self.secret.save()
        self.integration = IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            secret_ref=self.secret,
            request_template={
                "url": "https://jira.local/rest/api/3/issue",
                "body": {"fields": {"summary": "{{params.summary}}"}},
            },
            expected_params=["summary"],
        )
        self.secret_list_url = "/api/v1/http-connector-secrets/"
        self.secret_detail_url = f"/api/v1/http-connector-secrets/{self.secret.pk}/"
        self.integration_list_url = "/api/v1/http-connectors/"
        self.integration_detail_url = f"/api/v1/http-connectors/{self.integration.pk}/"
        self.integration_validate_url = "/api/v1/http-connectors/validate/"

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
        self.assertTrue(secrets_response.data[0]["has_credential"])
        self.assertNotIn("token_value", secrets_response.data[0])

    def test_soc_lead_can_create_secret_ref(self):
        self.client.force_authenticate(self.lead)

        response = self.client.post(
            self.secret_list_url,
            {
                "name": "slack.default",
                "description": "Token do Slack",
                "enabled": True,
                "credential_kind": "token",
                "token_value": "slack-secret-value",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        secret = IntegrationSecretRef.objects.get(name="slack.default")
        self.assertEqual(secret.get_credential()["token"], "slack-secret-value")
        self.assertEqual(secret.created_by, self.lead)
        self.assertEqual(secret.rotated_by, self.lead)
        self.assertNotIn("token_value", response.data)

    def test_soc_lead_can_rotate_secret_without_receiving_current_value(self):
        self.client.force_authenticate(self.lead)

        response = self.client.patch(
            self.secret_detail_url,
            {
                "description": "Token padrao atualizado",
                "credential_kind": "token",
                "token_value": "rotated-token",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.secret.refresh_from_db()
        self.assertEqual(self.secret.get_credential()["token"], "rotated-token")
        self.assertEqual(self.secret.rotated_by, self.lead)
        self.assertNotIn("token_value", response.data)

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
                "secret_ref": self.secret.pk,
                "auth_strategy": "query_param",
                "auth_query_param": "token",
                "request_template": {
                    "url": "https://ti.local/ioc",
                    "query": {"value": "{{params.value}}"},
                },
                "expected_params": ["value"],
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

    def test_create_integration_derives_expected_params_from_template_when_omitted(self):
        self.client.force_authenticate(self.lead)

        response = self.client.post(
            self.integration_list_url,
            {
                "name": "Buscar dominio VT",
                "description": "Consulta dominio externo",
                "action_name": "ti.lookup_domain",
                "enabled": True,
                "method": "GET",
                "secret_ref": self.secret.pk,
                "auth_strategy": "header",
                "auth_header_name": "x-apikey",
                "request_template": {
                    "url": "https://ti.local/domain/{{params.domain}}",
                    "query": {"source": "{{params.source}}"},
                },
                "timeout_seconds": 10,
                "revision": 1,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["expected_params"], ["domain", "source"])

    def test_create_integration_accepts_output_template(self):
        self.client.force_authenticate(self.lead)

        response = self.client.post(
            self.integration_list_url,
            {
                "name": "VT Domain",
                "description": "Consulta dominio externo",
                "action_name": "vt.lookup_domain",
                "enabled": True,
                "method": "GET",
                "secret_ref": self.secret.pk,
                "auth_strategy": "header",
                "auth_header_name": "x-apikey",
                "request_template": {
                    "url": "https://vt.local/domain/{{params.domain}}",
                },
                "output_template": {
                    "domain": "{{response.body.data.id}}",
                    "reputation": "{{response.body.data.attributes.reputation}}",
                },
                "timeout_seconds": 10,
                "revision": 1,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            response.data["output_template"],
            {
                "domain": "{{response.body.data.id}}",
                "reputation": "{{response.body.data.attributes.reputation}}",
            },
        )

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
                "secret_ref": self.secret.pk,
                "auth_strategy": "bearer_header",
                "auth_header_name": "Authorization",
                "auth_prefix": "Bearer",
                "request_template": {
                    "url": "https://snow.local/api/tickets",
                    "body": {"short_description": "{{params.summary}}"},
                },
                "expected_params": ["summary"],
                "timeout_seconds": 15,
                "revision": 1,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {"valid": True})

    def test_validate_endpoint_rejects_expected_params_that_diverge_from_template(self):
        self.client.force_authenticate(self.lead)

        response = self.client.post(
            self.integration_validate_url,
            {
                "name": "Criar ticket ServiceNow",
                "description": "Abre chamado automaticamente",
                "action_name": "servicenow.create_ticket",
                "enabled": True,
                "method": "POST",
                "secret_ref": self.secret.pk,
                "auth_strategy": "bearer_header",
                "auth_header_name": "Authorization",
                "auth_prefix": "Bearer",
                "request_template": {
                    "url": "https://snow.local/api/tickets",
                    "body": {"short_description": "{{params.summary}}"},
                },
                "expected_params": ["description"],
                "timeout_seconds": 15,
                "revision": 1,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("expected_params", response.data)

    def test_invalid_integration_is_rejected_by_validate_endpoint(self):
        self.client.force_authenticate(self.lead)

        response = self.client.post(
            self.integration_validate_url,
            {
                "name": "Conector invalido",
                "description": "Usa payload e body juntos",
                "action_name": "ti.invalid_lookup",
                "enabled": True,
                "method": "POST",
                "secret_ref": self.secret.pk,
                "auth_strategy": "bearer_header",
                "request_template": {
                    "url": "https://ti.local/ioc",
                    "payload": {"value": "{{params.value}}"},
                    "body": "raw",
                },
                "expected_params": ["value"],
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
                "credential_kind": "token",
                "token_value": "slack-secret-value",
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
