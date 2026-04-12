from __future__ import annotations

from unittest.mock import Mock, patch

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

        automation_response = self.client.get(reverse("webui:automation_overview"))
        list_response = self.client.get(reverse("webui:http_connector_list"))
        secrets_response = self.client.get(reverse("webui:http_connector_secret_list"))
        self.assertEqual(automation_response.status_code, 200)
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(secrets_response.status_code, 200)

        secret_response = self.client.post(
            reverse("webui:http_connector_secret_create"),
            {
                "name": "jira.default",
                "description": "Token do Jira",
                "enabled": True,
                "credential_kind": "token",
                "token_value": "jira-secret-token",
            },
        )
        self.assertEqual(secret_response.status_code, 302)
        secret_ref = IntegrationSecretRef.objects.get(name="jira.default")
        self.assertEqual(secret_ref.get_credential()["token"], "jira-secret-token")
        self.assertEqual(secret_ref.created_by, self.lead)
        self.assertEqual(secret_ref.rotated_by, self.lead)

        integration_response = self.client.post(
            reverse("webui:http_connector_create"),
            {
                "name": "Criar issue Jira",
                "description": "Abre ticket automaticamente",
                "action_name": "jira.create_issue",
                "enabled": True,
                "method": "POST",
                "secret_ref": secret_ref.pk,
                "auth_strategy": "bearer_header",
                "auth_header_name": "Authorization",
                "auth_prefix": "Bearer",
                "auth_query_param": "api_key",
                "timeout_seconds": 15,
                "revision": 1,
                "request_template_text": '{"url": "https://jira.local/rest/api/3/issue", "body": {"summary": "{{params.summary}}"}}',
                "expected_params_text": '["summary"]',
            },
        )
        self.assertEqual(integration_response.status_code, 302)
        self.assertTrue(
            IntegrationDefinition.objects.filter(action_name="jira.create_issue").exists()
        )

    def test_soc_analyst_cannot_access_integration_management(self):
        self.client.force_login(self.analyst)

        responses = [
            self.client.get(reverse("webui:http_connector_list"), follow=True),
            self.client.get(reverse("webui:http_connector_secret_list"), follow=True),
            self.client.get(reverse("webui:http_connector_create"), follow=True),
            self.client.get(reverse("webui:http_connector_secret_create"), follow=True),
        ]

        for response in responses:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.request["PATH_INFO"], reverse("webui:dashboard"))
            self.assertContains(response, "Voce nao tem permissao para acessar esta pagina.")

    def test_invalid_json_is_rejected_in_integration_form(self):
        self.client.force_login(self.lead)
        secret_ref = IntegrationSecretRef(
            name="jira.default",
        )
        secret_ref.set_token_credential("jira-secret-token")
        secret_ref.full_clean()
        secret_ref.save()

        response = self.client.post(
            reverse("webui:http_connector_create"),
            {
                "name": "Criar issue Jira",
                "description": "Abre ticket automaticamente",
                "action_name": "jira.create_issue",
                "enabled": True,
                "method": "POST",
                "secret_ref": secret_ref.pk,
                "auth_strategy": "bearer_header",
                "auth_header_name": "Authorization",
                "auth_prefix": "Bearer",
                "auth_query_param": "api_key",
                "timeout_seconds": 15,
                "revision": 1,
                "request_template_text": '{"url": "https://jira.local/rest/api/3/issue"',
                "expected_params_text": '["summary"]',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "JSON invalido em request_template")
        self.assertFalse(
            IntegrationDefinition.objects.filter(action_name="jira.create_issue").exists()
        )

    def test_blank_expected_params_is_derived_from_template_in_form(self):
        self.client.force_login(self.lead)
        secret_ref = IntegrationSecretRef(name="jira.default")
        secret_ref.set_token_credential("jira-secret-token")
        secret_ref.full_clean()
        secret_ref.save()

        response = self.client.post(
            reverse("webui:http_connector_create"),
            {
                "name": "Buscar dominio",
                "description": "Consulta dominio automaticamente",
                "action_name": "ti.lookup_domain",
                "enabled": True,
                "method": "GET",
                "secret_ref": secret_ref.pk,
                "auth_strategy": "header",
                "auth_header_name": "x-apikey",
                "auth_prefix": "",
                "auth_query_param": "api_key",
                "timeout_seconds": 15,
                "revision": 1,
                "request_template_text": '{"url": "https://ti.local/domain/{{params.domain}}", "query": {"source": "{{params.source}}"}}',
                "expected_params_text": "",
            },
        )

        self.assertEqual(response.status_code, 302)
        connector = IntegrationDefinition.objects.get(action_name="ti.lookup_domain")
        self.assertEqual(connector.expected_params, ["domain", "source"])

    def test_guided_mode_can_create_connector_without_raw_request_template(self):
        self.client.force_login(self.lead)
        secret_ref = IntegrationSecretRef(name="jira.default")
        secret_ref.set_token_credential("jira-secret-token")
        secret_ref.full_clean()
        secret_ref.save()

        response = self.client.post(
            reverse("webui:http_connector_create"),
            {
                "request_editor_mode": "guided",
                "name": "Buscar dominio guiado",
                "description": "Consulta dominio por modo guiado",
                "action_name": "ti.lookup_domain_guided",
                "enabled": True,
                "method": "GET",
                "secret_ref": secret_ref.pk,
                "auth_strategy": "header",
                "auth_header_name": "x-apikey",
                "auth_prefix": "",
                "auth_query_param": "api_key",
                "timeout_seconds": 15,
                "revision": 1,
                "request_url": "https://ti.local/domain/{{params.domain}}",
                "request_headers_text": '{"Accept": "application/json"}',
                "request_query_text": '{"source": "{{params.source}}"}',
                "request_body_mode": "none",
                "request_payload_text": "{}",
                "request_body_text": "",
                "request_template_text": "",
                "expected_params_text": "",
            },
        )

        self.assertEqual(response.status_code, 302)
        connector = IntegrationDefinition.objects.get(action_name="ti.lookup_domain_guided")
        self.assertEqual(
            connector.request_template,
            {
                "url": "https://ti.local/domain/{{params.domain}}",
                "headers": {"Accept": "application/json"},
                "query": {"source": "{{params.source}}"},
            },
        )
        self.assertEqual(connector.expected_params, ["domain", "source"])

    def test_form_rejects_expected_params_that_diverge_from_template(self):
        self.client.force_login(self.lead)
        secret_ref = IntegrationSecretRef(name="jira.default")
        secret_ref.set_token_credential("jira-secret-token")
        secret_ref.full_clean()
        secret_ref.save()

        response = self.client.post(
            reverse("webui:http_connector_create"),
            {
                "name": "Buscar dominio",
                "description": "Consulta dominio automaticamente",
                "action_name": "ti.lookup_domain",
                "enabled": True,
                "method": "GET",
                "secret_ref": secret_ref.pk,
                "auth_strategy": "header",
                "auth_header_name": "x-apikey",
                "auth_prefix": "",
                "auth_query_param": "api_key",
                "timeout_seconds": 15,
                "revision": 1,
                "request_template_text": '{"url": "https://ti.local/domain/{{params.domain}}"}',
                "expected_params_text": '["source"]',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "expected_params deve corresponder")

    def test_secret_detail_page_precedes_edit_and_allows_rotation(self):
        self.client.force_login(self.lead)
        secret_ref = IntegrationSecretRef(
            name="jira.default",
            description="Token do Jira",
        )
        secret_ref.set_token_credential("first-secret")
        secret_ref.created_by = self.lead
        secret_ref.rotated_by = self.lead
        secret_ref.full_clean()
        secret_ref.save()

        detail_response = self.client.get(reverse("webui:http_connector_secret_detail", args=[secret_ref.pk]))
        self.assertEqual(detail_response.status_code, 200)
        self.assertNotContains(detail_response, "first-secret")
        self.assertContains(detail_response, "Editar")
        self.assertContains(detail_response, "A credencial e write-only")

        get_response = self.client.get(reverse("webui:http_connector_secret_edit", args=[secret_ref.pk]))
        self.assertEqual(get_response.status_code, 200)
        self.assertNotContains(get_response, "first-secret")
        self.assertContains(get_response, "Novo token ou API key")

        post_response = self.client.post(
            reverse("webui:http_connector_secret_edit", args=[secret_ref.pk]),
            {
                "name": "jira.default",
                "description": "Token rotacionado",
                "enabled": True,
                "credential_kind": "token",
                "token_value": "second-secret",
            },
        )
        self.assertEqual(post_response.status_code, 302)
        secret_ref.refresh_from_db()
        self.assertEqual(secret_ref.get_credential()["token"], "second-secret")
        self.assertEqual(secret_ref.rotated_by, self.lead)

    @patch("integrations.services.http_client.requests.request")
    def test_integration_edit_page_can_test_request_with_secret_ref(self, request_mock):
        self.client.force_login(self.lead)
        secret_ref = IntegrationSecretRef(name="jira.default", description="Token do Jira")
        secret_ref.set_token_credential("super-secret-token")
        secret_ref.created_by = self.lead
        secret_ref.rotated_by = self.lead
        secret_ref.full_clean()
        secret_ref.save()
        integration = IntegrationDefinition.objects.create(
            name="Buscar IOC",
            action_name="ti.lookup_ioc",
            enabled=True,
            method="GET",
            secret_ref=secret_ref,
            auth_strategy=IntegrationDefinition.AuthStrategy.QUERY_PARAM,
            auth_query_param="token",
            request_template={
                "url": "https://ti.local/ioc",
                "query": {"value": "{{params.value}}"},
            },
            expected_params=["value"],
        )

        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {"verdict": "malicious"}
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        test_response = self.client.post(
            reverse("webui:http_connector_test", args=[integration.pk]),
            {
                "params_text": '{"value": "malicious.example"}',
                "execute_request": "on",
            },
        )

        self.assertEqual(test_response.status_code, 200)
        self.assertContains(test_response, "Teste executado")
        self.assertContains(test_response, "&quot;verdict&quot;: &quot;malicious&quot;")
        self.assertContains(test_response, "&quot;token&quot;: &quot;***REDACTED***&quot;")
        self.assertContains(test_response, "parametro de query")

    @patch("integrations.services.http_client.requests.request")
    def test_integration_test_redacts_header_secret_and_shows_filtered_output(self, request_mock):
        self.client.force_login(self.lead)
        secret_ref = IntegrationSecretRef(name="virustotal.default", description="API key")
        secret_ref.set_token_credential("vt-super-secret")
        secret_ref.created_by = self.lead
        secret_ref.rotated_by = self.lead
        secret_ref.full_clean()
        secret_ref.save()
        integration = IntegrationDefinition.objects.create(
            name="VirusTotal Domain Lookup",
            action_name="virustotal.domain_lookup",
            enabled=True,
            method="GET",
            secret_ref=secret_ref,
            auth_strategy=IntegrationDefinition.AuthStrategy.HEADER,
            auth_header_name="x-apikey",
            request_template={
                "url": "https://www.virustotal.com/api/v3/domains/{{params.domain}}",
            },
            output_template={
                "domain": "{{response.body.data.id}}",
                "reputation": "{{response.body.data.attributes.reputation}}",
            },
            expected_params=["domain"],
        )

        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {
            "data": {
                "id": "primeup.com",
                "attributes": {"reputation": 0},
            }
        }
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        test_response = self.client.post(
            reverse("webui:http_connector_test", args=[integration.pk]),
            {
                "params_text": '{"domain": "primeup.com"}',
                "execute_request": "on",
            },
        )

        self.assertEqual(test_response.status_code, 200)
        self.assertContains(test_response, "&quot;x-apikey&quot;: &quot;***REDACTED***&quot;")
        self.assertContains(test_response, "&quot;domain&quot;: &quot;primeup.com&quot;")
        self.assertContains(test_response, "&quot;reputation&quot;: 0")
        self.assertNotContains(test_response, "vt-super-secret")

    def test_integration_test_ui_no_longer_exposes_runtime_context_field(self):
        self.client.force_login(self.lead)
        secret_ref = IntegrationSecretRef(name="jira.default", description="Token do Jira")
        secret_ref.set_token_credential("super-secret-token")
        secret_ref.created_by = self.lead
        secret_ref.rotated_by = self.lead
        secret_ref.full_clean()
        secret_ref.save()
        integration = IntegrationDefinition.objects.create(
            name="Buscar dominio VT",
            action_name="vt.domain_lookup",
            enabled=True,
            method="GET",
            secret_ref=secret_ref,
            auth_strategy=IntegrationDefinition.AuthStrategy.HEADER,
            auth_header_name="x-apikey",
            request_template={"url": "https://vt.local/domains/{{params.domain}}"},
            expected_params=["domain"],
        )

        response = self.client.get(reverse("webui:http_connector_edit", args=[integration.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Contexto adicional")
        self.assertNotContains(response, "runtime_context_text")
