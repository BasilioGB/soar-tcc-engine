from __future__ import annotations

from django.contrib import admin
from django.core.exceptions import ValidationError
from django.test import TestCase

from integrations.admin import HttpConnectorAdmin, HttpConnectorSecretAdmin
from integrations.models import IntegrationDefinition, IntegrationSecretRef


class IntegrationSecretRefModelTests(TestCase):
    def test_creates_secret_ref(self):
        secret = IntegrationSecretRef(
            name="jira.default",
            description="Token padrao do Jira",
        )
        secret.set_token_credential("super-secret-token")
        secret.full_clean()
        secret.save()

        self.assertTrue(secret.enabled)
        self.assertTrue(secret.has_credential)
        self.assertEqual(secret.get_credential()["token"], "super-secret-token")
        self.assertEqual(str(secret), "jira.default")

    def test_secret_ref_requires_credential(self):
        secret = IntegrationSecretRef(name="jira.default")

        with self.assertRaises(ValidationError) as ctx:
            secret.full_clean()

        self.assertIn("credential", ctx.exception.message_dict)

    def test_secret_ref_supports_basic_auth_credentials(self):
        secret = IntegrationSecretRef(name="snow.basic", credential_kind=IntegrationSecretRef.CredentialKind.BASIC_AUTH)
        secret.set_basic_auth_credential("svc-user", "svc-pass")
        secret.full_clean()
        secret.save()

        self.assertTrue(secret.has_credential)
        self.assertEqual(
            secret.get_credential(),
            {"username": "svc-user", "password": "svc-pass"},
        )

    def test_secret_ref_is_registered_in_admin(self):
        self.assertIsInstance(admin.site._registry[IntegrationSecretRef], HttpConnectorSecretAdmin)


class IntegrationDefinitionModelTests(TestCase):
    def setUp(self):
        self.secret = IntegrationSecretRef(
            name="jira.default",
        )
        self.secret.set_token_credential("super-secret-token")
        self.secret.full_clean()
        self.secret.save()

    def test_creates_configured_integration(self):
        integration = IntegrationDefinition.objects.create(
            name="Criar tarefa Jira",
            action_name="jira.create_issue",
            description="Abre ticket padrao na fila de infraestrutura",
            method=IntegrationDefinition.Method.POST,
            secret_ref=self.secret,
            request_template={
                "url": "https://example.atlassian.net/rest/api/3/issue",
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

        self.assertEqual(integration.secret_ref, self.secret)
        self.assertTrue(integration.enabled)
        self.assertEqual(integration.revision, 1)
        self.assertEqual(str(integration), "jira.create_issue")

    def test_action_name_must_be_unique(self):
        IntegrationDefinition.objects.create(
            name="Criar tarefa Jira",
            action_name="jira.create_issue",
            secret_ref=self.secret,
            request_template={"url": "https://example.local"},
        )
        duplicate = IntegrationDefinition(
            name="Criar tarefa Jira v2",
            action_name="jira.create_issue",
            secret_ref=self.secret,
            request_template={"url": "https://example.local/v2"},
        )

        with self.assertRaises(ValidationError):
            duplicate.validate_unique()

    def test_disabled_integration_is_persisted_without_runtime_side_effects(self):
        integration = IntegrationDefinition.objects.create(
            name="Consulta Jira",
            action_name="jira.get_issue",
            enabled=False,
            method=IntegrationDefinition.Method.GET,
            secret_ref=self.secret,
            request_template={"url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}"},
            expected_params=["key"],
        )

        self.assertFalse(integration.enabled)

    def test_secret_ref_is_required(self):
        integration = IntegrationDefinition(
            name="Consulta autenticada",
            action_name="jira.lookup_issue",
            request_template={"url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}"},
        )

        with self.assertRaises(ValidationError) as ctx:
            integration.full_clean()

        self.assertIn("secret_ref", ctx.exception.message_dict)

    def test_secret_ref_must_be_enabled_and_have_value(self):
        self.secret.enabled = False
        self.secret.save(update_fields=["enabled"])
        integration = IntegrationDefinition(
            name="Consulta autenticada",
            action_name="jira.lookup_issue",
            secret_ref=self.secret,
            request_template={"url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}"},
        )

        with self.assertRaises(ValidationError) as ctx:
            integration.full_clean()

        self.assertIn("secret_ref", ctx.exception.message_dict)

    def test_expected_params_must_be_unique_strings(self):
        integration = IntegrationDefinition(
            name="Consulta Jira",
            action_name="jira.lookup_issue",
            secret_ref=self.secret,
            request_template={"url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}"},
            expected_params=["key", "key"],
        )

        with self.assertRaises(ValidationError) as ctx:
            integration.full_clean()

        self.assertIn("expected_params", ctx.exception.message_dict)

    def test_expected_params_is_derived_from_request_template_when_blank(self):
        integration = IntegrationDefinition(
            name="Consulta Jira",
            action_name="jira.lookup_issue",
            secret_ref=self.secret,
            request_template={
                "url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}",
                "query": {"expand": "{{params.expand}}"},
            },
            expected_params=[],
        )

        integration.full_clean()

        self.assertEqual(integration.expected_params, ["key", "expand"])

    def test_expected_params_is_derived_from_request_and_output_templates(self):
        integration = IntegrationDefinition(
            name="Consulta VT",
            action_name="vt.lookup_domain",
            secret_ref=self.secret,
            request_template={"url": "https://vt.local/domains/{{params.domain}}"},
            output_template={"requested_domain": "{{params.domain}}"},
            expected_params=[],
        )

        integration.full_clean()

        self.assertEqual(integration.expected_params, ["domain"])

    def test_expected_params_must_match_template_params(self):
        integration = IntegrationDefinition(
            name="Consulta Jira",
            action_name="jira.lookup_issue",
            secret_ref=self.secret,
            request_template={"url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}"},
            expected_params=["summary"],
        )

        with self.assertRaises(ValidationError) as ctx:
            integration.full_clean()

        self.assertIn("expected_params", ctx.exception.message_dict)

    def test_request_template_cannot_define_auth_inline(self):
        integration = IntegrationDefinition(
            name="Consulta Jira",
            action_name="jira.lookup_issue",
            secret_ref=self.secret,
            request_template={
                "url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}",
                "auth": {"strategy": "header", "header_name": "x-api-key"},
            },
            expected_params=["key"],
        )

        with self.assertRaises(ValidationError) as ctx:
            integration.full_clean()

        self.assertIn("request_template", ctx.exception.message_dict)

    def test_basic_auth_requires_basic_secret(self):
        integration = IntegrationDefinition(
            name="Consulta Jira",
            action_name="jira.lookup_issue",
            secret_ref=self.secret,
            auth_strategy=IntegrationDefinition.AuthStrategy.BASIC,
            request_template={"url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}"},
            expected_params=["key"],
        )

        with self.assertRaises(ValidationError) as ctx:
            integration.full_clean()

        self.assertIn("secret_ref", ctx.exception.message_dict)

    def test_basic_auth_accepts_basic_secret(self):
        secret = IntegrationSecretRef(name="snow.basic", credential_kind=IntegrationSecretRef.CredentialKind.BASIC_AUTH)
        secret.set_basic_auth_credential("svc-user", "svc-pass")
        secret.full_clean()
        secret.save()
        integration = IntegrationDefinition(
            name="Consulta Snow",
            action_name="snow.lookup_ticket",
            secret_ref=secret,
            auth_strategy=IntegrationDefinition.AuthStrategy.BASIC,
            request_template={"url": "https://snow.local/api/{{params.number}}"},
            expected_params=["number"],
        )

        integration.full_clean()

    def test_definition_is_registered_in_admin(self):
        self.assertIsInstance(admin.site._registry[IntegrationDefinition], HttpConnectorAdmin)
