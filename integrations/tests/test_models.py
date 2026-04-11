from __future__ import annotations

from django.contrib import admin
from django.core.exceptions import ValidationError
from django.test import TestCase

from integrations.admin import IntegrationDefinitionAdmin, IntegrationSecretRefAdmin
from integrations.models import IntegrationDefinition, IntegrationSecretRef


class IntegrationSecretRefModelTests(TestCase):
    def test_creates_secret_ref(self):
        secret = IntegrationSecretRef.objects.create(
            name="jira.default",
            reference="JIRA_API_TOKEN",
            description="Token padrao do Jira",
        )

        self.assertEqual(secret.provider, IntegrationSecretRef.Provider.ENV)
        self.assertTrue(secret.enabled)
        self.assertEqual(str(secret), "jira.default")

    def test_secret_ref_is_registered_in_admin(self):
        self.assertIsInstance(admin.site._registry[IntegrationSecretRef], IntegrationSecretRefAdmin)


class IntegrationDefinitionModelTests(TestCase):
    def setUp(self):
        self.secret = IntegrationSecretRef.objects.create(
            name="jira.default",
            reference="JIRA_API_TOKEN",
        )

    def test_creates_configured_integration(self):
        integration = IntegrationDefinition.objects.create(
            name="Criar tarefa Jira",
            action_name="jira.create_issue",
            description="Abre ticket padrao na fila de infraestrutura",
            method=IntegrationDefinition.Method.POST,
            auth_type=IntegrationDefinition.AuthType.SECRET_REF,
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
            response_mapping={
                "issue_key": "body.key",
                "issue_url": "body.self",
            },
            post_response_actions=[
                {
                    "action": "incident.add_note",
                    "input": {
                        "message": "Ticket {{output.issue_key}} criado.",
                    },
                }
            ],
        )

        self.assertEqual(integration.secret_ref, self.secret)
        self.assertTrue(integration.enabled)
        self.assertEqual(integration.revision, 1)
        self.assertEqual(str(integration), "jira.create_issue")

    def test_action_name_must_be_unique(self):
        IntegrationDefinition.objects.create(
            name="Criar tarefa Jira",
            action_name="jira.create_issue",
            auth_type=IntegrationDefinition.AuthType.SECRET_REF,
            secret_ref=self.secret,
            request_template={"url": "https://example.local"},
        )
        duplicate = IntegrationDefinition(
            name="Criar tarefa Jira v2",
            action_name="jira.create_issue",
            auth_type=IntegrationDefinition.AuthType.SECRET_REF,
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
            request_template={"url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}"},
            expected_params=["key"],
            response_mapping={"issue_key": "body.key"},
        )

        self.assertFalse(integration.enabled)

    def test_secret_ref_is_required_for_secret_auth(self):
        integration = IntegrationDefinition(
            name="Consulta autenticada",
            action_name="jira.lookup_issue",
            auth_type=IntegrationDefinition.AuthType.SECRET_REF,
            request_template={"url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}"},
        )

        with self.assertRaises(ValidationError) as ctx:
            integration.full_clean()

        self.assertIn("secret_ref", ctx.exception.message_dict)

    def test_expected_params_must_be_unique_strings(self):
        integration = IntegrationDefinition(
            name="Consulta Jira",
            action_name="jira.lookup_issue",
            request_template={"url": "https://example.atlassian.net/rest/api/3/issue/{{params.key}}"},
            expected_params=["key", "key"],
        )

        with self.assertRaises(ValidationError) as ctx:
            integration.full_clean()

        self.assertIn("expected_params", ctx.exception.message_dict)

    def test_post_response_actions_must_contain_action_and_object_input(self):
        integration = IntegrationDefinition(
            name="Criar tarefa Jira",
            action_name="jira.create_issue",
            request_template={"url": "https://example.local"},
            post_response_actions=[
                {
                    "action": "incident.add_note",
                    "input": "mensagem invalida",
                }
            ],
        )

        with self.assertRaises(ValidationError) as ctx:
            integration.full_clean()

        self.assertIn("post_response_actions", ctx.exception.message_dict)

    def test_definition_is_registered_in_admin(self):
        self.assertIsInstance(admin.site._registry[IntegrationDefinition], IntegrationDefinitionAdmin)
