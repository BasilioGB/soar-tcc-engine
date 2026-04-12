from __future__ import annotations

from django.core.exceptions import ValidationError
from django.test import TestCase

from integrations.models import IntegrationDefinition, IntegrationSecretRef
from playbooks.validation import validate_playbook_semantics


class PlaybookSemanticValidationTests(TestCase):
    def setUp(self):
        self.secret = IntegrationSecretRef(name="jira.default")
        self.secret.set_token_credential("super-secret-token")
        self.secret.full_clean()
        self.secret.save()

    def test_accepts_valid_configured_action(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            secret_ref=self.secret,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary", "description"],
        )

        validate_playbook_semantics(
            {
                "name": "Configured integration flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "open_jira",
                        "action": "jira.create_issue",
                        "input": {
                            "summary": "Bloquear credencial",
                            "description": "Incidente 10",
                        },
                    }
                ],
            }
        )

    def test_rejects_unknown_action(self):
        with self.assertRaisesMessage(ValidationError, "acao 'jira.create_issue' nao encontrada"):
            validate_playbook_semantics(
                {
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
            )

    def test_rejects_missing_expected_params(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            secret_ref=self.secret,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary", "description"],
        )

        with self.assertRaisesMessage(ValidationError, "exige os parametros description"):
            validate_playbook_semantics(
                {
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
            )

    def test_rejects_disabled_integration(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            enabled=False,
            secret_ref=self.secret,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
        )

        with self.assertRaisesMessage(ValidationError, "conector HTTP 'jira.create_issue' esta desabilitado"):
            validate_playbook_semantics(
                {
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
            )

    def test_rejects_invalid_integration_contract(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            secret_ref=self.secret,
            request_template={
                "url": "https://jira.local/rest/api/3/issue",
                "payload": {"a": 1},
                "body": "raw",
            },
        )

        with self.assertRaisesMessage(ValidationError, "nao pode definir payload e body ao mesmo tempo"):
            validate_playbook_semantics(
                {
                    "name": "Configured integration flow",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "open_jira",
                            "action": "jira.create_issue",
                            "input": {},
                        }
                    ],
                }
            )
