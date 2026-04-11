from __future__ import annotations

from django.core.exceptions import ValidationError
from django.test import TestCase

from integrations.models import IntegrationDefinition
from playbooks.validation import validate_playbook_semantics


class PlaybookSemanticValidationTests(TestCase):
    def test_accepts_valid_configured_action(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary", "description"],
            response_mapping={"issue_key": "body.key"},
            post_response_actions=[
                {"action": "incident.add_note", "input": {"message": "ok"}}
            ],
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
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary", "description"],
            response_mapping={"issue_key": "body.key"},
            post_response_actions=[
                {"action": "incident.add_note", "input": {"message": "ok"}}
            ],
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
            request_template={"url": "https://jira.local/rest/api/3/issue"},
        )

        with self.assertRaisesMessage(ValidationError, "integracao 'jira.create_issue' esta desabilitada"):
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
            request_template={
                "url": "https://jira.local/rest/api/3/issue",
                "payload": {"a": 1},
                "body": "raw",
            },
            post_response_actions=[
                {"action": "http_webhook.post", "input": {"url": "https://hooks.local"}}
            ],
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
