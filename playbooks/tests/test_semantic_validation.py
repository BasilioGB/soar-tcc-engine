from __future__ import annotations

from django.core.exceptions import ValidationError
from django.test import TestCase

from integrations.models import IntegrationDefinition, IntegrationSecretRef
from playbooks.models import Playbook, PlaybookStep
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

    def test_accepts_configured_action_inside_control_branch(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            secret_ref=self.secret,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary", "description"],
        )

        validate_playbook_semantics(
            {
                "name": "Branch configured integration flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "decidir_veredito",
                        "action": "control.branch",
                        "branches": [
                            {
                                "name": "malicious",
                                "when": {"left": "{{incident.severity}}", "equals": "HIGH"},
                                "steps": [
                                    {
                                        "name": "open_jira",
                                        "action": "jira.create_issue",
                                        "input": {
                                            "summary": "Bloquear IOC",
                                            "description": "Incidente com IOC malicioso",
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )

    def test_rejects_unknown_action_inside_control_branch(self):
        with self.assertRaisesMessage(ValidationError, "Step 'open_jira': acao 'jira.create_issue' nao encontrada"):
            validate_playbook_semantics(
                {
                    "name": "Branch invalid integration flow",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "decidir_veredito",
                            "action": "control.branch",
                            "branches": [
                                {
                                    "name": "malicious",
                                    "when": {"left": "{{incident.severity}}", "equals": "HIGH"},
                                    "steps": [
                                        {
                                            "name": "open_jira",
                                            "action": "jira.create_issue",
                                            "input": {"summary": "Bloquear IOC"},
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            )

    def test_playbook_step_sync_includes_branch_and_default_steps(self):
        playbook = Playbook.objects.create(
            name="Branch step sync flow",
            enabled=True,
            dsl={
                "name": "Branch step sync flow",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "decidir_veredito",
                        "action": "control.branch",
                        "branches": [
                            {
                                "name": "malicious",
                                "when": {"left": "{{incident.severity}}", "equals": "HIGH"},
                                "steps": [
                                    {
                                        "name": "bloquear_ioc",
                                        "action": "task.create",
                                        "input": {"title": "Bloquear IOC malicioso"},
                                    }
                                ],
                            }
                        ],
                        "default": [
                            {
                                "name": "revisao_manual",
                                "action": "task.create",
                                "input": {"title": "Revisar resultado inconclusivo"},
                            }
                        ],
                    }
                ],
            },
        )

        synced_steps = list(
            PlaybookStep.objects.filter(playbook=playbook).order_by("order").values_list("name", "action")
        )
        self.assertEqual(
            synced_steps,
            [
                ("decidir_veredito", "control.branch"),
                ("bloquear_ioc", "task.create"),
                ("revisao_manual", "task.create"),
            ],
        )
