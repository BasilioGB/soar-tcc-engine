from __future__ import annotations

from django.test import TestCase

from integrations.models import IntegrationDefinition, IntegrationSecretRef
from webui.forms import PlaybookForm


class PlaybookFormValidationTests(TestCase):
    def setUp(self):
        self.secret = IntegrationSecretRef(name="jira.default")
        self.secret.set_token_credential("super-secret-token")
        self.secret.full_clean()
        self.secret.save()

    def test_form_rejects_missing_configured_integration_params(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            secret_ref=self.secret,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary", "description"],
        )

        form = PlaybookForm(
            data={
                "name": "Configured flow",
                "category": "Phishing",
                "description": "Fluxo com integracao configurada",
                "enabled": True,
                "type": "incident",
                "mode": "manual",
                "dsl_text": """
{
  "name": "Configured flow",
  "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
  "steps": [
    {
      "name": "open_jira",
      "action": "jira.create_issue",
      "input": {"summary": "Bloquear credencial"}
    }
  ]
}
""",
            }
        )

        self.assertFalse(form.is_valid())
        self.assertIn("dsl_text", form.errors)
        self.assertIn("description", form.errors["dsl_text"][0])
