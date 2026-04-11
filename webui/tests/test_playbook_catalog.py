from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from integrations.models import IntegrationDefinition


class PlaybookCatalogViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="catalog_user",
            password="pass",
            role=User.Roles.SOC_LEAD,
        )

    def test_playbook_form_shows_enabled_configured_integrations(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            description="Abre ticket automaticamente no Jira",
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary", "description"],
            response_mapping={"issue_key": "body.key"},
            post_response_actions=[
                {
                    "action": "incident.add_note",
                    "input": {"message": "Ticket {{output.issue_key}} criado"},
                }
            ],
            revision=3,
        )
        IntegrationDefinition.objects.create(
            name="Integracao desligada",
            action_name="jira.disabled_issue",
            description="Nao deve aparecer no catalogo",
            enabled=False,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
        )

        self.client.force_login(self.user)
        response = self.client.get(reverse("webui:playbook_create"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Integracoes configuradas")
        self.assertContains(response, "jira.create_issue")
        self.assertContains(response, "Criar issue Jira")
        self.assertContains(response, "issue_key")
        self.assertContains(response, "incident.add_note")
        self.assertContains(response, "Revision 3.")
        self.assertNotContains(response, "jira.disabled_issue")
