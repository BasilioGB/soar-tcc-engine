from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from integrations.models import IntegrationDefinition, IntegrationSecretRef
from playbooks.models import Playbook


class PlaybookCatalogViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="catalog_user",
            password="pass",
            role=User.Roles.SOC_LEAD,
        )
        self.secret = IntegrationSecretRef(name="jira.default")
        self.secret.set_token_credential("super-secret-token")
        self.secret.full_clean()
        self.secret.save()

    def test_playbook_form_shows_enabled_configured_integrations(self):
        IntegrationDefinition.objects.create(
            name="Criar issue Jira",
            action_name="jira.create_issue",
            description="Abre ticket automaticamente no Jira",
            secret_ref=self.secret,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
            expected_params=["summary", "description"],
            revision=3,
        )
        IntegrationDefinition.objects.create(
            name="Conector desligado",
            action_name="jira.disabled_issue",
            description="Nao deve aparecer no catalogo",
            enabled=False,
            secret_ref=self.secret,
            request_template={"url": "https://jira.local/rest/api/3/issue"},
        )

        self.client.force_login(self.user)
        response = self.client.get(reverse("webui:playbook_create"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Conectores HTTP")
        self.assertContains(response, "jira.create_issue")
        self.assertContains(response, "Criar issue Jira")
        self.assertContains(response, "corpo da resposta")
        self.assertContains(response, "Revision 3.")
        self.assertContains(response, "Contexto atual do catalogo")
        self.assertContains(response, "Exemplos de triggers")
        self.assertContains(response, "&quot;event&quot;: &quot;incident.updated&quot;")
        self.assertContains(response, "Ver comando")
        self.assertContains(response, "Copiar comando")
        self.assertContains(response, '&quot;action&quot;: &quot;jira.create_issue&quot;')
        self.assertNotContains(response, "jira.disabled_issue")

    def test_playbook_list_groups_entries_by_category(self):
        Playbook.objects.create(
            name="Phishing triage",
            category="Phishing",
            dsl={
                "name": "Phishing triage",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"labels": ["phishing"]}}],
                "steps": [{"name": "registrar", "action": "incident.add_note", "input": {"message": "ok"}}],
            },
            enabled=True,
            created_by=self.user,
        )
        Playbook.objects.create(
            name="Containment generic",
            category="Containment",
            dsl={
                "name": "Containment generic",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["HIGH"]}}],
                "steps": [{"name": "registrar", "action": "incident.add_note", "input": {"message": "ok"}}],
            },
            enabled=True,
            created_by=self.user,
        )

        self.client.force_login(self.user)
        response = self.client.get(reverse("webui:playbook_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Todas as categorias")
        self.assertContains(response, "Phishing")
        self.assertContains(response, "Containment")
        self.assertContains(response, "Phishing triage")
        self.assertContains(response, "Containment generic")
