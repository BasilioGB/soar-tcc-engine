from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from incidents.models import Artifact, Incident
from playbooks.models import Execution, Playbook


INCIDENT_MANUAL_DSL = {
    "name": "Manual incident run",
    "type": "incident",
    "mode": "manual",
    "filters": [
        {
            "target": "incident",
            "conditions": {"severity": ["MEDIUM", "HIGH", "CRITICAL"]},
        }
    ],
    "steps": [
        {
            "name": "registrar_inicio",
            "action": "incident.add_note",
            "input": {"message": "Execucao manual iniciada"},
        }
    ],
    "on_error": "continue",
}


ARTIFACT_MANUAL_DSL = {
    "name": "Manual artifact run",
    "type": "artifact",
    "mode": "manual",
    "filters": [
        {
            "target": "artifact",
            "conditions": {"type": ["DOMAIN"]},
        }
    ],
    "steps": [
        {
            "name": "registrar_inicio",
            "action": "incident.add_note",
            "input": {"message": "Execucao manual de artefato iniciada"},
        }
    ],
    "on_error": "continue",
}


class WebUIPlaybookHardeningTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(
            username="analyst",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        self.lead = User.objects.create_user(
            username="soclead",
            password="pass",
            role=User.Roles.SOC_LEAD,
        )
        self.incident = Incident.objects.create(
            title="Phishing",
            description="Email suspeito",
            created_by=self.lead,
        )
        self.artifact = Artifact.objects.create(type=Artifact.Type.DOMAIN, value="malicious.example")
        self.artifact.incidents.add(self.incident)
        self.incident_playbook = Playbook.objects.create(
            name="Manual incident run",
            category="Phishing",
            dsl=INCIDENT_MANUAL_DSL,
            enabled=True,
            created_by=self.lead,
        )
        self.artifact_playbook = Playbook.objects.create(
            name="Manual artifact run",
            category="Phishing",
            dsl=ARTIFACT_MANUAL_DSL,
            enabled=True,
            created_by=self.lead,
        )
        self.last_execution = Execution.objects.create(
            playbook=self.incident_playbook,
            incident=self.incident,
            created_by=self.lead,
        )

    def _urls(self) -> dict[str, str]:
        return {
            "run": reverse("webui:incident_playbook_run", kwargs={"pk": self.incident.pk}),
            "rerun": reverse("webui:incident_playbook_rerun", kwargs={"pk": self.incident.pk}),
            "artifact_action": reverse(
                "webui:incident_artifact_action",
                kwargs={"pk": self.incident.pk, "artifact_id": self.artifact.pk},
            ),
            "artifact_run": reverse(
                "webui:incident_artifact_run_playbook",
                kwargs={
                    "pk": self.incident.pk,
                    "artifact_id": self.artifact.pk,
                    "playbook_id": self.artifact_playbook.pk,
                },
            ),
            "playbook_run": reverse("webui:playbook_run", kwargs={"pk": self.incident_playbook.pk}),
        }

    def test_playbook_mutation_endpoints_require_post(self):
        self.client.force_login(self.lead)
        for name, url in self._urls().items():
            with self.subTest(endpoint=name):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 405)

    def test_soc_analyst_cannot_execute_playbooks(self):
        self.client.force_login(self.analyst)
        urls = self._urls()
        responses = [
            self.client.post(urls["run"], {"playbook_id": self.incident_playbook.pk}),
            self.client.post(urls["rerun"], {}),
            self.client.post(urls["artifact_action"], {"action": f"playbook:{self.artifact_playbook.pk}"}),
            self.client.post(urls["artifact_run"], {}),
            self.client.post(urls["playbook_run"], {"incident": self.incident.pk}),
        ]
        for response in responses:
            self.assertEqual(response.status_code, 403)
        self.assertEqual(Execution.objects.count(), 1)

    def test_soc_lead_can_execute_playbooks(self):
        self.client.force_login(self.lead)
        urls = self._urls()
        with (
            patch("webui.views.start_playbook_execution", return_value=SimpleNamespace(id=999)) as mocked_start,
            patch("webui.views.is_manual_playbook_available_for_incident", return_value=True),
            patch("webui.views.is_manual_playbook_available_for_artifact", return_value=True),
        ):
            responses = [
                self.client.post(urls["run"], {"playbook_id": self.incident_playbook.pk}),
                self.client.post(urls["rerun"], {}),
                self.client.post(urls["artifact_action"], {"action": f"playbook:{self.artifact_playbook.pk}"}),
                self.client.post(urls["artifact_run"], {}),
                self.client.post(urls["playbook_run"], {"incident": self.incident.pk}),
            ]
        for response in responses:
            self.assertEqual(response.status_code, 302)
        self.assertEqual(mocked_start.call_count, 5)

    def test_incident_detail_groups_manual_playbooks_by_category(self):
        self.client.force_login(self.lead)

        response = self.client.get(reverse("webui:incident_detail", kwargs={"pk": self.incident.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Playbooks manuais aplicaveis agrupados por categoria")
        self.assertContains(response, 'optgroup label="Phishing"')
        self.assertContains(response, 'label="Playbook: Phishing"')
