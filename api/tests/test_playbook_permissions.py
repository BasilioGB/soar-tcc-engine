from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from incidents.models import Incident
from playbooks.models import Execution, Playbook


INCIDENT_MANUAL_DSL = {
    "name": "Incident manual API",
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
            "input": {"message": "Execucao via API"},
        }
    ],
    "on_error": "continue",
}


class PlaybookPermissionHardeningTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(
            username="analyst_api",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        self.lead = User.objects.create_user(
            username="lead_api",
            password="pass",
            role=User.Roles.SOC_LEAD,
        )
        self.incident = Incident.objects.create(
            title="Malware",
            description="Execucao suspeita",
            created_by=self.lead,
        )
        self.playbook = Playbook.objects.create(
            name="Incident manual API",
            dsl=INCIDENT_MANUAL_DSL,
            enabled=True,
            created_by=self.lead,
        )
        self.last_execution = Execution.objects.create(
            playbook=self.playbook,
            incident=self.incident,
            created_by=self.lead,
        )
        self.run_playbook_url = f"/api/v1/incidents/{self.incident.pk}/run_playbook/"
        self.rerun_last_url = f"/api/v1/incidents/{self.incident.pk}/playbooks/rerun-last/"
        self.playbook_run_url = f"/api/v1/playbooks/{self.playbook.pk}/run/"

    def test_soc_analyst_is_forbidden_to_execute_playbooks(self):
        self.client.force_authenticate(self.analyst)
        responses = [
            self.client.post(self.run_playbook_url, {"playbook_id": self.playbook.pk}, format="json"),
            self.client.post(self.rerun_last_url, {}, format="json"),
            self.client.post(self.playbook_run_url, {"incident_id": self.incident.pk}, format="json"),
        ]
        for response in responses:
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_soc_lead_can_execute_playbooks(self):
        self.client.force_authenticate(self.lead)
        run_response = self.client.post(
            self.run_playbook_url,
            {"playbook_id": self.playbook.pk},
            format="json",
        )
        rerun_response = self.client.post(self.rerun_last_url, {}, format="json")
        playbook_run_response = self.client.post(
            self.playbook_run_url,
            {"incident_id": self.incident.pk},
            format="json",
        )
        self.assertEqual(run_response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(rerun_response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(playbook_run_response.status_code, status.HTTP_202_ACCEPTED)
        self.assertIn("step_results", run_response.data)
        self.assertNotIn("logs", run_response.data)
        self.assertGreaterEqual(len(run_response.data["step_results"]), 1)
        self.assertEqual(run_response.data["step_results"][0]["status"], "SUCCEEDED")
