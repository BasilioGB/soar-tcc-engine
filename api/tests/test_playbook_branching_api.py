from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase

from incidents.models import Incident, TimelineEntry


BRANCHING_API_DSL = {
    "name": "Branching API flow",
    "type": "incident",
    "mode": "manual",
    "filters": [{"target": "incident", "conditions": {"labels": ["branch-api"]}}],
    "steps": [
        {
            "name": "decidir_severidade",
            "action": "control.branch",
            "branches": [
                {
                    "name": "critical",
                    "when": {"left": "{{incident.severity}}", "equals": "CRITICAL"},
                    "steps": [
                        {
                            "name": "note_critical",
                            "action": "incident.add_note",
                            "input": {"message": "REST branch critical"},
                        }
                    ],
                },
                {
                    "name": "high",
                    "when": {"left": "{{incident.severity}}", "equals": "HIGH"},
                    "steps": [
                        {
                            "name": "note_high",
                            "action": "incident.add_note",
                            "input": {"message": "REST branch high"},
                        }
                    ],
                },
            ],
            "default": [
                {
                    "name": "note_default",
                    "action": "incident.add_note",
                    "input": {"message": "REST branch default"},
                }
            ],
        },
        {
            "name": "registrar_branch",
            "action": "incident.add_note",
            "input": {
                "message": "REST branch selecionado: {{results.decidir_severidade.selected_branch}}"
            },
        },
    ],
}


@override_settings(
    CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}},
    CELERY_TASK_ALWAYS_EAGER=True,
)
class PlaybookBranchingApiTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.lead = User.objects.create_user(
            username="lead_branch_api",
            password="pass",
            role=User.Roles.SOC_LEAD,
        )
        self.client.force_authenticate(self.lead)

    def test_rest_flow_validates_creates_lists_runs_and_reads_branch_execution(self):
        validate_response = self.client.post(
            "/api/v1/playbooks/validate/",
            {"dsl": BRANCHING_API_DSL},
            format="json",
        )
        self.assertEqual(validate_response.status_code, status.HTTP_200_OK)
        self.assertEqual(validate_response.data, {"valid": True})

        create_response = self.client.post(
            "/api/v1/playbooks/",
            {
                "name": "Branching API flow",
                "category": "Teste API",
                "description": "Validacao REST de control.branch.",
                "enabled": True,
                "dsl": BRANCHING_API_DSL,
            },
            format="json",
        )
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(create_response.data["mode"], "manual")
        self.assertEqual(create_response.data["type"], "incident")
        self.assertEqual(
            create_response.data["filters"],
            [{"target": "incident", "conditions": {"labels": ["branch-api"]}}],
        )
        playbook_id = create_response.data["id"]

        incident = Incident.objects.create(
            title="Branching API incident",
            description="Created as if it came from REST ingestion.",
            severity=Incident.Severity.HIGH,
            labels=["branch-api"],
            created_by=self.lead,
        )

        overview_response = self.client.get(f"/api/v1/incidents/{incident.pk}/playbooks/")
        self.assertEqual(overview_response.status_code, status.HTTP_200_OK)
        available_ids = {item["id"] for item in overview_response.data["available"]}
        self.assertIn(playbook_id, available_ids)

        run_response = self.client.post(
            f"/api/v1/incidents/{incident.pk}/run_playbook/",
            {"playbook_id": playbook_id},
            format="json",
        )
        self.assertEqual(run_response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(run_response.data["status"], "SUCCEEDED")
        execution_id = run_response.data["id"]

        step_results = {
            item["step_name"]: item
            for item in run_response.data["step_results"]
        }
        branch_result = step_results["decidir_severidade"]["result"]
        self.assertEqual(branch_result["selected_branch"], "high")
        self.assertTrue(branch_result["matched"])
        self.assertFalse(branch_result["used_default"])
        self.assertEqual(branch_result["evaluated_branches"], ["critical", "high"])
        self.assertEqual(branch_result["executed_steps"], ["note_high"])
        self.assertIn("note_high", step_results)
        self.assertIn("registrar_branch", step_results)

        status_response = self.client.get(
            f"/api/v1/incidents/{incident.pk}/playbooks/{execution_id}/status/"
        )
        self.assertEqual(status_response.status_code, status.HTTP_200_OK)
        self.assertEqual(status_response.data["status"], "SUCCEEDED")
        status_steps = {
            item["step_name"]: item
            for item in status_response.data["step_results"]
        }
        self.assertEqual(
            status_steps["decidir_severidade"]["result"]["selected_branch"],
            "high",
        )
        self.assertTrue(
            TimelineEntry.objects.filter(
                incident=incident,
                message="REST branch selecionado: high",
            ).exists()
        )
