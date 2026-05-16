from django.contrib.auth import get_user_model
from django.core.management import call_command
from io import StringIO
from rest_framework import status
from rest_framework.test import APITestCase

from incidents.models import Artifact, Incident, TimelineEntry
from incidents.services import create_task
from playbooks.models import Execution
from playbooks.services import get_manual_playbooks_for_incident


class IncidentEndpointTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="apiuser", password="pass")
        self.client.force_authenticate(self.user)
        self.incident = Incident.objects.create(title="Malware", description="Execução suspeita", created_by=self.user)

    def test_update_status_endpoint(self):
        url = f"/api/v1/incidents/{self.incident.id}/status/"
        response = self.client.patch(url, {"status": Incident.Status.IN_PROGRESS}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.status, Incident.Status.IN_PROGRESS)
        self.assertEqual(
            response.data["classification"],
            Incident.Classification.UNDETERMINED,
        )

    def test_labels_endpoint(self):
        url = f"/api/v1/incidents/{self.incident.id}/labels/"
        response = self.client.patch(url, {"add": ["malware"]}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("malware", response.data["labels"])

    def test_task_creation_endpoint(self):
        url = f"/api/v1/incidents/{self.incident.id}/tasks/"
        response = self.client.post(url, {"title": "Isolar host"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Incident.objects.get(id=self.incident.id).tasks.count(), 1)

    def test_timeline_endpoint_returns_entries(self):
        create_task(incident=self.incident, title="Monitorar", owner=None, eta=None, actor=self.user)
        url = f"/api/v1/incidents/{self.incident.id}/timeline/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)

    def test_communications_endpoint(self):
        url = f"/api/v1/incidents/{self.incident.id}/communications/"
        payload = {"channel": "internal", "message": "Equipe acionada"}
        response = self.client.post(url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(self.incident.communications.count(), 1)

    def test_create_ioc_incident_via_rest_preserves_artifact_attributes(self):
        payload = {
            "title": "IOC via REST",
            "description": "Alerta REST com infraestrutura maliciosa correlacionada.",
            "severity": Incident.Severity.HIGH,
            "labels": [
                "phishing",
                "credential-compromise",
                "ioc-malicious-infrastructure",
                "auto-treatment",
            ],
            "artifacts": [
                {
                    "type": Artifact.Type.IP,
                    "value": "203.0.113.96",
                    "attributes": {
                        "siem_source": "SOC-SIEM",
                        "alert_id": "REST-IOC-001",
                        "ioc_origin": "firewall_connection",
                    },
                },
                {
                    "type": Artifact.Type.DOMAIN,
                    "value": "ioc-rest.example",
                    "attributes": {
                        "siem_source": "SOC-SIEM",
                        "alert_id": "REST-IOC-001",
                        "ioc_origin": "dns_resolution",
                    },
                },
                {
                    "type": Artifact.Type.URL,
                    "value": "https://ioc-rest.example/c2/checkin",
                    "attributes": {
                        "siem_source": "SOC-SIEM",
                        "alert_id": "REST-IOC-001",
                        "ioc_origin": "proxy_log",
                    },
                },
                {
                    "type": Artifact.Type.HASH,
                    "value": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "attributes": {
                        "siem_source": "SOC-SIEM",
                        "alert_id": "REST-IOC-001",
                        "hash_algorithm": "sha256",
                        "ioc_origin": "edr_detection",
                    },
                },
            ],
        }

        response = self.client.post("/api/v1/incidents/", payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        incident = Incident.objects.get(title="IOC via REST")
        self.assertEqual(
            set(incident.labels),
            {"phishing", "ioc-malicious-infrastructure", "auto-treatment"},
        )
        self.assertEqual(incident.artifacts.count(), 4)
        ip_artifact = incident.artifacts.get(type=Artifact.Type.IP)
        self.assertEqual(ip_artifact.attributes.get("alert_id"), "REST-IOC-001")
        self.assertEqual(ip_artifact.attributes.get("ioc_origin"), "firewall_connection")

    def test_link_artifact_endpoint_preserves_attributes(self):
        url = f"/api/v1/incidents/{self.incident.id}/artifacts/link/"
        payload = {
            "type": Artifact.Type.URL,
            "value": "https://ioc-link.example/c2",
            "attributes": {
                "siem_source": "SOC-SIEM",
                "alert_id": "REST-LINK-001",
                "ioc_origin": "proxy_log",
            },
        }

        response = self.client.post(url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        artifact = Artifact.objects.get(value="https://ioc-link.example/c2")
        self.assertEqual(artifact.attributes.get("alert_id"), "REST-LINK-001")
        self.assertEqual(response.data["attributes"]["ioc_origin"], "proxy_log")

    def test_rest_ioc_incident_triggers_automatic_playbook(self):
        call_command("seed_demo", force=True, structures_only=True, stdout=StringIO())
        payload = {
            "title": "IOC REST automatico",
            "description": "Alerta REST deve acionar resposta automatizada de IOC.",
            "severity": Incident.Severity.HIGH,
            "labels": ["ioc-malicious-infrastructure", "auto-treatment"],
            "artifacts": [
                {
                    "type": Artifact.Type.IP,
                    "value": "203.0.113.120",
                    "attributes": {"alert_id": "REST-IOC-AUTO-002", "ioc_origin": "firewall_connection"},
                },
                {
                    "type": Artifact.Type.DOMAIN,
                    "value": "ioc-auto-rest.example",
                    "attributes": {"alert_id": "REST-IOC-AUTO-002", "ioc_origin": "dns_resolution"},
                },
            ],
        }

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post("/api/v1/incidents/", payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        incident = Incident.objects.get(title="IOC REST automatico")
        execution = Execution.objects.get(
            incident=incident,
            playbook__name="IOC malicious infrastructure response",
        )
        self.assertEqual(execution.status, Execution.Status.SUCCEEDED)
        self.assertTrue(
            incident.tasks.filter(title__icontains="Validar reputacao e origem do IOC").exists()
        )
        self.assertTrue(
            incident.tasks.filter(title__icontains="Bloquear IP, dominio, URL e hash").exists()
        )

    def test_rest_manual_ioc_incident_blocks_automatic_and_exposes_manual_playbook(self):
        call_command("seed_demo", force=True, structures_only=True, stdout=StringIO())
        payload = {
            "title": "IOC REST manual",
            "description": "Alerta REST deve ficar disponivel para checklist manual de IOC.",
            "severity": Incident.Severity.HIGH,
            "labels": ["ioc-malicious-infrastructure", "manual-treatment"],
            "artifacts": [
                {
                    "type": Artifact.Type.URL,
                    "value": "https://ioc-manual-rest.example/c2",
                    "attributes": {"alert_id": "REST-IOC-MANUAL-002", "ioc_origin": "proxy_log"},
                },
            ],
        }

        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post("/api/v1/incidents/", payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        incident = Incident.objects.get(title="IOC REST manual")
        self.assertFalse(
            Execution.objects.filter(
                incident=incident,
                playbook__name="IOC malicious infrastructure response",
            ).exists()
        )
        manual_names = {playbook.name for playbook in get_manual_playbooks_for_incident(incident)}
        self.assertIn("IOC malicious infrastructure manual checklist", manual_names)
