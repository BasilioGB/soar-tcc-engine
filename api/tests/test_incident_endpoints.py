from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from incidents.models import Incident, TimelineEntry
from incidents.services import create_task


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
