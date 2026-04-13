from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from incidents.models import CustomFieldDefinition, Incident
from playbooks.models import Playbook


class IncidentCustomFieldsApiTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="analyst", password="pass", role=User.Roles.SOC_ANALYST)
        self.lead = User.objects.create_user(username="lead", password="pass", role=User.Roles.SOC_LEAD)
        self.client.force_authenticate(self.user)
        self.incident = Incident.objects.create(title="Malware", description="Execucao suspeita", created_by=self.user)
        self.active_definition = CustomFieldDefinition.objects.create(
            display_name="Asset Owner",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            is_active=True,
            created_by=self.lead,
            updated_by=self.lead,
        )
        self.inactive_definition = CustomFieldDefinition.objects.create(
            display_name="Legacy Code",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            is_active=False,
            created_by=self.lead,
            updated_by=self.lead,
        )
        self.active_key = str(self.active_definition.internal_id)
        self.inactive_key = str(self.inactive_definition.internal_id)

    def test_incident_response_returns_only_active_custom_fields(self):
        self.incident.custom_fields = {
            self.active_key: "Alice",
            self.inactive_key: "LEG-001",
            "removed_field": "should not show",
        }
        self.incident.save(update_fields=["custom_fields"])

        response = self.client.get(f"/api/v1/incidents/{self.incident.id}/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["custom_fields"], {self.active_key: "Alice"})

    def test_patch_reconciles_removed_definition_keys(self):
        self.incident.custom_fields = {
            self.active_key: "Alice",
            self.inactive_key: "LEG-001",
            "removed_field": "old",
        }
        self.incident.save(update_fields=["custom_fields"])

        response = self.client.patch(f"/api/v1/incidents/{self.incident.id}/", {"title": "Updated"}, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.incident.refresh_from_db()
        self.assertNotIn("removed_field", self.incident.custom_fields)
        self.assertIn(self.inactive_key, self.incident.custom_fields)

    def test_patch_validates_type_for_custom_field(self):
        attempts_definition = CustomFieldDefinition.objects.create(
            display_name="Attempts",
            field_type=CustomFieldDefinition.FieldType.INTEGER,
            is_active=True,
            created_by=self.lead,
            updated_by=self.lead,
        )
        attempts_key = str(attempts_definition.internal_id)

        invalid = self.client.patch(
            f"/api/v1/incidents/{self.incident.id}/",
            {"custom_fields": {attempts_key: "3"}},
            format="json",
        )
        self.assertEqual(invalid.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("custom_fields", invalid.data)

        valid = self.client.patch(
            f"/api/v1/incidents/{self.incident.id}/",
            {"custom_fields": {attempts_key: 3}},
            format="json",
        )
        self.assertEqual(valid.status_code, status.HTTP_200_OK)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.custom_fields.get(attempts_key), 3)

    def test_soft_delete_definition_removes_values_from_incidents(self):
        self.incident.custom_fields = {self.active_key: "Alice"}
        self.incident.save(update_fields=["custom_fields"])
        self.client.force_authenticate(self.lead)

        response = self.client.delete(f"/api/v1/custom-field-definitions/{self.active_definition.id}/")

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.active_definition.refresh_from_db()
        self.assertTrue(self.active_definition.is_deleted)
        self.assertFalse(self.active_definition.is_active)
        self.incident.refresh_from_db()
        self.assertNotIn(self.active_key, self.incident.custom_fields)

    def test_create_definition_auto_generates_api_name(self):
        self.client.force_authenticate(self.lead)

        response = self.client.post(
            "/api/v1/custom-field-definitions/",
            {
                "display_name": "Vendas Afetadas",
                "field_type": CustomFieldDefinition.FieldType.INTEGER,
                "is_active": True,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        created = CustomFieldDefinition.objects.get(id=response.data["id"])
        self.assertEqual(created.api_name, "vendas_afetadas")

    def test_delete_definition_is_blocked_when_referenced_by_playbook(self):
        self.client.force_authenticate(self.lead)
        Playbook.objects.create(
            name="Playbook with custom field reference",
            enabled=True,
            created_by=self.lead,
            dsl={
                "name": "Playbook with custom field reference",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "note",
                        "action": "incident.add_note",
                        "input": {"message": f"Owner: {{{{incident.custom_fields.{self.active_definition.api_name}}}}}"},
                    }
                ],
            },
        )

        response = self.client.delete(f"/api/v1/custom-field-definitions/{self.active_definition.id}/")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.active_definition.refresh_from_db()
        self.assertFalse(self.active_definition.is_deleted)
