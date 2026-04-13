from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from incidents.models import CustomFieldDefinition, Incident


class IncidentCustomFieldsWebUITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="incident_custom_fields_user",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        self.client.force_login(self.user)
        self.definition_text = CustomFieldDefinition.objects.create(
            display_name="Asset Owner",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            is_active=True,
            created_by=self.user,
            updated_by=self.user,
        )
        self.definition_int = CustomFieldDefinition.objects.create(
            display_name="Attempts",
            field_type=CustomFieldDefinition.FieldType.INTEGER,
            is_active=True,
            created_by=self.user,
            updated_by=self.user,
        )
        self.definition_inactive = CustomFieldDefinition.objects.create(
            display_name="Legacy Field",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            is_active=False,
            created_by=self.user,
            updated_by=self.user,
        )
        self.incident = Incident.objects.create(
            title="Incident with custom fields",
            created_by=self.user,
            custom_fields={
                str(self.definition_text.internal_id): "alice",
                str(self.definition_int.internal_id): 2,
                str(self.definition_inactive.internal_id): "legacy-value",
                "99999": "removed-definition-value",
            },
        )

    def test_incident_detail_shows_custom_fields_tab(self):
        response = self.client.get(reverse("webui:incident_detail", kwargs={"pk": self.incident.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Campos Customizados")
        self.assertContains(response, "Asset Owner")
        self.assertContains(response, "Attempts")
        self.assertNotContains(response, "Legacy Field")
        self.assertContains(response, "Editar")
        partial_response = self.client.get(
            reverse("webui:incident_custom_fields_partial", kwargs={"pk": self.incident.pk}),
        )
        self.assertEqual(partial_response.status_code, 200)
        self.assertNotContains(partial_response, 'name="value"')

    def test_custom_field_partial_opens_single_field_in_edit_mode(self):
        response = self.client.get(
            reverse("webui:incident_custom_fields_partial", kwargs={"pk": self.incident.pk}),
            {"edit": str(self.definition_text.internal_id)},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="value"')
        self.assertContains(response, "Cancelar")

    def test_update_custom_fields_persists_valid_values_and_reconciles_removed_keys(self):
        response = self.client.post(
            reverse("webui:incident_custom_fields_update", kwargs={"pk": self.incident.pk}),
            data={
                "internal_id": str(self.definition_text.internal_id),
                "value": "bob",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.custom_fields[str(self.definition_text.internal_id)], "bob")
        self.assertEqual(self.incident.custom_fields[str(self.definition_int.internal_id)], 2)
        self.assertEqual(
            self.incident.custom_fields[str(self.definition_inactive.internal_id)],
            "legacy-value",
        )
        self.assertNotIn("99999", self.incident.custom_fields)

        second_response = self.client.post(
            reverse("webui:incident_custom_fields_update", kwargs={"pk": self.incident.pk}),
            data={
                "internal_id": str(self.definition_int.internal_id),
                "value": "7",
            },
        )
        self.assertEqual(second_response.status_code, 302)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.custom_fields[str(self.definition_int.internal_id)], 7)

    def test_update_custom_fields_returns_validation_error_for_invalid_integer(self):
        response = self.client.post(
            reverse("webui:incident_custom_fields_update", kwargs={"pk": self.incident.pk}),
            data={
                "internal_id": str(self.definition_int.internal_id),
                "value": "not-a-number",
            },
            HTTP_HX_REQUEST="true",
        )

        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Informe um numero inteiro valido.", status_code=400)
