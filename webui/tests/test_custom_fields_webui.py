from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from incidents.models import CustomFieldDefinition, Incident


class WebUICustomFieldsTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(
            username="analyst_custom_fields_ui",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        self.lead = User.objects.create_user(
            username="lead_custom_fields_ui",
            password="pass",
            role=User.Roles.SOC_LEAD,
        )
        self.definition = CustomFieldDefinition.objects.create(
            display_name="Asset Owner",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            is_active=True,
            created_by=self.lead,
            updated_by=self.lead,
        )
        self.incident = Incident.objects.create(
            title="Custom field cleanup",
            created_by=self.lead,
            custom_fields={str(self.definition.internal_id): "alice"},
        )

    def test_soc_lead_can_manage_custom_fields(self):
        self.client.force_login(self.lead)

        list_response = self.client.get(reverse("webui:custom_field_list"))
        self.assertEqual(list_response.status_code, 200)

        create_response = self.client.post(
            reverse("webui:custom_field_create"),
            {
                "display_name": "Asset Priority",
                "field_type": CustomFieldDefinition.FieldType.INTEGER,
                "is_active": "on",
            },
        )
        self.assertEqual(create_response.status_code, 302)
        created = CustomFieldDefinition.objects.get(display_name="Asset Priority")
        self.assertGreater(created.internal_id, 0)
        self.assertEqual(created.created_by, self.lead)
        self.assertEqual(created.updated_by, self.lead)

        edit_response = self.client.post(
            reverse("webui:custom_field_edit", args=[self.definition.id]),
            {
                "display_name": "Asset Owner Updated",
            },
        )
        self.assertEqual(edit_response.status_code, 302)
        self.definition.refresh_from_db()
        self.assertEqual(self.definition.display_name, "Asset Owner Updated")
        self.assertFalse(self.definition.is_active)

        delete_response = self.client.post(reverse("webui:custom_field_delete", args=[self.definition.id]))
        self.assertEqual(delete_response.status_code, 302)
        self.definition.refresh_from_db()
        self.incident.refresh_from_db()
        self.assertTrue(self.definition.is_deleted)
        self.assertFalse(self.definition.is_active)
        self.assertNotIn(str(self.definition.internal_id), self.incident.custom_fields)

    def test_soc_analyst_cannot_manage_custom_fields(self):
        self.client.force_login(self.analyst)

        get_responses = [
            self.client.get(reverse("webui:custom_field_list"), follow=True),
            self.client.get(reverse("webui:custom_field_create"), follow=True),
            self.client.get(reverse("webui:custom_field_edit", args=[self.definition.id]), follow=True),
        ]

        for response in get_responses:
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.request["PATH_INFO"], reverse("webui:dashboard"))
            self.assertContains(response, "Voce nao tem permissao para acessar esta pagina.")

        delete_response = self.client.post(reverse("webui:custom_field_delete", args=[self.definition.id]))
        self.assertEqual(delete_response.status_code, 403)
