from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from incidents.models import CustomFieldDefinition


class CustomFieldDefinitionModelTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="lead", password="pass", role=User.Roles.SOC_LEAD)

    def test_internal_id_is_auto_generated_incremental(self):
        first = CustomFieldDefinition.objects.create(
            display_name="Asset Owner",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            created_by=self.user,
            updated_by=self.user,
        )
        second = CustomFieldDefinition.objects.create(
            display_name="Asset Priority",
            field_type=CustomFieldDefinition.FieldType.INTEGER,
            created_by=self.user,
            updated_by=self.user,
        )
        self.assertGreater(first.internal_id, 0)
        self.assertEqual(second.internal_id, first.internal_id + 1)

    def test_can_update_display_name(self):
        definition = CustomFieldDefinition.objects.create(
            display_name="Asset Owner",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            created_by=self.user,
            updated_by=self.user,
        )
        definition.display_name = "Owner"
        definition.updated_by = self.user
        definition.save()
        definition.refresh_from_db()
        self.assertEqual(definition.display_name, "Owner")

    def test_internal_id_cannot_be_changed(self):
        definition = CustomFieldDefinition.objects.create(
            display_name="Asset Owner",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            created_by=self.user,
            updated_by=self.user,
        )
        definition.internal_id = definition.internal_id + 1
        with self.assertRaises(ValidationError):
            definition.save()

    def test_field_type_cannot_be_changed(self):
        definition = CustomFieldDefinition.objects.create(
            display_name="Asset Owner",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            created_by=self.user,
            updated_by=self.user,
        )
        definition.field_type = CustomFieldDefinition.FieldType.INTEGER
        with self.assertRaises(ValidationError):
            definition.save()

    def test_api_name_is_auto_generated_when_missing(self):
        definition = CustomFieldDefinition.objects.create(
            display_name="Vendas Afetadas",
            field_type=CustomFieldDefinition.FieldType.INTEGER,
            created_by=self.user,
            updated_by=self.user,
        )
        self.assertEqual(definition.api_name, "vendas_afetadas")

    def test_api_name_can_be_informed_at_creation(self):
        definition = CustomFieldDefinition.objects.create(
            display_name="Asset Owner",
            api_name="owner_api",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            created_by=self.user,
            updated_by=self.user,
        )
        self.assertEqual(definition.api_name, "owner_api")

    def test_api_name_cannot_be_changed_after_creation(self):
        definition = CustomFieldDefinition.objects.create(
            display_name="Asset Owner",
            field_type=CustomFieldDefinition.FieldType.TEXT,
            created_by=self.user,
            updated_by=self.user,
        )
        definition.api_name = "novo_nome_api"
        with self.assertRaises(ValidationError):
            definition.save()
