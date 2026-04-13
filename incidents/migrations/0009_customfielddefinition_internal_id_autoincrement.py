from django.db import migrations, models


def migrate_custom_field_internal_ids(apps, schema_editor):
    definition_model = apps.get_model("incidents", "CustomFieldDefinition")
    incident_model = apps.get_model("incidents", "Incident")
    db_alias = schema_editor.connection.alias

    definitions = list(
        definition_model.objects.using(db_alias).order_by("id").values("id", "internal_id")
    )

    old_to_new_key: dict[str, str] = {}
    next_internal_id = 1
    for definition in definitions:
        definition_model.objects.using(db_alias).filter(pk=definition["id"]).update(
            internal_id_int=next_internal_id
        )
        old_value = definition.get("internal_id")
        if old_value is not None:
            old_to_new_key[str(old_value)] = str(next_internal_id)
        next_internal_id += 1

    for incident in incident_model.objects.using(db_alias).all().only("id", "custom_fields").iterator():
        stored = incident.custom_fields or {}
        if not isinstance(stored, dict):
            continue
        updated: dict[str, object] = {}
        changed = False
        for raw_key, value in stored.items():
            key = str(raw_key)
            mapped_key = old_to_new_key.get(key)
            if mapped_key is not None:
                updated[mapped_key] = value
                if mapped_key != key:
                    changed = True
                continue
            if key.isdigit() and int(key) > 0:
                normalized_numeric_key = str(int(key))
                updated[normalized_numeric_key] = value
                if normalized_numeric_key != key:
                    changed = True
                continue
            changed = True
        if changed or updated != stored:
            incident.custom_fields = updated
            incident.save(update_fields=["custom_fields"])


class Migration(migrations.Migration):
    dependencies = [
        ("incidents", "0008_incident_custom_fields_customfielddefinition"),
    ]

    operations = [
        migrations.AddField(
            model_name="customfielddefinition",
            name="internal_id_int",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.RunPython(
            migrate_custom_field_internal_ids,
            migrations.RunPython.noop,
        ),
        migrations.RemoveField(
            model_name="customfielddefinition",
            name="internal_id",
        ),
        migrations.RenameField(
            model_name="customfielddefinition",
            old_name="internal_id_int",
            new_name="internal_id",
        ),
        migrations.AlterField(
            model_name="customfielddefinition",
            name="internal_id",
            field=models.PositiveIntegerField(editable=False, unique=True),
        ),
    ]
