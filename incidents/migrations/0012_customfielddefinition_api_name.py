from __future__ import annotations

import re

from django.db import migrations, models
from django.utils.text import slugify


def _normalize_api_name(raw_value: str | None) -> str:
    base = slugify(raw_value or "", allow_unicode=False).replace("-", "_")
    base = re.sub(r"[^a-z0-9_]", "", base.lower())
    base = re.sub(r"_+", "_", base).strip("_")
    return base


def populate_api_names(apps, schema_editor):
    model = apps.get_model("incidents", "CustomFieldDefinition")
    used_names: set[str] = set()

    for definition in model.objects.using(schema_editor.connection.alias).all().order_by("id"):
        raw_name = (getattr(definition, "api_name", "") or "").strip() or definition.display_name
        base = _normalize_api_name(raw_name) or "custom_field"
        candidate = base
        suffix = 2
        while candidate in used_names:
            candidate = f"{base}_{suffix}"
            suffix += 1
        definition.api_name = candidate
        definition.save(update_fields=["api_name"])
        used_names.add(candidate)


class Migration(migrations.Migration):
    dependencies = [
        ("incidents", "0011_incident_secondary_assignees"),
    ]

    operations = [
        migrations.AddField(
            model_name="customfielddefinition",
            name="api_name",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.RunPython(populate_api_names, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="customfielddefinition",
            name="api_name",
            field=models.CharField(blank=True, max_length=128, unique=True),
        ),
    ]

