from __future__ import annotations

from django.db import migrations, models


def sync_type_from_dsl(apps, schema_editor):
    Playbook = apps.get_model("playbooks", "Playbook")
    for playbook in Playbook.objects.all():
        dsl_type = playbook.dsl.get("type") if isinstance(playbook.dsl, dict) else None
        if dsl_type not in {"incident", "artifact"}:
            dsl_type = "incident"
        playbook.type = dsl_type
        if isinstance(playbook.dsl, dict):
            playbook.dsl["type"] = dsl_type
        playbook.save(update_fields=["type", "dsl"])


class Migration(migrations.Migration):

    dependencies = [
        ("playbooks", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="playbook",
            name="type",
            field=models.CharField(
                choices=[("incident", "Incidente"), ("artifact", "Artefato")],
                default="incident",
                max_length=32,
            ),
        ),
        migrations.RunPython(sync_type_from_dsl, migrations.RunPython.noop),
    ]
