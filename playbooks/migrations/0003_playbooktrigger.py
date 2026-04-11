from __future__ import annotations

from django.db import migrations, models

def populate_triggers(apps, schema_editor):
    Playbook = apps.get_model("playbooks", "Playbook")
    PlaybookTrigger = apps.get_model("playbooks", "PlaybookTrigger")
    try:
        from playbooks.dsl import parse_playbook
    except Exception:  # pragma: no cover
        return

    for playbook in Playbook.objects.all():
        try:
            parsed = parse_playbook(playbook.dsl)
        except Exception:  # noqa: BLE001
            continue
        triggers = [
            PlaybookTrigger(
                playbook=playbook,
                event=trigger.event,
                filters=trigger.filters or {},
            )
            for trigger in parsed.triggers
        ]
        if triggers:
            PlaybookTrigger.objects.bulk_create(triggers, ignore_conflicts=True)




class Migration(migrations.Migration):

    dependencies = [
        ("playbooks", "0002_add_playbook_type"),
    ]

    operations = [
        migrations.CreateModel(
            name="PlaybookTrigger",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event", models.CharField(choices=[("incident.created", "Incidente criado"), ("incident.updated", "Incidente atualizado"), ("artifact.created", "Artefato criado")], max_length=64)),
                ("filters", models.JSONField(blank=True, default=dict)),
                ("active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("playbook", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="trigger_entries", to="playbooks.playbook")),
            ],
        ),
        migrations.AddIndex(
            model_name="playbooktrigger",
            index=models.Index(fields=["event"], name="playbooktr_event_d70721_idx"),
        ),
        migrations.AddIndex(
            model_name="playbooktrigger",
            index=models.Index(fields=["playbook", "event"], name="playbooktr_playboo_2066a2_idx"),
        ),
        migrations.RunPython(populate_triggers, migrations.RunPython.noop),
    ]
