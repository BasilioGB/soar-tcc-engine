from django.db import migrations, models
import django.utils.timezone


def set_default_detected(apps, schema_editor):
    Incident = apps.get_model("incidents", "Incident")
    for incident in Incident.objects.filter(detected_at__isnull=True):
        incident.detected_at = incident.created_at or django.utils.timezone.now()
        incident.save(update_fields=["detected_at"])


class Migration(migrations.Migration):
    dependencies = [
        ("incidents", "0006_artifact_file_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="incident",
            name="closed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="incident",
            name="detected_at",
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now, null=True),
        ),
        migrations.AddField(
            model_name="incident",
            name="occurred_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="incident",
            name="responded_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="incident",
            name="resolved_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.RunPython(set_default_detected, migrations.RunPython.noop),
    ]

