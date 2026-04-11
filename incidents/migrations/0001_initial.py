from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Incident",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("severity", models.CharField(choices=[("LOW", "Low"), ("MEDIUM", "Medium"), ("HIGH", "High"), ("CRITICAL", "Critical")], default="MEDIUM", max_length=16)),
                ("status", models.CharField(choices=[("NEW", "New"), ("IN_PROGRESS", "In progress"), ("CONTAINED", "Contained"), ("RESOLVED", "Resolved"), ("CLOSED", "Closed")], default="NEW", max_length=16)),
                ("labels", models.JSONField(blank=True, default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("assignee", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="incidents_assigned", to=settings.AUTH_USER_MODEL)),
                ("created_by", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="incidents_created", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="TimelineEntry",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("entry_type", models.CharField(choices=[("NOTE", "Note"), ("STATUS_UPDATE", "Status Update"), ("LABEL_ADDED", "Label Added"), ("PLAYBOOK_EXECUTION", "Playbook Execution")], default="NOTE", max_length=32)),
                ("message", models.TextField()),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="timeline_entries", to=settings.AUTH_USER_MODEL)),
                ("incident", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="timeline", to="incidents.incident")),
            ],
            options={
                "ordering": ["created_at"],
            },
        ),
        migrations.CreateModel(
            name="Artifact",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("type", models.CharField(choices=[("IP", "IP"), ("DOMAIN", "Domain"), ("URL", "URL"), ("EMAIL", "Email"), ("HASH", "Hash"), ("OTHER", "Other")], default="OTHER", max_length=16)),
                ("value", models.CharField(max_length=512)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("incident", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="artifacts", to="incidents.incident")),
            ],
            options={
                "ordering": ["created_at"],
                "unique_together": {("incident", "type", "value")},
            },
        ),
    ]
