from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("incidents", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Playbook",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=255, unique=True)),
                ("description", models.TextField(blank=True)),
                ("enabled", models.BooleanField(default=True)),
                ("dsl", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="playbooks_created", to=settings.AUTH_USER_MODEL)),
                ("updated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="playbooks_updated", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="PlaybookStep",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=128)),
                ("action", models.CharField(max_length=128)),
                ("order", models.PositiveIntegerField(default=0)),
                ("config", models.JSONField(blank=True, default=dict)),
                ("playbook", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="step_definitions", to="playbooks.playbook")),
            ],
            options={"ordering": ["order"], "unique_together": {("playbook", "name")}},
        ),
        migrations.CreateModel(
            name="Execution",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(choices=[("PENDING", "Pending"), ("RUNNING", "Running"), ("SUCCEEDED", "Succeeded"), ("FAILED", "Failed")], default="PENDING", max_length=16)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="executions_started", to=settings.AUTH_USER_MODEL)),
                ("incident", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="executions", to="incidents.incident")),
                ("playbook", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="executions", to="playbooks.playbook")),
            ],
            options={"ordering": ["-started_at", "-id"]},
        ),
        migrations.CreateModel(
            name="ExecutionLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("ts", models.DateTimeField(default=django.utils.timezone.now)),
                ("level", models.CharField(choices=[("INFO", "Info"), ("WARNING", "Warning"), ("ERROR", "Error")], default="INFO", max_length=16)),
                ("message", models.TextField()),
                ("step_name", models.CharField(blank=True, max_length=128)),
                ("execution", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="logs", to="playbooks.execution")),
            ],
            options={"ordering": ["ts", "id"]},
        ),
    ]
