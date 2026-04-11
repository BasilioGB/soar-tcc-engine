from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("playbooks", "0007_relax_domain_manual_review_filter"),
    ]

    operations = [
        migrations.CreateModel(
            name="ExecutionStepResult",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("step_name", models.CharField(max_length=128)),
                ("step_order", models.PositiveIntegerField()),
                ("status", models.CharField(choices=[("SUCCEEDED", "Succeeded"), ("FAILED", "Failed"), ("SKIPPED", "Skipped")], max_length=16)),
                ("started_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("finished_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("duration_ms", models.PositiveIntegerField(default=0)),
                ("resolved_input", models.JSONField(blank=True, default=dict)),
                ("result", models.JSONField(blank=True, null=True)),
                ("error_class", models.CharField(blank=True, max_length=128)),
                ("error_message", models.TextField(blank=True)),
                ("skipped_reason", models.CharField(blank=True, max_length=64)),
                ("execution", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="step_results", to="playbooks.execution")),
            ],
            options={
                "ordering": ["step_order", "id"],
            },
        ),
        migrations.AddIndex(
            model_name="executionstepresult",
            index=models.Index(fields=["execution", "step_order"], name="playbooks_e_executi_6b2d94_idx"),
        ),
        migrations.AddIndex(
            model_name="executionstepresult",
            index=models.Index(fields=["execution", "step_name"], name="playbooks_e_executi_8be7f1_idx"),
        ),
        migrations.AddIndex(
            model_name="executionstepresult",
            index=models.Index(fields=["status"], name="playbooks_e_status_3af7dd_idx"),
        ),
    ]
