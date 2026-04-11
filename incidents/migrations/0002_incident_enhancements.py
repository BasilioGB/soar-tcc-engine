from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("incidents", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="incident",
            name="business_unit",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name="incident",
            name="data_classification",
            field=models.CharField(
                choices=[
                    ("public", "Public"),
                    ("internal", "Internal"),
                    ("confidential", "Confidential"),
                    ("restricted", "Restricted"),
                ],
                default="internal",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="incident",
            name="escalation_level",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AddField(
            model_name="incident",
            name="escalation_targets",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="incident",
            name="estimated_cost",
            field=models.DecimalField(decimal_places=2, default=0, max_digits=12),
        ),
        migrations.AddField(
            model_name="incident",
            name="impact_systems",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="incident",
            name="kill_chain_phase",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="incident",
            name="mitre_tactics",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="incident",
            name="mitre_techniques",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="incident",
            name="risk_score",
            field=models.PositiveIntegerField(
                default=0,
                validators=[MinValueValidator(0), MaxValueValidator(100)],
            ),
        ),
        migrations.AddField(
            model_name="artifact",
            name="content_type",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name="artifact",
            name="file",
            field=models.FileField(blank=True, null=True, upload_to="artifacts/%Y/%m/%d/"),
        ),
        migrations.AddField(
            model_name="artifact",
            name="sha256",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="artifact",
            name="size",
            field=models.BigIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="artifact",
            name="value",
            field=models.CharField(blank=True, max_length=512),
        ),
        migrations.AlterField(
            model_name="timelineentry",
            name="entry_type",
            field=models.CharField(
                choices=[
                    ("NOTE", "Note"),
                    ("STATUS_CHANGED", "Status Changed"),
                    ("ASSIGNEE_CHANGED", "Assignee Changed"),
                    ("LABEL_ADDED", "Label Added"),
                    ("LABEL_REMOVED", "Label Removed"),
                    ("ARTIFACT_ADDED", "Artifact Added"),
                    ("TASK_UPDATE", "Task Update"),
                    ("ESCALATION", "Escalation"),
                    ("COMMUNICATION", "Communication"),
                    ("PLAYBOOK_EXECUTION", "Playbook Execution"),
                ],
                default="NOTE",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="timelineentry",
            name="meta",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AlterModelOptions(
            name="artifact",
            options={"ordering": ["created_at"]},
        ),
        migrations.CreateModel(
            name="IncidentTask",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=255)),
                ("eta", models.DateTimeField(blank=True, null=True)),
                ("done", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="incident_tasks_created",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("incident", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="tasks",
                    to="incidents.incident",
                )),
                ("owner", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="incident_tasks",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                "ordering": ["done", "eta", "-created_at"],
            },
        ),
        migrations.CreateModel(
            name="IncidentRelation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("relation_type", models.CharField(
                    choices=[
                        ("related", "Related"),
                        ("duplicate", "Duplicate"),
                        ("parent", "Parent"),
                        ("child", "Child"),
                    ],
                    max_length=16,
                )),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="incident_relations_created",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("from_incident", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="relations_from",
                    to="incidents.incident",
                )),
                ("to_incident", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="relations_to",
                    to="incidents.incident",
                )),
            ],
        ),
        migrations.AddConstraint(
            model_name="incidentrelation",
            constraint=models.UniqueConstraint(
                fields=("from_incident", "to_incident", "relation_type"),
                name="unique_incident_relation",
            ),
        ),
        migrations.CreateModel(
            name="CommunicationLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("channel", models.CharField(default="internal", max_length=32)),
                ("recipient_team", models.CharField(blank=True, max_length=128)),
                ("message", models.TextField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("created_by", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="communication_logs_created",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("incident", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="communications",
                    to="incidents.incident",
                )),
                ("recipient_user", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="incident_communications",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
