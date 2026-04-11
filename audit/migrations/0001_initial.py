from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("contenttypes", "0002_remove_content_type_name"),
    ]

    operations = [
        migrations.CreateModel(
            name="ActionLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("verb", models.CharField(max_length=128)),
                ("timestamp", models.DateTimeField(default=django.utils.timezone.now)),
                ("target_object_id", models.CharField(blank=True, max_length=64, null=True)),
                ("meta", models.JSONField(blank=True, default=dict)),
                ("actor", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="audit_logs", to=settings.AUTH_USER_MODEL)),
                ("target_content_type", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="contenttypes.contenttype")),
            ],
            options={
                "ordering": ["-timestamp"],
            },
        ),
        migrations.AddIndex(
            model_name="actionlog",
            index=models.Index(fields=["verb"], name="audit_action_verb_idx"),
        ),
        migrations.AddIndex(
            model_name="actionlog",
            index=models.Index(fields=["timestamp"], name="audit_action_ts_idx"),
        ),
    ]
