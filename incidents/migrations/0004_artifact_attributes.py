from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("incidents", "0003_alter_artifact_unique_together"),
    ]

    operations = [
        migrations.AddField(
            model_name="artifact",
            name="attributes",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]

