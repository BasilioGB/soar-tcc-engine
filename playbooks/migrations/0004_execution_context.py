from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("playbooks", "0003_playbooktrigger"),
    ]

    operations = [
        migrations.AddField(
            model_name="execution",
            name="context",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
