from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("integrations", "0008_rework_http_connector_secrets_as_credentials"),
    ]

    operations = [
        migrations.AddField(
            model_name="integrationdefinition",
            name="output_template",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
