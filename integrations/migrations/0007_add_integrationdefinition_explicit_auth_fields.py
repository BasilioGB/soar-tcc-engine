from django.db import migrations, models


def reset_connectors(apps, schema_editor):
    IntegrationDefinition = apps.get_model("integrations", "IntegrationDefinition")
    IntegrationDefinition.objects.all().delete()


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("integrations", "0006_remove_integrationdefinition_auth_type_and_more"),
    ]

    operations = [
        migrations.RunPython(reset_connectors, migrations.RunPython.noop),
        migrations.AddField(
            model_name="integrationdefinition",
            name="auth_basic_username",
            field=models.CharField(blank=True, default="", max_length=128),
        ),
        migrations.AddField(
            model_name="integrationdefinition",
            name="auth_header_name",
            field=models.CharField(blank=True, default="Authorization", max_length=128),
        ),
        migrations.AddField(
            model_name="integrationdefinition",
            name="auth_prefix",
            field=models.CharField(blank=True, default="Bearer", max_length=64),
        ),
        migrations.AddField(
            model_name="integrationdefinition",
            name="auth_query_param",
            field=models.CharField(blank=True, default="api_key", max_length=64),
        ),
        migrations.AddField(
            model_name="integrationdefinition",
            name="auth_strategy",
            field=models.CharField(
                choices=[
                    ("bearer_header", "Bearer Header"),
                    ("header", "Header"),
                    ("query_param", "Query Param"),
                    ("basic", "Basic Auth"),
                ],
                default="bearer_header",
                max_length=32,
            ),
        ),
    ]
