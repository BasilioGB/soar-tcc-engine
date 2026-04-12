from django.db import migrations, models


def reset_connectors_and_secrets(apps, schema_editor):
    IntegrationDefinition = apps.get_model("integrations", "IntegrationDefinition")
    IntegrationSecretRef = apps.get_model("integrations", "IntegrationSecretRef")
    IntegrationDefinition.objects.all().delete()
    IntegrationSecretRef.objects.all().delete()


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("integrations", "0007_add_integrationdefinition_explicit_auth_fields"),
    ]

    operations = [
        migrations.RunPython(reset_connectors_and_secrets, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name="integrationdefinition",
            name="auth_basic_username",
        ),
        migrations.RemoveField(
            model_name="integrationsecretref",
            name="secret_value_encrypted",
        ),
        migrations.AddField(
            model_name="integrationsecretref",
            name="credential_kind",
            field=models.CharField(
                choices=[
                    ("token", "Token/API Key"),
                    ("basic_auth", "Basic Auth"),
                ],
                default="token",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="integrationsecretref",
            name="credential_payload_encrypted",
            field=models.TextField(blank=True, default="", editable=False),
        ),
    ]
