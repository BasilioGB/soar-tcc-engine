from django.db import migrations, models
import django.db.models.deletion


def reset_connectors(apps, schema_editor):
    IntegrationDefinition = apps.get_model("integrations", "IntegrationDefinition")
    IntegrationDefinition.objects.all().delete()


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("integrations", "0005_remove_integrationdefinition_response_mapping"),
    ]

    operations = [
        migrations.RunPython(reset_connectors, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name="integrationdefinition",
            name="auth_type",
        ),
        migrations.AlterField(
            model_name="integrationdefinition",
            name="secret_ref",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="http_connectors",
                to="integrations.integrationsecretref",
            ),
        ),
    ]
