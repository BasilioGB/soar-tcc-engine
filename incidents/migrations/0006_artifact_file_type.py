from django.db import migrations, models


def set_file_type(apps, schema_editor):
    Artifact = apps.get_model("incidents", "Artifact")
    Artifact.objects.filter(file__isnull=False, type="OTHER").update(type="FILE")


def revert_file_type(apps, schema_editor):
    Artifact = apps.get_model("incidents", "Artifact")
    Artifact.objects.filter(type="FILE").update(type="OTHER")


class Migration(migrations.Migration):
    dependencies = [
        ("incidents", "0005_artifact_global_links"),
    ]

    operations = [
        migrations.AlterField(
            model_name="artifact",
            name="type",
            field=models.CharField(
                choices=[
                    ("IP", "IP"),
                    ("DOMAIN", "Domain"),
                    ("URL", "URL"),
                    ("EMAIL", "Email"),
                    ("HASH", "Hash"),
                    ("FILE", "File"),
                    ("OTHER", "Other"),
                ],
                default="OTHER",
                max_length=16,
            ),
        ),
        migrations.RunPython(set_file_type, revert_file_type),
    ]

