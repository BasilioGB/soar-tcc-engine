from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("playbooks", "0009_rename_playbooks_e_executi_6b2d94_idx_playbooks_e_executi_84a5e1_idx_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="playbook",
            name="category",
            field=models.CharField(db_index=True, default="Geral", max_length=64),
        ),
    ]
