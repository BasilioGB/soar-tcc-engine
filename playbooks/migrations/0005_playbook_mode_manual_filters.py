from __future__ import annotations





from django.db import migrations, models








def populate_playbook_mode(apps, schema_editor):


    Playbook = apps.get_model("playbooks", "Playbook")


    try:


        from playbooks.dsl import parse_playbook


    except Exception:  # pragma: no cover


        return


    for playbook in Playbook.objects.all():


        try:


            parsed = parse_playbook(playbook.dsl)


        except Exception:


            continue


        playbook.mode = parsed.mode.value


        if isinstance(playbook.dsl, dict):


            playbook.dsl["mode"] = parsed.mode.value


        playbook.save(update_fields=["mode", "dsl"])








def populate_manual_filters(apps, schema_editor):


    Playbook = apps.get_model("playbooks", "Playbook")


    PlaybookFilter = apps.get_model("playbooks", "PlaybookFilter")


    try:


        from playbooks.dsl import parse_playbook


    except Exception:  # pragma: no cover


        return


    for playbook in Playbook.objects.filter(mode="manual"):


        try:


            parsed = parse_playbook(playbook.dsl)


        except Exception:


            continue


        filters = [


            PlaybookFilter(


                playbook=playbook,


                target=manual_filter.target.value,


                conditions=manual_filter.conditions or {},


            )


            for manual_filter in parsed.filters


        ]


        if filters:


            PlaybookFilter.objects.bulk_create(filters, ignore_conflicts=True)








class Migration(migrations.Migration):





    dependencies = [


        ("playbooks", "0004_execution_context"),


    ]





    operations = [


        migrations.AddField(


            model_name="playbook",


            name="mode",


            field=models.CharField(choices=[("automatic", "Automatico"), ("manual", "Manual")], default="automatic", max_length=32),


        ),


        migrations.CreateModel(


            name="PlaybookFilter",


            fields=[


                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),


                ("target", models.CharField(choices=[("incident", "Incidente"), ("artifact", "Artefato")], max_length=32)),


                ("conditions", models.JSONField(blank=True, default=dict)),


                ("created_at", models.DateTimeField(auto_now_add=True)),


                ("updated_at", models.DateTimeField(auto_now=True)),


                ("playbook", models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="filter_entries", to="playbooks.playbook")),


            ],


        ),


        migrations.AddIndex(


            model_name="playbookfilter",


            index=models.Index(fields=["target"], name="playbookfilter_target_idx"),


        ),


        migrations.AddIndex(


            model_name="playbookfilter",


            index=models.Index(fields=["playbook", "target"], name="playbookfilter_playbook_target_idx"),


        ),


        migrations.RunPython(populate_playbook_mode, migrations.RunPython.noop),


        migrations.RunPython(populate_manual_filters, migrations.RunPython.noop),


    ]


