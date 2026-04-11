from __future__ import annotations

from django.db import migrations


def relax_domain_manual_review_filter(apps, schema_editor):
    Playbook = apps.get_model("playbooks", "Playbook")
    for playbook in Playbook.objects.filter(name="Domain manual review"):
        dsl = playbook.dsl or {}
        filters = dsl.get("filters") or []
        updated_filters = []
        changed = False
        if not filters:
            updated_filters = [{"target": "artifact", "conditions": {"type": ["DOMAIN"]}}]
            changed = True
        else:
            for entry in filters:
                if entry.get("target") == "artifact":
                    conditions = entry.get("conditions") or {}
                    if (
                        "incident_labels" in conditions
                        or "attribute_equals" in conditions
                        or conditions.get("type") != ["DOMAIN"]
                    ):
                        conditions.pop("incident_labels", None)
                        conditions.pop("attribute_equals", None)
                        conditions["type"] = ["DOMAIN"]
                        entry["conditions"] = conditions
                        changed = True
                updated_filters.append(entry)
        if changed:
            dsl["filters"] = updated_filters
            playbook.dsl = dsl
            playbook.save(update_fields=["dsl", "updated_at"])


class Migration(migrations.Migration):

    dependencies = [
        ("playbooks", "0006_rename_playbookfilter_target_idx_playbooks_p_target_bd82b6_idx_and_more"),
    ]

    operations = [
        migrations.RunPython(relax_domain_manual_review_filter, migrations.RunPython.noop),
    ]
