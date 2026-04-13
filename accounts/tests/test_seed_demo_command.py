from __future__ import annotations

import os
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from accounts.models import User
from incidents.models import Incident
from integrations.models import IntegrationDefinition, IntegrationSecretRef
from playbooks.models import Playbook


class SeedDemoCommandHardeningTests(TestCase):
    def test_seed_demo_requires_opt_in(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            with self.assertRaises(CommandError):
                call_command("seed_demo", stdout=StringIO())

    def test_seed_demo_accepts_force_flag(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, stdout=StringIO())
        self.assertTrue(User.objects.filter(username="admin").exists())
        self.assertTrue(IntegrationSecretRef.objects.filter(name="VIRUSTOTAL_API_KEY").exists())
        self.assertTrue(
            IntegrationDefinition.objects.filter(action_name="virustotal_config.domain_lookup").exists()
        )
        self.assertTrue(
            IntegrationDefinition.objects.filter(action_name="virustotal_config.url_report").exists()
        )
        self.assertTrue(Playbook.objects.filter(name="Credential phishing containment").exists())
        self.assertTrue(Playbook.objects.filter(name="Email evidence extraction").exists())
        self.assertTrue(Playbook.objects.filter(name="BEC financial response").exists())
        self.assertTrue(
            Playbook.objects.filter(name="Phishing triage", category="Tratamento - Phishing").exists()
        )
        self.assertTrue(Playbook.objects.filter(name="Domain manual review").exists())
        self.assertTrue(Playbook.objects.filter(name="URL manual review").exists())
        self.assertTrue(Incident.objects.filter(title="Email suspeito de phishing").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - MANUAL").exists())
        manual_compare = Incident.objects.get(title="Comparativo phishing - MANUAL")
        self.assertIn("manual-treatment", manual_compare.labels)
        url_auto = Playbook.objects.get(name="URL auto enrichment")
        url_steps = {step["name"]: step for step in url_auto.dsl.get("steps", [])}
        self.assertEqual(
            url_steps["consultar_vt"].get("when"),
            {"left": "{{results.submeter_vt.analysis_id}}", "exists": True},
        )
        self.assertEqual(
            url_steps["persistir_vt"].get("when"),
            {"left": "{{results.consultar_vt}}", "exists": True},
        )
        branch_playbooks = [
            (
                "Credential phishing containment",
                ["phishing", "credential-compromise"],
                None,
            ),
            (
                "Malware phishing containment",
                ["phishing"],
                ["malware", "malware-suspected", "attachment-execution"],
            ),
            (
                "BEC financial response",
                ["phishing"],
                ["bec", "finance-fraud", "invoice-fraud", "gift-card"],
            ),
            (
                "Mailbox compromise response",
                ["phishing"],
                ["mailbox-compromise", "account-compromise", "thread-hijack"],
            ),
        ]
        for playbook_name, expected_labels, expected_any_label in branch_playbooks:
            playbook = Playbook.objects.get(name=playbook_name)
            triggers = playbook.dsl.get("triggers", [])
            steps = playbook.dsl.get("steps", [])
            created_trigger = next(
                (trigger for trigger in triggers if trigger.get("event") == "incident.created"),
                None,
            )
            updated_trigger = next(
                (trigger for trigger in triggers if trigger.get("event") == "incident.updated"),
                None,
            )
            self.assertIsNotNone(created_trigger)
            self.assertIsNotNone(updated_trigger)
            self.assertEqual(
                updated_trigger.get("filters", {}).get("changed_fields"),
                ["labels"],
            )
            self.assertEqual(
                updated_trigger.get("filters", {}).get("labels"),
                expected_labels,
            )
            if expected_any_label is None:
                self.assertNotIn("any_label", updated_trigger.get("filters", {}))
            else:
                self.assertEqual(
                    updated_trigger.get("filters", {}).get("any_label"),
                    expected_any_label,
                )
            self.assertEqual(
                created_trigger.get("filters", {}).get("exclude_labels"),
                ["manual-treatment"],
            )
            self.assertEqual(
                updated_trigger.get("filters", {}).get("exclude_labels"),
                ["manual-treatment"],
            )
            self.assertGreater(len(steps), 0)
            self.assertEqual(steps[0].get("action"), "incident.update_status")
            self.assertEqual(steps[0].get("input", {}).get("status"), "IN_PROGRESS")

        phishing_manual = Playbook.objects.get(name="Phishing manual checklist")
        manual_filters = phishing_manual.dsl.get("filters", [])
        self.assertGreater(len(manual_filters), 0)
        first_conditions = manual_filters[0].get("conditions", {})
        self.assertEqual(first_conditions.get("labels"), ["phishing"])
        self.assertEqual(first_conditions.get("any_label"), ["manual-treatment"])

        automatic_playbooks = [
            playbook
            for playbook in Playbook.objects.filter(enabled=True)
            if (playbook.dsl or {}).get("mode") == "automatic"
        ]
        self.assertGreater(len(automatic_playbooks), 0)
        for playbook in automatic_playbooks:
            triggers = playbook.dsl.get("triggers", [])
            self.assertGreater(len(triggers), 0)
            for trigger in triggers:
                self.assertEqual(
                    trigger.get("filters", {}).get("exclude_labels"),
                    ["manual-treatment"],
                    msg=f"Playbook '{playbook.name}' sem guard de manual-treatment no trigger {trigger.get('event')}",
                )

    def test_seed_demo_structures_only_skips_incident_seed(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, structures_only=True, stdout=StringIO())

        self.assertTrue(User.objects.filter(username="admin").exists())
        self.assertTrue(IntegrationDefinition.objects.filter(action_name="virustotal_config.domain_lookup").exists())
        self.assertTrue(
            Playbook.objects.filter(name="Phishing triage", category="Tratamento - Phishing").exists()
        )
        self.assertEqual(Incident.objects.count(), 0)

    def test_seed_demo_incidents_only_skips_structure_seed(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, incidents_only=True, stdout=StringIO())

        self.assertTrue(User.objects.filter(username="admin").exists())
        self.assertTrue(Incident.objects.filter(title="Email suspeito de phishing").exists())
        self.assertFalse(IntegrationDefinition.objects.exists())
        self.assertFalse(Playbook.objects.exists())

    def test_seed_demo_phishing_comparison_only_mode(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, phishing_comparison=True, stdout=StringIO())

        self.assertTrue(User.objects.filter(username="admin").exists())
        self.assertFalse(IntegrationDefinition.objects.exists())
        self.assertFalse(Playbook.objects.exists())
        self.assertFalse(Incident.objects.filter(title="Email suspeito de phishing").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - MANUAL").exists())

        auto_incident = Incident.objects.get(title="Comparativo phishing - AUTO")
        auto_domain = auto_incident.artifacts.filter(type="DOMAIN", value="compare-auto.example").first()
        self.assertIsNotNone(auto_domain)
        self.assertEqual((auto_domain.attributes or {}).get("siem_source"), "SOC-SIEM")
        self.assertEqual((auto_domain.attributes or {}).get("alert_id"), "SIM-PHISH-AUTO-001")

    def test_seed_demo_rejects_conflicting_modes(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            with self.assertRaises(CommandError):
                call_command("seed_demo", force=True, structures_only=True, incidents_only=True, stdout=StringIO())
            with self.assertRaises(CommandError):
                call_command("seed_demo", force=True, structures_only=True, phishing_comparison=True, stdout=StringIO())

    def test_seed_wrapper_commands(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_structures", force=True, stdout=StringIO())

        self.assertTrue(
            Playbook.objects.filter(name="Phishing triage", category="Tratamento - Phishing").exists()
        )
        self.assertFalse(Incident.objects.exists())

        Incident.objects.all().delete()
        Playbook.objects.all().delete()
        IntegrationDefinition.objects.all().delete()

        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_incidents", force=True, stdout=StringIO())

        self.assertTrue(Incident.objects.filter(title="Email suspeito de phishing").exists())

        Incident.objects.all().delete()
        Playbook.objects.all().delete()
        IntegrationDefinition.objects.all().delete()

        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_phishing_comparison", force=True, stdout=StringIO())

        self.assertFalse(IntegrationDefinition.objects.exists())
        self.assertFalse(Playbook.objects.exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - MANUAL").exists())
        self.assertFalse(Incident.objects.filter(title="Email suspeito de phishing").exists())
