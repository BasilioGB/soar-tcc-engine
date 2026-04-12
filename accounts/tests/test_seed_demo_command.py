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
        self.assertTrue(Playbook.objects.filter(name="Phishing triage", category="Phishing").exists())
        self.assertTrue(Playbook.objects.filter(name="Domain manual review").exists())
        self.assertTrue(Playbook.objects.filter(name="URL manual review").exists())
        self.assertTrue(Incident.objects.filter(title="Email suspeito de phishing").exists())
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

    def test_seed_demo_structures_only_skips_incident_seed(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, structures_only=True, stdout=StringIO())

        self.assertTrue(User.objects.filter(username="admin").exists())
        self.assertTrue(IntegrationDefinition.objects.filter(action_name="virustotal_config.domain_lookup").exists())
        self.assertTrue(Playbook.objects.filter(name="Phishing triage", category="Phishing").exists())
        self.assertEqual(Incident.objects.count(), 0)

    def test_seed_demo_incidents_only_skips_structure_seed(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, incidents_only=True, stdout=StringIO())

        self.assertTrue(User.objects.filter(username="admin").exists())
        self.assertTrue(Incident.objects.filter(title="Email suspeito de phishing").exists())
        self.assertFalse(IntegrationDefinition.objects.exists())
        self.assertFalse(Playbook.objects.exists())

    def test_seed_demo_rejects_conflicting_modes(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            with self.assertRaises(CommandError):
                call_command("seed_demo", force=True, structures_only=True, incidents_only=True, stdout=StringIO())

    def test_seed_wrapper_commands(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_structures", force=True, stdout=StringIO())

        self.assertTrue(Playbook.objects.filter(name="Phishing triage", category="Phishing").exists())
        self.assertFalse(Incident.objects.exists())

        Incident.objects.all().delete()
        Playbook.objects.all().delete()
        IntegrationDefinition.objects.all().delete()

        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_incidents", force=True, stdout=StringIO())

        self.assertTrue(Incident.objects.filter(title="Email suspeito de phishing").exists())
