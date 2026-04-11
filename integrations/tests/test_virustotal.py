from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
os.environ.setdefault("DJANGO_SECRET_KEY", "dev-key")
os.environ.setdefault("DJANGO_DEBUG", "True")
os.environ.setdefault("DB_ENGINE", "django.db.backends.sqlite3")
os.environ.setdefault("DB_NAME", ":memory:")
os.environ.setdefault("CELERY_BROKER_URL", "redis://127.0.0.1:6379/0")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://127.0.0.1:6379/0")
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6379/1")
os.environ.setdefault("CACHE_URL", "redis://127.0.0.1:6379/2")
os.environ.setdefault("CHANNELS_REDIS_URL", "redis://127.0.0.1:6379/0")
django.setup()

from integrations.actions.virustotal import _fetch, domain_report, url_report


class VirusTotalActionTests(unittest.TestCase):
    @patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""}, clear=False)
    def test_fetch_requires_api_key(self):
        with self.assertRaisesRegex(ValueError, "VIRUSTOTAL_API_KEY nao configurada"):
            _fetch("https://www.virustotal.com/api/v3/domains/example.org")

    @patch("integrations.actions.virustotal._fetch")
    def test_domain_report_propagates_fetch_error(self, fetch_mock):
        fetch_mock.side_effect = ValueError("Erro ao consultar VirusTotal: timeout")
        incident = Mock()
        step = SimpleNamespace(input={"domain": "example.org"})

        with self.assertRaisesRegex(ValueError, "Erro ao consultar VirusTotal: timeout"):
            domain_report(step=step, context={"incident": incident, "actor": None})

        incident.log_timeline.assert_not_called()

    @patch("integrations.actions.virustotal.update_artifact_attributes")
    @patch("integrations.actions.virustotal._fetch")
    def test_domain_report_returns_real_payload_without_simulation_flags(
        self,
        fetch_mock,
        update_artifact_attributes_mock,
    ):
        fetch_mock.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "harmless": 10,
                        "undetected": 2,
                    },
                    "categories": {"vendor": "phishing"},
                    "whois": "registrar: test-reg",
                    "domain_registration": {
                        "created_date": "2024-01-01",
                        "expires_date": "2026-01-01",
                        "registrar": "test-reg",
                        "status": "active",
                    },
                    "reputation": "malicious",
                }
            }
        }
        incident = Mock()
        artifact = Mock()
        artifact.attributes = {}
        step = SimpleNamespace(input={"domain": "example.org"})

        result = domain_report(
            step=step,
            context={"incident": incident, "actor": None, "artifact_instance": artifact},
        )

        self.assertEqual(result["reputation"], "malicious")
        self.assertNotIn("simulated", result)
        self.assertNotIn("simulation_reason", result)
        incident.log_timeline.assert_called_once()
        timeline_extra = incident.log_timeline.call_args.kwargs["extra"]
        self.assertEqual(timeline_extra["source"], "virustotal")
        self.assertNotIn("simulated", timeline_extra)
        self.assertNotIn("simulation_reason", timeline_extra)
        update_artifact_attributes_mock.assert_called_once()
        vt_attributes = update_artifact_attributes_mock.call_args.kwargs["attributes"]["virustotal"]
        self.assertEqual(vt_attributes["source"], "virustotal")
        self.assertNotIn("simulated", vt_attributes)
        self.assertNotIn("simulation_reason", vt_attributes)

    @patch("integrations.actions.virustotal._fetch")
    def test_url_report_returns_not_found_without_simulation_flags(self, fetch_mock):
        fetch_mock.return_value = {"not_found": True, "status_code": 404}
        incident = Mock()
        step = SimpleNamespace(input={"url": "https://example.org/"})

        result = url_report(step=step, context={"incident": incident, "actor": None})

        self.assertTrue(result["not_found"])
        self.assertEqual(result["reputation"], "harmless")
        self.assertNotIn("simulated", result)
        self.assertNotIn("simulation_reason", result)
