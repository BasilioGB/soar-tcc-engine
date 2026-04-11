from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase

from automation.matcher import (
    match_artifact_rules,
    match_incident_rules,
    resolve_and_match_artifact_rules,
    resolve_and_match_incident_rules,
)


class MatcherTests(SimpleTestCase):
    def test_incident_rules_match_dict_and_object_sources(self):
        rules = {
            "labels": ["phishing"],
            "severity": ["HIGH"],
            "assignee": ["soclead"],
        }
        payload = {
            "labels": ["phishing", "vip"],
            "severity": "HIGH",
            "assignee": "soclead",
        }
        incident = SimpleNamespace(
            labels=["phishing", "vip"],
            severity="HIGH",
            assignee=SimpleNamespace(username="soclead"),
            assignee_id=12,
        )

        self.assertTrue(match_incident_rules(rules, payload))
        self.assertTrue(match_incident_rules(rules, incident))

    def test_artifact_rules_resolve_placeholders_for_payload_and_object_sources(self):
        rules = {
            "type": ["{{artifact.type}}"],
            "incident_labels": ["{{incident.labels.0}}"],
            "attribute_equals": {"expected_type": "{{artifact.type}}"},
        }
        payload = {
            "type": "DOMAIN",
            "value": "malicious.example",
            "incident_labels": ["phishing"],
            "attributes": {"expected_type": "DOMAIN"},
        }
        artifact = SimpleNamespace(
            type="DOMAIN",
            value="malicious.example",
            attributes={"expected_type": "DOMAIN"},
        )
        incident = SimpleNamespace(labels=["phishing"])
        payload_context = {
            "artifact": payload,
            "incident": {"labels": ["phishing"]},
            "payload": payload,
            "trigger_context": payload,
        }
        object_context = {
            "artifact": artifact,
            "incident": incident,
            "payload": artifact,
        }

        self.assertTrue(
            resolve_and_match_artifact_rules(
                rules,
                payload,
                incident_source=payload,
                resolution_context=payload_context,
                source="payload rules",
            )
        )
        self.assertTrue(
            resolve_and_match_artifact_rules(
                rules,
                artifact,
                incident_source=incident,
                resolution_context=object_context,
                source="object rules",
            )
        )

    def test_resolved_incident_rules_can_read_domain_objects(self):
        rules = {"severity": ["{{incident.severity}}"]}
        incident = SimpleNamespace(severity="MEDIUM")

        self.assertTrue(
            resolve_and_match_incident_rules(
                rules,
                incident,
                resolution_context={"incident": incident},
                source="incident object rules",
            )
        )
