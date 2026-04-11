from __future__ import annotations

from django.test import SimpleTestCase

from playbooks.dsl import ParseError, parse_playbook


class PlaybookDSLPlaceholderValidationTests(SimpleTestCase):
    def test_parse_accepts_placeholders_with_default_and_filters(self):
        parsed = parse_playbook(
            {
                "name": "DSL placeholders",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "note",
                        "action": "incident.add_note",
                        "input": {
                            "message": (
                                "{{incident.title|strip|upper}} / "
                                "{{incident.assignee.username|default:'unassigned'}}"
                            )
                        },
                    }
                ],
            }
        )

        self.assertEqual(parsed.steps[0].name, "note")

    def test_parse_rejects_unknown_filter(self):
        with self.assertRaises(ParseError):
            parse_playbook(
                {
                    "name": "DSL invalid filter",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "note",
                            "action": "incident.add_note",
                            "input": {"message": "{{incident.title|slugify}}"},
                        }
                    ],
                }
            )

    def test_parse_rejects_missing_default_argument(self):
        with self.assertRaises(ParseError):
            parse_playbook(
                {
                    "name": "DSL invalid default",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "note",
                            "action": "incident.add_note",
                            "input": {"message": "{{incident.assignee.username|default}}"},
                        }
                    ],
                }
            )

    def test_parse_rejects_malformed_placeholder(self):
        with self.assertRaises(ParseError):
            parse_playbook(
                {
                    "name": "DSL malformed placeholder",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "note",
                            "action": "incident.add_note",
                            "input": {"message": "{{incident.title"},
                        }
                    ],
                }
            )

    def test_parse_accepts_placeholders_in_filters_and_when(self):
        parsed = parse_playbook(
            {
                "name": "DSL trigger and when",
                "type": "artifact",
                "mode": "automatic",
                "triggers": [
                    {
                        "event": "artifact.created",
                        "filters": {
                            "attribute_equals": {
                                "expected_type": "{{artifact.type}}",
                            }
                        },
                    }
                ],
                "steps": [
                    {
                        "name": "note",
                        "action": "incident.add_note",
                        "when": {
                            "all": [
                                {"left": "{{artifact.type}}", "equals": "DOMAIN"},
                                {"not": {"left": "{{incident.labels}}", "contains": "ignored"}},
                            ]
                        },
                        "input": {"message": "placeholder conditional step"},
                    }
                ],
            }
        )

        self.assertEqual(parsed.triggers[0].event, "artifact.created")
        self.assertEqual(parsed.steps[0].name, "note")

    def test_parse_rejects_invalid_when_operator(self):
        with self.assertRaises(ParseError):
            parse_playbook(
                {
                    "name": "DSL invalid when",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "note",
                            "action": "incident.add_note",
                            "when": {"left": "{{incident.severity}}", "gt": "LOW"},
                            "input": {"message": "invalid condition"},
                        }
                    ],
                }
            )
