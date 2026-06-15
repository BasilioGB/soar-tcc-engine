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

    def test_parse_accepts_control_branch_contract(self):
        parsed = parse_playbook(
            {
                "name": "DSL branch contract",
                "type": "incident",
                "mode": "manual",
                "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                "steps": [
                    {
                        "name": "decidir_veredito",
                        "action": "control.branch",
                        "branches": [
                            {
                                "name": "malicious",
                                "when": {
                                    "left": "{{results.consultar_vt.stats.malicious}}",
                                    "not_equals": 0,
                                },
                                "steps": [
                                    {
                                        "name": "bloquear_ioc",
                                        "action": "task.create",
                                        "input": {"title": "Bloquear IOC malicioso"},
                                    }
                                ],
                            }
                        ],
                        "default": [
                            {
                                "name": "revisao_manual",
                                "action": "task.create",
                                "input": {"title": "Revisar resultado inconclusivo"},
                            }
                        ],
                    }
                ],
            }
        )

        branch_step = parsed.steps[0]
        self.assertEqual(branch_step.action, "control.branch")
        self.assertEqual(branch_step.branches[0].name, "malicious")
        self.assertEqual(branch_step.branches[0].steps[0].name, "bloquear_ioc")
        self.assertEqual(branch_step.default[0].name, "revisao_manual")
        self.assertEqual(
            [step.name for step in parsed.all_steps()],
            ["decidir_veredito", "bloquear_ioc", "revisao_manual"],
        )

    def test_parse_rejects_control_branch_without_branches(self):
        with self.assertRaises(ParseError):
            parse_playbook(
                {
                    "name": "DSL branch without branches",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "decidir_veredito",
                            "action": "control.branch",
                            "default": [
                                {
                                    "name": "revisao_manual",
                                    "action": "task.create",
                                    "input": {"title": "Revisar resultado"},
                                }
                            ],
                        }
                    ],
                }
            )

    def test_parse_rejects_branches_on_regular_step(self):
        with self.assertRaises(ParseError):
            parse_playbook(
                {
                    "name": "DSL invalid branch location",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "note",
                            "action": "incident.add_note",
                            "input": {"message": "regular step"},
                            "branches": [
                                {
                                    "name": "invalid",
                                    "when": {"left": "{{incident.severity}}", "equals": "HIGH"},
                                    "steps": [
                                        {
                                            "name": "nested_note",
                                            "action": "incident.add_note",
                                            "input": {"message": "invalid"},
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            )

    def test_parse_rejects_duplicate_top_level_step_names(self):
        with self.assertRaises(ParseError):
            parse_playbook(
                {
                    "name": "DSL duplicate steps",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "duplicado",
                            "action": "incident.add_note",
                            "input": {"message": "primeiro"},
                        },
                        {
                            "name": "duplicado",
                            "action": "incident.add_note",
                            "input": {"message": "segundo"},
                        },
                    ],
                }
            )

    def test_parse_rejects_duplicate_nested_step_names(self):
        with self.assertRaises(ParseError):
            parse_playbook(
                {
                    "name": "DSL duplicate nested steps",
                    "type": "incident",
                    "mode": "manual",
                    "filters": [{"target": "incident", "conditions": {"severity": ["MEDIUM"]}}],
                    "steps": [
                        {
                            "name": "decidir_veredito",
                            "action": "control.branch",
                            "branches": [
                                {
                                    "name": "malicious",
                                    "when": {"left": "{{incident.severity}}", "equals": "HIGH"},
                                    "steps": [
                                        {
                                            "name": "registrar_resultado",
                                            "action": "incident.add_note",
                                            "input": {"message": "malicioso"},
                                        }
                                    ],
                                }
                            ],
                            "default": [
                                {
                                    "name": "registrar_resultado",
                                    "action": "incident.add_note",
                                    "input": {"message": "default"},
                                }
                            ],
                        }
                    ],
                }
            )
