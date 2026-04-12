from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase

from integrations.services.template_renderer import (
    build_render_context,
    extract_expected_params,
    render_request_template,
    validate_template_structure,
)


class TemplateRendererTests(SimpleTestCase):
    def setUp(self):
        self.runtime_context = {
            "incident": SimpleNamespace(
                id=42,
                title="  phishing em massa  ",
                labels=["phishing", "vip"],
                assignee=None,
            ),
            "artifact": {
                "id": 7,
                "type": "DOMAIN",
                "value": "malicious.example",
            },
            "execution": {"id": 99},
            "results": {
                "fetch_context": {
                    "payload": {
                        "incident_id": 42,
                        "artifact_value": "malicious.example",
                    }
                }
            },
            "trigger_context": {"event": "artifact.created"},
        }

    def test_build_render_context_injects_params_output_and_response(self):
        context = build_render_context(
            self.runtime_context,
            params={"summary": "IOC detected"},
            output={"ticket_key": "INFRA-1"},
            response={"status_code": 201},
        )

        self.assertEqual(context["params"]["summary"], "IOC detected")
        self.assertEqual(context["output"]["ticket_key"], "INFRA-1")
        self.assertEqual(context["response"]["status_code"], 201)
        self.assertEqual(context["incident"].id, 42)

    def test_render_request_template_supports_nested_structures_and_params(self):
        rendered = render_request_template(
            {
                "url": "https://jira.local/incidents/{{incident.id}}",
                "headers": {
                    "X-Event": "{{trigger_context.event}}",
                    "X-Title": "{{incident.title|strip|upper}}",
                },
                "payload": {
                    "summary": "{{params.summary}}",
                    "description": "IOC {{artifact.value}} on incident {{incident.id}}",
                    "labels": "{{incident.labels}}",
                    "items": [
                        "{{results.fetch_context.payload.incident_id}}",
                        "{{artifact.value}}",
                    ],
                },
            },
            self.runtime_context,
            params={"summary": "Investigate IOC"},
        )

        self.assertEqual(rendered["url"], "https://jira.local/incidents/42")
        self.assertEqual(rendered["headers"]["X-Event"], "artifact.created")
        self.assertEqual(rendered["headers"]["X-Title"], "PHISHING EM MASSA")
        self.assertEqual(rendered["payload"]["summary"], "Investigate IOC")
        self.assertEqual(rendered["payload"]["description"], "IOC malicious.example on incident 42")
        self.assertEqual(rendered["payload"]["labels"], ["phishing", "vip"])
        self.assertEqual(rendered["payload"]["items"], [42, "malicious.example"])

    def test_render_request_template_supports_default_filter(self):
        rendered = render_request_template(
            {
                "payload": {
                    "assignee": "{{incident.assignee.username|default:'unassigned'|upper}}",
                }
            },
            self.runtime_context,
        )

        self.assertEqual(rendered["payload"]["assignee"], "UNASSIGNED")

    def test_validate_template_structure_rejects_invalid_placeholder(self):
        with self.assertRaisesMessage(ValueError, "Filtro desconhecido 'slugify'"):
            validate_template_structure(
                {
                    "payload": {
                        "summary": "{{incident.title|slugify}}",
                    }
                }
            )

    def test_render_request_template_raises_clear_error_when_placeholder_is_missing(self):
        with self.assertRaisesMessage(ValueError, "Placeholder 'params.summary'"):
            render_request_template(
                {
                    "payload": {
                        "summary": "{{params.summary}}",
                    }
                },
                self.runtime_context,
            )

    def test_extract_expected_params_collects_unique_top_level_param_names(self):
        params = extract_expected_params(
            {
                "url": "https://ti.local/ioc/{{params.value}}",
                "payload": {
                    "summary": "{{params.summary}}",
                    "meta": ["{{params.value}}", "{{incident.id}}", "{{params.filters.0}}"],
                },
            }
        )

        self.assertEqual(params, ["value", "summary", "filters"])
