from __future__ import annotations

import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import django
import requests

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

from integrations.actions.http_webhook import send_webhook


class HttpWebhookActionTests(unittest.TestCase):
    @patch("integrations.actions.http_webhook.requests.request")
    def test_sends_json_payload_with_headers_and_timeout(self, request_mock):
        response = Mock()
        response.status_code = 202
        response.headers = {"Content-Type": "application/json", "X-Request-Id": "abc"}
        response.json.return_value = {"ok": True, "job_id": "42"}
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        step = SimpleNamespace(
            input={
                "url": "https://hooks.example.local/incident",
                "method": "patch",
                "payload": {"incident_id": 7},
                "headers": {"Authorization": "Bearer token"},
                "timeout": 9,
            }
        )

        result = send_webhook(step=step, context={})

        request_mock.assert_called_once_with(
            method="PATCH",
            url="https://hooks.example.local/incident",
            headers={"Authorization": "Bearer token"},
            timeout=9.0,
            json={"incident_id": 7},
        )
        self.assertEqual(result["status_code"], 202)
        self.assertEqual(result["method"], "PATCH")
        self.assertEqual(result["payload"], {"incident_id": 7})
        self.assertEqual(result["body"], {"ok": True, "job_id": "42"})
        self.assertEqual(result["response_headers"]["X-Request-Id"], "abc")

    @patch("integrations.actions.http_webhook.requests.request")
    def test_sends_raw_body_when_provided(self, request_mock):
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "text/plain"}
        response.text = "accepted"
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        step = SimpleNamespace(
            input={
                "url": "https://hooks.example.local/raw",
                "body": "plain-text",
                "headers": {"Content-Type": "text/plain"},
            }
        )

        result = send_webhook(step=step, context={})

        request_mock.assert_called_once_with(
            method="POST",
            url="https://hooks.example.local/raw",
            headers={"Content-Type": "text/plain"},
            timeout=15.0,
            data="plain-text",
        )
        self.assertEqual(result["request_body"], "plain-text")
        self.assertEqual(result["body"], "accepted")

    def test_rejects_payload_and_body_together(self):
        step = SimpleNamespace(
            input={
                "url": "https://hooks.example.local/conflict",
                "payload": {"a": 1},
                "body": "b",
            }
        )

        with self.assertRaisesRegex(ValueError, "Use payload ou body no webhook, nao ambos"):
            send_webhook(step=step, context={})

    @patch("integrations.actions.http_webhook.requests.request")
    def test_raises_when_http_request_fails(self, request_mock):
        request_mock.side_effect = requests.RequestException("timeout")
        step = SimpleNamespace(input={"url": "https://hooks.example.local/fail"})

        with self.assertRaisesRegex(ValueError, "Falha ao enviar webhook HTTP: timeout"):
            send_webhook(step=step, context={})

    @patch("integrations.actions.http_webhook.requests.request")
    def test_raises_when_status_code_is_error(self, request_mock):
        response = Mock()
        response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
        request_mock.return_value = response
        step = SimpleNamespace(input={"url": "https://hooks.example.local/fail"})

        with self.assertRaisesRegex(ValueError, "Falha ao enviar webhook HTTP: 500 Server Error"):
            send_webhook(step=step, context={})
