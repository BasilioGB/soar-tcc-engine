from __future__ import annotations

import os
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

from integrations.services.http_client import execute_request, normalize_method, parse_timeout


class HttpClientServiceTests(unittest.TestCase):
    def test_normalize_method_uppercases_and_defaults_to_post(self):
        self.assertEqual(normalize_method(None), "POST")
        self.assertEqual(normalize_method("patch"), "PATCH")

    def test_parse_timeout_accepts_numbers_and_uses_default(self):
        self.assertEqual(parse_timeout(None), 15.0)
        self.assertEqual(parse_timeout("9"), 9.0)

    @patch("integrations.services.http_client.requests.request")
    def test_execute_request_parses_json_response(self, request_mock):
        response = Mock()
        response.status_code = 201
        response.headers = {"Content-Type": "application/json"}
        response.json.return_value = {"ok": True, "id": "42"}
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        result = execute_request(
            method="post",
            url="https://hooks.example.local/json",
            headers={"Authorization": "Bearer token"},
            timeout="12",
            payload={"id": 7},
        )

        request_mock.assert_called_once_with(
            method="POST",
            url="https://hooks.example.local/json",
            headers={"Authorization": "Bearer token"},
            timeout=12.0,
            json={"id": 7},
        )
        self.assertEqual(result["status_code"], 201)
        self.assertEqual(result["body"], {"ok": True, "id": "42"})

    @patch("integrations.services.http_client.requests.request")
    def test_execute_request_parses_text_response(self, request_mock):
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "text/plain"}
        response.text = "accepted"
        response.raise_for_status.return_value = None
        request_mock.return_value = response

        result = execute_request(
            method="get",
            url="https://hooks.example.local/text",
        )

        request_mock.assert_called_once_with(
            method="GET",
            url="https://hooks.example.local/text",
            headers={},
            timeout=15.0,
        )
        self.assertEqual(result["body"], "accepted")

    def test_execute_request_rejects_invalid_timeout(self):
        with self.assertRaisesRegex(ValueError, "Webhook timeout invalido"):
            execute_request(method="post", url="https://hooks.example.local", timeout="abc")

    @patch("integrations.services.http_client.requests.request")
    def test_execute_request_raises_when_request_fails(self, request_mock):
        request_mock.side_effect = requests.RequestException("timeout")

        with self.assertRaisesRegex(ValueError, "Falha ao enviar webhook HTTP: timeout"):
            execute_request(method="post", url="https://hooks.example.local/fail")
