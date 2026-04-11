from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError
from django.db import models


class IntegrationSecretRef(models.Model):
    class Provider(models.TextChoices):
        ENV = "env", "Environment Variable"

    name = models.CharField(max_length=128, unique=True)
    provider = models.CharField(max_length=32, choices=Provider.choices, default=Provider.ENV)
    reference = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class IntegrationDefinition(models.Model):
    class Method(models.TextChoices):
        GET = "GET", "GET"
        POST = "POST", "POST"
        PUT = "PUT", "PUT"
        PATCH = "PATCH", "PATCH"
        DELETE = "DELETE", "DELETE"

    class AuthType(models.TextChoices):
        NONE = "none", "None"
        SECRET_REF = "secret_ref", "Secret Ref"

    name = models.CharField(max_length=255, unique=True)
    action_name = models.CharField(max_length=128, unique=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    method = models.CharField(max_length=8, choices=Method.choices, default=Method.POST)
    auth_type = models.CharField(max_length=32, choices=AuthType.choices, default=AuthType.NONE)
    secret_ref = models.ForeignKey(
        IntegrationSecretRef,
        related_name="integrations",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
    )
    request_template = models.JSONField(default=dict, blank=True)
    expected_params = models.JSONField(default=list, blank=True)
    response_mapping = models.JSONField(default=dict, blank=True)
    post_response_actions = models.JSONField(default=list, blank=True)
    timeout_seconds = models.PositiveIntegerField(default=15)
    revision = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["action_name"]

    def __str__(self) -> str:
        return self.action_name

    def clean(self) -> None:
        super().clean()
        errors: dict[str, list[str]] = {}

        if not self.action_name or "." not in self.action_name:
            errors.setdefault("action_name", []).append(
                "Use um nome de action com namespace, por exemplo 'jira.create_issue'."
            )

        if self.auth_type == self.AuthType.SECRET_REF and self.secret_ref is None:
            errors.setdefault("secret_ref", []).append(
                "Selecione um secret_ref quando auth_type for 'secret_ref'."
            )
        if self.auth_type == self.AuthType.NONE and self.secret_ref is not None:
            errors.setdefault("secret_ref", []).append(
                "Nao informe secret_ref quando auth_type for 'none'."
            )

        self._validate_request_template(errors)
        self._validate_expected_params(errors)
        self._validate_response_mapping(errors)
        self._validate_post_response_actions(errors)

        if errors:
            raise ValidationError(errors)

    def _validate_request_template(self, errors: dict[str, list[str]]) -> None:
        if not isinstance(self.request_template, dict):
            errors.setdefault("request_template", []).append("request_template deve ser um objeto JSON.")
            return

        for key in ("url", "headers", "query", "payload", "body"):
            if key in self.request_template and self.request_template[key] is None:
                errors.setdefault("request_template", []).append(
                    f"O campo '{key}' nao pode ser nulo dentro de request_template."
                )

    def _validate_expected_params(self, errors: dict[str, list[str]]) -> None:
        params = self.expected_params
        if not isinstance(params, list):
            errors.setdefault("expected_params", []).append("expected_params deve ser uma lista.")
            return

        normalized: list[str] = []
        for item in params:
            if not isinstance(item, str) or not item.strip():
                errors.setdefault("expected_params", []).append(
                    "Todos os expected_params devem ser strings nao vazias."
                )
                return
            normalized.append(item.strip())

        if len(set(normalized)) != len(normalized):
            errors.setdefault("expected_params", []).append(
                "expected_params nao pode conter valores duplicados."
            )

    def _validate_response_mapping(self, errors: dict[str, list[str]]) -> None:
        mapping = self.response_mapping
        if not isinstance(mapping, dict):
            errors.setdefault("response_mapping", []).append("response_mapping deve ser um objeto JSON.")
            return

        for key, value in mapping.items():
            if not isinstance(key, str) or not key.strip():
                errors.setdefault("response_mapping", []).append(
                    "Todas as chaves de response_mapping devem ser strings nao vazias."
                )
                break
            if not isinstance(value, str) or not value.strip():
                errors.setdefault("response_mapping", []).append(
                    "Todos os valores de response_mapping devem ser caminhos string nao vazios."
                )
                break

    def _validate_post_response_actions(self, errors: dict[str, list[str]]) -> None:
        actions = self.post_response_actions
        if not isinstance(actions, list):
            errors.setdefault("post_response_actions", []).append(
                "post_response_actions deve ser uma lista."
            )
            return

        for action in actions:
            if not isinstance(action, dict):
                errors.setdefault("post_response_actions", []).append(
                    "Cada item de post_response_actions deve ser um objeto."
                )
                return
            action_name = action.get("action")
            action_input = action.get("input", {})
            if not isinstance(action_name, str) or not action_name.strip():
                errors.setdefault("post_response_actions", []).append(
                    "Cada post_response_action deve informar um campo 'action' nao vazio."
                )
                return
            if not isinstance(action_input, dict):
                errors.setdefault("post_response_actions", []).append(
                    "O campo 'input' de post_response_actions deve ser um objeto."
                )
                return

