from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from integrations.services.template_renderer import extract_expected_params
from integrations.services.secret_crypto import decrypt_secret, encrypt_secret


class IntegrationSecretRef(models.Model):
    class CredentialKind(models.TextChoices):
        TOKEN = "token", "Token/API Key"
        BASIC_AUTH = "basic_auth", "Basic Auth"

    name = models.CharField(max_length=128, unique=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    credential_kind = models.CharField(
        max_length=32,
        choices=CredentialKind.choices,
        default=CredentialKind.TOKEN,
    )
    credential_payload_encrypted = models.TextField(blank=True, default="", editable=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="created_http_connector_secrets",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    rotated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="rotated_http_connector_secrets",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    rotated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "Secret do conector HTTP"
        verbose_name_plural = "Secrets dos conectores HTTP"

    def __str__(self) -> str:
        return self.name

    @property
    def has_credential(self) -> bool:
        return bool(self.credential_payload_encrypted)

    def clean(self) -> None:
        super().clean()
        errors: dict[str, list[str]] = {}
        if not self.credential_payload_encrypted:
            errors.setdefault("credential", []).append("Informe uma credencial para o secret.")
        else:
            credential = self.get_credential()
            if self.credential_kind == self.CredentialKind.TOKEN:
                if not (credential.get("token") or "").strip():
                    errors.setdefault("token_value", []).append("Informe um token ou API key.")
            elif self.credential_kind == self.CredentialKind.BASIC_AUTH:
                if not (credential.get("username") or "").strip():
                    errors.setdefault("basic_auth_username", []).append(
                        "Informe o usuario do Basic Auth."
                    )
                if not (credential.get("password") or "").strip():
                    errors.setdefault("basic_auth_password", []).append(
                        "Informe a senha do Basic Auth."
                    )
        if errors:
            raise ValidationError(errors)

    def set_token_credential(self, raw_value: str) -> None:
        value = (raw_value or "").strip()
        if not value:
            raise ValidationError({"token_value": ["Informe um token ou API key."]})
        self.credential_kind = self.CredentialKind.TOKEN
        self.credential_payload_encrypted = encrypt_secret(value)

    def set_basic_auth_credential(self, username: str, password: str) -> None:
        normalized_username = (username or "").strip()
        normalized_password = (password or "").strip()
        errors: dict[str, list[str]] = {}
        if not normalized_username:
            errors.setdefault("basic_auth_username", []).append("Informe o usuario do Basic Auth.")
        if not normalized_password:
            errors.setdefault("basic_auth_password", []).append("Informe a senha do Basic Auth.")
        if errors:
            raise ValidationError(errors)
        self.credential_kind = self.CredentialKind.BASIC_AUTH
        self.credential_payload_encrypted = encrypt_secret(
            f"{normalized_username}\n{normalized_password}"
        )

    def get_credential(self) -> dict[str, str]:
        if not self.credential_payload_encrypted:
            raise ValueError(f"Secret '{self.name}' nao possui credencial armazenada")
        payload = decrypt_secret(self.credential_payload_encrypted)
        if self.credential_kind == self.CredentialKind.TOKEN:
            return {"token": payload}
        username, _, password = payload.partition("\n")
        return {"username": username, "password": password}


class IntegrationDefinition(models.Model):
    class Method(models.TextChoices):
        GET = "GET", "GET"
        POST = "POST", "POST"
        PUT = "PUT", "PUT"
        PATCH = "PATCH", "PATCH"
        DELETE = "DELETE", "DELETE"

    class AuthStrategy(models.TextChoices):
        BEARER_HEADER = "bearer_header", "Bearer Header"
        HEADER = "header", "Header"
        QUERY_PARAM = "query_param", "Query Param"
        BASIC = "basic", "Basic Auth"

    name = models.CharField(max_length=255, unique=True)
    action_name = models.CharField(max_length=128, unique=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    method = models.CharField(max_length=8, choices=Method.choices, default=Method.POST)
    secret_ref = models.ForeignKey(
        IntegrationSecretRef,
        related_name="http_connectors",
        on_delete=models.PROTECT,
    )
    auth_strategy = models.CharField(
        max_length=32,
        choices=AuthStrategy.choices,
        default=AuthStrategy.BEARER_HEADER,
    )
    auth_header_name = models.CharField(max_length=128, blank=True, default="Authorization")
    auth_prefix = models.CharField(max_length=64, blank=True, default="Bearer")
    auth_query_param = models.CharField(max_length=64, blank=True, default="api_key")
    request_template = models.JSONField(default=dict, blank=True)
    output_template = models.JSONField(default=dict, blank=True)
    expected_params = models.JSONField(default=list, blank=True)
    timeout_seconds = models.PositiveIntegerField(default=15)
    revision = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["action_name"]
        verbose_name = "Conector HTTP"
        verbose_name_plural = "Conectores HTTP"

    def __str__(self) -> str:
        return self.action_name

    def clean(self) -> None:
        super().clean()
        errors: dict[str, list[str]] = {}
        from integrations.registry import list_actions

        if not self.action_name or "." not in self.action_name:
            errors.setdefault("action_name", []).append(
                "Use um nome de action com namespace, por exemplo 'jira.create_issue'."
            )
        if self.action_name in set(list_actions()):
            errors.setdefault("action_name", []).append(
                f"A action '{self.action_name}' colide com uma action estatica da engine."
            )

        if self.secret_ref_id is None:
            errors.setdefault("secret_ref", []).append(
                "Selecione um secret_ref para o conector HTTP."
            )
        if self.secret_ref_id is not None and not self.secret_ref.enabled:
            errors.setdefault("secret_ref", []).append("O secret selecionado esta desabilitado.")
        if self.secret_ref_id is not None and not self.secret_ref.has_credential:
            errors.setdefault("secret_ref", []).append(
                "O secret selecionado nao possui credencial armazenada."
            )

        self._validate_auth(errors)
        self._validate_request_template(errors)
        self._validate_output_template(errors)
        self._validate_expected_params(errors)
        if errors:
            raise ValidationError(errors)

    def save(self, *args, **kwargs):
        self._sync_expected_params()
        return super().save(*args, **kwargs)

    def _validate_auth(self, errors: dict[str, list[str]]) -> None:
        if self.auth_strategy in {self.AuthStrategy.BEARER_HEADER, self.AuthStrategy.HEADER}:
            if not (self.auth_header_name or "").strip():
                errors.setdefault("auth_header_name", []).append(
                    "Informe o nome do header usado para autenticacao."
                )
        if self.auth_strategy == self.AuthStrategy.QUERY_PARAM:
            if not (self.auth_query_param or "").strip():
                errors.setdefault("auth_query_param", []).append(
                    "Informe o parametro de query usado para autenticacao."
                )
        if self.auth_strategy == self.AuthStrategy.BASIC:
            if self.secret_ref_id is not None and self.secret_ref.credential_kind != IntegrationSecretRef.CredentialKind.BASIC_AUTH:
                errors.setdefault("secret_ref", []).append(
                    "Basic Auth exige um secret do tipo Basic Auth."
                )
        elif (
            self.secret_ref_id is not None
            and self.secret_ref.credential_kind != IntegrationSecretRef.CredentialKind.TOKEN
        ):
            errors.setdefault("secret_ref", []).append(
                "Essa estrategia exige um secret do tipo Token/API Key."
            )

    def _validate_request_template(self, errors: dict[str, list[str]]) -> None:
        if not isinstance(self.request_template, dict):
            errors.setdefault("request_template", []).append("request_template deve ser um objeto JSON.")
            return
        if "auth" in self.request_template:
            errors.setdefault("request_template", []).append(
                "request_template nao pode definir auth; use os campos de autenticacao do conector."
            )
        if self.request_template.get("payload") is not None and self.request_template.get("body") is not None:
            errors.setdefault("request_template", []).append(
                "request_template nao pode definir payload e body ao mesmo tempo."
            )

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
            return

        derived_params = extract_expected_params(
            [self.request_template or {}, self.output_template or {}]
        )
        if not normalized:
            self.expected_params = derived_params
            return

        if normalized != derived_params:
            derived_label = ", ".join(derived_params) if derived_params else "(nenhum)"
            errors.setdefault("expected_params", []).append(
                "expected_params deve corresponder aos placeholders {{params.*}} do request_template/output_template: "
                f"{derived_label}."
            )

    def _sync_expected_params(self) -> None:
        params = self.expected_params
        if isinstance(params, list) and params:
            return
        self.expected_params = extract_expected_params(
            [self.request_template or {}, self.output_template or {}]
        )

    def _validate_output_template(self, errors: dict[str, list[str]]) -> None:
        if self.output_template in (None, ""):
            self.output_template = {}
            return
        if not isinstance(self.output_template, dict):
            errors.setdefault("output_template", []).append("output_template deve ser um objeto JSON.")
