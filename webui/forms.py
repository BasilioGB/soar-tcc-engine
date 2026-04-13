from __future__ import annotations

import json
from typing import Any

from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone

from integrations.models import IntegrationDefinition, IntegrationSecretRef
from incidents.models import Artifact, CustomFieldDefinition, Incident
from playbooks.models import Playbook
from playbooks.dsl import ParseError, parse_playbook
from playbooks.validation import validate_playbook_semantics


def _apply_default_input_classes(form: forms.Form) -> None:
    for field in form.fields.values():
        if isinstance(field.widget, forms.CheckboxInput):
            field.widget.attrs.setdefault("class", "")
            continue
        css = field.widget.attrs.get("class", "")
        field.widget.attrs["class"] = f"{css} border rounded px-3 py-2 w-full".strip()


def _parse_json_text(value: str, *, expected_type: type, field_label: str):
    try:
        data = json.loads(value)
    except json.JSONDecodeError as exc:
        raise forms.ValidationError(f"JSON invalido em {field_label}: {exc}")
    if not isinstance(data, expected_type):
        type_label = "objeto JSON" if expected_type is dict else "lista JSON"
        raise forms.ValidationError(f"{field_label} deve ser um {type_label}")
    return data


def _parse_json_value(value: str, *, field_label: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise forms.ValidationError(f"JSON invalido em {field_label}: {exc}")


class IncidentFilterForm(forms.Form):
    ownership = forms.ChoiceField(
        required=False,
        choices=[
            ("all", "Todos"),
            ("mine", "Meus incidentes"),
            ("escalated", "Escalados para mim"),
        ],
        initial="all",
    )
    search = forms.CharField(required=False, label="Busca")
    status = forms.ChoiceField(required=False, choices=[("", "Todos")] + list(Incident.Status.choices))
    severity = forms.ChoiceField(required=False, choices=[("", "Todas")] + list(Incident.Severity.choices))

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            css = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = f"{css} border rounded px-3 py-2".strip()


class ArtifactForm(forms.ModelForm):
    class Meta:
        model = Artifact
        fields = ["type", "value"]
        labels = {"type": "Tipo", "value": "Valor"}
        widgets = {
            "type": forms.Select(attrs={"class": "border rounded px-3 py-2 w-full"}),
            "value": forms.TextInput(attrs={"class": "border rounded px-3 py-2 w-full"}),
        }


class TimelineEntryForm(forms.Form):
    message = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 3, "class": "border rounded w-full px-3 py-2"}),
        label="Adicionar nota",
    )


class PlaybookForm(forms.ModelForm):
    dsl_text = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 12, "class": "font-mono border rounded px-3 py-2 w-full"}),
        label="DSL (JSON)",
    )
    type = forms.ChoiceField(choices=Playbook.Type.choices, label="Tipo", initial=Playbook.Type.INCIDENT)
    mode = forms.ChoiceField(choices=Playbook.Mode.choices, label="Modo", initial=Playbook.Mode.AUTOMATIC)

    class Meta:
        model = Playbook
        fields = ["name", "category", "description", "enabled", "type", "mode"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.dsl:
            self.fields["dsl_text"].initial = json.dumps(self.instance.dsl, indent=2)
        if self.instance and self.instance.type:
            self.fields["type"].initial = self.instance.type
        if self.instance and self.instance.mode:
            self.fields["mode"].initial = self.instance.mode
        _apply_default_input_classes(self)

    def clean_dsl_text(self):
        text = self.cleaned_data["dsl_text"]
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise forms.ValidationError(f"JSON invalido: {exc}")
        if not isinstance(data, dict):
            raise forms.ValidationError("DSL deve ser um objeto JSON")
        return data

    def clean(self):
        cleaned_data = super().clean()
        dsl_data = cleaned_data.get("dsl_text")
        if not isinstance(dsl_data, dict):
            return cleaned_data

        merged_dsl = dict(dsl_data)
        if cleaned_data.get("type"):
            merged_dsl["type"] = cleaned_data["type"]
        if cleaned_data.get("mode"):
            merged_dsl["mode"] = cleaned_data["mode"]

        self.instance.dsl = merged_dsl
        if cleaned_data.get("type"):
            self.instance.type = cleaned_data["type"]
        if cleaned_data.get("mode"):
            self.instance.mode = cleaned_data["mode"]

        try:
            parsed = parse_playbook(merged_dsl)
            validate_playbook_semantics(merged_dsl, parsed_playbook=parsed)
        except ParseError as exc:
            self.add_error("dsl_text", str(exc))
        except DjangoValidationError as exc:
            for message in exc.messages:
                self.add_error("dsl_text", message)

        return cleaned_data

    def add_error(self, field, error):
        # When model validation raises errors keyed by the JSONField name, redirect them
        # to the visible DSL textarea. Django may call add_error(None, errors_dict), so
        # we need to unwrap that case as well.
        if hasattr(error, "error_dict"):
            error = error.error_dict
        if field in (None, forms.forms.NON_FIELD_ERRORS) and isinstance(error, dict):
            dsl_errors = error.pop("dsl", None)
            if dsl_errors:
                self.add_error("dsl_text", dsl_errors)
                if not error:
                    return
        if field == "dsl":
            field = "dsl_text"
        super().add_error(field, error)

    def save(self, commit: bool = True):
        instance = super().save(commit=False)
        dsl_data = dict(self.cleaned_data["dsl_text"])
        dsl_data["type"] = self.cleaned_data["type"]
        dsl_data["mode"] = self.cleaned_data["mode"]
        instance.dsl = dsl_data
        instance.type = self.cleaned_data["type"]
        instance.mode = self.cleaned_data["mode"]
        if commit:
            instance.save()
        return instance


class HttpConnectorSecretForm(forms.ModelForm):
    token_value = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        label="Token ou API key",
        required=False,
        strip=False,
        help_text="O valor e salvo e nao sera exibido novamente.",
    )
    basic_auth_username = forms.CharField(
        label="Usuario do Basic Auth",
        required=False,
    )
    basic_auth_password = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        label="Senha do Basic Auth",
        required=False,
        strip=False,
        help_text="A senha e salva e nao sera exibida novamente.",
    )

    class Meta:
        model = IntegrationSecretRef
        fields = ["name", "description", "enabled", "credential_kind"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        credential = self.instance.get_credential() if self.instance and self.instance.pk and self.instance.has_credential else {}
        if self.instance and self.instance.pk:
            self.fields["token_value"].label = "Novo token ou API key"
            self.fields["token_value"].help_text = "Preencha apenas para rotacionar a credencial do tipo token."
            self.fields["basic_auth_password"].help_text = "Preencha apenas para rotacionar a senha do Basic Auth."
            if self.instance.credential_kind == IntegrationSecretRef.CredentialKind.BASIC_AUTH:
                self.fields["basic_auth_username"].initial = credential.get("username", "")
        else:
            self.fields["token_value"].required = False
        _apply_default_input_classes(self)

    def clean(self):
        cleaned_data = super().clean()
        kind = cleaned_data.get("credential_kind") or IntegrationSecretRef.CredentialKind.TOKEN
        token_value = cleaned_data.get("token_value")
        basic_username = cleaned_data.get("basic_auth_username")
        basic_password = cleaned_data.get("basic_auth_password")
        if not self.instance.pk:
            if kind == IntegrationSecretRef.CredentialKind.TOKEN and not token_value:
                self.add_error("token_value", "Informe um token ou API key.")
            if kind == IntegrationSecretRef.CredentialKind.BASIC_AUTH:
                if not basic_username:
                    self.add_error("basic_auth_username", "Informe o usuario do Basic Auth.")
                if not basic_password:
                    self.add_error("basic_auth_password", "Informe a senha do Basic Auth.")
        return cleaned_data

    def _post_clean(self):
        kind = self.data.get("credential_kind") or IntegrationSecretRef.CredentialKind.TOKEN
        token_value = self.data.get("token_value", "")
        basic_username = self.data.get("basic_auth_username", "")
        basic_password = self.data.get("basic_auth_password", "")
        previous_kind = self.instance.credential_kind if self.instance.pk else None
        self.instance.credential_kind = kind
        if kind == IntegrationSecretRef.CredentialKind.TOKEN:
            if token_value:
                self.instance.set_token_credential(token_value)
            elif self.instance.pk and self.instance.credential_payload_encrypted and previous_kind == kind:
                self.instance.credential_payload_encrypted = self.instance.credential_payload_encrypted
            else:
                self.instance.credential_payload_encrypted = ""
        elif kind == IntegrationSecretRef.CredentialKind.BASIC_AUTH:
            current_username = ""
            if self.instance.pk and self.instance.has_credential:
                current_username = self.instance.get_credential().get("username", "")
            if basic_password:
                self.instance.set_basic_auth_credential(basic_username or current_username, basic_password)
            elif self.instance.pk and self.instance.credential_payload_encrypted and previous_kind == kind:
                self.instance.credential_payload_encrypted = self.instance.credential_payload_encrypted
            else:
                self.instance.credential_payload_encrypted = ""
        super()._post_clean()

    def save(self, actor=None, commit: bool = True):
        instance = super().save(commit=False)
        kind = self.cleaned_data.get("credential_kind") or IntegrationSecretRef.CredentialKind.TOKEN
        token_value = self.cleaned_data.get("token_value")
        basic_username = self.cleaned_data.get("basic_auth_username")
        basic_password = self.cleaned_data.get("basic_auth_password")
        if actor and instance.pk is None and instance.created_by_id is None:
            instance.created_by = actor
        if kind == IntegrationSecretRef.CredentialKind.TOKEN and token_value:
            instance.set_token_credential(token_value)
            if actor:
                instance.rotated_by = actor
            instance.rotated_at = timezone.now()
        elif kind == IntegrationSecretRef.CredentialKind.BASIC_AUTH and basic_password:
            current_username = ""
            if instance.pk and instance.has_credential:
                current_username = instance.get_credential().get("username", "")
            instance.set_basic_auth_credential(basic_username or current_username, basic_password)
            if actor:
                instance.rotated_by = actor
            instance.rotated_at = timezone.now()
        if commit:
            instance.save()
        return instance


class CustomFieldDefinitionForm(forms.ModelForm):
    class Meta:
        model = CustomFieldDefinition
        fields = ["display_name", "field_type", "is_active"]
        labels = {
            "display_name": "Nome de exibicao",
            "field_type": "Tipo",
            "is_active": "Ativo",
        }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            self.fields["field_type"].disabled = True
            self.fields["field_type"].help_text = "Tipo nao pode ser alterado apos a criacao."
        _apply_default_input_classes(self)


class HttpConnectorForm(forms.ModelForm):
    class RequestEditorMode:
        GUIDED = "guided"
        ADVANCED = "advanced"
        CHOICES = (
            (GUIDED, "Guiado"),
            (ADVANCED, "Avancado"),
        )

    class GuidedBodyMode:
        NONE = "none"
        PAYLOAD = "payload"
        RAW = "raw"
        CHOICES = (
            (NONE, "Sem corpo"),
            (PAYLOAD, "Payload JSON"),
            (RAW, "Body bruto"),
        )

    request_editor_mode = forms.ChoiceField(
        choices=RequestEditorMode.CHOICES,
        required=False,
        initial=RequestEditorMode.GUIDED,
        widget=forms.RadioSelect,
        label="Modo de edicao",
    )
    request_url = forms.CharField(required=False, label="URL")
    request_headers_text = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 5, "class": "font-mono border rounded px-3 py-2 w-full"}),
        label="Headers (JSON)",
        required=False,
        initial="{}",
    )
    request_query_text = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 5, "class": "font-mono border rounded px-3 py-2 w-full"}),
        label="Query params (JSON)",
        required=False,
        initial="{}",
    )
    request_body_mode = forms.ChoiceField(
        choices=GuidedBodyMode.CHOICES,
        required=False,
        initial=GuidedBodyMode.NONE,
        label="Corpo do request",
    )
    request_payload_text = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 8, "class": "font-mono border rounded px-3 py-2 w-full"}),
        label="Payload JSON",
        required=False,
        initial="{}",
    )
    request_body_text = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 8, "class": "font-mono border rounded px-3 py-2 w-full"}),
        label="Body bruto",
        required=False,
    )
    request_template_text = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 12, "class": "font-mono border rounded px-3 py-2 w-full"}),
        label="Request template (JSON)",
        required=False,
    )
    output_template_text = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 10, "class": "font-mono border rounded px-3 py-2 w-full"}),
        label="Output (JSON)",
        required=False,
        initial="{}",
    )
    expected_params_text = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 5, "class": "font-mono border rounded px-3 py-2 w-full"}),
        label="Expected params (JSON)",
        required=False,
        initial="[]",
    )
    class Meta:
        model = IntegrationDefinition
        fields = [
            "name",
            "description",
            "action_name",
            "enabled",
            "method",
            "secret_ref",
            "auth_strategy",
            "auth_header_name",
            "auth_prefix",
            "auth_query_param",
            "timeout_seconds",
            "revision",
        ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fields["secret_ref"].required = True
        request_template = self.instance.request_template or {}
        if self.instance and self.instance.pk:
            self.fields["request_template_text"].initial = json.dumps(
                request_template,
                indent=2,
                ensure_ascii=False,
            )
            self.fields["output_template_text"].initial = json.dumps(
                self.instance.output_template or {},
                indent=2,
                ensure_ascii=False,
            )
            self.fields["expected_params_text"].initial = json.dumps(
                self.instance.expected_params or [],
                indent=2,
                ensure_ascii=False,
            )
        self._initialize_guided_fields(request_template)
        _apply_default_input_classes(self)
        self.fields["request_editor_mode"].widget.attrs["class"] = "flex gap-4"

    def _initialize_guided_fields(self, request_template: dict[str, Any]) -> None:
        if not isinstance(request_template, dict):
            return
        self.fields["request_url"].initial = request_template.get("url", "")
        self.fields["request_headers_text"].initial = json.dumps(
            request_template.get("headers") or {},
            indent=2,
            ensure_ascii=False,
        )
        self.fields["request_query_text"].initial = json.dumps(
            request_template.get("query") or {},
            indent=2,
            ensure_ascii=False,
        )
        if request_template.get("payload") is not None:
            self.fields["request_body_mode"].initial = self.GuidedBodyMode.PAYLOAD
            self.fields["request_payload_text"].initial = json.dumps(
                request_template.get("payload"),
                indent=2,
                ensure_ascii=False,
            )
        elif request_template.get("body") is not None:
            self.fields["request_body_mode"].initial = self.GuidedBodyMode.RAW
            body_value = request_template.get("body")
            if isinstance(body_value, str):
                self.fields["request_body_text"].initial = body_value
            else:
                self.fields["request_body_text"].initial = json.dumps(body_value, indent=2, ensure_ascii=False)
        else:
            self.fields["request_body_mode"].initial = self.GuidedBodyMode.NONE
            self.fields["request_payload_text"].initial = "{}"
            self.fields["request_body_text"].initial = ""

        self.fields["request_editor_mode"].initial = self.RequestEditorMode.GUIDED

    def _normalize_request_editor_mode(self, cleaned_data: dict[str, Any]) -> str:
        mode = cleaned_data.get("request_editor_mode")
        if mode in {self.RequestEditorMode.GUIDED, self.RequestEditorMode.ADVANCED}:
            return mode
        if (self.data.get("request_template_text") or "").strip():
            return self.RequestEditorMode.ADVANCED
        return self.RequestEditorMode.GUIDED

    def clean_request_template_text(self):
        raw_value = self.cleaned_data.get("request_template_text", "")
        if not raw_value:
            return {}
        return _parse_json_text(raw_value, expected_type=dict, field_label="request_template")

    def clean_expected_params_text(self):
        raw_value = self.cleaned_data["expected_params_text"]
        return _parse_json_text(raw_value or "[]", expected_type=list, field_label="expected_params")

    def clean_output_template_text(self):
        raw_value = self.cleaned_data.get("output_template_text", "")
        if not raw_value:
            return {}
        return _parse_json_text(raw_value, expected_type=dict, field_label="output_template")

    def clean(self):
        cleaned_data = super().clean()
        if self.errors:
            return cleaned_data

        editor_mode = self._normalize_request_editor_mode(cleaned_data)
        cleaned_data["request_editor_mode"] = editor_mode

        if editor_mode == self.RequestEditorMode.GUIDED:
            request_template = self._build_request_template_from_guided_input(cleaned_data)
            if self.errors:
                return cleaned_data
            cleaned_data["request_template_text"] = request_template

        self.instance.name = cleaned_data.get("name")
        self.instance.description = cleaned_data.get("description", "")
        self.instance.action_name = cleaned_data.get("action_name")
        self.instance.enabled = cleaned_data.get("enabled", False)
        self.instance.method = cleaned_data.get("method")
        self.instance.secret_ref = cleaned_data.get("secret_ref")
        self.instance.auth_strategy = cleaned_data.get("auth_strategy")
        self.instance.auth_header_name = cleaned_data.get("auth_header_name", "")
        self.instance.auth_prefix = cleaned_data.get("auth_prefix", "")
        self.instance.auth_query_param = cleaned_data.get("auth_query_param", "")
        self.instance.timeout_seconds = cleaned_data.get("timeout_seconds")
        self.instance.revision = cleaned_data.get("revision")
        self.instance.request_template = cleaned_data.get("request_template_text", {})
        self.instance.output_template = cleaned_data.get("output_template_text", {})
        self.instance.expected_params = cleaned_data.get("expected_params_text", [])

        field_map = {
            "request_template": "request_template_text",
            "output_template": "output_template_text",
            "expected_params": "expected_params_text",
        }
        try:
            self.instance.full_clean()
        except DjangoValidationError as exc:
            if hasattr(exc, "message_dict"):
                for field, messages in exc.message_dict.items():
                    target_field = field_map.get(field, field)
                    for message in messages:
                        self.add_error(target_field, message)
            else:
                for message in exc.messages:
                    self.add_error(None, message)
        else:
            cleaned_data["expected_params_text"] = self.instance.expected_params
            cleaned_data["output_template_text"] = self.instance.output_template

        return cleaned_data

    def _build_request_template_from_guided_input(self, cleaned_data: dict[str, Any]) -> dict[str, Any]:
        url = (cleaned_data.get("request_url") or "").strip()
        if not url:
            self.add_error("request_url", "Informe a URL do request.")
            return {}

        headers_raw = (cleaned_data.get("request_headers_text") or "").strip()
        query_raw = (cleaned_data.get("request_query_text") or "").strip()
        body_mode = cleaned_data.get("request_body_mode") or self.GuidedBodyMode.NONE

        headers = {}
        if headers_raw:
            try:
                headers = _parse_json_text(headers_raw, expected_type=dict, field_label="headers")
            except forms.ValidationError as exc:
                self.add_error("request_headers_text", exc)

        query = {}
        if query_raw:
            try:
                query = _parse_json_text(query_raw, expected_type=dict, field_label="query")
            except forms.ValidationError as exc:
                self.add_error("request_query_text", exc)

        payload = None
        raw_body = None
        if body_mode == self.GuidedBodyMode.PAYLOAD:
            payload_raw = (cleaned_data.get("request_payload_text") or "").strip()
            if not payload_raw:
                self.add_error("request_payload_text", "Informe um payload JSON.")
            else:
                try:
                    payload = _parse_json_value(payload_raw, field_label="payload")
                except forms.ValidationError as exc:
                    self.add_error("request_payload_text", exc)
        elif body_mode == self.GuidedBodyMode.RAW:
            raw_body = cleaned_data.get("request_body_text") or ""
            if raw_body == "":
                self.add_error("request_body_text", "Informe o body bruto.")

        if self.errors:
            return {}

        request_template: dict[str, Any] = {"url": url}
        if headers:
            request_template["headers"] = headers
        if query:
            request_template["query"] = query
        if body_mode == self.GuidedBodyMode.PAYLOAD:
            request_template["payload"] = payload
        elif body_mode == self.GuidedBodyMode.RAW:
            request_template["body"] = raw_body
        return request_template

    def add_error(self, field, error):
        if hasattr(error, "error_dict"):
            error = error.error_dict
        if field in (None, forms.forms.NON_FIELD_ERRORS) and isinstance(error, dict):
            mapped_error = {}
            for error_field, messages in error.items():
                target_field = "expected_params_text" if error_field == "expected_params" else error_field
                mapped_error[target_field] = messages
            error = mapped_error
        if field == "expected_params":
            field = "expected_params_text"
        super().add_error(field, error)

    def save(self, commit: bool = True):
        instance = super().save(commit=False)
        instance.request_template = self.cleaned_data["request_template_text"]
        instance.output_template = self.cleaned_data["output_template_text"]
        instance.expected_params = self.cleaned_data["expected_params_text"]
        if commit:
            instance.save()
        return instance


class IntegrationTestForm(forms.Form):
    params_text = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 8, "class": "font-mono border rounded px-3 py-2 w-full"}),
        label="Parametros de teste (JSON)",
        required=False,
        initial="{}",
    )
    execute_request = forms.BooleanField(
        required=False,
        initial=True,
        label="Enviar request HTTP",
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        _apply_default_input_classes(self)

    def clean_params_text(self):
        raw_value = self.cleaned_data["params_text"]
        return _parse_json_text(raw_value or "{}", expected_type=dict, field_label="params")

class PlaybookRunForm(forms.Form):
    incident = forms.ModelChoiceField(
        queryset=Incident.objects.all(),
        widget=forms.Select(attrs={"class": "border rounded px-3 py-2 w-full"}),
    )


class IncidentRunPlaybookForm(forms.Form):
    playbook = forms.ModelChoiceField(
        queryset=Playbook.objects.filter(enabled=True),
        widget=forms.Select(attrs={"class": "border rounded px-3 py-2 w-full"}),
    )


class IncidentLifecycleForm(forms.Form):
    DATETIME_FORMAT = "%Y-%m-%dT%H:%M"

    occurred_at = forms.DateTimeField(
        required=False,
        input_formats=[DATETIME_FORMAT],
        widget=forms.DateTimeInput(
            format=DATETIME_FORMAT,
            attrs={"class": "border rounded px-3 py-2 w-full", "type": "datetime-local"},
        ),
        label="Ocorrencia",
    )
    detected_at = forms.DateTimeField(
        required=False,
        input_formats=[DATETIME_FORMAT],
        widget=forms.DateTimeInput(
            format=DATETIME_FORMAT,
            attrs={"class": "border rounded px-3 py-2 w-full", "type": "datetime-local"},
        ),
        label="Deteccao",
    )
    responded_at = forms.DateTimeField(
        required=False,
        input_formats=[DATETIME_FORMAT],
        widget=forms.DateTimeInput(
            format=DATETIME_FORMAT,
            attrs={"class": "border rounded px-3 py-2 w-full", "type": "datetime-local"},
        ),
        label="Resposta",
    )
    resolved_at = forms.DateTimeField(
        required=False,
        input_formats=[DATETIME_FORMAT],
        widget=forms.DateTimeInput(
            format=DATETIME_FORMAT,
            attrs={"class": "border rounded px-3 py-2 w-full", "type": "datetime-local"},
        ),
        label="Resolucao",
    )
    closed_at = forms.DateTimeField(
        required=False,
        input_formats=[DATETIME_FORMAT],
        widget=forms.DateTimeInput(
            format=DATETIME_FORMAT,
            attrs={"class": "border rounded px-3 py-2 w-full", "type": "datetime-local"},
        ),
        label="Encerramento",
    )

    def clean(self):
        data = super().clean()
        for key, value in data.items():
            if isinstance(value, timezone.datetime) and timezone.is_naive(value):
                data[key] = timezone.make_aware(value, timezone.get_current_timezone())
        return data


class TailwindAuthenticationForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            css = field.widget.attrs.get("class", "")
            field.widget.attrs["class"] = f"{css} border rounded px-3 py-2 w-full".strip()
            if name == "username":
                field.widget.attrs.setdefault("autofocus", True)

