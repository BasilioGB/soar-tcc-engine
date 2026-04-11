from __future__ import annotations

import json
from typing import Any

from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone

from incidents.models import Artifact, Incident
from playbooks.models import Playbook
from playbooks.dsl import ParseError, parse_playbook
from playbooks.validation import validate_playbook_semantics


class IncidentFilterForm(forms.Form):
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
        fields = ["name", "description", "enabled", "type", "mode"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.dsl:
            self.fields["dsl_text"].initial = json.dumps(self.instance.dsl, indent=2)
        if self.instance and self.instance.type:
            self.fields["type"].initial = self.instance.type
        if self.instance and self.instance.mode:
            self.fields["mode"].initial = self.instance.mode
        for name, field in self.fields.items():
            if name == "enabled":
                field.widget.attrs.setdefault("class", "")
            else:
                css = field.widget.attrs.get("class", "")
                field.widget.attrs["class"] = f"{css} border rounded px-3 py-2 w-full".strip()

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

