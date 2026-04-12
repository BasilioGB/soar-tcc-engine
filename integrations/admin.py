from django import forms
from django.contrib import admin
from django.utils import timezone

from .models import IntegrationDefinition, IntegrationSecretRef


class HttpConnectorSecretAdminForm(forms.ModelForm):
    token_value = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        required=False,
        help_text="O valor salvo nao sera exibido novamente. Preencha para criar ou rotacionar.",
        label="Token ou API key",
    )
    basic_auth_username = forms.CharField(
        required=False,
        label="Usuario do Basic Auth",
    )
    basic_auth_password = forms.CharField(
        widget=forms.PasswordInput(render_value=False),
        required=False,
        help_text="A senha salva nao sera exibida novamente. Preencha para criar ou rotacionar.",
        label="Senha do Basic Auth",
    )

    class Meta:
        model = IntegrationSecretRef
        fields = ["name", "description", "enabled", "credential_kind"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk and self.instance.credential_kind == IntegrationSecretRef.CredentialKind.BASIC_AUTH and self.instance.has_credential:
            self.fields["basic_auth_username"].initial = self.instance.get_credential().get("username", "")

    def clean(self):
        cleaned_data = super().clean()
        kind = cleaned_data.get("credential_kind") or IntegrationSecretRef.CredentialKind.TOKEN
        if not self.instance.pk:
            if kind == IntegrationSecretRef.CredentialKind.TOKEN and not cleaned_data.get("token_value"):
                self.add_error("token_value", "Informe um token ou API key.")
            if kind == IntegrationSecretRef.CredentialKind.BASIC_AUTH:
                if not cleaned_data.get("basic_auth_username"):
                    self.add_error("basic_auth_username", "Informe o usuario do Basic Auth.")
                if not cleaned_data.get("basic_auth_password"):
                    self.add_error("basic_auth_password", "Informe a senha do Basic Auth.")
        return cleaned_data

    def _post_clean(self):
        kind = self.data.get("credential_kind") or IntegrationSecretRef.CredentialKind.TOKEN
        token_value = self.data.get("token_value", "")
        basic_username = self.data.get("basic_auth_username", "")
        basic_password = self.data.get("basic_auth_password", "")
        previous_kind = self.instance.credential_kind if self.instance.pk else None
        self.instance.credential_kind = kind
        if kind == IntegrationSecretRef.CredentialKind.TOKEN and token_value:
            self.instance.set_token_credential(token_value)
        elif kind == IntegrationSecretRef.CredentialKind.BASIC_AUTH and basic_password:
            current_username = ""
            if self.instance.pk and self.instance.has_credential:
                current_username = self.instance.get_credential().get("username", "")
            self.instance.set_basic_auth_credential(basic_username or current_username, basic_password)
        elif self.instance.pk and previous_kind == kind:
            self.instance.credential_payload_encrypted = self.instance.credential_payload_encrypted
        else:
            self.instance.credential_payload_encrypted = ""
        super()._post_clean()

    def save(self, commit=True):
        instance = super().save(commit=False)
        if instance.credential_kind == IntegrationSecretRef.CredentialKind.TOKEN and self.cleaned_data.get("token_value"):
            instance.set_token_credential(self.cleaned_data["token_value"])
        elif instance.credential_kind == IntegrationSecretRef.CredentialKind.BASIC_AUTH and self.cleaned_data.get("basic_auth_password"):
            username = self.cleaned_data.get("basic_auth_username")
            current_username = ""
            if instance.pk and instance.has_credential:
                current_username = instance.get_credential().get("username", "")
            instance.set_basic_auth_credential(username or current_username, self.cleaned_data["basic_auth_password"])
        if commit:
            instance.save()
        return instance


@admin.register(IntegrationSecretRef)
class HttpConnectorSecretAdmin(admin.ModelAdmin):
    form = HttpConnectorSecretAdminForm
    list_display = ("name", "credential_kind", "enabled", "has_credential", "created_by", "rotated_by", "updated_at")
    list_filter = ("enabled", "credential_kind")
    search_fields = ("name", "description")
    readonly_fields = ("created_at", "updated_at", "created_by", "rotated_by", "rotated_at")

    def save_model(self, request, obj, form, change):
        if not change and obj.created_by_id is None:
            obj.created_by = request.user
        if form.cleaned_data.get("token_value") or form.cleaned_data.get("basic_auth_password"):
            obj.rotated_by = request.user
            obj.rotated_at = timezone.now()
        super().save_model(request, obj, form, change)


@admin.register(IntegrationDefinition)
class HttpConnectorAdmin(admin.ModelAdmin):
    list_display = (
        "action_name",
        "name",
        "method",
        "auth_strategy",
        "secret_ref",
        "enabled",
        "revision",
        "updated_at",
    )
    list_filter = ("enabled", "method", "auth_strategy")
    search_fields = ("action_name", "name", "description")
    autocomplete_fields = ("secret_ref",)
    readonly_fields = ("created_at", "updated_at")

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        form.base_fields["secret_ref"].required = True
        return form
