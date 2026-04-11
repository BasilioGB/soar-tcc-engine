from django.contrib import admin

from .models import IntegrationDefinition, IntegrationSecretRef


@admin.register(IntegrationSecretRef)
class IntegrationSecretRefAdmin(admin.ModelAdmin):
    list_display = ("name", "provider", "reference", "enabled", "updated_at")
    list_filter = ("provider", "enabled")
    search_fields = ("name", "reference", "description")
    readonly_fields = ("created_at", "updated_at")


@admin.register(IntegrationDefinition)
class IntegrationDefinitionAdmin(admin.ModelAdmin):
    list_display = (
        "action_name",
        "name",
        "method",
        "auth_type",
        "secret_ref",
        "enabled",
        "revision",
        "updated_at",
    )
    list_filter = ("enabled", "method", "auth_type")
    search_fields = ("action_name", "name", "description")
    autocomplete_fields = ("secret_ref",)
    readonly_fields = ("created_at", "updated_at")

