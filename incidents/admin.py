from django.contrib import admin

from .models import (
    Artifact,
    CommunicationLog,
    CustomFieldDefinition,
    Incident,
    IncidentRelation,
    IncidentTask,
    TimelineEntry,
)


class TimelineInline(admin.TabularInline):
    model = TimelineEntry
    extra = 0
    readonly_fields = ("entry_type", "message", "created_by", "created_at")
    can_delete = False


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "title",
        "severity",
        "status",
        "classification",
        "risk_score",
        "assignee",
        "created_at",
    )
    list_filter = ("severity", "status", "classification", "data_classification", "created_at")
    search_fields = ("title", "description", "labels")
    raw_id_fields = ("created_by", "assignee")
    readonly_fields = ("created_at", "updated_at")
    inlines = [TimelineInline]
    readonly_fields = ("created_at", "updated_at")


@admin.register(Artifact)
class ArtifactAdmin(admin.ModelAdmin):
    list_display = ("type", "value", "file", "size", "created_at", "incident_count")
    search_fields = ("value", "attributes")
    list_filter = ("type",)

    @admin.display(description="Incidentes")
    def incident_count(self, obj):
        return obj.incidents.count()


@admin.register(TimelineEntry)
class TimelineEntryAdmin(admin.ModelAdmin):
    list_display = ("incident", "entry_type", "created_by", "created_at")
    search_fields = ("message",)
    list_filter = ("entry_type", "created_at")
    raw_id_fields = ("incident", "created_by")


@admin.register(IncidentTask)
class IncidentTaskAdmin(admin.ModelAdmin):
    list_display = ("incident", "title", "owner", "eta", "done", "created_at")
    list_filter = ("done",)
    search_fields = ("title",)
    raw_id_fields = ("incident", "owner", "created_by")


@admin.register(IncidentRelation)
class IncidentRelationAdmin(admin.ModelAdmin):
    list_display = ("from_incident", "relation_type", "to_incident", "created_by", "created_at")
    list_filter = ("relation_type",)
    raw_id_fields = ("from_incident", "to_incident", "created_by")
    search_fields = ("from_incident__title", "to_incident__title")


@admin.register(CommunicationLog)
class CommunicationLogAdmin(admin.ModelAdmin):
    list_display = ("incident", "channel", "recipient_team", "recipient_user", "created_by", "created_at")
    list_filter = ("channel",)
    raw_id_fields = ("incident", "recipient_user", "created_by")
    search_fields = ("message", "recipient_team")


@admin.register(CustomFieldDefinition)
class CustomFieldDefinitionAdmin(admin.ModelAdmin):
    list_display = (
        "internal_id",
        "display_name",
        "field_type",
        "is_active",
        "is_deleted",
        "created_by",
        "updated_by",
        "updated_at",
    )
    list_filter = ("field_type", "is_active", "is_deleted")
    search_fields = ("internal_id", "display_name")
    raw_id_fields = ("created_by", "updated_by")
