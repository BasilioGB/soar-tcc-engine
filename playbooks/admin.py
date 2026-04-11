from django.contrib import admin

from .models import (
    Execution,
    ExecutionLog,
    ExecutionStepResult,
    Playbook,
    PlaybookFilter,
    PlaybookStep,
    PlaybookTrigger,
)


class PlaybookStepInline(admin.TabularInline):
    model = PlaybookStep
    extra = 0
    fields = ("order", "name", "action", "config")


class PlaybookTriggerInline(admin.TabularInline):
    model = PlaybookTrigger
    extra = 0
    fields = ("event", "filters", "active")


class PlaybookFilterInline(admin.TabularInline):
    model = PlaybookFilter
    extra = 0
    fields = ("target", "conditions")


@admin.register(Playbook)
class PlaybookAdmin(admin.ModelAdmin):
    list_display = ("name", "type", "mode", "enabled", "created_at", "updated_at")
    list_filter = ("enabled", "type", "mode")
    search_fields = ("name", "description")
    inlines = [PlaybookStepInline, PlaybookTriggerInline, PlaybookFilterInline]
    readonly_fields = ("created_at", "updated_at")


class ExecutionLogInline(admin.TabularInline):
    model = ExecutionLog
    extra = 0
    readonly_fields = ("ts", "level", "message", "step_name")


class ExecutionStepResultInline(admin.TabularInline):
    model = ExecutionStepResult
    extra = 0
    readonly_fields = (
        "step_order",
        "step_name",
        "status",
        "started_at",
        "finished_at",
        "duration_ms",
        "resolved_input",
        "result",
        "error_class",
        "error_message",
        "skipped_reason",
    )


@admin.register(Execution)
class ExecutionAdmin(admin.ModelAdmin):
    list_display = ("id", "playbook", "incident", "status", "started_at", "finished_at")
    list_filter = ("status", "playbook")
    search_fields = ("playbook__name", "incident__title")
    inlines = [ExecutionLogInline, ExecutionStepResultInline]
    raw_id_fields = ("playbook", "incident", "created_by")


@admin.register(ExecutionLog)
class ExecutionLogAdmin(admin.ModelAdmin):
    list_display = ("execution", "level", "step_name", "ts")
    list_filter = ("level",)
    search_fields = ("message", "step_name")


@admin.register(ExecutionStepResult)
class ExecutionStepResultAdmin(admin.ModelAdmin):
    list_display = ("execution", "step_order", "step_name", "status", "duration_ms")
    list_filter = ("status",)
    search_fields = ("step_name", "error_class", "error_message")
