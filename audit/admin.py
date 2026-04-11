from django.contrib import admin
from .models import ActionLog


@admin.register(ActionLog)
class ActionLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'verb', 'actor', 'target_content_type')
    list_filter = ('verb', 'timestamp')
    search_fields = ('verb', 'meta')
    autocomplete_fields = ('actor',)
