from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets = BaseUserAdmin.fieldsets + (
        ("Role & Profile", {"fields": ("role", "display_name", "timezone")}),
    )
    list_display = ("username", "email", "role", "is_active", "last_login")
    list_filter = ("role", "is_active", "is_staff")
    search_fields = ("username", "email", "display_name")
    ordering = ("username",)
