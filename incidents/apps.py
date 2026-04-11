from django.apps import AppConfig


class IncidentsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "incidents"
    verbose_name = "Incident Management"

    def ready(self) -> None:
        from . import signals  # noqa: F401
