from django.apps import AppConfig


class PlaybooksConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'playbooks'
    verbose_name = 'Playbooks'

    def ready(self) -> None:
        from . import signals  # noqa: F401
