from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "accounts"
    verbose_name = "User Accounts"

    def ready(self) -> None:
        # Import signals on app ready
        from . import signals  # noqa: F401
