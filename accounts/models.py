from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    class Roles(models.TextChoices):
        ADMIN = "ADMIN", "Admin"
        SOC_LEAD = "SOC_LEAD", "SOC Lead"
        SOC_ANALYST = "SOC_ANALYST", "SOC Analyst"

    role = models.CharField(max_length=32, choices=Roles.choices, default=Roles.SOC_ANALYST)
    display_name = models.CharField(max_length=128, blank=True)
    timezone = models.CharField(max_length=64, default="UTC", help_text="IANA timezone name")

    def __str__(self) -> str:
        return self.display_name or self.get_full_name() or self.username

    def save(self, *args, **kwargs):
        if not self.display_name:
            full_name = self.get_full_name()
            self.display_name = full_name or self.username
        return super().save(*args, **kwargs)

    @property
    def is_admin(self) -> bool:
        return self.role == self.Roles.ADMIN

    @property
    def is_soc_lead(self) -> bool:
        return self.role == self.Roles.SOC_LEAD

    @property
    def is_soc_analyst(self) -> bool:
        return self.role == self.Roles.SOC_ANALYST
