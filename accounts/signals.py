from django.apps import apps
from django.contrib.auth.models import Group
from django.db.models.signals import post_migrate, post_save
from django.dispatch import receiver

from .models import User


ROLE_GROUP_MAP = {
    User.Roles.ADMIN: {"name": "Admin"},
    User.Roles.SOC_LEAD: {"name": "SOC Lead"},
    User.Roles.SOC_ANALYST: {"name": "SOC Analyst"},
}


@receiver(post_migrate)
def ensure_role_groups(sender, **kwargs):
    if sender.name != "accounts":
        return
    for role, meta in ROLE_GROUP_MAP.items():
        Group.objects.get_or_create(name=meta["name"])


def assign_default_group(user: User) -> None:
    group_name = ROLE_GROUP_MAP.get(user.role, {}).get("name")
    if not group_name:
        return
    group = Group.objects.filter(name=group_name).first()
    if group:
        user.groups.add(group)


@receiver(post_save, sender=User)
def ensure_group_on_create(sender, instance: User, created: bool, **kwargs):
    if created:
        assign_default_group(instance)
