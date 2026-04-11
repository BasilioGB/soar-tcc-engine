from rest_framework import serializers

from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "display_name",
            "role",
            "timezone",
            "is_active",
            "date_joined",
        ]
        read_only_fields = ["id", "is_active", "date_joined"]
