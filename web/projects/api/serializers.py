from rest_framework import serializers
from projects.models import Project, Notification


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ["id", "name", "description", "subscriptions", "active"]
        read_only_fields = ["organization"]


class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ["id", "subscriptions"]
        read_only_fields = ["subscriptions"]


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ["id", "name", "type",
                  "configuration", "is_enabled", "project"]
        read_only_fields = ["project"]
