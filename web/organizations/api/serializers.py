from rest_framework import serializers
from organizations.models import Organization, Membership

class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ["id", "name"]

class MembershipSerializer(serializers.ModelSerializer):
    class Meta:
        model = Membership
        fields = ["id", "user", "organization", "role", "date_invited", "date_joined"]
        read_only_fields = ["organization", "date_invited", "date_joined"]  # Поля только для чтения