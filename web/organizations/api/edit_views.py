from rest_framework import viewsets, permissions
from organizations.models import Organization, Membership
from organizations.api.serializers import OrganizationSerializer, MembershipSerializer
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import ValidationError
from opencve.validators import slug_regex_validator


class OrganizationEditViewSet(viewsets.ModelViewSet):
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Возвращает только организации, в которых состоит текущий пользователь
        return Organization.objects.filter(members=self.request.user)

    def perform_create(self, serializer):
        # Сохраняет организацию, добавляя текущего пользователя как владельца
        organization = serializer.save()
        Membership.objects.create(
            user=self.request.user,
            organization=organization,
            role=Membership.OWNER,  # Устанавливаем роль владельца
        )


class MembershipEditViewSet(viewsets.ModelViewSet):
    serializer_class = MembershipSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Возвращает только членства в организациях, где текущий пользователь является участником
        return Membership.objects.filter(organization__members=self.request.user)

    def perform_create(self, serializer):
        org_name = self.kwargs.get("org_name")

        # Проверка формата имени организации
        if not slug_regex_validator(org_name):
            raise ValidationError("Organization name must be a valid slug.")

        # Поиск организации по имени и текущему пользователю
        organization = get_object_or_404(
            Organization,
            members=self.request.user,
            name=org_name,
        )

        # Сохранение членства с указанием организации и роли (по умолчанию MEMBER)
        serializer.save(organization=organization, role=Membership.MEMBER)
