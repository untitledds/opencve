from rest_framework import viewsets, permissions
from projects.models import Project, Notification
from projects.api.serializers import (
    ProjectSerializer,
    SubscriptionSerializer,
    NotificationSerializer,
)
from organizations.mixins import OrganizationIsMemberMixin
from organizations.models import Organization
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import ValidationError
from opencve.validators import slug_regex_validator


class ProjectViewSet(OrganizationIsMemberMixin, viewsets.ModelViewSet):
    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Возвращает проекты организаций, в которых состоит текущий пользователь
        return Project.objects.filter(organization__members=self.request.user)

    def perform_create(self, serializer):
        org_name = self.kwargs.get("org_name")

        # Проверка формата имени организации
        if not slug_regex_validator(org_name):
            raise ValidationError("Organization name must be a valid slug.")

        organization = get_object_or_404(
            Organization,
            members=self.request.user,
            name=org_name,
        )
        serializer.save(organization=organization)


class SubscriptionViewSet(OrganizationIsMemberMixin, viewsets.ModelViewSet):
    serializer_class = SubscriptionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Возвращает проекты организаций, в которых состоит текущий пользователь
        return Project.objects.filter(organization__members=self.request.user)

    def perform_create(self, serializer):
        project_name = self.kwargs.get("project_name")

        # Проверка формата имени проекта
        if not slug_regex_validator(project_name):
            raise ValidationError("Project name must be a valid slug.")

        project = get_object_or_404(
            Project,
            organization__members=self.request.user,
            name=project_name,
        )
        # Добавляем подписку в JSONField
        subscriptions = project.subscriptions
        subscriptions[self.kwargs["type"]] = self.kwargs["id"]
        project.subscriptions = subscriptions
        project.save()

    def perform_destroy(self, instance):
        project_name = self.kwargs.get("project_name")

        # Проверка формата имени проекта
        if not slug_regex_validator(project_name):
            raise ValidationError("Project name must be a valid slug.")

        project = get_object_or_404(
            Project,
            organization__members=self.request.user,
            name=project_name,
        )
        # Удаляем подписку из JSONField
        subscriptions = project.subscriptions
        if self.kwargs["type"] in subscriptions:
            del subscriptions[self.kwargs["type"]]
        project.subscriptions = subscriptions
        project.save()


class NotificationViewSet(OrganizationIsMemberMixin, viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        project_name = self.kwargs.get("project_name")

        # Проверка формата имени проекта
        if not slug_regex_validator(project_name):
            raise ValidationError("Project name must be a valid slug.")

        project = get_object_or_404(
            Project,
            organization__members=self.request.user,
            name=project_name,
        )
        return Notification.objects.filter(project=project)

    def perform_create(self, serializer):
        project_name = self.kwargs.get("project_name")

        # Проверка формата имени проекта
        if not slug_regex_validator(project_name):
            raise ValidationError("Project name must be a valid slug.")

        project = get_object_or_404(
            Project,
            organization__members=self.request.user,
            name=project_name,
        )
        serializer.save(project=project)
