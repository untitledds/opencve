from django.urls import path, include
from rest_framework_nested import routers

from organizations.api.edit_views import OrganizationEditViewSet, MembershipEditViewSet
from projects.api.views import NotificationViewSet, SubscriptionViewSet, ProjectViewSet

# Маршрутизатор для редактирования (/api/edit/*)
edit_router = routers.SimpleRouter(trailing_slash=False)
edit_router.register(r"organizations", OrganizationEditViewSet,
                     basename="edit-organization")
edit_router.register(r"organizations/(?P<org_name>[^/.]+)/members",
                     MembershipEditViewSet, basename="edit-organization-members")
edit_router.register(
    r"organizations/(?P<org_name>[^/.]+)/projects", ProjectViewSet, basename="edit-organization-projects")

# Вложенные маршруты для проектов в /api/edit/*
edit_projects_router = routers.NestedSimpleRouter(
    edit_router, r"organizations/(?P<org_name>[^/.]+)/projects", lookup="project")
edit_projects_router.register(
    r"notifications", NotificationViewSet, basename="edit-project-notifications")
edit_projects_router.register(
    r"subscriptions", SubscriptionViewSet, basename="edit-project-subscriptions")

urlpatterns = [
    path("", include(edit_router.urls)),
    path("", include(edit_projects_router.urls)),
]