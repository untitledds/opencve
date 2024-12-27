import pytest
from django.urls import reverse


def test_create_notification(auth_client, create_organization, create_project):
    org = create_organization(name="Org1")
    project = create_project(name="Project1", organization=org)
    client = auth_client()
    data = {"name": "Notification1", "type": "email", "project": project.id}
    response = client.post(reverse("edit-project-notifications-list", kwargs={
                           "org_name": org.name, "project_pk": project.id}), data, format="json")
    assert response.status_code == 201
    assert response.json()["name"] == "Notification1"


def test_delete_notification(auth_client, create_organization, create_project, create_notification):
    org = create_organization(name="Org1")
    project = create_project(name="Project1", organization=org)
    notification = create_notification(
        name="NotificationToDelete", project=project)
    client = auth_client()
    response = client.delete(reverse("edit-project-notifications-detail", kwargs={
                             "org_name": org.name, "project_pk": project.id, "pk": notification.id}))
    assert response.status_code == 204
