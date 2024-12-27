import pytest
from django.urls import reverse


def test_create_subscription(auth_client, create_organization, create_project):
    org = create_organization(name="Org1")
    project = create_project(name="Project1", organization=org)
    client = auth_client()
    data = {"type": "vendor", "id": "vendor1"}
    response = client.post(reverse("edit-project-subscriptions-list", kwargs={
                           "org_name": org.name, "project_pk": project.id}), data, format="json")
    assert response.status_code == 201
    assert response.json()["type"] == "vendor"


def test_delete_subscription(auth_client, create_organization, create_project):
    org = create_organization(name="Org1")
    project = create_project(name="Project1", organization=org)
    client = auth_client()
    data = {"type": "vendor", "id": "vendor1"}
    response = client.post(reverse("edit-project-subscriptions-list", kwargs={
                           "org_name": org.name, "project_pk": project.id}), data, format="json")
    subscription_id = response.json()["id"]
    response = client.delete(reverse("edit-project-subscriptions-detail", kwargs={
                             "org_name": org.name, "project_pk": project.id, "pk": subscription_id}))
    assert response.status_code == 204
