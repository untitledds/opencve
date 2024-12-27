import pytest
from django.urls import reverse


def test_create_project(auth_client, create_organization):
    org = create_organization(name="Org1")
    client = auth_client()
    data = {"name": "Project1", "organization": org.id}
    response = client.post(reverse("edit-organization-projects-list",
                           kwargs={"org_name": org.name}), data, format="json")
    assert response.status_code == 201
    assert response.json()["name"] == "Project1"


def test_update_project(auth_client, create_organization, create_project):
    org = create_organization(name="Org1")
    project = create_project(name="OldProject", organization=org)
    client = auth_client()
    data = {"name": "NewProject", "organization": org.id}
    response = client.put(reverse("edit-organization-projects-detail",
                          kwargs={"org_name": org.name, "pk": project.id}), data, format="json")
    assert response.status_code == 200
    assert response.json()["name"] == "NewProject"


def test_delete_project(auth_client, create_organization, create_project):
    org = create_organization(name="Org1")
    project = create_project(name="ProjectToDelete", organization=org)
    client = auth_client()
    response = client.delete(reverse(
        "edit-organization-projects-detail", kwargs={"org_name": org.name, "pk": project.id}))
    assert response.status_code == 204
