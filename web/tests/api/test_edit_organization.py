import pytest
from django.urls import reverse


def test_unauthenticated_user(client):
    response = client.get(reverse("edit-organization-list"))
    assert response.status_code == 403


def test_list_organizations(auth_client, create_organization):
    org = create_organization(name="Org1")
    client = auth_client()
    response = client.get(reverse("edit-organization-list"))
    assert response.status_code == 200
    assert response.json()["results"][0]["name"] == "Org1"


def test_create_organization(auth_client):
    client = auth_client()
    data = {"name": "NewOrg"}
    response = client.post(
        reverse("edit-organization-list"), data, format="json")
    assert response.status_code == 201
    assert response.json()["name"] == "NewOrg"


def test_update_organization(auth_client, create_organization):
    org = create_organization(name="OldOrg")
    client = auth_client()
    data = {"name": "NewOrg"}
    response = client.put(reverse("edit-organization-detail",
                          kwargs={"pk": org.id}), data, format="json")
    assert response.status_code == 200
    assert response.json()["name"] == "NewOrg"


def test_delete_organization(auth_client, create_organization):
    org = create_organization(name="OrgToDelete")
    client = auth_client()
    response = client.delete(
        reverse("edit-organization-detail", kwargs={"pk": org.id}))
    assert response.status_code == 204


def test_get_nonexistent_organization(auth_client):
    client = auth_client()
    response = client.get(
        reverse("edit-organization-detail", kwargs={"pk": 999}))
    assert response.status_code == 404
