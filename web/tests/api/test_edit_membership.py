import pytest
from django.urls import reverse


def test_create_membership(auth_client, create_organization, create_user):
    org = create_organization(name="Org1")
    user = create_user(username="user1")
    client = auth_client()
    data = {"user": user.id, "role": "member"}
    response = client.post(reverse("edit-organization-members-list",
                           kwargs={"org_name": org.name}), data, format="json")
    assert response.status_code == 201
    assert response.json()["role"] == "member"


def test_delete_membership(auth_client, create_organization, create_user):
    org = create_organization(name="Org1")
    user = create_user(username="user1")
    client = auth_client()
    data = {"user": user.id, "role": "member"}
    response = client.post(reverse("edit-organization-members-list",
                           kwargs={"org_name": org.name}), data, format="json")
    membership_id = response.json()["id"]
    response = client.delete(reverse(
        "edit-organization-members-detail", kwargs={"org_name": org.name, "pk": membership_id}))
    assert response.status_code == 204
