import pytest
from django.urls import reverse
from datetime import datetime


def test_unauthenticated_user(client, auth_client):
    """
    Тест для проверки доступа неавторизованного пользователя.
    """
    response = client.get(reverse("extended-cve-list"))
    assert response.status_code == 403

    client = auth_client()
    response = client.get(reverse("extended-cve-list"))
    assert response.status_code == 200


@pytest.mark.django_db
def test_list_extended_cves(create_cve, auth_client):
    """
    Тест для проверки списка CVE в расширенном API.
    """
    client = auth_client()
    response = client.get(reverse("extended-cve-list"))
    assert response.json()["results"] == []

    create_cve("CVE-2021-44228")
    response = client.get(reverse("extended-cve-list"))
    assert response.json()["count"] == 1

    # Проверка наличия всех полей согласно сериализации
    cve = response.json()["results"][0]
    assert "created_at" in cve
    assert "updated_at" in cve
    assert "cve_id" in cve
    assert "description" in cve
    assert "cvss_score" in cve
    assert "cvss_human_score" in cve
    assert "humanized_title" in cve

    create_cve("CVE-2022-22965")
    response = client.get(reverse("extended-cve-list"))
    assert response.json()["count"] == 2

    # Проверка наличия всех полей для каждого CVE
    for cve in response.json()["results"]:
        assert "created_at" in cve
        assert "updated_at" in cve
        assert "cve_id" in cve
        assert "description" in cve
        assert "cvss_score" in cve
        assert "cvss_human_score" in cve
        assert "humanized_title" in cve


@pytest.mark.parametrize(
    "params,result",
    [
        ("", ["CVE-2021-44228", "CVE-2022-22965"]),  # no filter
        ("?search=log4j", ["CVE-2021-44228"]),  # text in description
        ("?search=spring", ["CVE-2022-22965"]),  # text in description
        ("?search=44228", ["CVE-2021-44228"]),  # test in CVE ID
        ("?search=oracle", ["CVE-2022-22965"]),  # text in vendors
        ("?weakness=CWE-400", ["CVE-2021-44228"]),
        ("?cvss=low", []),
        ("?cvss=critical", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("?vendor=siemens", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("?vendor=veritas", ["CVE-2022-22965"]),
        ("?vendor=veritas&product=flex_appliance", ["CVE-2022-22965"]),
    ],
)
def test_list_extended_cves_with_filters(create_cve, auth_client, params, result):
    """
    Тест для проверки фильтрации CVE в расширенном API.
    """
    client = auth_client()
    response = client.get(reverse("extended-cve-list"))
    assert response.json()["results"] == []

    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    response = client.get(f"{reverse('extended-cve-list')}{params}")
    assert sorted(c["cve_id"] for c in response.json()["results"]) == result

    # Проверка наличия всех полей для каждого CVE
    for cve in response.json()["results"]:
        assert "created_at" in cve
        assert "updated_at" in cve
        assert "cve_id" in cve
        assert "description" in cve
        assert "cvss_score" in cve
        assert "cvss_human_score" in cve
        assert "humanized_title" in cve


def test_list_extended_cves_filtering_by_not_existing_vendors(create_cve, auth_client):
    """
    Тест для проверки фильтрации по несуществующим вендорам и продуктам.
    """
    client = auth_client()
    create_cve("CVE-2021-44228")

    response = client.get(f"{reverse('extended-cve-list')}?vendor=siemens")
    assert response.status_code == 200
    response = client.get(f"{reverse('extended-cve-list')}?vendor=foobar")
    assert response.status_code == 404

    response = client.get(
        f"{reverse('extended-cve-list')}?vendor=siemens&product=mendix"
    )
    assert response.status_code == 200
    response = client.get(
        f"{reverse('extended-cve-list')}?vendor=siemens&product=foobar"
    )
    assert response.status_code == 404


@pytest.mark.django_db
def test_get_extended_cve(create_cve, open_file, auth_client):
    """
    Тест для проверки получения деталей CVE в расширенном API.
    """
    client = auth_client()
    response = client.get(
        reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2021-44228"})
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "No Cve matches the given query."}

    create_cve("CVE-2021-44228")
    response = client.get(
        reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2021-44228"})
    )
    assert response.status_code == 200

    # Проверка наличия всех полей согласно сериализации
    cve = response.json()
    assert "created_at" in cve
    assert "updated_at" in cve
    assert "cve_id" in cve
    assert "title" in cve
    assert "humanized_title" in cve
    assert "description" in cve
    assert "metrics" in cve
    assert "weaknesses" in cve
    assert "vendors" in cve
    assert "nvd_json" in cve
    assert "mitre_json" in cve
    assert "redhat_json" in cve
    assert "vulnrichment_json" in cve
    assert "tags" in cve

    expected_result = open_file("serialized_cves/CVE-2021-44228.json")
    assert response.json() == expected_result


@pytest.mark.django_db
def test_cve_dates(create_cve, auth_client):
    client = auth_client()
    create_cve("CVE-2022-20698")
    response = client.get(
        reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2022-20698"})
    )
    assert response.json()["created_at"] == "2022-01-14T05:15:11.361911Z"
    assert response.json()["updated_at"] == "2024-11-06T16:32:32.016000Z"

    create_cve("CVE-2022-22965")
    response = client.get(
        reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2022-22965"})
    )
    assert response.json()["created_at"] == "2022-03-30T00:00:00Z"
    assert response.json()["updated_at"] == "2024-07-31T20:10:19.936000Z"
