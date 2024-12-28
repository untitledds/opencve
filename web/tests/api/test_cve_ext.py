import pytest
from django.urls import reverse
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model


@pytest.mark.django_db
def test_unauthenticated_user(client):
    """
    Тест для проверки доступа неавторизованного пользователя.
    """
    response = client.get(reverse("extended-cve-list"))
    assert response.status_code == 403  # Доступ запрещен

    # Создаем пользователя и авторизуем его
    User = get_user_model()
    user = User.objects.create_user(username="testuser", password="testpass")
    client = APIClient()
    client.force_authenticate(user=user)

    # Проверяем доступ авторизованного пользователя
    response = client.get(reverse("extended-cve-list"))
    assert response.status_code == 200  # Доступ разрешен


@pytest.mark.django_db
def test_list_cves(create_cve, auth_client):
    """
    Тест для проверки списка CVE.
    """
    client = auth_client()
    response = client.get(reverse("extended-cve-list"))
    assert response.json()["results"] == []

    # Создаем CVE и проверяем, что он появляется в списке
    create_cve("CVE-2021-44228")
    response = client.get(reverse("extended-cve-list"))
    assert response.json()["count"] == 1
    assert response.json()["results"] == [
        {
            "created_at": "2021-12-10T00:00:00Z",
            "updated_at": "2024-07-24T17:08:24.167000Z",
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.",
            "cvss_score": 10.0,
            "cvss_human_score": "Critical",
            "humanized_title": "Apache log4j2 jndi features do not protect against attacker controlled ldap and other jndi related endpoints",
        }
    ]


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
@pytest.mark.django_db
def test_list_cves_with_filters(create_cve, auth_client, params, result):
    """
    Тест для проверки фильтрации CVE.
    """
    client = auth_client()
    response = client.get(reverse("extended-cve-list"))
    assert response.json()["results"] == []

    # Создаем тестовые CVE
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    # Выполняем запрос с фильтрами
    response = client.get(f"{reverse('extended-cve-list')}{params}")
    assert sorted(c["cve_id"] for c in response.json()["results"]) == result


@pytest.mark.django_db
def test_list_cves_filtering_by_not_existing_vendors(create_cve, auth_client):
    """
    Тест для проверки фильтрации по несуществующим вендорам и продуктам.
    """
    client = auth_client()
    create_cve("CVE-2021-44228")

    # Проверяем фильтрацию по существующему вендору
    response = client.get(f"{reverse('extended-cve-list')}?vendor=siemens")
    assert response.status_code == 200

    # Проверяем фильтрацию по несуществующему вендору
    response = client.get(f"{reverse('extended-cve-list')}?vendor=foobar")
    assert response.status_code == 404


@pytest.mark.django_db
def test_get_cve(create_cve, open_file, auth_client):
    """
    Тест для проверки получения деталей CVE.
    """
    client = auth_client()

    # Проверяем, что CVE не существует
    response = client.get(reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2021-44228"}))
    assert response.status_code == 404

    # Создаем CVE и проверяем, что он возвращается
    create_cve("CVE-2021-44228")
    response = client.get(reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2021-44228"}))
    assert response.status_code == 200
    expected_result = open_file("serialized_cves/CVE-2021-44228.json")
    assert response.json() == expected_result
