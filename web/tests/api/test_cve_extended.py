import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIRequestFactory
from cves.models import Cve
from cves.serializers_extended.extended import (
    CveExtendedListSerializer,
    CveExtendedDetailSerializer,
)
from cves.views_extended.extended import CveExtendedViewSet
from users.models import UserTag, CveTag
from unittest.mock import patch


# Тесты для проверки использования CveExtendedListSerializer
@pytest.mark.django_db
def test_cve_extended_list_serializer_used(create_cve):
    """
    Тест для проверки, что для списка CVE используется CveExtendedListSerializer.
    """
    # Создаем тестовый CVE
    create_cve("CVE-2022-22965")

    # Создаем экземпляр CveExtendedViewSet
    viewset = CveExtendedViewSet()

    # Создаем фиктивный запрос для списка CVE
    factory = APIRequestFactory()
    request = factory.get("/api/extended/cve/")
    viewset.request = request
    viewset.action = "list"

    # Получаем сериализатор
    serializer_class = viewset.get_serializer_class()

    # Проверяем, что используется CveExtendedListSerializer
    assert serializer_class == CveExtendedListSerializer


@pytest.mark.django_db
def test_cve_extended_list_serializer_data(create_cve):
    """
    Тест для проверки данных, возвращаемых CveExtendedListSerializer.
    """
    # Создаем тестовый CVE
    cve = create_cve("CVE-2022-22965")

    # Создаем экземпляр CveExtendedListSerializer
    serializer = CveExtendedListSerializer(cve)

    # Проверяем, что данные сериализованы корректно
    assert serializer.data == {
        "cve_id": "CVE-2022-22965",
        "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.",
        "cvss_score": 9.8,
        "humanized_title": "CVE-2022-22965",
    }


@pytest.mark.django_db
def test_cve_extended_list_view(auth_client, create_cve):
    """
    Тест для проверки, что список CVE возвращает данные в формате CveExtendedListSerializer.
    """
    client = auth_client()

    # Создаем тестовый CVE
    create_cve("CVE-2022-22965")

    # Выполняем запрос на получение списка CVE
    response = client.get(reverse("extended-cve-list"))

    # Проверяем статус ответа
    assert response.status_code == status.HTTP_200_OK

    # Проверяем, что данные соответствуют формату CveExtendedListSerializer
    assert response.json()["results"] == [
        {
            "cve_id": "CVE-2022-22965",
            "description": "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.",
            "cvss_score": 9.8,
            "humanized_title": "CVE-2022-22965",
        }
    ]


# Тесты для фильтрации CVE
@pytest.mark.parametrize(
    "params,expected_cve_ids",
    [
        # Без фильтра
        ("", ["CVE-2022-22965", "CVE-2022-20698"]),
        # Фильтрация по дате
        (
            "?start_date=2024-07-31",
            ["CVE-2022-22965", "CVE-2022-20698"],
        ),  # Оба CVE после 2024-07-31
        (
            "?end_date=2024-07-31",
            ["CVE-2022-22965"],
        ),  # Только CVE-2022-22965 до 2024-07-31
        # Фильтрация по вендору
        ("?vendor=vmware", ["CVE-2022-22965"]),  # Вендор "vmware"
        ("?vendor=clamav", ["CVE-2022-20698"]),  # Вендор "clamav"
        # Фильтрация по продукту
        ("?product=spring_framework", ["CVE-2022-22965"]),  # Продукт "spring_framework"
        ("?product=clamav", ["CVE-2022-20698"]),  # Продукт "clamav"
        # Фильтрация по CVSS
        ("?cvss=high", ["CVE-2022-22965"]),  # CVSS >= 7.0
        ("?cvss=medium", ["CVE-2022-20698"]),  # CVSS >= 4.0 и < 7.0
        ("?cvss=critical", ["CVE-2022-22965"]),  # CVSS >= 9.0
        # Комбинированные фильтры
        (
            "?vendor=vmware&cvss=high",
            ["CVE-2022-22965"],
        ),  # Вендор "vmware" и CVSS >= 7.0
        (
            "?product=clamav&cvss=medium",
            ["CVE-2022-20698"],
        ),  # Продукт "clamav" и CVSS >= 4.0 и < 7.0
    ],
)
@pytest.mark.django_db
def test_list_cves_with_filters(create_cve, auth_client, params, expected_cve_ids):
    """
    Тест для проверки фильтрации CVE.
    """
    client = auth_client()

    # Создаем тестовые CVE
    create_cve("CVE-2022-22965")  # CVSS: 9.8, вендоры: vmware, oracle, cisco
    create_cve("CVE-2022-20698")  # CVSS: 7.5, вендоры: clamav

    # Выполняем запрос с фильтрами
    response = client.get(f"{reverse('extended-cve-list')}{params}")

    # Проверяем статус ответа
    assert response.status_code == status.HTTP_200_OK

    # Проверяем, что возвращены только ожидаемые CVE
    cve_ids = [cve["cve_id"] for cve in response.json()["results"]]
    assert sorted(cve_ids) == sorted(expected_cve_ids)


@pytest.mark.django_db
def test_cve_filter_by_vendor_case_insensitive(create_cve, auth_client):
    """
    Тест для проверки фильтрации по вендору без учета регистра.
    """
    client = auth_client()

    # Создаем CVE с вендорами
    create_cve("CVE-2022-22965")  # Вендоры: vmware, oracle, cisco

    # Проверяем фильтрацию по вендору с разным регистром
    response = client.get(f"{reverse('extended-cve-list')}?vendor=vmware")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["results"]) == 1

    response = client.get(f"{reverse('extended-cve-list')}?vendor=Vmware")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["results"]) == 1

    response = client.get(f"{reverse('extended-cve-list')}?vendor=VMWARE")
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["results"]) == 1


# Тесты для деталей CVE
@pytest.mark.django_db
def test_cve_detail_serializer_context_fields(create_cve, create_user, auth_client):
    """
    Тест для проверки полей, зависящих от контекста, в CveExtendedDetailSerializer.
    """
    client = auth_client()

    # Создаем пользователя и тег
    user = create_user(username="john", email="john@doe.com")
    user_tag = user.tags.first()
    assert user_tag.name == "log4j"
    assert user_tag.color == "#0A0031"
    assert user_tag.description == "This is an example tag"

    # Создаем CVE
    cve = create_cve("CVE-2022-22965")

    # Связываем тег с CVE
    cve_tag = CveTag.objects.create(tags=[user_tag.name], cve=cve, user=user)

    # Получаем детали CVE
    response = client.get(
        reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2022-22965"})
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["tags"] == [
        {
            "color": "#0A0031",
            "description": "This is an example tag",
        }
    ]


# Тест для обработки ошибок
@pytest.mark.django_db
def test_cve_detail_internal_server_error(auth_client):
    """
    Тест для проверки обработки 500 ошибки при получении деталей CVE.
    """
    client = auth_client()

    # Мокируем ошибку сервера
    with patch(
        "cves.views_extended.extended.CveExtendedViewSet.retrieve",
        side_effect=Exception("Internal Server Error"),
    ):
        response = client.get(
            reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2022-22965"})
        )
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert response.json() == {"error": "Internal server error"}
