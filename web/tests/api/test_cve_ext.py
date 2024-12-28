import pytest
from django.contrib import auth
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from cves.models import Cve
from users.models import UserTag, CveTag


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.parametrize(
    "params,result",
    [
        ("", ["CVE-2021-44228", "CVE-2022-22965"]),  # no filter
        ("search=log4j", ["CVE-2021-44228"]),  # text in description
        ("search=spring", ["CVE-2022-22965"]),  # text in description
        ("search=44228", ["CVE-2021-44228"]),  # text in CVE ID
        ("search=oracle", ["CVE-2022-22965"]),  # text in vendors
        ("weakness=CWE-400", ["CVE-2021-44228"]),
        ("cvss=low", []),
        ("cvss=critical", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("vendor=siemens", ["CVE-2021-44228", "CVE-2022-22965"]),
        ("vendor=veritas", ["CVE-2022-22965"]),
        ("vendor=veritas&product=flex_appliance", ["CVE-2022-22965"]),
    ],
)
def test_cve_extended_viewset_filter(db, create_cve, client, params, result):
    """
    Тест для проверки фильтрации CVE через CveExtendedViewSet.
    """
    # Создаем тестовые CVE
    create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    # Получаем пользователя
    user = auth.get_user(client)

    # Выполняем запрос к API с фильтрами
    response = client.get(f"{reverse('extended-cve-list')}?{params}")

    # Проверяем статус ответа
    assert response.status_code == 200

    # Проверяем, что возвращены только ожидаемые CVE
    cve_ids = [cve["cve_id"] for cve in response.json()["results"]]
    assert sorted(cve_ids) == result


def test_cve_extended_viewset_filter_with_tag(db, create_cve, create_user):
    """
    Тест для проверки фильтрации CVE по тегу через CveExtendedViewSet.
    """
    # Создаем тестовые CVE
    cve1 = create_cve("CVE-2021-44228")
    create_cve("CVE-2022-22965")

    # Создаем пользователя и тег
    user = create_user()
    tag = UserTag.objects.create(name="test", user=user)
    CveTag.objects.create(user=user, cve=cve1, tags=[tag.name])

    # Создаем клиент API
    client = APIClient()
    client.force_authenticate(user=user)

    # Выполняем запрос к API с фильтром по тегу
    response = client.get(f"{reverse('extended-cve-list')}?tag=test")

    # Проверяем статус ответа
    assert response.status_code == 200

    # Проверяем, что возвращен только CVE-2021-44228
    cve_ids = [cve["cve_id"] for cve in response.json()["results"]]
    assert cve_ids == ["CVE-2021-44228"]
