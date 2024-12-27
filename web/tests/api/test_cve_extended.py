import pytest
from datetime import datetime
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch, PropertyMock
from cves.models import Cve
from users.models import UserTag, CveTag


# Тесты для списка CVE
class TestCveList:
    @pytest.mark.django_db
    def test_unauthenticated_user(self, client):
        """
        Тест для проверки доступа неавторизованного пользователя.
        """
        response = client.get(reverse("extended-cve-list"))
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.django_db
    def test_authenticated_user(self, auth_client):
        """
        Тест для проверки доступа авторизованного пользователя.
        """
        client = auth_client()
        response = client.get(reverse("extended-cve-list"))
        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.django_db
    def test_list_cves(self, create_cve, auth_client):
        """
        Тест для проверки списка CVE.
        """
        client = auth_client()
        response = client.get(reverse("extended-cve-list"))
        assert response.json()["results"] == []

        # Создаем тестовый CVE
        create_cve("CVE-2024-31331")
        response = client.get(reverse("extended-cve-list"))
        assert response.json()["count"] == 1
        assert response.json()["results"] == [
            {
                "cve_id": "CVE-2024-31331",
                "description": "In setMimeGroup of PackageManagerService.java, there is a possible way to hide the service from Settings due to a logic error in the code. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.",
                "cvss_score": 7.8,
                "humanized_title": "CVE-2024-31331",
            }
        ]

    @pytest.mark.django_db
    def test_list_cves_multiple(self, create_cve, auth_client):
        """
        Тест для проверки списка нескольких CVE.
        """
        client = auth_client()
        response = client.get(reverse("extended-cve-list"))
        assert response.json()["results"] == []

        create_cve("CVE-2024-31331")
        create_cve("CVE-2024-31332")
        response = client.get(reverse("extended-cve-list"))
        assert response.json()["count"] == 2
        assert response.json()["results"] == [
            {
                "cve_id": "CVE-2024-31331",
                "description": "In setMimeGroup of PackageManagerService.java, there is a possible way to hide the service from Settings due to a logic error in the code. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.",
                "cvss_score": 7.8,
                "humanized_title": "CVE-2024-31331",
            },
            {
                "cve_id": "CVE-2024-31332",
                "description": "Another CVE description.",
                "cvss_score": 8.0,
                "humanized_title": "CVE-2024-31332",
            },
        ]

    @pytest.mark.parametrize(
        "params,result",
        [
            ("", ["CVE-2024-31331"]),  # no filter
            (
                "?search=PackageManagerService",
                ["CVE-2024-31331"],
            ),  # text in description
            ("?search=31331", ["CVE-2024-31331"]),  # text in CVE ID
            ("?cvss=high", ["CVE-2024-31331"]),  # CVSS >= 7.0
            ("?cvss=low", []),  # No CVEs with low score
            ("?vendor=google", ["CVE-2024-31331"]),  # filter by vendor
            ("?product=android", ["CVE-2024-31331"]),  # filter by product
        ],
    )
    @pytest.mark.django_db
    def test_list_cves_with_filters(self, create_cve, auth_client, params, result):
        """
        Тест для проверки фильтрации CVE.
        """
        client = auth_client()
        create_cve("CVE-2024-31331")

        response = client.get(f"{reverse('extended-cve-list')}{params}")
        assert sorted(c["cve_id"] for c in response.json()["results"]) == result


# Тесты для деталей CVE
class TestCveDetail:
    @pytest.mark.django_db
    def test_get_cve(self, create_cve, auth_client):
        """
        Тест для проверки получения деталей CVE.
        """
        client = auth_client()
        response = client.get(
            reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2024-31331"})
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

        # Создаем тестовый CVE
        create_cve("CVE-2024-31331")
        response = client.get(
            reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2024-31331"})
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {
            "cve_id": "CVE-2024-31331",
            "description": "In setMimeGroup of PackageManagerService.java, there is a possible way to hide the service from Settings due to a logic error in the code. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.",
            "cvssV3_1_data": {
                "score": 7.8,
                "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            },
            "ssvc_data": {
                "options": {
                    "Automatable": "no",
                    "Exploitation": "none",
                    "Technical Impact": "total",
                },
                "version": "2.0.3",
            },
            "nvd_json": {},
            "mitre_json": {},
            "redhat_json": {},
            "vulnrichment_json": {},
            "kev_data": {},
            "cvssV2_0_data": {},
            "vendors": {"google": ["android"]},
            "weaknesses": [],
            "tags": [],
        }

    @pytest.mark.django_db
    def test_cve_detail_serializer_context_fields(
        self, create_cve, create_user, create_user_tag, create_cve_tag, auth_client
    ):
        """
        Тест для проверки полей, зависящих от контекста, в CveExtendedDetailSerializer.
        """
        client = auth_client()
        cve = create_cve("CVE-2024-31331")

        # Создаем тег для пользователя
        user = create_user()
        user_tag = create_user_tag(user=user)

        # Связываем тег с CVE
        create_cve_tag(user=user, cve=cve, tags=[user_tag.name])

        response = client.get(
            reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2024-31331"})
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["vendors"] == {"google": ["android"]}
        assert response.json()["weaknesses"] == []
        assert response.json()["tags"] == [{"color": "#000000", "description": None}]

    @pytest.mark.django_db
    def test_list_cves_by_date(self, create_cve, auth_client):
        """
        Тест для проверки фильтрации по дате.
        """
        client = auth_client()
        create_cve("CVE-2024-31331", updated_at="2024-01-01T00:00:00Z")
        create_cve("CVE-2024-31332", updated_at="2024-02-01T00:00:00Z")

        # Фильтрация по начальной дате
        response = client.get(f"{reverse('extended-cve-list')}?start_date=2024-01-15")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1
        assert response.json()["results"][0]["cve_id"] == "CVE-2024-31332"

        # Фильтрация по конечной дате
        response = client.get(f"{reverse('extended-cve-list')}?end_date=2024-01-15")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1
        assert response.json()["results"][0]["cve_id"] == "CVE-2024-31331"

    @patch("cves.models.Cve.nvd_json", new_callable=PropertyMock)
    @patch("cves.models.Cve.mitre_json", new_callable=PropertyMock)
    @patch("cves.models.Cve.vulnrichment_json", new_callable=PropertyMock)
    @pytest.mark.django_db
    def test_cve_detail_with_mocked_json(
        self, mock_nvd, mock_mitre, mock_vulnrichment, create_cve, auth_client
    ):
        """
        Тест для проверки JSON-данных с использованием моков.
        """
        # Мокируем JSON-данные
        mock_nvd.return_value = {"key": "nvd_value"}
        mock_mitre.return_value = {"key": "mitre_value"}
        mock_vulnrichment.return_value = {"key": "vulnrichment_value"}

        # Создаем CVE
        create_cve("CVE-2024-31331")

        # Получаем детали CVE
        client = auth_client()
        response = client.get(
            reverse("extended-cve-detail", kwargs={"cve_id": "CVE-2024-31331"})
        )

        # Проверяем, что мокированные данные возвращаются
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["nvd_json"] == {"key": "nvd_value"}
        assert response.json()["mitre_json"] == {"key": "mitre_value"}
        assert response.json()["vulnrichment_json"] == {"key": "vulnrichment_value"}
