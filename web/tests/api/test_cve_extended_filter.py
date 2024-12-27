import pytest
from datetime import datetime
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch, PropertyMock
from cves.models import Cve
from cves.views_extended.extended import CveFilter


# Тесты для фильтрации CVE
class TestCveFilter:
    @pytest.mark.django_db
    def test_cve_filter_by_vendor_case_insensitive(self, create_cve, auth_client):
        """
        Тест для проверки фильтрации по вендору без учета регистра.
        """
        # Создаем CVE с вендорами
        create_cve("CVE-2022-22965", vendors=["Google", "google", "GOOGLE"])

        client = auth_client()

        # Проверяем фильтрацию по вендору с разным регистром
        response = client.get(f"{reverse('extended-cve-list')}?vendor=Google")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1

        response = client.get(f"{reverse('extended-cve-list')}?vendor=google")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1

        response = client.get(f"{reverse('extended-cve-list')}?vendor=GOOGLE")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1

    @pytest.mark.django_db
    def test_cve_filter_by_product_case_insensitive(self, create_cve, auth_client):
        """
        Тест для проверки фильтрации по продукту без учета регистра.
        """
        # Создаем CVE с продуктами
        create_cve("CVE-2022-22965", vendors=["Google$PRODUCT$Android"])

        client = auth_client()

        # Проверяем фильтрацию по продукту с разным регистром
        response = client.get(f"{reverse('extended-cve-list')}?product=Android")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1

        response = client.get(f"{reverse('extended-cve-list')}?product=android")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1

        response = client.get(f"{reverse('extended-cve-list')}?product=ANDROID")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1

    @pytest.mark.django_db
    def test_cve_filter_by_date(self, create_cve, auth_client):
        """
        Тест для проверки фильтрации по дате.
        """
        # Создаем CVE с разными датами
        create_cve("CVE-2022-22965", updated_at=datetime(2022, 1, 1))
        create_cve("CVE-2023-22490", updated_at=datetime(2023, 1, 1))

        client = auth_client()

        # Фильтрация по начальной дате
        response = client.get(f"{reverse('extended-cve-list')}?start_date=2022-01-01")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 2

        # Фильтрация по конечной дате
        response = client.get(f"{reverse('extended-cve-list')}?end_date=2022-12-31")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1

    @pytest.mark.django_db
    def test_cve_filter_by_cvss(self, create_cve, auth_client):
        """
        Тест для проверки фильтрации по CVSS.
        """
        # Создаем CVE с разными уровнями CVSS
        create_cve("CVE-2022-22965", metrics={"cvssV3_1": {"data": {"score": 7.5}}})
        create_cve("CVE-2023-22490", metrics={"cvssV3_1": {"data": {"score": 5.0}}})

        client = auth_client()

        # Фильтрация по высокому уровню CVSS
        response = client.get(f"{reverse('extended-cve-list')}?cvss=high")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1
        assert response.json()["results"][0]["cve_id"] == "CVE-2022-22965"

        # Фильтрация по среднему уровню CVSS
        response = client.get(f"{reverse('extended-cve-list')}?cvss=medium")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1
        assert response.json()["results"][0]["cve_id"] == "CVE-2023-22490"
