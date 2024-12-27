import pytest
from datetime import datetime
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch, PropertyMock
from cves.models import Cve


# Тесты для фильтрации CVE
class TestCveFilter:
    @pytest.mark.django_db
    def test_cve_filter_by_vendor_case_insensitive(self, create_cve, auth_client):
        """
        Тест для проверки фильтрации по вендору без учета регистра.
        """
        client = auth_client()

        # Создаем CVE с вендорами
        create_cve("CVE-2022-22965")  # Вендоры будут взяты из JSON-файла

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
        client = auth_client()

        # Создаем CVE с продуктами
        create_cve("CVE-2022-22965")  # Продукты и вендоры будут взяты из JSON-файла

        # Проверяем фильтрацию по продукту с разным регистром
        response = client.get(f"{reverse('extended-cve-list')}?product=flex_appliance")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1

        response = client.get(f"{reverse('extended-cve-list')}?product=FLex_appliaCE")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1

        response = client.get(f"{reverse('extended-cve-list')}?product=fleX_AppLiance")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1

    @pytest.mark.django_db
    def test_cve_filter_by_date(self, create_cve, auth_client):
        """
        Тест для проверки фильтрации по дате.
        """
        client = auth_client()

        # Создаем CVE с разными датами обновления
        create_cve(
            "CVE-2022-22965"
        )  # Дата обновления: 2024-07-31T20:10:19.936000+00:00
        create_cve(
            "CVE-2022-20698"
        )  # Дата обновления: 2024-11-06T16:32:32.016000+00:00

        # Фильтрация по начальной дате
        response = client.get(f"{reverse('extended-cve-list')}?start_date=2024-07-31")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 2

        # Фильтрация по конечной дате
        response = client.get(f"{reverse('extended-cve-list')}?end_date=2024-07-31")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1
        assert response.json()["results"][0]["cve_id"] == "CVE-2022-22965"

    @pytest.mark.django_db
    def test_cve_filter_by_cvss(self, create_cve, auth_client):
        """
        Тест для проверки фильтрации по CVSS.
        """
        client = auth_client()

        # Создаем CVE с разными уровнями CVSS
        create_cve("CVE-2022-22965")  # CVSS-оценка: 9.8
        create_cve("CVE-2022-20698")  # CVSS-оценка: 7.5

        # Фильтрация по высокому уровню CVSS
        response = client.get(f"{reverse('extended-cve-list')}?cvss=high")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1
        assert response.json()["results"][0]["cve_id"] == "CVE-2022-22965"

        # Фильтрация по среднему уровню CVSS
        response = client.get(f"{reverse('extended-cve-list')}?cvss=medium")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()["results"]) == 1
        assert response.json()["results"][0]["cve_id"] == "CVE-2022-20698"
