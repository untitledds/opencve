import pytest
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.http.request import QueryDict
from cves.models import Cve
from cves.serializers_extended.extended import (
    CveExtendedListSerializer,
    CveExtendedDetailSerializer,
)
from users.models import User, UserTag, CveTag
from cves.utils import list_filtered_cves
import json


class CveExtendedViewSetTests(APITestCase):
    def setUp(self):
        # Создаем тестовые данные
        self.cve1 = Cve.objects.create(
            cve_id="CVE-2023-1234",
            description="Test CVE 1",
            title="Test CVE 1 Title",
            metrics={
                "cvssV3_1": {"data": {"score": 9.8}},
                "cvssV2": {"data": {"score": 7.5}},
            },
        )
        self.cve2 = Cve.objects.create(
            cve_id="CVE-2023-5678",
            description="Test CVE 2",
            title="Test CVE 2 Title",
            metrics={
                "cvssV3_1": {"data": {"score": 8.5}},
                "cvssV2": {"data": {"score": 6.5}},
            },
        )

        # Создаем тестового пользователя
        self.user = User.objects.create_user(
            username="testuser", password="testpassword", email="test@example.com"
        )

    def test_authentication_required(self):
        """
        Тест для проверки авторизации (доступ к защищенным маршрутам).
        """
        url = reverse("extended-cve-list")

        # Делаем запрос без авторизации
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Авторизуем пользователя
        self.client.force_authenticate(user=self.user)

        # Повторяем запрос
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_cve_not_found(self):
        """
        Тест для проверки 404 ошибки при запросе несуществующего CVE.
        """
        url = reverse("extended-cve-detail", args=["CVE-9999-9999"])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_cve_filtering(self):
        """
        Тест для проверки фильтрации CVE по дате.
        """
        self.client.force_authenticate(user=self.user)

        # Добавляем фильтрацию по дате
        url = (
            reverse("extended-cve-list") + "?start_date=2023-01-01&end_date=2023-12-31"
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Оба CVE попадают в диапазон дат
        self.assertEqual(len(response.data), 2)

    def test_cve_ordering(self):
        """
        Тест для проверки сортировки CVE по дате обновления.
        """
        self.client.force_authenticate(user=self.user)

        # Добавляем сортировку по дате обновления
        url = reverse("extended-cve-list") + "?ordering=-updated_at"
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["cve_id"], self.cve2.cve_id)
        self.assertEqual(response.data[1]["cve_id"], self.cve1.cve_id)

    def test_cve_list_serializer(self):
        """
        Тест для проверки сериализатора CveExtendedListSerializer.
        """
        self.client.force_authenticate(user=self.user)

        url = reverse("extended-cve-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        serializer = CveExtendedListSerializer([self.cve1, self.cve2], many=True)
        self.assertEqual(response.data, serializer.data)

    def test_cve_list_serializer_cvss_score(self):
        """
        Тест для проверки поля cvss_score в CveExtendedListSerializer.
        """
        self.client.force_authenticate(user=self.user)
        url = reverse("extended-cve-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["cvss_score"], 9.8)
        self.assertEqual(response.data[1]["cvss_score"], 8.5)

    def test_cve_list_serializer_humanized_title(self):
        """
        Тест для проверки поля humanized_title в CveExtendedListSerializer.
        """
        self.client.force_authenticate(user=self.user)
        url = reverse("extended-cve-list")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data[0]["humanized_title"], "Test Cve 1 Title")
        self.assertEqual(response.data[1]["humanized_title"], "Test Cve 2 Title")

    def test_cve_detail_serializer(self):
        """
        Тест для проверки сериализатора CveExtendedDetailSerializer.
        """
        self.client.force_authenticate(user=self.user)

        url = reverse("extended-cve-detail", args=[self.cve1.cve_id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        serializer = CveExtendedDetailSerializer(self.cve1)
        self.assertEqual(response.data, serializer.data)

    def test_cve_detail_serializer_json_fields(self):
        """
        Тест для проверки JSON-полей в CveExtendedDetailSerializer.
        """
        self.client.force_authenticate(user=self.user)
        url = reverse("extended-cve-detail", args=[self.cve1.cve_id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["nvd_json"], {})
        self.assertEqual(response.data["mitre_json"], {})
        self.assertEqual(response.data["redhat_json"], {})
        self.assertEqual(response.data["vulnrichment_json"], {})

    def test_cve_detail_serializer_metrics_fields(self):
        """
        Тест для проверки полей, связанных с метриками, в CveExtendedDetailSerializer.
        """
        self.client.force_authenticate(user=self.user)
        url = reverse("extended-cve-detail", args=[self.cve1.cve_id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["kev_data"], {})
        self.assertEqual(response.data["ssvc_data"], {})
        self.assertEqual(response.data["cvssV2_0_data"], {})
        self.assertEqual(response.data["cvssV3_1_data"], {"score": 9.8})

    def test_cve_detail_serializer_context_fields(self):
        """
        Тест для проверки полей, зависящих от контекста, в CveExtendedDetailSerializer.
        """
        self.client.force_authenticate(user=self.user)
        url = reverse("extended-cve-detail", args=[self.cve1.cve_id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["vendors"], {})
        self.assertEqual(response.data["weaknesses"], [])
        self.assertEqual(response.data["tags"], [])

    def test_delete_user_cascade(self):
        """
        Тест для проверки каскадного удаления данных пользователя.
        """
        user_tag = UserTag.objects.create(
            name="Test Tag", color="#000000", user=self.user
        )
        cve = Cve.objects.create(cve_id="CVE-2024-1234")
        CveTag.objects.create(user=self.user, cve=cve, tags=[user_tag.name])

        user_id = self.user.id
        assert User.objects.filter(id=user_id).count() == 1
        assert UserTag.objects.filter(user_id=user_id).count() == 1
        assert CveTag.objects.filter(user_id=user_id).count() == 1

        self.user.delete()

        assert User.objects.filter(id=user_id).count() == 0
        assert UserTag.objects.filter(user_id=user_id).count() == 0
        assert CveTag.objects.filter(user_id=user_id).count() == 0

    @pytest.mark.parametrize(
        "params,result",
        [
            ("", ["CVE-2023-1234", "CVE-2023-5678"]),  # no filter
            # text in description
            ("search=Test", ["CVE-2023-1234", "CVE-2023-5678"]),
            ("search=1234", ["CVE-2023-1234"]),  # text in CVE ID
            # Only CVE-2023-1234 has CVSS >= 9.0
            ("cvss=critical", ["CVE-2023-1234"]),
            ("cvss=low", []),  # No CVEs with low score
        ],
    )
    def test_list_filtered_cves(self, params, result):
        """
        Тест для проверки фильтрации CVE с использованием list_filtered_cves.
        """
        self.client.force_authenticate(user=self.user)
        filtered_cves = list_filtered_cves(QueryDict(params), self.user)
        assert sorted([c.cve_id for c in filtered_cves]) == result

    def test_list_cves_with_tag(self):
        """
        Тест для проверки фильтрации CVE по тегам.
        """
        user_tag = UserTag.objects.create(
            name="Test Tag", color="#000000", user=self.user
        )
        CveTag.objects.create(user=self.user, cve=self.cve1, tags=[user_tag.name])

        filtered_cves = list_filtered_cves(QueryDict("tag=Test Tag"), self.user)
        assert sorted([c.cve_id for c in filtered_cves]) == ["CVE-2023-1234"]
