import pytest
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.http.request import QueryDict
from cves.models import Cve
from cves.serializers.extended import CveExtendedListSerializer, CveDetailSerializer
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
            cvssV3_1={"score": 9.8},
            cvssV2={"score": 7.5}
        )
        self.cve2 = Cve.objects.create(
            cve_id="CVE-2023-5678",
            description="Test CVE 2",
            title="Test CVE 2 Title",
            cvssV3_1={"score": 8.5},
            cvssV2={"score": 6.5}
        )

        # Создаем тестового пользователя
        self.user = User.objects.create_user(
            username="testuser",
            password="testpassword",
            email="test@example.com"
        )

    def test_authentication_required(self):
        """
        Тест для проверки авторизации (доступ к защищенным маршрутам).
        """
        # Получаем URL для списка CVE
        url = reverse("extended-cve-list")

        # Делаем запрос без авторизации
        response = self.client.get(url)

        # Проверяем, что возвращается 403 (или 401, в зависимости от настроек)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Авторизуем пользователя
        self.client.force_authenticate(user=self.user)

        # Повторяем запрос
        response = self.client.get(url)

        # Проверяем, что теперь доступ разрешен
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_cve_not_found(self):
        """
        Тест для проверки 404 ошибки при запросе несуществующего CVE.
        """
        # Пытаемся получить несуществующий CVE
        url = reverse("extended-cve-detail", args=["CVE-9999-9999"])
        response = self.client.get(url)

        # Проверяем, что возвращается 404
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_cve_filtering(self):
        """
        Тест для проверки фильтрации CVE по дате.
        """
        # Авторизуем пользователя
        self.client.force_authenticate(user=self.user)

        # Добавляем фильтрацию по дате
        url = reverse("extended-cve-list") + "?start_date=2023-01-01&end_date=2023-12-31"
        response = self.client.get(url)

        # Проверяем статус ответа
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Проверяем, что данные отфильтрованы
        self.assertEqual(len(response.data), 2)

    def test_cve_ordering(self):
        """
        Тест для проверки сортировки CVE по дате обновления.
        """
        # Авторизуем пользователя
        self.client.force_authenticate(user=self.user)

        # Добавляем сортировку по дате обновления
        url = reverse("extended-cve-list") + "?ordering=-updated_at"
        response = self.client.get(url)

        # Проверяем статус ответа
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Проверяем, что данные отсортированы
        self.assertEqual(response.data[0]["cve_id"], self.cve2.cve_id)
        self.assertEqual(response.data[1]["cve_id"], self.cve1.cve_id)

    def test_cve_list_serializer(self):
        """
        Тест для проверки сериализатора CveExtendedListSerializer.
        """
        # Авторизуем пользователя
        self.client.force_authenticate(user=self.user)

        # Получаем URL для списка CVE
        url = reverse("extended-cve-list")
        response = self.client.get(url)

        # Проверяем статус ответа
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Проверяем, что данные соответствуют сериализатору
        serializer = CveExtendedListSerializer([self.cve1, self.cve2], many=True)
        self.assertEqual(response.data, serializer.data)

    def test_cve_detail_serializer(self):
        """
        Тест для проверки сериализатора CveDetailSerializer.
        """
        # Авторизуем пользователя
        self.client.force_authenticate(user=self.user)

        # Получаем URL для деталей CVE
        url = reverse("extended-cve-detail", args=[self.cve1.cve_id])
        response = self.client.get(url)

        # Проверяем статус ответа
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Проверяем, что данные соответствуют сериализатору
        serializer = CveDetailSerializer(self.cve1)
        self.assertEqual(response.data, serializer.data)

    def test_cve_detail_with_context(self):
        """
        Комплексный тест для проверки деталей CVE с контекстными данными.
        """
        # Авторизуем пользователя
        self.client.force_authenticate(user=self.user)

        # Получаем URL для деталей CVE
        url = reverse("extended-cve-detail", args=[self.cve1.cve_id])
        response = self.client.get(url)

        # Проверяем статус ответа
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Проверяем, что данные соответствуют ожидаемым
        self.assertEqual(response.data["cve_id"], self.cve1.cve_id)
        self.assertEqual(response.data["description"], self.cve1.description)

        # Проверяем, что дополнительные данные присутствуют
        self.assertIn("vendors", response.data)
        self.assertIn("weaknesses", response.data)
        self.assertIn("nvd_json", response.data)
        self.assertIn("mitre_json", response.data)
        self.assertIn("redhat_json", response.data)
        self.assertIn("vulnrichment_json", response.data)

        # Проверяем, что JSON-данные корректны
        self.assertEqual(json.loads(response.data["nvd_json"]), {})
        self.assertEqual(json.loads(response.data["mitre_json"]), {})
        self.assertEqual(json.loads(response.data["redhat_json"]), {})
        self.assertEqual(json.loads(response.data["vulnrichment_json"]), {})

    def test_delete_user_cascade(self):
        """
        Тест для проверки каскадного удаления данных пользователя.
        """
        # Создаем теги и CVE, связанные с пользователем
        user_tag = UserTag.objects.create(name="Test Tag", color="#000000", user=self.user)
        cve = Cve.objects.create(cve_id="CVE-2024-1234")
        CveTag.objects.create(user=self.user, cve=cve, tags=[user_tag.name])

        # Проверяем, что данные существуют
        user_id = self.user.id
        assert User.objects.filter(id=user_id).count() == 1
        assert UserTag.objects.filter(user_id=user_id).count() == 1
        assert CveTag.objects.filter(user_id=user_id).count() == 1

        # Удаляем пользователя
        self.user.delete()

        # Проверяем, что данные удалены каскадно
        assert User.objects.filter(id=user_id).count() == 0
        assert UserTag.objects.filter(user_id=user_id).count() == 0
        assert CveTag.objects.filter(user_id=user_id).count() == 0

    @pytest.mark.parametrize(
        "params,result",
        [
            ("", ["CVE-2023-1234", "CVE-2023-5678"]),  # no filter
            ("search=Test", ["CVE-2023-1234", "CVE-2023-5678"]),  # text in description
            ("search=1234", ["CVE-2023-1234"]),  # text in CVE ID
            ("cvss=critical", ["CVE-2023-1234", "CVE-2023-5678"]),
            ("cvss=low", []),
        ],
    )
    def test_list_filtered_cves(self, params, result):
        """
        Тест для проверки фильтрации CVE с использованием list_filtered_cves.
        """
        # Авторизуем пользователя
        self.client.force_authenticate(user=self.user)

        # Выполняем фильтрацию
        filtered_cves = list_filtered_cves(QueryDict(params), self.user)

        # Проверяем, что результат соответствует ожидаемому
        assert sorted([c.cve_id for c in filtered_cves]) == result

    def test_list_cves_with_tag(self):
        """
        Тест для проверки фильтрации CVE по тегам.
        """
        # Создаем тег и связываем его с CVE
        user_tag = UserTag.objects.create(name="Test Tag", color="#000000", user=self.user)
        CveTag.objects.create(user=self.user, cve=self.cve1, tags=[user_tag.name])

        # Выполняем фильтрацию по тегу
        filtered_cves = list_filtered_cves(QueryDict("tag=Test Tag"), self.user)

        # Проверяем, что результат соответствует ожидаемому
        assert sorted([c.cve_id for c in filtered_cves]) == ["CVE-2023-1234"]