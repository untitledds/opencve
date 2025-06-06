from cves.models import Vendor, Product
from projects.models import Project
from organizations.models import Organization
from .extended_utils import get_humanized_title, get_user_organization
from cves.templatetags.opencve_extras import cvss_human_score
from cves.utils import list_to_dict_vendors
import json
import logging
from cves.constants import PRODUCT_SEPARATOR
from django.conf import settings

logger = logging.getLogger(__name__)


class SubscriptionMixin:
    """Миксин для работы с подписками на вендоров и продукты"""

    def get_subscription_status(self, obj_type, obj_name):
        """
        Проверяет состояние подписки для вендора или продукта
        :param obj_type: 'vendor' или 'product'
        :param obj_name: Имя вендора или продукта (в формате vendor$PRODUCT$product для продуктов)
        :return: True если подписан, иначе False
        """
        request = getattr(self, "context", {}).get("request")
        if not request or not request.user.is_authenticated:
            return False

        try:
            project = self._get_current_project(request)
            if not project:
                return False

            if obj_type == "vendor":
                subscribed_items = project.subscriptions.get("vendors", [])
                return obj_name in subscribed_items
            elif obj_type == "product":
                subscribed_items = project.subscriptions.get("products", [])
                # Для продуктов сравниваем полное имя (vendor$PRODUCT$product)
                return any(
                    item.endswith(PRODUCT_SEPARATOR + obj_name)
                    for item in subscribed_items
                )
            return False
        except Exception as e:
            logger.error(f"Error checking subscription: {e}")
            return False

    def _get_current_project(self, request):
        """Получает текущий проект (из параметров или дефолтный)"""
        project_id = request.query_params.get("project_id")

        if project_id:
            return Project.objects.filter(id=project_id).first()

        organization = get_user_organization(request.user)
        if not organization:
            return None

        default_project_name = getattr(
            settings, "GLOBAL_DEFAULT_PROJECT_NAME", "Default Project"
        )
        return Project.objects.filter(
            name=default_project_name, organization=organization
        ).first()


class CveProductsMixin(SubscriptionMixin):
    """
    Миксин для получения продуктов, вендоров и генерации заголовка CVE.
    """

    def get_vendors(self, instance):
        """
        Возвращает список уникальных вендоров, связанных с CVE.
        :param instance: Объект CVE.
        :return: Список вендоров.
        """
        vendors = instance.vendors

        # Если vendors — строка, пытаемся десериализовать её в список
        if isinstance(vendors, str):
            try:
                vendors = json.loads(vendors)
            except json.JSONDecodeError:
                logger.warning(
                    f"Vendors is a string for CVE {instance.cve_id}: {vendors}"
                )
                vendors = [vendors]  # Возвращаем как список с одним элементом

        # Если vendors не список, возвращаем пустой список
        if not isinstance(vendors, list):
            return []

        # Извлекаем вендоры и убираем дубликаты
        vendors_list = [
            v.split("$PRODUCT$")[0] if "$PRODUCT$" in v else v for v in vendors
        ]
        return list(set(vendors_list))

    def get_products(self, instance):
        """
        Возвращает список уникальных продуктов, связанных с CVE.
        :param instance: Объект CVE.
        :return: Список уникальных продуктов.
        """
        vendors = instance.vendors
        products = set()  # Используем set для хранения уникальных значений

        if isinstance(vendors, list):
            # Фильтруем только продукты (строки с $PRODUCT$)
            products.update(
                v.split("$PRODUCT$")[1] for v in vendors if "$PRODUCT$" in v
            )
        elif isinstance(vendors, str):
            try:
                # Если vendors — это JSON-строка, преобразуем её в список
                vendors_list = json.loads(vendors)
                products.update(
                    v.split("$PRODUCT$")[1] for v in vendors_list if "$PRODUCT$" in v
                )
            except json.JSONDecodeError:
                # Если это не JSON, возвращаем пустой список
                logger.warning(
                    f"Vendors is a string for CVE {instance.cve_id}: {vendors}"
                )
                if "$PRODUCT$" in vendors:
                    products.add(vendors.split("$PRODUCT$")[1])
        else:
            # Возвращаем пустой список, если формат данных неизвестен
            pass

        return list(products)  # Преобразуем set обратно в список

    def get_humanized_title(self, instance):
        """
        Возвращает человеко-читаемый заголовок для CVE.
        :param instance: Объект CVE.
        :return: Строка с заголовком.
        """
        return get_humanized_title(
            cvss_human_score=self.get_cvss_human_score(instance),
            cve_id=instance.cve_id,
            vendors=instance.vendors,
        )

    def get_title(self, instance):
        """
        Возвращает title экземпляра, если он не пустой или не нулевой.
        Иначе генерирует заголовок с помощью get_humanized_title.
        :param instance: Объект CVE.
        :return: Строка с заголовком.
        """
        if instance.title and instance.title.strip():
            return instance.title
        return get_humanized_title(
            cvss_human_score=self.get_cvss_human_score(instance),
            cve_id=instance.cve_id,
            vendors=instance.vendors,
        )

    def get_cvss_human_score(self, instance):
        """
        Возвращает человеко-читаемый уровень CVSS (например, "High", "Critical").
        :param instance: Объект CVE.
        :return: Уровень CVSS.
        """
        cvss = self._get_cvss_data(instance)
        return cvss_human_score(cvss["score"]).title() if cvss else None

    def _get_cvss_data(self, instance):
        """
        Возвращает данные CVSS из первой доступной версии.
        :param instance: Объект CVE.
        :return: Данные CVSS или None.
        """
        cvss_fields = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
        for field in cvss_fields:
            cvss = instance.metrics.get(field, {}).get("data", {})
            if cvss and "score" in cvss:
                return cvss
        return None

    def get_vendors_with_subscriptions(self, instance):
        """Возвращает вендоров с информацией о подписке"""
        vendor_names = self.get_vendors(instance)
        return [
            {
                "name": vendor_name,
                "is_subscribed": self.get_subscription_status("vendor", vendor_name),
            }
            for vendor_name in vendor_names
        ]

    def get_products_with_subscriptions(self, instance):
        """Возвращает продукты с информацией о подписке"""
        product_names = self.get_products(instance)
        vendors_dict = list_to_dict_vendors(instance.vendors)

        result = []
        for product_name in product_names:
            # Находим вендора для продукта
            vendor_name = next(
                (v for v, products in vendors_dict.items() if product_name in products),
                None,
            )
            if vendor_name:
                full_name = f"{vendor_name}{PRODUCT_SEPARATOR}{product_name}"
                result.append(
                    {
                        "name": product_name,
                        "vendor": vendor_name,
                        "is_subscribed": self.get_subscription_status(
                            "product", full_name
                        ),
                    }
                )
        return result
