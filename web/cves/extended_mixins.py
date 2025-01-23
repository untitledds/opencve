from cves.models import Vendor, Product
from .extended_utils import get_humanized_title
from cves.templatetags.opencve_extras import cvss_human_score
from cves.utils import list_to_dict_vendors
import json
import logging

logger = logging.getLogger(__name__)


class CveProductsMixin:
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
        Возвращает список продуктов, связанных с CVE.
        :param instance: Объект CVE.
        :return: Список продуктов.
        """
        vendors = instance.vendors
        if isinstance(vendors, list):
            # Фильтруем только продукты (строки с $PRODUCT$)
            products = [v.split("$PRODUCT$")[1] for v in vendors if "$PRODUCT$" in v]
            return products
        elif isinstance(vendors, str):
            try:
                # Если vendors — это JSON-строка, преобразуем её в список
                vendors_list = json.loads(vendors)
                products = [
                    v.split("$PRODUCT$")[1] for v in vendors_list if "$PRODUCT$" in v
                ]
                return products
            except json.JSONDecodeError:
                # Если это не JSON, возвращаем пустой список
                logger.warning(
                    f"Vendors is a string for CVE {instance.cve_id}: {vendors}"
                )
                return [vendors.split("$PRODUCT$")[1]] if "$PRODUCT$" in vendors else []
        else:
            # Возвращаем пустой список, если формат данных неизвестен
            return []

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
