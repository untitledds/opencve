from cves.models import Vendor, Product
from .extended_utils import get_humanized_title
from cves.templatetags.opencve_extras import cvss_human_score


class CveProductsMixin:
    """
    Миксин для получения продуктов и генерации заголовка CVE.
    """

    def get_products(self, instance):
        """
        Возвращает список продуктов, связанных с CVE через вендоров.
        :param instance: Объект CVE.
        :return: Список продуктов.
        """
        products = []
        for vendor_name in instance.vendors:
            # Находим вендора по имени
            vendor = Vendor.objects.filter(name=vendor_name).first()
            if vendor:
                # Находим все продукты для этого вендора
                vendor_products = Product.objects.filter(vendor=vendor)
                products.extend([product.vendored_name for product in vendor_products])
        return products

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
