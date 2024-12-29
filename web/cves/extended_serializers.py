from rest_framework import serializers
from cves.models import Cve, Product, Vendor
from cves.utils import humanize, get_metric_from_vector
from cves.templatetags.opencve_extras import cvss_human_score, cvss_level
from cves.constants import (
    CVSS_CHART_BACKGROUNDS,
    CVSS_HUMAN_SCORE,
    CVSS_NAME_MAPPING,
    CVSS_VECTORS_MAPPING,
    PRODUCT_SEPARATOR,
)

CVSS_FIELDS = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


class ExtendedCveListSerializer(serializers.ModelSerializer):
    cvss_score = serializers.SerializerMethodField()
    cvss_human_score = serializers.SerializerMethodField()
    humanized_title = serializers.SerializerMethodField()
    products = serializers.SerializerMethodField()

    class Meta:
        model = Cve
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "description",
            "cvss_score",
            "cvss_human_score",
            "humanized_title",
            "vendors",
            "products",
        ]

    def _get_cvss_data(self, instance):
        """
        Возвращает данные CVSS из первой доступной версии.
        """
        for field in CVSS_FIELDS:
            cvss = instance.metrics.get(field, {}).get("data", {})
            if cvss and "score" in cvss:
                return cvss
        return None

    def get_cvss_score(self, instance):
        """
        Возвращает CVSS score из первой доступной версии CVSS.
        """
        cvss = self._get_cvss_data(instance)
        return cvss["score"] if cvss else None

    def get_cvss_human_score(self, instance):
        """
        Возвращает человеко-читаемый уровень CVSS (например, "High", "Critical").
        """
        cvss = self._get_cvss_data(instance)
        return cvss_human_score(cvss["score"]).title() if cvss else None

    def get_humanized_title(self, instance):
        """
        Возвращает человеко-читаемый заголовок.
        Если title отсутствует, собирает его из cvss_human_score, cve_id, vendors и products.
        Любая из частей может быть None.
        """
        if instance.title:
            return humanize(instance.title)
        else:
            # Собираем заголовок из других полей
            parts = []

            # Добавляем cvss_human_score, если он не None
            if instance.cvss_human_score:
                parts.append(f"CVSS: {instance.cvss_human_score}")

            # Добавляем cve_id, если он не None
            if instance.cve_id:
                parts.append(f"CVE: {instance.cve_id}")

            # Добавляем vendors, если они не None и не пустые
            if instance.vendors:
                vendors = ", ".join(instance.vendors)
                parts.append(f"Vendors: {vendors}")

            # Добавляем products, если они не None и не пустые
            if instance.products:
                products = ", ".join(instance.products)
                parts.append(f"Products: {products}")

            # Если ни одно из полей не заполнено, возвращаем заглушку
            if not parts:
                return "No title available"

            # Соединяем части в одну строку
            return " ".join(parts)

    def get_products(self, instance):
        """
        Возвращает список продуктов, связанных с CVE через вендоров.
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


class ExtendedCveDetailSerializer(serializers.ModelSerializer):
    humanized_title = serializers.SerializerMethodField()
    nvd_json = serializers.SerializerMethodField()
    mitre_json = serializers.SerializerMethodField()
    redhat_json = serializers.SerializerMethodField()
    vulnrichment_json = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    products = serializers.SerializerMethodField()

    class Meta:
        model = Cve
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "title",
            "humanized_title",
            "description",
            "metrics",
            "weaknesses",
            "vendors",
            "products",
            "nvd_json",
            "mitre_json",
            "redhat_json",
            "vulnrichment_json",
            "tags",
        ]

    def get_humanized_title(self, instance):
        return humanize(instance.title)

    def get_nvd_json(self, instance):
        return instance.nvd_json

    def get_mitre_json(self, instance):
        return instance.mitre_json

    def get_redhat_json(self, instance):
        return instance.redhat_json

    def get_vulnrichment_json(self, instance):
        return instance.vulnrichment_json

    def get_tags(self, instance):
        if (
            self.context.get("request")
            and self.context["request"].user.is_authenticated
        ):
            cve_tags = instance.cve_tags.filter(
                user=self.context["request"].user
            ).first()
            return cve_tags.tags if cve_tags else []
        return []

    def get_products(self, instance):
        """
        Возвращает список продуктов, связанных с CVE через вендоров.
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


class SubscriptionSerializer(serializers.Serializer):
    obj_type = serializers.ChoiceField(choices=["vendor", "product"])
    obj_id = serializers.UUIDField()
    project_id = serializers.UUIDField()


class ProjectSubscriptionsSerializer(serializers.Serializer):
    vendors = serializers.ListField(child=serializers.CharField())
    products = serializers.ListField(child=serializers.CharField())
