from rest_framework import serializers
from cves.models import Cve, Product, Vendor
from .extended_mixins import CveProductsMixin
from cves.serializers import Vendor, Product
from cves.constants import (
    CVSS_CHART_BACKGROUNDS,
    CVSS_HUMAN_SCORE,
    CVSS_NAME_MAPPING,
    CVSS_VECTORS_MAPPING,
    PRODUCT_SEPARATOR,
)

CVSS_FIELDS = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


class ExtendedCveListSerializer(serializers.ModelSerializer, CveProductsMixin):
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

    def get_vendors(self, instance):
        """
        Возвращает словарь вендоров и их продуктов.
        """
        return super().get_vendors(instance)  # Используем метод из миксина

    def get_products(self, instance):
        """
        Возвращает список продуктов, связанных с CVE через вендоров.
        """
        return super().get_products(instance)  # Используем метод из миксина

    def get_cvss_score(self, instance):
        """
        Возвращает CVSS score из первой доступной версии CVSS.
        """
        cvss = self._get_cvss_data(instance)
        return cvss["score"] if cvss else None


class ExtendedCveDetailSerializer(serializers.ModelSerializer, CveProductsMixin):
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


class SubscriptionSerializer(serializers.Serializer):
    obj_type = serializers.ChoiceField(choices=["vendor", "product"])
    obj_id = serializers.UUIDField()
    project_id = serializers.UUIDField()
    project_name = serializers.CharField(required=False)  # Добавим поле для имени проекта
    org_name = serializers.CharField(required=False)  # Добавим поле для имени организации


class ProjectSubscriptionsSerializer(serializers.Serializer):
    vendors = serializers.ListField(child=serializers.CharField())
    products = serializers.ListField(child=serializers.CharField())


class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = ["id", "name"]


class ProductSerializer(serializers.ModelSerializer):
    vendor = VendorSerializer()

    class Meta:
        model = Product
        fields = ["id", "name", "vendor"]


class DetailedSubscriptionSerializer(serializers.Serializer):
    project_id = serializers.UUIDField(help_text="UUID проекта.")
    subscriptions = ProjectSubscriptionsSerializer(help_text="Подписки проекта.")
    vendor_details = VendorSerializer(many=True, read_only=True)
    product_details = ProductSerializer(many=True, read_only=True)
