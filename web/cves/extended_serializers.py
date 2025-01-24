from rest_framework import serializers
import json
from cves.models import Cve, Product, Vendor
from .extended_mixins import CveProductsMixin
from cves.serializers import Vendor, Product
from users.models import CveTag, UserTag
from cves.utils import list_to_dict_vendors

CVSS_FIELDS = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


class ExtendedCveListSerializer(serializers.ModelSerializer, CveProductsMixin):
    cvss_score = serializers.SerializerMethodField()
    cvss_human_score = serializers.SerializerMethodField()
    title = serializers.SerializerMethodField()
    products = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    vendors = serializers.SerializerMethodField()

    class Meta:
        model = Cve
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "title",
            "description",
            "cvss_score",
            "cvss_human_score",
            "vendors",
            "products",
            "tags",
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

    def get_title(self, instance):
        """
        Возвращает title экземпляра или сгенерированный заголовок.
        """
        return super().get_title(instance)

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


class ExtendedCveDetailSerializer(serializers.ModelSerializer, CveProductsMixin):
    title = serializers.SerializerMethodField()
    nvd_json = serializers.SerializerMethodField()
    mitre_json = serializers.SerializerMethodField()
    redhat_json = serializers.SerializerMethodField()
    vulnrichment_json = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    products = serializers.SerializerMethodField()
    vendors = serializers.SerializerMethodField()
    affected = serializers.SerializerMethodField()

    class Meta:
        model = Cve
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "title",
            "description",
            "metrics",
            "weaknesses",
            "affected",
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

    def get_title(self, instance):
        """
        Возвращает title экземпляра или сгенерированный заголовок.
        """
        return super().get_title(instance)

    def get_affected(self, instance):
        vendors = instance.vendors
        if isinstance(vendors, str):
            try:
                vendors = json.loads(vendors)
            except json.JSONDecodeError:
                vendors = [vendors]
        elif not isinstance(vendors, list):
            vendors = []

        return list_to_dict_vendors(vendors)

    def get_vendors(self, instance):
        """
        Возвращает словарь вендоров и их продуктов.
        """
        return super().get_vendors(instance)  # Используем метод из миксина


class SubscriptionSerializer(serializers.Serializer):
    obj_type = serializers.ChoiceField(choices=["vendor", "product"])
    obj_id = serializers.UUIDField()
    project_id = serializers.UUIDField(required=False)
    project_name = serializers.CharField(
        required=False
    )  # Добавим поле для имени проекта
    org_name = serializers.CharField(
        required=False
    )  # Добавим поле для имени организации


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


class UserTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserTag
        fields = ["id", "name", "color", "description"]


class CveTagSerializer(serializers.ModelSerializer):
    cve_ids = serializers.ListField(
        child=serializers.CharField(), write_only=True  # Принимаем список cve_id
    )
    tags = serializers.ListField(child=serializers.CharField())

    class Meta:
        model = CveTag
        fields = ["id", "cve_ids", "tags"]  # Поле "user" больше не нужно
        read_only_fields = ["id"]

    def validate_cve_ids(self, value):
        # Проверяем, что каждый cve_id имеет формат CVE-XXXX-XXXX
        for cve_id in value:
            if not cve_id.startswith("CVE-"):
                raise serializers.ValidationError(
                    f"cve_id '{cve_id}' must start with 'CVE-'."
                )
        return value

    def create(self, validated_data):
        # Удаляем cve_ids, если он не используется
        validated_data.pop("cve_ids", None)

        tags = validated_data.pop("tags")

        # Получаем объекты Cve из контекста
        cves = self.context.get("cves", [])

        # Получаем текущего пользователя из контекста
        user = self.context["request"].user

        # Создаем или обновляем теги для каждого cve_id
        created_tags = []
        for cve in cves:
            cve_tag, created = CveTag.objects.get_or_create(
                cve=cve,
                user=user,  # Используем текущего пользователя
                defaults={"tags": tags},
            )
            if not created:
                cve_tag.tags = list(set(cve_tag.tags + tags))  # Убираем дубликаты
                cve_tag.save()
            created_tags.append(cve_tag)

        return created_tags

    def to_representation(self, instance):
        # Преобразуем список CveTag в список словарей
        return [
            {
                "id": tag.id,
                "cve_id": tag.cve.cve_id,  # Используем cve_id из объекта Cve
                "tags": tag.tags,
            }
            for tag in instance
        ]
