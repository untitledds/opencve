from rest_framework import serializers
import json
from cves.models import Cve, Product, Vendor
from cves.templatetags.opencve_extras import cvss_human_score
from cves.extended_utils import (
    get_current_project_for_user,
    get_products,
    get_humanized_title,
)

# from cves.serializers import Vendor, Product
from users.models import CveTag, UserTag
from cves.utils import list_to_dict_vendors
from cves.constants import PRODUCT_SEPARATOR


CVSS_FIELDS = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


class ExtendedCveListSerializer(serializers.ModelSerializer):
    cvss_score = serializers.SerializerMethodField()
    cvss_human_score = serializers.SerializerMethodField()
    title = serializers.SerializerMethodField()
    vendors = serializers.SerializerMethodField()
    products = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()

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

    def get_cvss_score(self, obj):
        for field in CVSS_FIELDS:
            cvss = obj.metrics.get(field, {}).get("data", {})
            if cvss and "score" in cvss:
                return cvss["score"]
        return None

    def get_cvss_human_score(self, obj):
        score = self.get_cvss_score(obj)
        return cvss_human_score(score).title() if score else None

    def get_title(self, obj):
        if obj.title and obj.title.strip():
            return obj.title
        return get_humanized_title(
            cvss_human_score=self.get_cvss_human_score(obj),
            cve_id=obj.cve_id,
            vendors=obj.vendors,
        )

    def get_vendors(self, obj):
        if isinstance(obj.vendors, str):
            try:
                vendors = json.loads(obj.vendors)
            except:
                vendors = [obj.vendors]
        elif isinstance(obj.vendors, list):
            vendors = obj.vendors
        else:
            vendors = []
        return list_to_dict_vendors(vendors)

    def get_products(self, obj):
        return get_products(self.get_vendors(obj))

    def get_tags(self, obj):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            cve_tag = obj.cve_tags.filter(user=request.user).first()
            return cve_tag.tags if cve_tag else []
        return []


class ExtendedCveDetailSerializer(ExtendedCveListSerializer):
    nvd_json = serializers.SerializerMethodField()
    mitre_json = serializers.SerializerMethodField()
    redhat_json = serializers.SerializerMethodField()
    vulnrichment_json = serializers.SerializerMethodField()
    affected = serializers.SerializerMethodField()
    weakness_ref = serializers.SerializerMethodField()

    class Meta:
        model = Cve
        fields = ExtendedCveListSerializer.Meta.fields + [
            "metrics",
            "weaknesses",
            "affected",
            "nvd_json",
            "mitre_json",
            "redhat_json",
            "vulnrichment_json",
            "references",
            "weakness_ref",
        ]

    def get_nvd_json(self, obj):
        return obj.nvd_json

    def get_mitre_json(self, obj):
        return obj.mitre_json

    def get_redhat_json(self, obj):
        return obj.redhat_json

    def get_vulnrichment_json(self, obj):
        return obj.vulnrichment_json

    def get_affected(self, obj):
        return self.get_vendors(obj)

    def get_weakness_ref(self, obj):
        weaknesses = obj.weaknesses
        if not isinstance(weaknesses, list):
            return []
        return [
            f"https://cwe.mitre.org/data/definitions/{w.split('-')[1]}.html"
            for w in weaknesses
            if isinstance(w, str) and w.startswith("CWE-")
        ]


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


class ExtendedVendorListSerializer(serializers.ModelSerializer):
    products_count = serializers.SerializerMethodField()
    is_subscribed = serializers.SerializerMethodField()

    class Meta:
        model = Vendor
        fields = ["id", "name", "products_count", "is_subscribed"]

    def get_products_count(self, obj):
        return obj.products.exclude(name="").exclude(name__isnull=True).count()

    def get_is_subscribed(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return False

        project = get_current_project_for_user(
            request.user,
            project_id=request.query_params.get("project_id"),
            use_default="myproject" in request.query_params,
        )
        if not project:
            return False

        return obj.name in project.subscriptions.get("vendors", [])


class ProductSerializer(serializers.ModelSerializer):
    vendor = VendorSerializer(required=False)
    is_subscribed = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ["id", "name", "vendor", "is_subscribed"]

    def get_is_subscribed(self, obj):
        # Формируем полное имя продукта (vendor$PRODUCT$product)
        subscription_mixin = self.context.get("subscription_mixin")
        if subscription_mixin:
            full_name = f"{obj.vendor.name}{PRODUCT_SEPARATOR}{obj.name}"
            return subscription_mixin.get_subscription_status("product", full_name)
        return False

    def to_representation(self, instance):
        """Кастомизация представления в зависимости от контекста"""
        data = super().to_representation(instance)

        # Если в контексте указано vendor_name, убираем вендора из основного ответа
        if self.context.get("vendor_name") and "vendor" in data:
            data.pop("vendor", None)

        return data


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
    cve_id = serializers.CharField(source="cve.cve_id", read_only=True)

    class Meta:
        model = CveTag
        # Поле "user" больше не нужно
        fields = ["id", "cve_ids", "tags", "cve_id"]
        read_only_fields = ["id", "cve_id"]

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
                # Убираем дубликаты
                cve_tag.tags = list(set(cve_tag.tags + tags))
                cve_tag.save()
            created_tags.append(cve_tag)

        # Возвращаем все созданные или обновленные теги
        return created_tags


class ExtendedProductListSerializer(serializers.ModelSerializer):
    is_subscribed = serializers.SerializerMethodField()
    vendor = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ["id", "name", "vendor", "is_subscribed"]

    def to_representation(self, instance):
        if not instance.name or not instance.name.strip():
            return None
        return super().to_representation(instance)

    def get_is_subscribed(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return False

        project = get_current_project_for_user(
            request.user,
            project_id=request.query_params.get("project_id"),
            use_default="myproject" in request.query_params,
        )
        if not project:
            return False

        full_name = f"{obj.vendor.name}{PRODUCT_SEPARATOR}{obj.name}"
        return full_name in project.subscriptions.get("products", [])

    def get_vendor(self, obj):
        if self.context.get("hide_vendor_in_product"):
            return None
        return {
            "id": str(obj.vendor.id),
            "name": obj.vendor.name,
            "display_name": obj.vendor.human_name,
            "is_subscribed": self._get_vendor_subscription(
                obj.vendor, self.context["request"]
            ),
        }

    def _get_vendor_subscription(self, vendor, request):
        project = get_current_project_for_user(
            request.user,
            project_id=request.query_params.get("project_id"),
            use_default="myproject" in request.query_params,
        )
        if not project:
            return False
        return vendor.name in project.subscriptions.get("vendors", [])
