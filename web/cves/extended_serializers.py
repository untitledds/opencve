from rest_framework import serializers
import json
from cves.models import Cve, Product, Vendor
from users.models import CveTag, UserTag
from cves.utils import list_to_dict_vendors
from cves.constants import PRODUCT_SEPARATOR
from .extended_utils import (
    get_cvss_data,
    get_humanized_title,
    get_cvss_human_score,
    get_vendors_list,
    get_products_list,
    get_vendors_with_subscriptions,
    get_products_with_subscriptions,
    get_subscription_status,
)


CVSS_FIELDS = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


class ExtendedCveListSerializer(serializers.ModelSerializer):
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
        return get_vendors_list(instance)

    def get_products(self, instance):
        return get_products_list(instance)

    def get_cvss_score(self, instance):
        cvss = get_cvss_data(instance)
        return cvss["score"] if cvss else None

    def get_title(self, instance):
        if instance.title and instance.title.strip():
            return instance.title
        return get_humanized_title(
            cvss_human_score=self.get_cvss_human_score(instance),
            cve_id=instance.cve_id,
            vendors=instance.vendors,
        )

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

    def get_cvss_human_score(self, instance):
        cvss = get_cvss_data(instance)
        return get_cvss_human_score(cvss["score"]) if cvss else None


class ExtendedCveDetailSerializer(serializers.ModelSerializer):
    title = serializers.SerializerMethodField()
    nvd_json = serializers.SerializerMethodField()
    mitre_json = serializers.SerializerMethodField()
    redhat_json = serializers.SerializerMethodField()
    vulnrichment_json = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    products = serializers.SerializerMethodField()
    vendors = serializers.SerializerMethodField()
    affected = serializers.SerializerMethodField()
    weakness_ref = serializers.SerializerMethodField()

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
            "references",
            "weakness_ref",
        ]

    def get_weakness_ref(self, instance):
        weaknesses = instance.weaknesses
        if not weaknesses or not isinstance(weaknesses, list):
            return []

        weakness_refs = []
        for weakness in weaknesses:
            if isinstance(weakness, str) and weakness.startswith("CWE-"):
                try:
                    cwe_id = weakness.split("-")[1]
                    weakness_refs.append(
                        f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                    )
                except IndexError:
                    continue
        return weakness_refs

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
        if instance.title and instance.title.strip():
            return instance.title
        return get_humanized_title(
            cvss_human_score=self.get_cvss_human_score(instance),
            cve_id=instance.cve_id,
            vendors=instance.vendors,
        )

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
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            return get_vendors_with_subscriptions(instance, request.user)
        return get_vendors_list(instance)

    def get_products(self, instance):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            return get_products_with_subscriptions(instance, request.user)
        return get_products_list(instance)

    def get_cvss_human_score(self, instance):
        cvss = get_cvss_data(instance)
        return get_cvss_human_score(cvss["score"]) if cvss else None


class SubscriptionSerializer(serializers.Serializer):
    obj_type = serializers.ChoiceField(choices=["vendor", "product"])
    obj_id = serializers.UUIDField()
    project_id = serializers.UUIDField(required=False)
    project_name = serializers.CharField(required=False)
    org_name = serializers.CharField(required=False)


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
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
            "products_count",
            "is_subscribed",
        ]

    def get_products_count(self, obj):
        return obj.products.count()

    def get_is_subscribed(self, obj):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            return get_subscription_status("vendor", obj.name, request.user)
        return False


class ProductSerializer(serializers.ModelSerializer):
    vendor = VendorSerializer(required=False)
    is_subscribed = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ["id", "name", "vendor", "is_subscribed"]

    def get_is_subscribed(self, obj):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            full_name = f"{obj.vendor.name}{PRODUCT_SEPARATOR}{obj.name}"
            return get_subscription_status("product", full_name, request.user)
        return False

    def to_representation(self, instance):
        data = super().to_representation(instance)
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
    cve_ids = serializers.ListField(child=serializers.CharField(), write_only=True)
    tags = serializers.ListField(child=serializers.CharField())
    cve_id = serializers.CharField(source="cve.cve_id", read_only=True)

    class Meta:
        model = CveTag
        fields = ["id", "cve_ids", "tags", "cve_id"]
        read_only_fields = ["id", "cve_id"]

    def validate_cve_ids(self, value):
        for cve_id in value:
            if not cve_id.startswith("CVE-"):
                raise serializers.ValidationError(
                    f"cve_id '{cve_id}' must start with 'CVE-'."
                )
        return value

    def create(self, validated_data):
        validated_data.pop("cve_ids", None)
        tags = validated_data.pop("tags")
        cves = self.context.get("cves", [])
        user = self.context["request"].user

        created_tags = []
        for cve in cves:
            cve_tag, created = CveTag.objects.get_or_create(
                cve=cve,
                user=user,
                defaults={"tags": tags},
            )
            if not created:
                cve_tag.tags = list(set(cve_tag.tags + tags))
                cve_tag.save()
            created_tags.append(cve_tag)

        return created_tags


class ExtendedProductListSerializer(serializers.ModelSerializer):
    is_subscribed = serializers.SerializerMethodField()
    vendor = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ["id", "name", "vendor", "is_subscribed"]

    def get_is_subscribed(self, obj):
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            full_name = f"{obj.vendor.name}{PRODUCT_SEPARATOR}{obj.name}"
            return get_subscription_status("product", full_name, request.user)
        return False

    def get_vendor(self, obj):
        if self.context.get("hide_vendor_in_product", False):
            return None

        request = self.context.get("request")
        return {
            "id": str(obj.vendor.id),
            "name": obj.vendor.name,
            "is_subscribed": (
                get_subscription_status("vendor", obj.vendor.name, request.user)
                if request and request.user.is_authenticated
                else False
            ),
        }

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if self.context.get("hide_vendor_in_product", False):
            data.pop("vendor", None)
        return data
