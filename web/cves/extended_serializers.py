# web/cves/extended_serializers.py
from rest_framework import serializers
import json
from django.db import transaction
from typing import Dict, Any, List, Optional
from cves.models import Cve, Product, Vendor
from users.models import CveTag, UserTag
from cves.utils import list_to_dict_vendors
from cves.constants import PRODUCT_SEPARATOR
from cves.extended_utils import (
    get_cvss_data,
    get_humanized_title,
    get_cvss_human_score,
    get_vendors_list,
    get_products_list,
    get_vendors_with_subscriptions,
    get_products_with_subscriptions,
    get_subscription_status,
)
from rest_framework.exceptions import ValidationError


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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cvss_cache: Dict[str, Optional[Dict[str, Any]]] = {}

    def _get_cvss_data(self, instance: Cve) -> Optional[Dict[str, Any]]:
        key = str(instance.id)
        if key not in self._cvss_cache:
            self._cvss_cache[key] = get_cvss_data(instance)
        return self._cvss_cache[key]

    def get_vendors(self, instance: Cve) -> List[str]:
        return get_vendors_list(instance)

    def get_products(self, instance: Cve) -> List[str]:
        return get_products_list(instance)

    def get_cvss_score(self, instance: Cve) -> Optional[float]:
        cvss = self._get_cvss_data(instance)
        return cvss["score"] if cvss else None

    def get_cvss_human_score(self, instance: Cve) -> Optional[str]:
        cvss = self._get_cvss_data(instance)
        return get_cvss_human_score(cvss["score"]) if cvss else None

    def get_title(self, instance: Cve) -> str:
        if instance.title and instance.title.strip():
            return instance.title.strip()
        return get_humanized_title(
            cvss_human_score=self.get_cvss_human_score(instance),
            cve_id=instance.cve_id,
            vendors=instance.vendors,
        )

    def get_tags(self, instance: Cve) -> List[str]:
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return []
        user_tags = getattr(instance, "user_cve_tags", [])
        return user_tags[0].tags if user_tags else []


class ExtendedCveDetailSerializer(serializers.ModelSerializer):
    title = serializers.SerializerMethodField()
    nvd_json = serializers.JSONField(read_only=True)
    mitre_json = serializers.JSONField(read_only=True)
    redhat_json = serializers.JSONField(read_only=True)
    vulnrichment_json = serializers.JSONField(read_only=True)
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cvss_cache: Dict[str, Optional[Dict[str, Any]]] = {}

    def _get_cvss_data(self, instance: Cve) -> Optional[Dict[str, Any]]:
        key = str(instance.id)
        if key not in self._cvss_cache:
            self._cvss_cache[key] = get_cvss_data(instance)
        return self._cvss_cache[key]

    def get_weakness_ref(self, instance: Cve) -> List[str]:
        weaknesses = instance.weaknesses
        if not isinstance(weaknesses, list):
            return []
        return [
            f"https://cwe.mitre.org/data/definitions/{w.split('-', 1)[1]}.html"
            for w in weaknesses
            if isinstance(w, str) and w.startswith("CWE-") and "-" in w
        ]

    def get_tags(self, instance: Cve) -> List[str]:
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return []
        user_tags = getattr(instance, "user_cve_tags", [])
        return user_tags[0].tags if user_tags else []

    def get_title(self, instance: Cve) -> str:
        if instance.title and instance.title.strip():
            return instance.title.strip()
        return get_humanized_title(
            cvss_human_score=self.get_cvss_human_score(instance),
            cve_id=instance.cve_id,
            vendors=instance.vendors,
        )

    def get_cvss_human_score(self, instance: Cve) -> Optional[str]:
        cvss = self._get_cvss_data(instance)
        return get_cvss_human_score(cvss["score"]) if cvss else None

    def get_affected(self, instance: Cve) -> Dict[str, List[str]]:
        vendors = instance.vendors
        if isinstance(vendors, str):
            try:
                vendors = json.loads(vendors)
            except (json.JSONDecodeError, TypeError):
                vendors = [vendors] if vendors else []
        return list_to_dict_vendors(vendors)

    def get_vendors(self, instance: Cve) -> List[Dict[str, Any]]:
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            return get_vendors_with_subscriptions(instance, request.user)
        return [{"name": v} for v in get_vendors_list(instance)]

    def get_products(self, instance: Cve) -> List[Dict[str, Any]]:
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            return get_products_with_subscriptions(instance, request.user)
        return [{"name": p} for p in get_products_list(instance)]


class SubscriptionSerializer(serializers.Serializer):
    obj_type = serializers.ChoiceField(choices=["vendor", "product"])
    obj_id = serializers.UUIDField()

    def save(self, **kwargs):
        from projects.services.subscription_service import update_subscription

        user = self.context["request"].user
        obj_type = self.validated_data["obj_type"]
        obj_id = self.validated_data["obj_id"]
        action = kwargs.get("action")  # "subscribe" or "unsubscribe"

        return update_subscription(
            user=user,
            obj_type=obj_type,
            obj_id=obj_id,
            action=action,
        )


# --- Vendor & Product Serializers ---
class VendorSerializer(serializers.ModelSerializer):
    is_subscribed = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()

    class Meta:
        model = Vendor
        fields = ["id", "name", "is_subscribed"]

    def get_name(self, obj):
        return obj.human_name

    def get_is_subscribed(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return False
        return get_subscription_status("vendor", obj.name, request.user)


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

    def get_products_count(self, obj: Vendor) -> int:
        # Используем prefetch_related — безопасно
        return obj.products.count()

    def get_is_subscribed(self, obj: Vendor) -> bool:
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            return get_subscription_status("vendor", obj.name, request.user)
        return False


class ProductSerializer(serializers.ModelSerializer):
    vendor = VendorSerializer(read_only=True)
    is_subscribed = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ["id", "name", "vendor", "is_subscribed"]

    def get_is_subscribed(self, obj: Product) -> bool:
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            full_name = f"{obj.vendor.name}{PRODUCT_SEPARATOR}{obj.name}"
            return get_subscription_status("product", full_name, request.user)
        return False


class ExtendedProductListSerializer(serializers.ModelSerializer):
    is_subscribed = serializers.SerializerMethodField()
    vendor = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = ["id", "name", "is_subscribed"]

    def get_is_subscribed(self, obj: Product) -> bool:
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            full_name = f"{obj.vendor.name}{PRODUCT_SEPARATOR}{obj.name}"
            return get_subscription_status("product", full_name, request.user)
        return False

    def get_vendor(self, obj: Product) -> Optional[Dict[str, Any]]:
        if self.context.get("hide_vendor_in_product"):
            return None
        return VendorSerializer(obj.vendor).data

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if self.context.get("hide_vendor_in_product"):
            data.pop("vendor", None)  # Удаляем поле vendor полностью
        return data


# --- Tag Serializers ---
class UserTagSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserTag
        fields = ["id", "name", "color", "description"]
        read_only_fields = ["id"]

    def validate_name(self, value: str) -> str:
        user = self.context["request"].user
        qs = UserTag.objects.filter(user=user, name=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("You already have a tag with this name.")
        return value

    def create(self, validated_data: Dict[str, Any]) -> UserTag:
        validated_data["user"] = self.context["request"].user
        return super().create(validated_data)

    def update(self, instance: UserTag, validated_data: Dict[str, Any]) -> UserTag:
        validated_data.pop("user", None)
        return super().update(instance, validated_data)


class CveTagSerializer(serializers.ModelSerializer):
    cve_ids = serializers.ListField(child=serializers.CharField(), write_only=True)
    tags = serializers.ListField(child=serializers.CharField())
    cve_id = serializers.CharField(source="cve.cve_id", read_only=True)

    class Meta:
        model = CveTag
        fields = ["id", "cve_ids", "tags", "cve_id"]
        read_only_fields = ["id", "cve_id"]

    def validate_cve_ids(self, value: List[str]) -> List[str]:
        for cve_id in value:
            if not cve_id.startswith("CVE-"):
                raise serializers.ValidationError(f"Invalid CVE ID: {cve_id}")
        return value

    @transaction.atomic
    def create(self, validated_data: Dict[str, Any]) -> List[CveTag]:
        cve_ids = validated_data.pop("cve_ids")
        tags = set(validated_data.get("tags", []))
        user = self.context["request"].user

        cves = Cve.objects.filter(cve_id__in=cve_ids)
        found_ids = {cve.cve_id for cve in cves}
        missing = set(cve_ids) - found_ids
        if missing:
            raise ValidationError({"cve_ids": [f"Not found: {', '.join(missing)}"]})

        instances = []
        for cve in cves:
            cve_tag, created = CveTag.objects.get_or_create(
                cve=cve, user=user, defaults={"tags": []}
            )
            old_tags = set(cve_tag.tags)
            new_tags = old_tags | tags
            if new_tags != old_tags:
                cve_tag.tags = list(new_tags)
                cve_tag.save()
            instances.append(cve_tag)

        return instances
