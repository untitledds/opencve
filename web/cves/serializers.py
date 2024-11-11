from rest_framework import serializers
from cves.models import Cve, Product, Vendor, Weakness
from cves.templatetags.opencve_extras import cvss_human_score, humanize

class CveListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cve
        fields = ["created_at", "updated_at", "cve_id", "description"]

class CveDetailSerializer(serializers.ModelSerializer):
    nvd_json = serializers.JSONField()
    mitre_json = serializers.JSONField()
    redhat_json = serializers.JSONField()
    vulnrichment_json = serializers.JSONField()
    kev_data = serializers.JSONField(source='kev')
    ssvc_data = serializers.JSONField(source='ssvc')
    cvssV2_0_data = serializers.JSONField(source='cvssV2_0')
    cvssV3_1_data = serializers.JSONField(source='cvssV3_1')
    references = serializers.JSONField()
    vendors = serializers.JSONField()
    weaknesses = serializers.JSONField()

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
            "vendors",
            "nvd_json",
            "mitre_json",
            "redhat_json",
            "vulnrichment_json",
            "kev_data",
            "ssvc_data",
            "cvssV2_0_data",
            "cvssV3_1_data",
            "references",
        ]

class WeaknessListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Weakness
        fields = [
            "created_at",
            "updated_at",
            "cwe_id",
        ]

class VendorListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
        ]

class ProductListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = [
            "id",
            "created_at",
            "updated_at",
            "name",
        ]

class CveExtendedListSerializer(serializers.ModelSerializer):
    cvssV3_1_score = serializers.SerializerMethodField()
    cvssV3_1_human_score = serializers.SerializerMethodField()
    humanized_description = serializers.SerializerMethodField()

    class Meta:
        model = Cve
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "description",
            "humanized_description",
            "cvssV3_1_score",
            "cvssV3_1_human_score",
        ]

    def get_cvssV3_1_score(self, obj):
        return obj.cvssV3_1.get('score')

    def get_cvssV3_1_human_score(self, obj):
        score = obj.cvssV3_1.get('score')
        return cvss_human_score(score).title() if score else None

    def get_humanized_description(self, obj):
        return humanize(obj.description)
