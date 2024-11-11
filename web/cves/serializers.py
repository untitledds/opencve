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
    cvssV3_1_score = serializers.JSONField(source='cvssV3_1.score')
    cvssV3_1_human_score = serializers.JSONField(source='cvssV3_1.score', read_only=True)
    humanized_description = serializers.JSONField(source='description', read_only=True)

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

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['cvssV3_1_human_score'] = cvss_human_score(data['cvssV3_1_score']).title() if data['cvssV3_1_score'] else None
        data['humanized_description'] = humanize(data['description'])
        return data
