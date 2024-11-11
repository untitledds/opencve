from rest_framework import serializers
from cves.models import Cve, Product, Vendor, Weakness
from cves.templatetags.opencve_extras import cvss_human_score, humanize

class CveListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cve
        fields = [ "created_at", "updated_at", "cve_id", "description" ]

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
    cvss_score = serializers.SerializerMethodField()
    cvss_human_score = serializers.SerializerMethodField()

    class Meta:
        model = Cve
        fields = [
            "created_at",
            "updated_at",
            "cve_id",
            "description",
            "cvss_score",
            "cvss_human_score",
        ]

    def get_cvss_score(self, instance):
        cvss_fields = ['cvssV3_1', 'cvssV4_0', 'cvssV3_0', 'cvssV2']
        for field in cvss_fields:
            cvss = getattr(instance, field, None)
            if cvss and 'score' in cvss:
                return cvss['score']
        return None

    def get_cvss_human_score(self, instance):
        cvss_fields = ['cvssV3_1', 'cvssV4_0', 'cvssV3_0', 'cvssV2']
        for field in cvss_fields:
            cvss = getattr(instance, field, None)
            if cvss and 'score' in cvss:
                return cvss_human_score(cvss['score']).title()
        return None


    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['cvss_score'] = self.get_cvss_score(instance)
        data['cvss_human_score'] = self.get_cvss_human_score(instance)
        return data
