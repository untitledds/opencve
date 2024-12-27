from rest_framework import serializers
from cves.models import Cve
from cves.templatetags.opencve_extras import cvss_human_score
from cves.utils import humanize


# Константы для CVSS-полей
CVSS_FIELDS = ["cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2"]


class CveExtendedListSerializer(serializers.ModelSerializer):
    cvss_score = serializers.SerializerMethodField()
    cvss_human_score = serializers.SerializerMethodField()
    humanized_title = serializers.SerializerMethodField()

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
        """
        return humanize(instance.title)


class CveExtendedDetailSerializer(serializers.ModelSerializer):
    # JSON-поля
    nvd_json = serializers.SerializerMethodField()
    mitre_json = serializers.SerializerMethodField()
    redhat_json = serializers.SerializerMethodField()
    vulnrichment_json = serializers.SerializerMethodField()
    kev_data = serializers.SerializerMethodField()
    ssvc_data = serializers.SerializerMethodField()
    cvssV2_0_data = serializers.SerializerMethodField()
    cvssV3_1_data = serializers.SerializerMethodField()
    references = serializers.SerializerMethodField()

    # Методы для получения дополнительных данных
    vendors = serializers.SerializerMethodField()
    weaknesses = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    humanized_title = serializers.SerializerMethodField()

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
            "nvd_json",
            "mitre_json",
            "redhat_json",
            "vulnrichment_json",
            "kev_data",
            "ssvc_data",
            "cvssV2_0_data",
            "cvssV3_1_data",
            "references",
            "tags",
        ]

    def get_humanized_title(self, instance):
        """
        Возвращает человеко-читаемый заголовок.
        """
        return humanize(instance.title)

    def get_vendors(self, instance):
        """
        Возвращает словарь вендоров.
        """
        return self.context.get("vendors", {})

    def get_weaknesses(self, instance):
        """
        Возвращает список уязвимостей.
        """
        return self.context.get("weaknesses", [])

    def get_tags(self, instance):
        """
        Возвращает теги, связанные с CVE.
        """
        return self.context.get("tags", [])

    def get_kev_data(self, instance):
        """
        Возвращает данные KEV.
        """
        return instance.metrics.get("kev", {})

    def get_ssvc_data(self, instance):
        """
        Возвращает данные SSVC.
        """
        return instance.metrics.get("ssvc", {})

    def get_cvssV2_0_data(self, instance):
        """
        Возвращает данные CVSS v2.0.
        """
        return instance.metrics.get("cvssV2_0", {}).get("data", {})

    def get_cvssV3_1_data(self, instance):
        """
        Возвращает данные CVSS v3.1.
        """
        return instance.metrics.get("cvssV3_1", {}).get("data", {})

    def get_nvd_json(self, instance):
        """
        Возвращает данные NVD.
        """
        return self.context.get("nvd_json", {})

    def get_mitre_json(self, instance):
        """
        Возвращает данные MITRE.
        """
        return self.context.get("mitre_json", {})

    def get_redhat_json(self, instance):
        """
        Возвращает данные Red Hat.
        """
        return self.context.get("redhat_json", {})

    def get_vulnrichment_json(self, instance):
        """
        Возвращает данные Vulnrichment.
        """
        return self.context.get("vulnrichment_json", {})

    def get_references(self, instance):
        """
        Возвращает список ссылок.
        """
        return instance.kb_json.get("opencve", {}).get("references", [])
