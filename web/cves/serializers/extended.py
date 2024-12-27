from rest_framework import serializers
from cves.models import Cve
from cves.templatetags.opencve_extras import cvss_human_score
from cves.utils import humanize

class CveExtendedListSerializer(serializers.ModelSerializer):
    cvss_score = serializers.SerializerMethodField()
    cvss_human_score = serializers.SerializerMethodField()
    humanized_title = serializers.SerializerMethodField()

    class Meta:
        model = Cve
        fields = [
            "created_at", "updated_at", "cve_id", "description",
            "cvss_score", "cvss_human_score", "humanized_title"
        ]

    def get_cvss_score(self, instance):
        """
        Возвращает CVSS score из первой доступной версии CVSS.
        """
        for field in ['cvssV3_1', 'cvssV4_0', 'cvssV3_0', 'cvssV2']:
            cvss = getattr(instance, field, None)
            if cvss and 'score' in cvss:
                return cvss['score']
        return None

    def get_cvss_human_score(self, instance):
        """
        Возвращает человеко-читаемый уровень CVSS (например, "High", "Critical").
        """
        for field in ['cvssV3_1', 'cvssV4_0', 'cvssV3_0', 'cvssV2']:
            cvss = getattr(instance, field, None)
            if cvss and 'score' in cvss:
                return cvss_human_score(cvss['score']).title()
        return None

    def get_humanized_title(self, instance):
        """
        Возвращает человеко-читаемый заголовок.
        """
        return humanize(instance.title)


class CveDetailSerializer(serializers.ModelSerializer):
    # JSON-поля
    nvd_json = serializers.JSONField(default=dict)
    mitre_json = serializers.JSONField(default=dict)
    redhat_json = serializers.JSONField(default=dict)
    vulnrichment_json = serializers.JSONField(default=dict)
    kev_data = serializers.JSONField(source='kev', default=dict)
    ssvc_data = serializers.JSONField(source='ssvc', default=dict)
    cvssV2_0_data = serializers.JSONField(source='cvssV2_0', default=dict)
    cvssV3_1_data = serializers.JSONField(source='cvssV3_1', default=dict)
    references = serializers.JSONField(default=list)

    # Методы для получения дополнительных данных
    vendors = serializers.SerializerMethodField()
    weaknesses = serializers.SerializerMethodField()
    tags = serializers.SerializerMethodField()
    humanized_title = serializers.SerializerMethodField()

    class Meta:
        model = Cve
        fields = [
            "created_at", "updated_at", "cve_id", "title", "humanized_title", "description",
            "metrics", "weaknesses", "vendors", "nvd_json", "mitre_json",
            "redhat_json", "vulnrichment_json", "kev_data", "ssvc_data",
            "cvssV2_0_data", "cvssV3_1_data", "references", "tags"
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

    def to_representation(self, instance):
        """
        Переопределяет метод to_representation для обработки отсутствующих данных.
        """
        data = super().to_representation(instance)
        # Убедимся, что все JSON-поля имеют значение по умолчанию
        for field in data:
            if data[field] is None:
                data[field] = {} if field.endswith("_json") or field.endswith("_data") else []
        return data