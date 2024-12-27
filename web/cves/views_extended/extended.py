from rest_framework import viewsets, status, filters
from rest_framework.response import Response
from django.http import Http404
from cves.views import CveDetailView
from cves.models import Cve
from cves.serializers_extended.extended import (
    CveExtendedListSerializer,
    CveExtendedDetailSerializer,
)
from cves.utils import list_to_dict_vendors, list_weaknesses
from users.models import CveTag, UserTag  # Импорт моделей для работы с тегами
import logging
import json

# Настройка логгера
logger = logging.getLogger(__name__)


class CveFilter(filters.BaseFilterBackend):
    """
    Фильтр для CVE по дате.
    """

    def filter_queryset(self, request, queryset, view):
        # Фильтрация по дате
        start_date = request.query_params.get("start_date")
        end_date = request.query_params.get("end_date")

        if start_date:
            queryset = queryset.filter(updated_at__gte=start_date)
        if end_date:
            queryset = queryset.filter(updated_at__lte=end_date)
        # Фильтрация по вендору (без учета регистра)
        vendor = request.query_params.get("vendor")
        if vendor:
            queryset = queryset.filter(vendors__icontains=f"{vendor.lower()}")

        # Фильтрация по продукту (без учета регистра)
        product = request.query_params.get("product")
        if product:
            queryset = queryset.filter(vendors__icontains=f"{product.lower()}")
        # Фильтрация по CVSS
        cvss = request.query_params.get("cvss")
        if cvss:
            if cvss == "empty":
                queryset = queryset.filter(metrics__cvssV3_1__data__score__isnull=True)
            elif cvss == "low":
                queryset = queryset.filter(
                    metrics__cvssV3_1__data__score__gte=0,
                    metrics__cvssV3_1__data__score__lte=3.9,
                )
            elif cvss == "medium":
                queryset = queryset.filter(
                    metrics__cvssV3_1__data__score__gte=4.0,
                    metrics__cvssV3_1__data__score__lte=6.9,
                )
            elif cvss == "high":
                queryset = queryset.filter(
                    metrics__cvssV3_1__data__score__gte=7.0,
                    metrics__cvssV3_1__data__score__lte=8.9,
                )
            elif cvss == "critical":
                queryset = queryset.filter(
                    metrics__cvssV3_1__data__score__gte=9.0,
                    metrics__cvssV3_1__data__score__lte=10.0,
                )

        return queryset


class CveExtendedViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet для возврата данных CveDetailView в формате JSON.
    """

    queryset = Cve.objects.all()
    serializer_class = CveExtendedListSerializer
    filter_backends = [CveFilter, filters.OrderingFilter]
    ordering_fields = ["created_at", "updated_at"]
    ordering = ["-updated_at"]

    def get_serializer_class(self):
        # Используем CveExtendedListSerializer для списка и CveExtendedDetailSerializer для деталей
        if self.action == "retrieve":
            return CveExtendedDetailSerializer
        return CveExtendedListSerializer

    def get_serializer_context(self):
        """
        Добавляет дополнительные данные в контекст сериализатора.
        """
        context = super().get_serializer_context()
        if self.action == "retrieve":
            cve = self.get_object()
            # Используем свойства модели для получения данных
            context.update(
                {
                    "vendors": cve.vendors,  # Используем поле vendors
                    "weaknesses": cve.weaknesses,  # Используем поле weaknesses
                    "nvd_json": cve.nvd_json,  # Используем свойство nvd_json
                    "mitre_json": cve.mitre_json,  # Используем свойство mitre_json
                    "redhat_json": cve.redhat_json,  # Используем свойство redhat_json
                    # Используем свойство vulnrichment_json
                    "vulnrichment_json": cve.vulnrichment_json,
                }
            )

            if self.request.user.is_authenticated:
                # Логика работы с тегами, аналогичная CveDetailView
                user_tags = {
                    t.name: {"color": t.color, "description": t.description}
                    for t in UserTag.objects.filter(user=self.request.user).all()
                }
                context["user_tags"] = user_tags
                cve_tags = CveTag.objects.filter(
                    user=self.request.user, cve=cve
                ).first()
                if cve_tags:
                    context["tags"] = [user_tags[tag] for tag in cve_tags.tags]
        return context

    def retrieve(self, request, *args, **kwargs):
        """
        Переопределяет метод retrieve для обработки ошибок и логирования.
        """
        try:
            return super().retrieve(request, *args, **kwargs)
        except Exception as e:
            cve_id = kwargs.get("cve_id")
            logger.error(f"Error retrieving CVE {cve_id}: {e}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
