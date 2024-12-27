from rest_framework import viewsets, status, filters
from rest_framework.response import Response
from django.http import Http404
from cves.views import CveDetailView
from cves.models import Cve, CveTag
from cves.serializers_extended.extended import (
    CveExtendedListSerializer,
    CveExtendedDetailSerializer,
)
from cves.utils import list_to_dict_vendors, list_weaknesses
import logging
import json

# Настройка логгера
logger = logging.getLogger(__name__)


class CveFilter(filters.BaseFilterBackend):
    """
    Фильтр для CVE по дате.
    """

    def filter_queryset(self, request, queryset, view):
        start_date = request.query_params.get("start_date")
        end_date = request.query_params.get("end_date")

        if start_date:
            queryset = queryset.filter(updated_at__gte=start_date)
        if end_date:
            queryset = queryset.filter(updated_at__lte=end_date)

        return queryset


class CveExtendedViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet для возврата данных CveDetailView в формате JSON.
    """

    serializer_class = CveExtendedListSerializer
    filter_backends = [CveFilter, filters.OrderingFilter]  # Используем CveFilter
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
            # Используем CveDetailView для получения контекста
            view = CveDetailView()
            view.object = cve
            view_context = view.get_context_data()
            # Добавляем данные из контекста CveDetailView
            context.update(
                {
                    "vendors": list_to_dict_vendors(view_context.get("vendors", {})),
                    "weaknesses": list_weaknesses(view_context.get("weaknesses", [])),
                    "nvd_json": json.loads(view_context.get("nvd_json", "{}")),
                    "mitre_json": json.loads(view_context.get("mitre_json", "{}")),
                    "redhat_json": json.loads(view_context.get("redhat_json", "{}")),
                    "vulnrichment_json": json.loads(
                        view_context.get("vulnrichment_json", "{}")
                    ),
                }
            )

        if self.request.user.is_authenticated:
            user_tags = {
                t.name: {"color": t.color, "description": t.description}
                for t in UserTag.objects.filter(user=self.request.user).all()
            }
            context["user_tags"] = user_tags
            if self.action == "retrieve":
                cve = self.get_object()
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
            cve_id = kwargs.get("cve_id")
            cve = Cve.objects.get(cve_id=cve_id)
            return super().retrieve(request, *args, **kwargs)
        except Cve.DoesNotExist:
            raise Http404("CVE not found")
        except Exception as e:
            logger.error(f"Error retrieving CVE: {e}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
