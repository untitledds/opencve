# cves/extended_views.py
from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from django.db import transaction
from cves.models import Cve, Vendor, Product, Weakness
from users.models import CveTag, UserTag
from cves.extended_serializers import (
    ExtendedCveListSerializer,
    ExtendedCveDetailSerializer,
    ExtendedVendorListSerializer,
    ExtendedProductListSerializer,
    SubscriptionSerializer,
    UserTagSerializer,
    CveTagSerializer,
)
from cves.serializers import (
    WeaknessListSerializer,
)
from cves.extended_utils import (
    extended_list_filtered_cves,
    get_user_subscriptions,
    get_detailed_subscriptions,
    process_subscription,
    get_current_project_for_user,
)


class ExtendedCveViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedCveListSerializer
    queryset = Cve.objects.order_by("-updated_at")
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "cve_id"

    def get_serializer_class(self):
        if self.action == "retrieve":
            return ExtendedCveDetailSerializer
        return ExtendedCveListSerializer

    def get_queryset(self):
        if self.action == "retrieve":
            return self.queryset.all()

        request = self.request
        params = request.GET

        # Начинаем с полного queryset
        base_queryset = self.queryset.order_by("-updated_at")

        # Проверяем, нужно ли фильтровать по подпискам проекта по умолчанию
        use_default = "myproject" in params

        if use_default:
            # Кэшируем проект
            if not hasattr(request, "_cached_default_project"):
                project = get_current_project_for_user(request.user, use_default=True)
                setattr(request, "_cached_default_project", project)
            else:
                project = request._cached_default_project

            if not project:
                return Cve.objects.none()

            vendor_keys = project.subscriptions.get("vendors", [])
            product_keys = project.subscriptions.get("products", [])
            all_keys = [k for k in (vendor_keys + product_keys) if k]

            if not all_keys:
                return Cve.objects.none()

            # Фильтруем по подпискам — это становится базовым queryset
            base_queryset = base_queryset.filter(vendors__has_any_keys=all_keys)

        # Применяем все остальные фильтры (search, cvss, severity и т.д.)
        # Передаём изменённый base_queryset как основу
        return extended_list_filtered_cves(
            params, request.user, base_queryset=base_queryset
        )


class ExtendedVendorViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedVendorListSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = Vendor.objects.order_by("name")
    lookup_field = "id"
    lookup_url_kwarg = "id"

    def get_queryset(self):
        queryset = self.queryset
        search = self.request.GET.get("search")
        if search:
            queryset = queryset.filter(name__icontains=search)
        return queryset


class ExtendedProductViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedProductListSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "id"
    lookup_url_kwarg = "id"
    queryset = (
        Product.objects.select_related("vendor")
        .filter(name__isnull=False)
        .exclude(name="")
        .order_by("name")
    )

    def get_queryset(self):
        vendor_id = self.kwargs.get("vendor_id")
        search = self.request.GET.get("search")
        queryset = self.queryset

        if vendor_id:
            vendor = get_object_or_404(Vendor, id=vendor_id)
            queryset = queryset.filter(vendor=vendor)
        if search:
            queryset = queryset.filter(name__icontains=search)
        return queryset

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["hide_vendor_in_product"] = bool(self.kwargs.get("vendor_id"))
        return context


class ExtendedSubscriptionViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = SubscriptionSerializer

    @action(detail=False, methods=["post"])
    def subscribe(self, request):
        return self._handle_subscription(request, "subscribe")

    @action(detail=False, methods=["post"])
    def unsubscribe(self, request):
        return self._handle_subscription(request, "unsubscribe")

    @action(detail=False, methods=["get"])
    def project_subscriptions(self, request):
        project = self._get_project(request)
        subscriptions = {
            "vendors": project.subscriptions.get("vendors", []),
            "products": project.subscriptions.get("products", []),
        }
        return Response({"status": "success", "data": subscriptions})

    @action(detail=False, methods=["get"])
    def user_subscriptions(self, request):
        subscriptions = get_user_subscriptions(request.user)
        return Response({"status": "success", "data": subscriptions})

    @action(detail=False, methods=["get"])
    def detailed_project_subscriptions(self, request):
        project = self._get_project(request)
        data = get_detailed_subscriptions(project)
        return Response({"status": "success", "data": data})

    def _handle_subscription(self, request, action):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            result = process_subscription(
                user=request.user,
                obj_type=serializer.validated_data["obj_type"],
                obj_id=serializer.validated_data["obj_id"],
                action=action,
                project_id=serializer.validated_data.get("project_id"),
                use_default=True,
            )
            return Response({"status": "success", **result}, status=status.HTTP_200_OK)
        except ValueError as e:
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def _get_project(self, request):
        project_id = request.query_params.get("project_id")
        return get_current_project_for_user(
            request.user,
            project_id=project_id,
            use_default="myproject" in request.query_params,
        )


class UserTagViewSet(viewsets.ModelViewSet):
    serializer_class = UserTagSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UserTag.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class CveTagViewSet(viewsets.ModelViewSet):
    serializer_class = CveTagSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return CveTag.objects.filter(user=self.request.user)

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        # Обработка входных данных
        cve_ids = list(set(request.data.get("cve_ids", [])))
        tags = list(set(request.data.get("tags", [])))

        if not cve_ids or not tags:
            return Response(
                {
                    "status": "error",
                    "message": "Both 'cve_ids' and 'tags' are required.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Получаем все CVE одним запросом
        cves = Cve.objects.filter(cve_id__in=cve_ids)
        existing_cve_ids = set(cves.values_list("cve_id", flat=True))
        missing_cve_ids = set(cve_ids) - existing_cve_ids

        if missing_cve_ids:
            return Response(
                {
                    "status": "error",
                    "message": f"CVE(s) not found: {', '.join(sorted(missing_cve_ids))}",
                    "missing_cve_ids": sorted(missing_cve_ids),
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        # Bulk create/update
        cve_tags_to_create = []
        cve_tags_to_update = []

        for cve in cves:
            try:
                cve_tag = CveTag.objects.get(cve=cve, user=request.user)
                cve_tag.tags = list(set(cve_tag.tags + tags))
                cve_tags_to_update.append(cve_tag)
            except CveTag.DoesNotExist:
                cve_tags_to_create.append(CveTag(cve=cve, user=request.user, tags=tags))
        # Выполняем массовые операции
        created_tags = CveTag.objects.bulk_create(cve_tags_to_create)
        CveTag.objects.bulk_update(cve_tags_to_update, ["tags"])

        # Сериализуем все созданные и обновленные теги
        all_tags = created_tags + cve_tags_to_update
        serializer = self.get_serializer(all_tags, many=True)

        return Response(
            {
                "status": "success",
                "message": f"Tags assigned to {len(all_tags)} CVE(s)",
                "data": serializer.data,
            },
            status=status.HTTP_201_CREATED,
        )


class ExtendedWeaknessViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = WeaknessListSerializer
    queryset = Weakness.objects.all().order_by("cwe_id")
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "cwe_id"
