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
from rest_framework.pagination import PageNumberPagination


class OptionalPagination(PageNumberPagination):
    page_size_query_param = "page_size"
    max_page_size = 1000

    def paginate_queryset(self, queryset, request, view=None):
        if request.query_params.get(self.page_size_query_param) == "all":
            return None
        return super().paginate_queryset(queryset, request, view)


class ExtendedCveViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedCveListSerializer
    queryset = Cve.objects.order_by("-updated_at")
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "cve_id"
    pagination_class = OptionalPagination

    def get_serializer_class(self):
        if self.action == "retrieve":
            return ExtendedCveDetailSerializer
        return ExtendedCveListSerializer

    def get_queryset(self):
        if self.action == "retrieve":
            return self.queryset.all()
        return extended_list_filtered_cves(self.request.GET, self.request.user)


class ExtendedVendorViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedVendorListSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = Vendor.objects.order_by("name")
    lookup_field = "id"
    lookup_url_kwarg = "id"
    pagination_class = OptionalPagination

    def get_queryset(self):
        queryset = self.queryset.all()
        search = self.request.GET.get("search")
        if search:
            queryset = queryset.filter(name__icontains=search)
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(
            page or queryset, many=True, context={"request": request}
        )
        data = [item for item in serializer.data if item is not None]
        return (
            self.get_paginated_response({"status": "success", "vendors": data})
            if page
            else Response({"status": "success", "vendors": data})
        )

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, context={"request": request})
        return Response({"status": "success", "data": serializer.data})


class ExtendedProductViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedProductListSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "id"
    lookup_url_kwarg = "id"
    pagination_class = OptionalPagination

    def get_queryset(self):
        vendor_id = self.kwargs.get("vendor_id")
        search = self.request.GET.get("search")
        queryset = (
            Product.objects.select_related("vendor")
            .filter(name__isnull=False)
            .exclude(name="")
            .order_by("name")
        )
        if vendor_id:
            vendor = get_object_or_404(Vendor, id=vendor_id)
            queryset = queryset.filter(vendor=vendor)
        if search:
            queryset = queryset.filter(name__icontains=search)
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        page = self.paginate_queryset(queryset)
        serializer = self.get_serializer(
            page or queryset,
            many=True,
            context={
                "request": request,
                "hide_vendor_in_product": bool(self.kwargs.get("vendor_id")),
                "vendor_name": self.kwargs.get("vendor_id"),
            },
        )
        data = [item for item in serializer.data if item is not None]
        response_data = {"status": "success", "products": data}
        if self.kwargs.get("vendor_id"):
            vendor = get_object_or_404(Vendor, id=self.kwargs["vendor_id"])
            response_data["vendor"] = {
                "id": str(vendor.id),
                "name": vendor.name,
                "display_name": vendor.human_name,
                "is_subscribed": self._get_vendor_subscription(vendor, request),
            }
        return (
            self.get_paginated_response(response_data)
            if page
            else Response(response_data)
        )

    def _get_vendor_subscription(self, vendor, request):
        project = get_current_project_for_user(
            request.user,
            project_id=request.query_params.get("project_id"),
            use_default="myproject" in request.query_params,
        )
        if not project:
            return False
        return vendor.name in project.subscriptions.get("vendors", [])

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(
            instance,
            context={
                "request": request,
                "vendor_name": instance.vendor.name,
                "hide_vendor_in_product": False,
            },
        )
        return Response({"status": "success", "data": serializer.data})


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
        cve_ids = request.data.get("cve_ids", [])
        tags = request.data.get("tags", [])

        if not cve_ids or not tags:
            return Response(
                {
                    "status": "error",
                    "message": "Both 'cve_ids' and 'tags' are required.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Преобразуем в списки
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        if isinstance(tags, str):
            tags = [tags]

        # Убираем дубликаты
        tags = list(set(tags))

        # Получаем объекты CVE
        cves = []
        for cve_id in cve_ids:
            try:
                cve = Cve.objects.get(cve_id=cve_id)
                cves.append(cve)
            except Cve.DoesNotExist:
                return Response(
                    {"status": "error", "message": f"CVE with ID {cve_id} not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

        # Создаём или обновляем теги
        created_tags = []
        for cve in cves:
            cve_tag, created = CveTag.objects.get_or_create(
                cve=cve, user=request.user, defaults={"tags": tags}
            )
            if not created:
                cve_tag.tags = list(set(cve_tag.tags + tags))
                cve_tag.save()
            created_tags.append(cve_tag)

        # Сериализуем
        serializer = self.get_serializer(created_tags, many=True)
        return Response(
            {
                "status": "success",
                "message": "Tags assigned successfully.",
                "data": serializer.data,
            },
            status=status.HTTP_201_CREATED,
        )


class ExtendedWeaknessViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = WeaknessListSerializer
    queryset = Weakness.objects.all().order_by("cwe_id")
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "cwe_id"
