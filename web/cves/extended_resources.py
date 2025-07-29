# web/cves/extended_resources.py
from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from django.db import transaction
from cves.models import Cve, Vendor, Product, Weakness
from users.models import UserTag, CveTag
from cves.serializers import WeaknessListSerializer
from cves.extended_serializers import (
    ExtendedCveListSerializer,
    ExtendedCveDetailSerializer,
    SubscriptionSerializer,
    UserTagSerializer,
    CveTagSerializer,
    ExtendedVendorListSerializer,
    ExtendedProductListSerializer,
)
from cves.extended_utils import extended_list_filtered_cves, get_user_subscriptions


class ExtendedCveViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedCveListSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "cve_id"

    serializer_classes = {
        "list": ExtendedCveListSerializer,
        "retrieve": ExtendedCveDetailSerializer,
    }

    def get_queryset(self):
        return extended_list_filtered_cves(self.request.GET, self.request.user)

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        if self.action == "list":
            user = self.request.user
            # Оптимизация: prefetch user's CveTag для всех CVE
            context["request"] = self.request
            # Внешний код должен делать prefetch, если нужно
        return context


class ExtendedWeaknessViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = WeaknessListSerializer
    queryset = Weakness.objects.order_by("cwe_id")
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "cwe_id"


class ExtendedVendorViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedVendorListSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = Vendor.objects.order_by("name")
    lookup_field = "id"

    def get_queryset(self):
        queryset = super().get_queryset()
        search = self.request.GET.get("search")
        if search:
            queryset = queryset.filter(name__icontains=search)
        # Оптимизация: предзагрузка продуктов для подсчёта
        return queryset.prefetch_related("products")


class ExtendedProductViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedProductListSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "id"
    lookup_url_kwarg = "id"

    def get_queryset(self):
        base_qs = (
            Product.objects.select_related("vendor")
            .exclude(name__in=["", None])
            .order_by("name")
        )
        vendor_id = self.kwargs.get("vendor_id")
        if vendor_id:
            get_object_or_404(Vendor, id=vendor_id)
            base_qs = base_qs.filter(vendor_id=vendor_id)
        search = self.request.GET.get("search")
        if search:
            base_qs = base_qs.filter(name__icontains=search)

        return base_qs

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["hide_vendor_in_product"] = bool(self.kwargs.get("vendor_id"))
        return context


class ExtendedSubscriptionViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = SubscriptionSerializer

    @action(detail=False, methods=["post"])
    @transaction.atomic
    def subscribe(self, request):
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        result = serializer.save(action="subscribe")
        return Response(result, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["post"])
    @transaction.atomic
    def unsubscribe(self, request):
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        result = serializer.save(action="unsubscribe")
        return Response(result, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"])
    def user_subscriptions(self, request):
        subscriptions = get_user_subscriptions(request.user)
        return Response(subscriptions)


class UserTagViewSet(viewsets.ModelViewSet):
    serializer_class = UserTagSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UserTag.objects.filter(user=self.request.user).order_by("name")

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=["post"])
    @transaction.atomic
    def assign_to_cves(self, request, pk=None):
        user_tag = self.get_object()
        cve_ids = request.data.get("cve_ids", [])

        if not isinstance(cve_ids, list):
            return Response({"detail": "cve_ids must be a list"}, status=400)
        if not cve_ids:
            return Response({"detail": "cve_ids is required"}, status=400)

        cves = Cve.objects.filter(cve_id__in=cve_ids)
        found_ids = {cve.cve_id for cve in cves}
        missing = set(cve_ids) - found_ids
        if missing:
            return Response(
                {"detail": f"CVEs not found: {', '.join(missing)}"}, status=404
            )

        updated_count = 0
        for cve in cves:
            cve_tag, created = CveTag.objects.get_or_create(
                cve=cve, user=request.user, defaults={"tags": []}
            )
            if user_tag.name not in cve_tag.tags:
                cve_tag.tags.append(user_tag.name)
                cve_tag.save()
                updated_count += 1

        return Response(
            {
                "status": "success",
                "assigned_to": updated_count,
                "tag": UserTagSerializer(user_tag).data,
                "cves": list(found_ids),
            }
        )


class CveTagViewSet(viewsets.ModelViewSet):
    serializer_class = CveTagSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return CveTag.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        # Вызывается внутри create(), перед сохранением
        serializer.save(user=self.request.user)

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instances = serializer.save()  # возвращает список CveTag
        response_data = CveTagSerializer(instances, many=True).data
        return Response(
            {
                "status": "success",
                "message": f"Tags applied to {len(instances)} CVE(s).",
                "data": response_data,
            },
            status=status.HTTP_201_CREATED,
        )
