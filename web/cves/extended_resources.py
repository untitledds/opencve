from rest_framework import mixins, viewsets, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from cves.models import Cve, Vendor, Product, Weakness
from organizations.models import Project
from cves.serializers import VendorListSerializer, ProductListSerializer, WeaknessListSerializer
from .extended_serializers import ExtendedCveListSerializer, ExtendedCveDetailSerializer
from .extended_utils import extended_list_filtered_cves
from cves.utils import is_valid_uuid

class ExtendedCveViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedCveListSerializer
    queryset = Cve.objects.order_by("-updated_at").all()
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "cve_id"

    serializer_classes = {
        "list": ExtendedCveListSerializer,
        "retrieve": ExtendedCveDetailSerializer,
    }

    def get_queryset(self):
        if self.action == "retrieve":
            return self.queryset
        return extended_list_filtered_cves(self.request.GET, self.request.user)

    def get_serializer_class(self):
        return self.serializer_classes.get(self.action, self.serializer_class)

class ExtendedWeaknessViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = WeaknessListSerializer
    queryset = Weakness.objects.all().order_by("cwe_id")
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "cwe_id"

class ExtendedVendorViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = VendorListSerializer
    permission_classes = (permissions.IsAuthenticated,)
    queryset = Vendor.objects.order_by("name").all()
    lookup_field = "name"
    lookup_url_kwarg = "name"

class ExtendedProductViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ProductListSerializer
    permission_classes = (permissions.IsAuthenticated,)
    lookup_field = "name"
    lookup_url_kwarg = "name"

    def get_queryset(self):
        vendor = get_object_or_404(Vendor, name=self.kwargs["vendor_name"])
        return Product.objects.filter(vendor=vendor).order_by("name").all()

class ExtendedSubscriptionViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=["post"])
    def subscribe(self, request):
        """
        Подписка на вендора или продукт.
        """
        return self._handle_subscription(request, "subscribe")

    @action(detail=False, methods=["post"])
    def unsubscribe(self, request):
        """
        Отписка от вендора или продукта.
        """
        return self._handle_subscription(request, "unsubscribe")

    def _handle_subscription(self, request, action):
        obj_type = request.data.get("obj_type")
        obj_id = request.data.get("obj_id")
        project_id = request.data.get("project_id")

        if (
            not all([obj_type, obj_id, project_id])
            or not is_valid_uuid(obj_id)
            or not is_valid_uuid(project_id)
            or obj_type not in ["vendor", "product"]
        ):
            return Response({"status": "error", "message": "Invalid request"}, status=400)

        # Проверяем, что проект принадлежит текущей организации пользователя
        project = get_object_or_404(
            Project, id=project_id, organization=request.user_organization
        )

        if obj_type == "vendor":
            vendor = get_object_or_404(Vendor, id=obj_id)
            project_vendors = set(project.subscriptions.get("vendors", []))

            if action == "subscribe":
                project_vendors.add(vendor.name)
            else:
                try:
                    project_vendors.remove(vendor.name)
                except KeyError:
                    return Response({"status": "error", "message": "Not subscribed"}, status=400)

            project.subscriptions["vendors"] = list(project_vendors)

        elif obj_type == "product":
            product = get_object_or_404(Product, id=obj_id)
            project_products = set(project.subscriptions.get("products", []))

            if action == "subscribe":
                project_products.add(product.vendored_name)
            else:
                try:
                    project_products.remove(product.vendored_name)
                except KeyError:
                    return Response({"status": "error", "message": "Not subscribed"}, status=400)

            project.subscriptions["products"] = list(project_products)

        project.save()
        return Response({"status": "ok"})
