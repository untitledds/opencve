from rest_framework import mixins, viewsets, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from cves.models import Cve, Vendor, Product, Weakness
from projects.models import Project
from cves.serializers import (
    VendorListSerializer,
    ProductListSerializer,
    WeaknessListSerializer,
)
from .extended_serializers import (
    ExtendedCveListSerializer,
    ExtendedCveDetailSerializer,
    ProjectSubscriptionsSerializer,
    SubscriptionSerializer,
)
from .extended_utils import extended_list_filtered_cves, get_products
from opencve.utils import is_valid_uuid
from cves.utils import list_to_dict_vendors


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

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)

        # Добавляем структурированные данные в ответ
        for cve_data in response.data:
            cve_data["vendors"] = list_to_dict_vendors(cve_data["vendors"])
            cve_data["products"] = get_products(cve_data["vendors"])

        return response


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
    serializer_class = (
        SubscriptionSerializer  # Указываем сериализатор для входных данных
    )

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
        # Валидируем входные данные с помощью сериализатора
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        obj_type = serializer.validated_data["obj_type"]
        obj_id = serializer.validated_data["obj_id"]
        project_id = serializer.validated_data["project_id"]

        # Получаем проект и проверяем, что он принадлежит текущей организации пользователя
        project = get_object_or_404(
            Project, id=project_id, organization=request.user.organization
        )

        if obj_type == "vendor":
            self._handle_vendor_subscription(project, obj_id, action)
        elif obj_type == "product":
            self._handle_product_subscription(project, obj_id, action)

        project.save()

        # Возвращаем информацию о текущих подписках проекта
        return Response(self._get_project_subscriptions(project))

    def _handle_vendor_subscription(self, project, vendor_id, action):
        vendor = get_object_or_404(Vendor, id=vendor_id)
        project_vendors = set(project.subscriptions.get("vendors", []))

        if action == "subscribe":
            project_vendors.add(vendor.name)
        else:
            try:
                project_vendors.remove(vendor.name)
            except KeyError:
                return Response(
                    {"status": "error", "message": "Not subscribed"}, status=400
                )

        project.subscriptions["vendors"] = list(project_vendors)

    def _handle_product_subscription(self, project, product_id, action):
        product = get_object_or_404(Product, id=product_id)
        project_products = set(project.subscriptions.get("products", []))

        if action == "subscribe":
            project_products.add(product.vendored_name)
        else:
            try:
                project_products.remove(product.vendored_name)
            except KeyError:
                return Response(
                    {"status": "error", "message": "Not subscribed"}, status=400
                )

        project.subscriptions["products"] = list(project_products)

    def _get_project_subscriptions(self, project):
        # Сериализуем информацию о подписках проекта
        return ProjectSubscriptionsSerializer(
            {
                "vendors": project.subscriptions.get("vendors", []),
                "products": project.subscriptions.get("products", []),
            }
        ).data
