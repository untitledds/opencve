from rest_framework import mixins, viewsets, permissions
import logging
import json
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from django.http import Http404
from cves.models import Cve, Vendor, Product, Weakness
from .extended_utils import get_detailed_subscriptions, get_user_organization
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
    DetailedSubscriptionSerializer,
)
from .extended_utils import extended_list_filtered_cves, get_products
from opencve.utils import is_valid_uuid
from cves.utils import list_to_dict_vendors

logger = logging.getLogger(__name__)


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

        for cve_data in response.data:
            logger.debug(f"Processing CVE: {cve_data}")
            logger.debug(f"Type of cve_data: {type(cve_data)}")

            # Если cve_data — строка, десериализуем её
            if isinstance(cve_data, str):
                try:
                    cve_data = json.loads(cve_data)
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON data: {e}")
                    continue

            # Проверка структуры данных
            if not isinstance(cve_data, dict) or "vendors" not in cve_data:
                logger.warning(f"Invalid data format for CVE: {cve_data}")
                continue

            # Обработка данных
            if isinstance(cve_data["vendors"], list) and all(
                isinstance(v, str) for v in cve_data["vendors"]
            ):
                cve_data["vendors"] = list_to_dict_vendors(cve_data["vendors"])
                cve_data["products"] = get_products(cve_data["vendors"])
            else:
                logger.warning(
                    f"Invalid vendors format for CVE {cve_data.get('cve_id')}: {cve_data.get('vendors')}"
                )
                cve_data["vendors"] = (
                    {}
                )  # Возвращаем пустой словарь, если данные некорректны
                cve_data["products"] = []  # Возвращаем пустой список продуктов

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

    def list(self, request, *args, **kwargs):
        """
        Возвращает список продуктов для конкретного вендора.
        """
        vendor_name = self.kwargs.get("vendor_name")
        if not vendor_name:
            return Response(
                {"status": "error", "message": "Vendor name is required"}, status=400
            )

        products = self.get_queryset()

        # Сериализация данных
        serializer = self.get_serializer(products, many=True)
        return Response({"status": "success", "products": serializer.data})


class ExtendedSubscriptionViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = SubscriptionSerializer

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

    @action(detail=False, methods=["get"])
    def project_subscriptions(self, request):
        """
        Получить подписки проекта.
        """
        project = self._get_project(request)
        subscriptions = self._get_subscriptions(project=project)

        if not subscriptions["vendors"] and not subscriptions["products"]:
            return self._return_response(
                {}, error_message="No subscriptions found for this project"
            )

        return self._return_response(subscriptions)

    @action(detail=False, methods=["get"])
    def check_user_in_project(self, request):
        """
        Проверить, принадлежит ли пользователь к проекту.
        """
        project_id = request.query_params.get("project_id")
        project = get_object_or_404(Project, id=project_id)

        organization = get_user_organization(request.user)
        if not organization:
            return self._return_response(
                {"is_member": False},
                error_message="User is not a member of any organization",
            )

        is_member = project.organization == organization
        return self._return_response({"is_member": is_member})

    @action(detail=False, methods=["get"])
    def user_subscriptions(self, request):
        """
        Получить все подписки пользователя.
        """
        organization = get_user_organization(request.user)
        if not organization:
            return self._return_response(
                {}, error_message="User is not a member of any organization"
            )

        projects = Project.objects.filter(organization=organization)
        subscriptions = self._get_subscriptions(projects=projects)

        if not subscriptions["vendors"] and not subscriptions["products"]:
            return self._return_response(
                {}, error_message="No subscriptions found for this user"
            )

        return self._return_response(
            {
                "vendors": list(subscriptions["vendors"]),
                "products": list(subscriptions["products"]),
            }
        )

    @action(detail=False, methods=["get"])
    def detailed_project_subscriptions(self, request):
        """
        Получить детальную информацию о подписках проекта.
        """
        project = self._get_project(request)
        detailed_subscriptions = get_detailed_subscriptions(project)

        if (
            not detailed_subscriptions["subscriptions"]["vendors"]
            and not detailed_subscriptions["subscriptions"]["products"]
        ):
            return self._return_response(
                {}, error_message="No detailed subscriptions found for this project"
            )

        # Сериализуем данные с помощью DetailedSubscriptionSerializer
        serialized_data = DetailedSubscriptionSerializer(detailed_subscriptions).data
        return self._return_response(serialized_data)

    def _handle_subscription(self, request, action):
        """
        Обрабатывает подписку или отписку на вендора или продукта.
        :param request: Запрос от клиента.
        :param action: Действие ("subscribe" или "unsubscribe").
        :return: Ответ с измененными подписками или ошибкой.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        obj_type = serializer.validated_data["obj_type"]
        obj_id = serializer.validated_data["obj_id"]
        # Безопасное получение project_id, project_name и org_name
        project_id = serializer.validated_data.get("project_id")  # Используем .get()
        project_name = serializer.validated_data.get(
            "project_name"
        )  # Используем .get()
        org_name = serializer.validated_data.get("org_name")  # Используем .get()
        if project_id:
            project = self._get_project_by_id(project_id)
        elif project_name and org_name:
            # Если project_id не указан, но есть имя проекта и организации, ищем проект по ним
            organization = get_user_organization(request.user)
            if not organization:
                return self._return_response(
                    {}, error_message="User is not a member of any organization"
                )

            project = get_object_or_404(
                Project,
                name=project_name,
                organization__name=org_name,
                organization=organization,
            )
        else:
            return self._return_response(
                {},
                error_message="Either project_id or project_name and org_name must be provided",
            )

        return self._process_subscription(project, obj_id, obj_type, action)

    def _process_subscription(self, project, obj_id, obj_type, action):
        """
        Выполняет логику подписки/отписки на вендора или продукта.
        :param project: Проект, для которого выполняется действие.
        :param obj_id: UUID объекта (вендора или продукта).
        :param obj_type: Тип объекта ("vendor" или "product").
        :param action: Действие ("subscribe" или "unsubscribe").
        :return: Ответ с измененными подписками и статусом операции.
        """
        if obj_type == "vendor":
            key = "vendors"
            obj = get_object_or_404(Vendor, id=obj_id)
            obj_name = obj.name
        elif obj_type == "product":
            key = "products"
            obj = get_object_or_404(Product, id=obj_id)
            obj_name = obj.vendored_name
        else:
            return self._return_response({}, error_message="Invalid object type")

        subscriptions = set(project.subscriptions.get(key, []))

        if action == "subscribe":
            subscriptions.add(obj_name)
            message = f"{obj_type.capitalize()} {obj_name} subscribed successfully"
        else:
            if obj_name not in subscriptions:
                return self._return_response(
                    {}, error_message=f"Not subscribed to this {obj_type}"
                )
            subscriptions.remove(obj_name)
            message = f"{obj_type.capitalize()} {obj_name} unsubscribed successfully"

        project.subscriptions[key] = list(subscriptions)
        project.save()

        return self._return_response(
            {
                "subscriptions": self._get_project_subscriptions(project),
                "message": message,
            }
        )

    def _get_project_subscriptions(self, project):
        """
        Возвращает информацию о текущих подписках проекта.
        :param project: Проект, для которого возвращаются подписки.
        :return: Сериализованные данные о подписках.
        """
        subscriptions = {
            "vendors": project.subscriptions.get("vendors", []),
            "products": project.subscriptions.get("products", []),
        }

        if not subscriptions["vendors"] and not subscriptions["products"]:
            return {"message": "No subscriptions found for this project"}

        return ProjectSubscriptionsSerializer(subscriptions).data

    def _get_project(self, request):
        """
        Получает проект по project_id из запроса и проверяет, принадлежит ли он организации пользователя.
        :param request: Запрос от клиента.
        :return: Проект.
        """
        project_id = request.query_params.get("project_id")
        return self._get_project_by_id(project_id)

    def _get_project_by_id(self, project_id):
        """
        Получает проект по project_id и проверяет, принадлежит ли он организации пользователя.
        :param project_id: UUID проекта.
        :return: Проект.
        """
        organization = get_user_organization(self.request.user)
        if not organization:
            raise Http404("User is not a member of any organization")

        project = get_object_or_404(Project, id=project_id, organization=organization)
        return project

    def _get_subscriptions(self, project=None, projects=None):
        """
        Возвращает подписки для проекта или списка проектов.
        :param project: Проект, для которого возвращаются подписки.
        :param projects: Список проектов, для которых возвращаются подписки.
        :return: Словарь с подписками.
        """
        subscriptions = {"vendors": set(), "products": set()}

        if project:
            project_vendors = project.subscriptions.get("vendors", [])
            project_products = project.subscriptions.get("products", [])
            subscriptions["vendors"].update(project_vendors)
            subscriptions["products"].update(project_products)
        elif projects:
            for project in projects:
                project_vendors = project.subscriptions.get("vendors", [])
                project_products = project.subscriptions.get("products", [])
                subscriptions["vendors"].update(project_vendors)
                subscriptions["products"].update(project_products)

        return subscriptions

    def _return_response(self, data, success_message=None, error_message=None):
        """
        Возвращает Response с данными или сообщением об ошибке.
        :param data: Данные для возврата.
        :param success_message: Сообщение об успешной операции.
        :param error_message: Сообщение об ошибке.
        :return: Response.
        """
        if error_message:
            return Response({"status": "error", "message": error_message}, status=400)

        if success_message:
            data["message"] = success_message

        return Response({"status": "success", **data})
