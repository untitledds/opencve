from rest_framework import viewsets, permissions, status
from cves.constants import PRODUCT_SEPARATOR
import logging
import json
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.http import Http404
from django.db import transaction
from cves.models import Cve, Vendor, Product, Weakness
from .extended_utils import get_detailed_subscriptions, get_user_organization
from projects.models import Project, get_default_subscriptions
from users.models import UserTag, CveTag
from cves.serializers import (
    WeaknessListSerializer,
)
from .extended_serializers import (
    ExtendedCveListSerializer,
    ExtendedCveDetailSerializer,
    ProjectSubscriptionsSerializer,
    SubscriptionSerializer,
    DetailedSubscriptionSerializer,
    UserTagSerializer,
    CveTagSerializer,
    ExtendedVendorListSerializer,
    ExtendedProductListSerializer,
)
from .extended_utils import extended_list_filtered_cves, get_products
from .extended_mixins import SubscriptionMixin

# from opencve.utils import is_valid_uuid
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
    serializer_class = ExtendedVendorListSerializer
    permission_classes = (permissions.IsAuthenticated,)
    queryset = Vendor.objects.order_by("name").all()
    lookup_field = "name"
    lookup_url_kwarg = "name"

    def get_queryset(self):
        """
        Переопределение queryset для поддержки поиска.
        """
        queryset = Vendor.objects.order_by("name").all()

        # Применяем фильтрацию только для действия list
        if self.action == "list":
            search_query = self.request.GET.get("search", None)
            if search_query:
                # Используем icontains для поиска без учета регистра
                queryset = queryset.filter(name__icontains=search_query)

        return queryset

    def list(self, request, *args, **kwargs):
        """
        Возвращает список вендоров с поддержкой поиска.
        """
        queryset = self.get_queryset()
        page = self.paginate_queryset(queryset)

        # Создаем миксин для подписок
        subscription_mixin = SubscriptionMixin()
        subscription_mixin.context = {"request": request}

        if page is not None:
            serializer = self.get_serializer(
                page, many=True, context={"subscription_mixin": subscription_mixin}
            )
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(
            queryset, many=True, context={"subscription_mixin": subscription_mixin}
        )
        return Response({"status": "success", "vendors": serializer.data})

    @action(detail=False, methods=["get"])
    def search(self, request):
        """
        Отдельный endpoint для поиска вендоров.
        """
        search_query = request.query_params.get("q", "")
        if not search_query:
            return Response({"results": []})

        # Используем icontains для поиска без учета регистра
        vendors = Vendor.objects.filter(name__icontains=search_query)[:50]
        serializer = self.get_serializer(vendors, many=True)
        return Response({"results": serializer.data})


class ExtendedProductViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExtendedProductListSerializer
    permission_classes = (permissions.IsAuthenticated,)
    lookup_field = "name"
    lookup_url_kwarg = "name"

    def get_queryset(self):
        """
        Переопределение queryset для поддержки поиска по всем продуктам
        или только по продуктам конкретного вендора.
        """
        vendor_name = self.kwargs.get("vendor_name")
        search_query = self.request.GET.get("search", None)
        queryset = Product.objects.select_related("vendor").order_by("name")

        if vendor_name:
            # Если указан vendor_name, фильтруем продукты по вендору
            vendor = get_object_or_404(Vendor, name=vendor_name)
            queryset = queryset.filter(vendor=vendor)

        # Применяем фильтрацию по имени продукта, если есть параметр search
        if search_query:
            queryset = queryset.filter(name__icontains=search_query)

        return queryset

    def list(self, request, *args, **kwargs):
        """
        Возвращает список продуктов с поддержкой поиска.
        """
        vendor_name = self.kwargs.get("vendor_name")
        queryset = self.get_queryset()
        page = self.paginate_queryset(queryset)

        # Создаем миксин для подписок
        subscription_mixin = SubscriptionMixin()
        subscription_mixin.context = {"request": request}

        if page is not None:
            serializer = self.get_serializer(
                page, many=True, context={"subscription_mixin": subscription_mixin}
            )
            return self.get_paginated_response(serializer.data)

        # Сериализация данных
        serializer = self.get_serializer(
            queryset, many=True, context={"subscription_mixin": subscription_mixin}
        )
        response_data = {
            "status": "success",
            "products": serializer.data,
        }

        # Добавляем информацию о вендоре, если он указан
        if vendor_name:
            response_data.update(
                {
                    "vendor": vendor_name,
                    "vendor_subscribed": subscription_mixin.get_subscription_status(
                        "vendor",
                        vendor_name,  # Используем переменную вместо kwargs для ясности
                    ),
                }
            )

        return Response(response_data)


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
            return self._return_response({})

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
            return self._return_response({})

        projects = Project.objects.filter(organization=organization)
        subscriptions = self._get_subscriptions(projects=projects)

        if not subscriptions["vendors"] and not subscriptions["products"]:
            return self._return_response({})

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
            return self._return_response({})

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
        if project_id:
            project = self._get_project_by_id(project_id)
        else:
            # Если project_id не указан, но есть имя проекта и организации, ищем проект по ним
            organization = get_user_organization(request.user)
            if not organization:
                return self._return_response(
                    {}, error_message=f"User is not a member of any organization"
                )

            default_project_name = getattr(
                settings, "GLOBAL_DEFAULT_PROJECT_NAME", "default"
            )
            project = get_object_or_404(
                Project,
                name=default_project_name,
                organization=organization,
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

        # Получаем проект по ID
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
            projects = [project]
        for project in projects:
            project_vendors = project.subscriptions.get("vendors", [])
            subscriptions["vendors"].update(project_vendors)
            for product in project.subscriptions.get("products", []):
                _, p_name = product.split(PRODUCT_SEPARATOR)
                subscriptions["products"].add(p_name)
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

        if not data:  # Если данных нет, возвращаем 204
            return Response(
                {"status": "success", "message": success_message},
                status=status.HTTP_204_NO_CONTENT,
            )

        return Response({"status": "success", **data})


class UserTagViewSet(viewsets.ModelViewSet):
    serializer_class = UserTagSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Возвращаем только теги текущего пользователя
        return UserTag.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        # Автоматически назначаем текущего пользователя как владельца тега
        serializer.save(user=self.request.user)


class CveTagViewSet(viewsets.ModelViewSet):
    serializer_class = CveTagSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Возвращаем только теги, связанные с текущим пользователем
        return CveTag.objects.filter(user=self.request.user)

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        # Получаем cve_ids и tags из тела запроса
        cve_ids = request.data.get("cve_ids", [])
        tags = request.data.get("tags", [])

        # Проверяем, что cve_ids и tags переданы
        if not cve_ids or not tags:
            raise ValidationError(
                {"detail": "Both 'cve_ids' and 'tags' are required."},
                code=status.HTTP_400_BAD_REQUEST,
            )

        # Преобразуем cve_ids и tags в списки (если они переданы как строки)
        cve_ids = [cve_ids] if isinstance(cve_ids, str) else cve_ids
        tags = [tags] if isinstance(tags, str) else tags

        # Убираем дубликаты тегов
        tags = list(set(tags))

        # Получаем объекты Cve по cve_ids
        cves = []
        for cve_id in cve_ids:
            cve = get_object_or_404(Cve, cve_id=cve_id)
            cves.append(cve)

        # Передаем объекты Cve и текущего пользователя в контекст сериализатора
        serializer = self.get_serializer(data={"cve_ids": cve_ids, "tags": tags})
        serializer.context["cves"] = cves
        serializer.context["request"] = request  # Передаем request в контекст
        serializer.is_valid(raise_exception=True)

        # Создаем или обновляем теги
        created_tags = serializer.save()

        # Сериализуем созданные теги с many=True
        serializer = self.get_serializer(created_tags, many=True)

        # Возвращаем ответ
        response_data = {
            "status": "success",
            "message": "Tags assigned successfully.",
            "data": serializer.data,
        }
        return Response(response_data, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer):
        # Текущий пользователь автоматически добавляется в validated_data
        serializer.save()
