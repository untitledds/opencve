from django.http import Http404
from django.db.models import Q
from django.shortcuts import get_object_or_404
from cves.utils import list_filtered_cves, list_to_dict_vendors
from cves.models import Vendor, Product
from projects.models import Project
from organizations.models import Membership
from django.conf import settings
import logging

from cves.constants import PRODUCT_SEPARATOR
from users.models import CveTag

logger = logging.getLogger(__name__)


def escape_like_value(value: str) -> str:
    """
    Экранирует строку для безопасного использования в Django ORM с lookup'ами
    __contains, __icontains, __startswith, __endswith.

    Экранирует символы, имеющие особое значение в SQL LIKE:
    - % : любое количество символов
    - _ : один символ
    - \ : символ экранирования

    Пример:
        escape_like_value("100%") -> "100\\%"
        escape_like_value("test_product") -> "test\\_product"
    """
    if not isinstance(value, str):
        value = str(value)

    return (
        value.replace("\\", "\\\\")  # Сначала экранируем сам обратный слэш
        .replace("%", "\\%")  # Затем % и _
        .replace("_", "\\_")
    )


def parse_cvss_filter(value: str) -> tuple[str, float]:
    """
    Парсит строку фильтрации CVSS.
    Поддерживаемые форматы: >7.0, >=7.0, <5.0, <=5.0, =7.5, 7.5 (эквивалентно =7.5)
    Возвращает: (lookup_type, float_value)
    """
    value = value.strip()
    if value.startswith(">="):
        return "gte", float(value[2:])
    elif value.startswith("<="):
        return "lte", float(value[2:])
    elif value.startswith(">"):
        return "gt", float(value[1:])
    elif value.startswith("<"):
        return "lt", float(value[1:])
    elif value.startswith("="):
        return "exact", float(value[1:])
    else:
        # По умолчанию — точное совпадение
        return "exact", float(value)


def get_user_organization(user):
    """
    Возвращает организацию пользователя.
    :param user: Объект пользователя.
    :return: Организация пользователя или None.
    """
    membership = Membership.objects.filter(user=user).first()
    return membership.organization if membership else None


def get_current_project_for_user(user, project_id=None, use_default=False):
    if not user or not user.is_authenticated:
        return None

    organization = get_user_organization(user)
    if not organization:
        raise Http404("User not in organization")

    if project_id:
        return get_object_or_404(Project, id=project_id, organization=organization)

    if use_default:
        default_name = getattr(settings, "GLOBAL_DEFAULT_PROJECT_NAME", "default")
        return get_object_or_404(Project, name=default_name, organization=organization)

    return None


def extended_list_filtered_cves(params, user):
    """
    Расширенная фильтрация CVE с поддержкой:
    - created_at, updated_at
    - severity, vendor, product
    - cvss_score (>, <, >=, <=)
    - cwe, kev, has_tag, is_subscribed
    - references, has_exploit
    """
    queryset = list_filtered_cves(params, user)

    # --- Даты ---
    if params.get("created_at"):
        queryset = queryset.filter(created_at__date__gte=params["created_at"])

    if params.get("updated_at"):
        queryset = queryset.filter(updated_at__date__gte=params["updated_at"])

    # --- Severity ---
    if params.get("severity"):
        queryset = queryset.filter(severity=params["severity"].upper())

    # --- Vendor / Product ---
    if params.get("vendor"):
        queryset = queryset.filter(vendors__icontains=params["vendor"])

    if params.get("product"):
        safe_product = escape_like_value(params["product"])
        queryset = queryset.filter(
            vendors__icontains=f"{PRODUCT_SEPARATOR}{safe_product}"
        )

    # --- CVSS Score ---
    if params.get("cvss_score"):
        try:
            op, value = parse_cvss_filter(params["cvss_score"])
            lookup = f"cvssV3_1__data__score__{op}"
            queryset = queryset.filter(**{lookup: value})
        except (ValueError, TypeError, KeyError):
            pass

    # --- CWE ---
    if params.get("cwe"):
        cwe_id = params["cwe"].upper()
        if cwe_id.startswith("CWE-"):
            queryset = queryset.filter(weaknesses__icontains=cwe_id)

    # --- KEV ---
    if params.get("kev", "").lower() == "true":
        queryset = queryset.filter(kev__isnull=False)

    # --- Has Tag ---
    if params.get("has_tag") and user.is_authenticated:
        tag = params["has_tag"]
        cve_ids = CveTag.objects.filter(user=user, tags__icontains=tag).values_list(
            "cve_id", flat=True
        )
        queryset = queryset.filter(id__in=cve_ids)

    # --- Only Subscribed ---
    if params.get("is_subscribed", "").lower() == "true":
        project = get_current_project_for_user(user, use_default=True)
        if project:
            vendors = project.subscriptions.get("vendors", [])
            products = project.subscriptions.get("products", [])
            all_keys = [k for k in (vendors + products) if k]
            if all_keys:
                q_filter = Q()
                for key in all_keys:
                    q_filter |= Q(vendors__icontains=key)
                queryset = queryset.filter(q_filter)

    # --- References ---
    if params.get("references"):
        queryset = queryset.filter(references__icontains=params["references"])

    # --- Has Exploit ---
    if params.get("has_exploit", "").lower() == "true":
        exploit_domains = [
            "exploit-db.com",
            "packetstormsecurity.com",
            "github.com/exploit",
        ]
        q_filter = Q()
        for domain in exploit_domains:
            q_filter |= Q(references__icontains=domain)
        queryset = queryset.filter(q_filter)

    return queryset


def get_products(vendors_dict):
    """
    Возвращает список продуктов, подверженных уязвимости.
    :param vendors_dict: Словарь вендоров и их продуктов.
    :return: Список имён продуктов.
    """
    products = []
    for vendor_name, product_names in vendors_dict.items():
        # Находим вендора
        vendor = Vendor.objects.filter(name=vendor_name).first()
        if vendor:
            # Находим все продукты для этого вендора
            if product_names:
                # Если указаны конкретные продукты, добавляем их
                valid_products = [p for p in product_names if p and p.strip()]
                products.extend(valid_products)
            else:
                # Если продукты не указаны, добавляем все продукты вендора
                vendor_products = (
                    Product.objects.filter(vendor=vendor, name__isnull=False)
                    .exclude(name="")
                    .distinct()
                )
                products.extend([product.name for product in vendor_products])
    return list(set(products))


def get_humanized_title(cvss_human_score, cve_id, vendors):
    """
    Возвращает человеко-читаемый заголовок.
    :param cvss_human_score: Уровень критичности уязвимости (например, "High").
    :param cve_id: Идентификатор CVE (например, "CVE-2023-1234").
    :param vendors: Список вендоров и продуктов.
    :return: Строка с заголовком.
    """
    # Преобразуем список вендоров в словарь
    vendors_dict = list_to_dict_vendors(vendors)

    # Получаем список продуктов
    products = get_products(vendors_dict)

    # Собираем заголовок из частей
    parts = []

    # Добавляем уровень CVSS
    if cvss_human_score:
        parts.append(f"{cvss_human_score} severity")

    # Добавляем CVE ID
    if cve_id:
        parts.append(f"({cve_id})")

    # Добавляем вендоров
    if vendors_dict:
        vendor_names = list(vendors_dict.keys())
        if len(vendor_names) == 1:
            parts.append(f"in {vendor_names[0]}")
        else:
            parts.append(f"in {vendor_names[0]} and {len(vendor_names) - 1} other")

    # Добавляем продукты
    if products:
        if len(products) == 1:
            parts.append(f"affecting {products[0]}")
        else:
            parts.append(f"affecting {products[0]} and {len(products) - 1} other")

    # Если ни одно из полей не заполнено, возвращаем заглушку
    if not parts:
        return "No title available"

    # Соединяем части в одну строку
    return " ".join(parts)


def get_detailed_subscriptions(project):
    """
    Возвращает детальную информацию о подписках проекта.
    """
    vendor_names = project.subscriptions.get("vendors", [])
    product_keys = project.subscriptions.get("products", [])

    vendors = Vendor.objects.filter(name__in=vendor_names)
    products = Product.objects.filter(vendored_name__in=product_keys).select_related(
        "vendor"
    )

    return {
        "project_id": str(project.id),
        "subscriptions": {
            "vendors": [v.name for v in vendors],
            "products": [p.vendored_name for p in products],
        },
        "vendor_details": [
            {"id": str(v.id), "name": v.name, "display_name": v.human_name}
            for v in vendors
        ],
        "product_details": [
            {
                "id": str(p.id),
                "name": p.name,
                "display_name": p.human_name,
                "vendor": p.vendor.name,
                "vendor_display_name": p.vendor.human_name,
            }
            for p in products
        ],
    }


def get_user_subscriptions(user):
    """
    Возвращает все подписки пользователя (всех проектов в его организации).
    С human_name для фронтенда.
    """
    organization = get_user_organization(user)
    if not organization:
        return []

    projects = Project.objects.filter(organization=organization)
    subscriptions = []

    for project in projects:
        # Вендоры
        for vendor_name in project.subscriptions.get("vendors", []):
            vendor = Vendor.objects.filter(name=vendor_name).first()
            if vendor:
                subscriptions.append(
                    {"type": "vendor", "id": str(vendor.id), "name": vendor.human_name}
                )

        # Продукты
        for product_key in project.subscriptions.get("products", []):
            if PRODUCT_SEPARATOR not in product_key:
                continue
            try:
                vendor_name, product_name = product_key.split(PRODUCT_SEPARATOR, 1)
            except ValueError:
                continue

            product = (
                Product.objects.filter(name=product_name, vendor__name=vendor_name)
                .select_related("vendor")
                .first()
            )

            if product:
                subscriptions.append(
                    {
                        "type": "product",
                        "id": str(product.id),
                        "name": product.human_name,
                        "vendor_name": product.vendor.human_name,
                    }
                )

    return subscriptions


def process_subscription(
    user, obj_type, obj_id, action, project_id=None, use_default=False
):
    """
    Логика подписки/отписки.
    Возвращает структурированный ответ для фронта.
    """
    OBJ_CONFIG = {
        "vendor": {"model": Vendor, "name_attr": "name", "key": "vendors"},
        "product": {"model": Product, "name_attr": "vendored_name", "key": "products"},
    }

    if obj_type not in OBJ_CONFIG:
        raise ValueError("Invalid object type")

    config = OBJ_CONFIG[obj_type]

    try:
        obj = config["model"].objects.get(id=obj_id)
        technical_name = getattr(obj, config["name_attr"])
        display_name = getattr(obj, "human_name")
    except config["model"].DoesNotExist:
        raise ValueError(f"{obj_type.capitalize()} not found")

    project = get_current_project_for_user(
        user, project_id=project_id, use_default=use_default
    )
    if not project:
        raise Http404("Project not found")

    key = config["key"]
    subscriptions = set(project.subscriptions.get(key, []))

    is_subscribed = technical_name in subscriptions

    if action == "subscribe" and is_subscribed:
        raise ValueError("Already subscribed")
    if action == "unsubscribe" and not is_subscribed:
        raise ValueError("Not subscribed")

    if action == "subscribe":
        subscriptions.add(technical_name)
        message = f"Subscribed to {obj_type}: {display_name}"
    else:
        subscriptions.remove(technical_name)
        message = f"Unsubscribed from {obj_type}: {display_name}"

    project.subscriptions[key] = list(subscriptions)
    project.save(update_fields=["subscriptions"])

    return {
        "message": message,
        "changed": {
            "type": obj_type,
            "id": str(obj.id),
            "name": technical_name,
            "display_name": display_name,
            "action": action,
        },
        "subscriptions": {
            "vendors": project.subscriptions.get("vendors", []),
            "products": project.subscriptions.get("products", []),
        },
    }


from rest_framework.pagination import PageNumberPagination


class OptionalPagination(PageNumberPagination):
    """Пагинатор с возможностью отключения через параметр page_size=all"""

    page_size_query_param = "page_size"
    max_page_size = 1000

    def paginate_queryset(self, queryset, request, view=None):
        if request.query_params.get(self.page_size_query_param) == "all":
            return None  # Отключаем пагинацию
        return super().paginate_queryset(queryset, request, view)
