from typing import Dict, List, Optional, Any
from cves.utils import list_filtered_cves, list_to_dict_vendors
from cves.models import Vendor, Product, Cve
from organizations.models import Membership
from django.utils.dateparse import parse_date
from projects.models import Project
from django.conf import settings
import logging
from cves.constants import PRODUCT_SEPARATOR
from cves.templatetags.opencve_extras import (
    cvss_human_score as get_cvss_human_score_from_lib,
)

logger = logging.getLogger(__name__)


# QuerySet[Cve]
def extended_list_filtered_cves(params: Dict[str, Any], user) -> Any:
    """
    Расширенная фильтрация CVE с поддержкой фильтрации по created_at и updated_at.
    """
    queryset = list_filtered_cves(params, user)

    for date_field, param_key in [
        ("created_at__date__gte", "created_at"),
        ("updated_at__date__gte", "updated_at"),
    ]:
        date_str = params.get(param_key)
        if date_str:
            parsed = parse_date(date_str)
            if parsed:
                queryset = queryset.filter(**{date_field: parsed})

    return queryset


def get_user_subscriptions(user):
    """
    Возвращает подписки пользователя в формате:
    {
        "vendors": [
            {"type": "vendor", "id": "...", "name": "Human Name"}
        ],
        "products": [
            {"type": "product", "id": "...", "name": "Human Name", "vendor": "Vendor Name"}
        ]
    }
    """
    try:
        project = _get_current_project(user)
        if not project:
            return {"vendors": [], "products": []}

        vendor_names = project.subscriptions.get("vendors", [])
        product_names = project.subscriptions.get("products", [])  # это vendored_name

        # Получаем объекты
        vendors = Vendor.objects.filter(name__in=vendor_names)
        products = Product.objects.filter(
            vendored_name__in=product_names
        ).select_related("vendor")

        # Формируем ответ
        result = {
            "vendors": [
                {
                    "type": "vendor",
                    "id": str(vendor.id),
                    "name": vendor.human_name,
                }
                for vendor in vendors
            ],
            "products": [
                {
                    "type": "product",
                    "id": str(product.id),
                    "name": product.human_name,
                    "vendor": product.vendor.human_name,
                }
                for product in products
            ],
        }

        return result

    except Exception as e:
        logger.error(f"Error getting user subscriptions: {e}")
        return {"vendors": [], "products": []}


def list_filtered_products(queryset, params, user):
    """
    Фильтрация queryset продуктов по параметрам.
    Пока только search и vendor_id, но можно расширять.
    """
    vendor_id = params.get("vendor_id")
    if vendor_id:
        queryset = queryset.filter(vendor_id=vendor_id)

    search = params.get("search")
    if search:
        queryset = queryset.filter(name__icontains=search)

    return queryset


def get_products(vendors_dict: Dict[str, List[str]]) -> List[str]:
    """
    Извлекает список имён продуктов из словаря vendors_dict.
    Args:
        vendors_dict: { vendor_name: [product_name, ...], ... }

    Returns:
        Список уникальных продуктов.
    """
    products = []
    for product_names in vendors_dict.values():
        if product_names:
            products.extend(product_names)
    return list(set(products))


def get_humanized_title(
    cvss_human_score: Optional[str], cve_id: Optional[str], vendors: List[str]
) -> str:
    """
    Генерирует человекочитаемое название уведомления на основе CVSS, CVE ID и списка вендоров/продуктов.
    """
    vendors_dict = list_to_dict_vendors(vendors)
    products = get_products(vendors_dict)

    parts = []

    if cvss_human_score:
        parts.append(f"{cvss_human_score} severity")
    if cve_id:
        parts.append(f"({cve_id})")

    # Вендоры
    vendor_names = list(vendors_dict.keys())
    if len(vendor_names) == 1:
        parts.append(f"in {vendor_names[0]}")
    elif len(vendor_names) > 1:
        n = len(vendor_names) - 1
        suffix = "other" if n == 1 else "others"
        parts.append(f"in {vendor_names[0]} and {n} {suffix}")

    # Продукты
    if len(products) == 1:
        parts.append(f"affecting {products[0]}")
    elif len(products) > 1:
        n = len(products) - 1
        suffix = "other" if n == 1 else "others"
        parts.append(f"affecting {products[0]} and {n} {suffix}")

    return " ".join(parts) if parts else "No title available"


def get_detailed_subscriptions(project: Project) -> Dict[str, Any]:
    """
    Возвращает детали подписок проекта: вендоры, продукты, их ID и имена.
    """
    vendor_names = project.subscriptions.get("vendors", [])
    product_names = project.subscriptions.get("products", [])

    vendors = Vendor.objects.filter(name__in=vendor_names)
    products = Product.objects.filter(name__in=product_names).select_related("vendor")

    return {
        "project_id": project.id,
        "subscriptions": {
            "vendors": [v.human_name for v in vendors],
            "products": [p.human_name for p in products],
        },
        "vendor_details": [{"id": v.id, "name": v.human_name} for v in vendors],
        "product_details": [
            {
                "id": p.id,
                "name": p.human_name,
                "vendor": p.vendor.human_name,
            }
            for p in products
        ],
    }


def get_user_organization(user) -> Optional[Any]:  # Organization or None
    """
    Возвращает организацию пользователя или None.
    """
    membership = Membership.objects.filter(user=user).first()
    return membership.organization if membership else None


def get_subscription_status(obj_type: str, obj_name: str, user) -> bool:
    """
    Проверяет, подписан ли пользователь на объект (vendor/product).
    """
    if obj_type not in ["vendor", "product"]:
        return False

    try:
        project = _get_current_project(user)
        if not project:
            return False

        subscribed_items = project.subscriptions.get(
            "vendors" if obj_type == "vendor" else "products", []
        )
        return obj_name in subscribed_items

    except Exception as e:
        logger.error(f"Error checking subscription for {obj_type} '{obj_name}': {e}")
        return False


def _get_current_project(user) -> Optional[Project]:
    """
    Возвращает текущий проект пользователя (по умолчанию).
    """
    organization = get_user_organization(user)
    if not organization:
        logger.error(f"User {user} is not in any organization.")
        return None

    default_project_name = getattr(settings, "GLOBAL_DEFAULT_PROJECT_NAME", "default")
    try:
        return Project.objects.get(name=default_project_name, organization=organization)
    except Project.DoesNotExist:
        logger.warning(
            f"Default project '{default_project_name}' not found for organization {organization}."
        )
        return None


def get_cvss_data(instance) -> Optional[Dict[str, Any]]:
    """
    Ищет первый доступный CVSS-метрик с полем 'score'.
    """
    cvss_fields = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
    for field in cvss_fields:
        cvss = instance.metrics.get(field, {}).get("data", {})
        if cvss.get("score") is not None:
            return cvss
    return None


def get_cvss_human_score(score: Optional[float]) -> Optional[str]:
    """
    Возвращает человекочитаемую оценку CVSS (например, "High").
    """
    if not score:
        return None
    return get_cvss_human_score_from_lib(score).title()


def get_vendors_list(instance) -> List[str]:
    """
    Извлекает уникальные имена вендоров из списка `instance.vendors`.
    Формат: vendor или vendor###product.
    """
    vendors = getattr(instance, "vendors", [])
    if not isinstance(vendors, list):
        return []

    return list(
        {
            v.split(PRODUCT_SEPARATOR, 1)[0] if PRODUCT_SEPARATOR in v else v
            for v in vendors
        }
    )


def get_products_list(instance) -> List[str]:
    """
    Извлекает уникальные имена продуктов из `instance.vendors`.
    """
    vendors = getattr(instance, "vendors", [])
    if not isinstance(vendors, list):
        return list()

    products = {
        v.split(PRODUCT_SEPARATOR, 1)[1] for v in vendors if PRODUCT_SEPARATOR in v
    }
    return list(products)


def get_vendors_with_subscriptions(instance, user) -> List[Dict[str, Any]]:
    """
    Возвращает список вендоров с флагом подписки.
    """
    vendor_names = get_vendors_list(instance)
    return [
        {
            "name": name,
            "is_subscribed": get_subscription_status("vendor", name, user),
        }
        for name in vendor_names
    ]


def get_products_with_subscriptions(instance, user) -> List[Dict[str, Any]]:
    """
    Возвращает список продуктов с флагом подписки и именем вендора.
    """
    product_names = get_products_list(instance)
    vendors_dict = list_to_dict_vendors(getattr(instance, "vendors", []))

    result = []
    for product_name in product_names:
        vendor_name = next(
            (v for v, products in vendors_dict.items() if product_name in products),
            None,
        )
        if not vendor_name:
            continue

        full_name = f"{vendor_name}{PRODUCT_SEPARATOR}{product_name}"
        result.append(
            {
                "name": product_name,
                "vendor": vendor_name,
                "is_subscribed": get_subscription_status("product", full_name, user),
            }
        )
    return result
