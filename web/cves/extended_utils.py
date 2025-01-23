from django.db.models import Q
from django.utils import timezone
from cves.utils import list_filtered_cves, list_to_dict_vendors
from cves.models import Vendor, Product
from organizations.models import Membership


def extended_list_filtered_cves(params, user):
    """
    Расширенная версия list_filtered_cves с добавлением фильтрации по дате.
    """
    queryset = list_filtered_cves(params, user)

    # Фильтрация по дате создания
    created_at = params.get("created_at")
    if created_at:
        queryset = queryset.filter(created_at__date__gte=created_at)

    # Фильтрация по дате обновления
    updated_at = params.get("updated_at")
    if updated_at:
        queryset = queryset.filter(updated_at__date__gte=updated_at)

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
                products.extend(product_names)
            else:
                # Если продукты не указаны, добавляем все продукты вендора
                vendor_products = Product.objects.filter(vendor=vendor)
                products.extend([product.name for product in vendor_products])
    return products


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
    product_names = project.subscriptions.get("products", [])

    vendors = Vendor.objects.filter(name__in=vendor_names)
    products = Product.objects.filter(name__in=product_names).select_related("vendor")

    return {
        "project_id": project.id,
        "subscriptions": {
            "vendors": [vendor.name for vendor in vendors],
            "products": [product.vendored_name for product in products],
        },
        "vendor_details": [
            {"id": vendor.id, "name": vendor.name} for vendor in vendors
        ],
        "product_details": [
            {"id": product.id, "name": product.name, "vendor": product.vendor.name}
            for product in products
        ],
    }


def get_user_organization(user):
    """
    Возвращает организацию пользователя.
    :param user: Объект пользователя.
    :return: Организация пользователя или None.
    """
    membership = Membership.objects.filter(user=user).first()
    return membership.organization if membership else None
