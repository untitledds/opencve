from cves.utils import list_filtered_cves, list_to_dict_vendors
from cves.models import Vendor, Product, Cve
from organizations.models import Membership
from projects.models import Project
from django.conf import settings
import json
import logging
from cves.constants import PRODUCT_SEPARATOR
from cves.templatetags.opencve_extras import (
    cvss_human_score as get_cvss_human_score_from_lib,
)

logger = logging.getLogger(__name__)


def extended_list_filtered_cves(params, user):
    queryset = list_filtered_cves(params, user)

    created_at = params.get("created_at")
    if created_at:
        queryset = queryset.filter(created_at__date__gte=created_at)

    updated_at = params.get("updated_at")
    if updated_at:
        queryset = queryset.filter(updated_at__date__gte=updated_at)

    return queryset


def get_products(vendors_dict):
    products = []
    for vendor_name, product_names in vendors_dict.items():
        vendor = Vendor.objects.filter(name=vendor_name).first()
        if vendor:
            if product_names:
                products.extend(product_names)
            else:
                vendor_products = Product.objects.filter(vendor=vendor)
                products.extend([product.name for product in vendor_products])
    return products


def get_humanized_title(cvss_human_score, cve_id, vendors):
    vendors_dict = list_to_dict_vendors(vendors)
    products = get_products(vendors_dict)

    parts = []
    if cvss_human_score:
        parts.append(f"{cvss_human_score} severity")
    if cve_id:
        parts.append(f"({cve_id})")
    if vendors_dict:
        vendor_names = list(vendors_dict.keys())
        if len(vendor_names) == 1:
            parts.append(f"in {vendor_names[0]}")
        else:
            parts.append(f"in {vendor_names[0]} and {len(vendor_names) - 1} other")
    if products:
        if len(products) == 1:
            parts.append(f"affecting {products[0]}")
        else:
            parts.append(f"affecting {products[0]} and {len(products) - 1} other")
    if not parts:
        return "No title available"
    return " ".join(parts)


def get_detailed_subscriptions(project):
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
    membership = Membership.objects.filter(user=user).first()
    return membership.organization if membership else None


def get_subscription_status(obj_type, obj_name, user):
    try:
        project = _get_current_project(user)
        if not project:
            return False

        if obj_type == "vendor":
            subscribed_items = project.subscriptions.get("vendors", [])
            return obj_name in subscribed_items
        elif obj_type == "product":
            subscribed_items = project.subscriptions.get("products", [])
            return obj_name in subscribed_items
        return False
    except Exception as e:
        logger.error(f"Error checking subscription: {e}")
        return False


def _get_current_project(user):
    organization = get_user_organization(user)
    if not organization:
        logger.error(f"{user} not found in org")
        return None

    default_project_name = getattr(settings, "GLOBAL_DEFAULT_PROJECT_NAME", "default")
    return Project.objects.filter(
        name=default_project_name, organization=organization
    ).first()


def get_cvss_data(instance):
    cvss_fields = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
    for field in cvss_fields:
        cvss = instance.metrics.get(field, {}).get("data", {})
        if cvss and "score" in cvss:
            return cvss
    return None


def get_cvss_human_score(score):
    return get_cvss_human_score_from_lib(score).title() if score else None


def get_vendors_list(instance):
    vendors = instance.vendors
    if isinstance(vendors, str):
        try:
            vendors = json.loads(vendors)
        except json.JSONDecodeError:
            logger.warning(f"Vendors is a string for CVE {instance.cve_id}: {vendors}")
            vendors = [vendors]

    if not isinstance(vendors, list):
        return []

    vendors_list = [v.split("$PRODUCT$")[0] if "$PRODUCT$" in v else v for v in vendors]
    return list(set(vendors_list))


def get_products_list(instance):
    vendors = instance.vendors
    products = set()

    if isinstance(vendors, list):
        products.update(v.split("$PRODUCT$")[1] for v in vendors if "$PRODUCT$" in v)
    elif isinstance(vendors, str):
        try:
            vendors_list = json.loads(vendors)
            products.update(
                v.split("$PRODUCT$")[1] for v in vendors_list if "$PRODUCT$" in v
            )
        except json.JSONDecodeError:
            logger.warning(f"Vendors is a string for CVE {instance.cve_id}: {vendors}")
            if "$PRODUCT$" in vendors:
                products.add(vendors.split("$PRODUCT$")[1])

    return list(products)


def get_vendors_with_subscriptions(instance, user):
    vendor_names = get_vendors_list(instance)
    return [
        {
            "name": vendor_name,
            "is_subscribed": get_subscription_status("vendor", vendor_name, user),
        }
        for vendor_name in vendor_names
    ]


def get_products_with_subscriptions(instance, user):
    product_names = get_products_list(instance)
    vendors_dict = list_to_dict_vendors(instance.vendors)

    result = []
    for product_name in product_names:
        vendor_name = next(
            (v for v, products in vendors_dict.items() if product_name in products),
            None,
        )
        if vendor_name:
            full_name = f"{vendor_name}{PRODUCT_SEPARATOR}{product_name}"
            result.append(
                {
                    "name": product_name,
                    "vendor": vendor_name,
                    "is_subscribed": get_subscription_status(
                        "product", full_name, user
                    ),
                }
            )
    return result


class OptionalPagination(PageNumberPagination):
    page_size_query_param = "page_size"
    max_page_size = 1000

    def paginate_queryset(self, queryset, request, view=None):
        if request.query_params.get(self.page_size_query_param) == "all":
            return None
        return super().paginate_queryset(queryset, request, view)
