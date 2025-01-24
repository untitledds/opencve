from django.contrib import admin
from django.urls import include, path
from rest_framework_nested import routers

from cves.resources import (
    CveViewSet,
    ProductCveViewSet,
    ProductViewSet,
    VendorCveViewSet,
    VendorViewSet,
    WeaknessCveViewSet,
    WeaknessViewSet,
)
from organizations.resources import OrganizationViewSet
from projects.resources import ProjectCveViewSet, ProjectViewSet
from users.views import CustomLoginView, CustomSignupView
from cves.extended_resources import (
    ExtendedCveViewSet,
    ExtendedWeaknessViewSet,
    ExtendedVendorViewSet,
    ExtendedProductViewSet,
    ExtendedSubscriptionViewSet,
    CveTagViewSet,
    UserTagViewSet,
)

# API Router
router = routers.SimpleRouter(trailing_slash=False)
router.register(r"cve", CveViewSet, basename="cve")

router.register(r"weaknesses", WeaknessViewSet, basename="weakness")
weaknesses_router = routers.NestedSimpleRouter(router, r"weaknesses", lookup="weakness")
weaknesses_router.register(r"cve", WeaknessCveViewSet, basename="weakness-cves")

router.register(r"organizations", OrganizationViewSet, basename="organization")
organizations_router = routers.NestedSimpleRouter(
    router, r"organizations", lookup="organization"
)
organizations_router.register(
    r"projects", ProjectViewSet, basename="organization-projects"
)

projects_cves_router = routers.NestedSimpleRouter(
    organizations_router, "projects", lookup="project"
)
projects_cves_router.register(
    r"cve", ProjectCveViewSet, basename="organization-projects-cves"
)

router.register(r"vendors", VendorViewSet, basename="vendor")
vendors_router = routers.NestedSimpleRouter(router, r"vendors", lookup="vendor")
vendors_router.register(r"products", ProductViewSet, basename="vendor-products")
vendors_router.register(r"cve", VendorCveViewSet, basename="vendor-cves")
products_cves_router = routers.NestedSimpleRouter(
    vendors_router, "products", lookup="product"
)
products_cves_router.register(f"cve", ProductCveViewSet, basename="product-cves")

# Extended API Router
extended_router = routers.SimpleRouter(trailing_slash=False)
extended_router.register(r"extended/cve", ExtendedCveViewSet, basename="extended-cve")
extended_router.register(
    r"extended/weakness", ExtendedWeaknessViewSet, basename="extended-weakness"
)
extended_router.register(
    r"extended/vendor", ExtendedVendorViewSet, basename="extended-vendor"
)
extended_vendor_router = routers.NestedSimpleRouter(
    extended_router, r"extended/vendor", lookup="vendor"
)
extended_vendor_router.register(
    r"product", ExtendedProductViewSet, basename="extended-vendor-product"
)
extended_router.register(
    r"extended/product", ExtendedProductViewSet, basename="extended-product"
)
extended_router.register(
    r"extended/subscription",
    ExtendedSubscriptionViewSet,
    basename="extended-subscription",
)

# Добавляем маршруты для тегов в extended_router
extended_router.register(r"extended/tags", UserTagViewSet, basename="usertag")

extended_router.register(r"extended/tags/cve", CveTagViewSet, basename="cvetag")


urlpatterns = [
    path("__debug__/", include("debug_toolbar.urls")),
    path("", include("changes.urls")),
    path("", include("cves.urls")),
    path("", include("onboarding.urls")),
    path("", include("organizations.urls")),
    path("", include("projects.urls")),
    path("", include("django_prometheus.urls")),
    path("settings/", include("allauth.urls")),
    path(r"login/", CustomLoginView.as_view(), name="account_login"),
    path(r"signup/", CustomSignupView.as_view(), name="account_signup"),
    path("settings/", include("users.urls")),
    path("admin/", admin.site.urls),
    path("hijack/", include("hijack.urls")),
    # API routes
    path("api/", include(router.urls)),
    path("api/", include(organizations_router.urls)),
    path("api/", include(projects_cves_router.urls)),
    path("api/", include(vendors_router.urls)),
    path("api/", include(products_cves_router.urls)),
    path("api/", include(weaknesses_router.urls)),
    # Extended API routes
    path("api/", include(extended_router.urls)),
    path("api/", include(extended_vendor_router.urls)),
]
