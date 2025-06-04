from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth import get_user_model
from django.db import transaction
from organizations.models import Organization, Membership
from projects.models import Project, get_default_subscriptions
from django.utils.timezone import now
from allauth.account.models import EmailAddress
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class ProxyHeaderAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.username_header = self._get_header_name(
            getattr(settings, "PROXY_HEADER_USER", "Remote-User")
        )
        self.email_header = self._get_header_name(
            getattr(settings, "PROXY_HEADER_EMAIL", "Remote-Email")
        )
        self.organization_name = getattr(
            settings, "GLOBAL_ORGANIZATION_NAME", "Default"
        )
        self.default_project_name = getattr(
            settings, "GLOBAL_DEFAULT_PROJECT_NAME", "Default Project"
        )

        logger.debug(
            f"Initializing ProxyHeaderAuthenticationMiddleware with settings: "
            f"username_header='{self.username_header}' (original: '{getattr(settings, 'PROXY_HEADER_USER', 'Remote-User')}'), "
            f"email_header='{self.email_header}' (original: '{getattr(settings, 'PROXY_HEADER_EMAIL', 'Remote-Email')}'), "
            f"organization_name='{self.organization_name}'"
            f"default_project_name='{self.default_project_name}'"
        )

    def _get_header_name(self, header_name):
        """Преобразует имя заголовка в формат, используемый Django в request.META"""
        return f"HTTP_{header_name.upper().replace('-', '_')}"

    def __call__(self, request):
        logger.debug(
            f"Incoming request - path: {request.path}, "
            f"authenticated: {request.user.is_authenticated}, "
            f"all headers: { {k: v for k, v in request.META.items() if k.startswith('HTTP_')} }"
        )

        if not request.user.is_authenticated:
            username = request.META.get(self.username_header)
            email = request.META.get(self.email_header)

            logger.debug(
                f"Checking proxy headers - {self.username_header}: {username}, "
                f"{self.email_header}: {email}"
            )

            if username and email:
                logger.info(
                    f"Attempting proxy authentication for user: {username}, "
                    f"email: {email}"
                )
                try:
                    with transaction.atomic():
                        self._process_proxy_auth(request, username, email)
                except Exception as e:
                    logger.error(
                        f"Proxy authentication failed for {username}. Error: {str(e)}",
                        exc_info=True,
                    )
            else:
                logger.debug(
                    "Proxy authentication skipped - missing required headers: "
                    f"username {'present' if username else 'missing'}, "
                    f"email {'present' if email else 'missing'}"
                )
        else:
            logger.debug(
                f"User {request.user.username} already authenticated - "
                "skipping proxy authentication"
            )

        response = self.get_response(request)

        logger.debug(
            f"Request completed - path: {request.path}, "
            f"status: {response.status_code}"
        )

        return response

    def _process_proxy_auth(self, request, username, email):
        """Обрабатывает аутентификацию через прокси-заголовки."""
        logger.debug(
            f"Starting proxy authentication process for user: {username}, "
            f"email: {email}"
        )
        try:
            with transaction.atomic():
                (
                    org,
                    org_created,
                ) = Organization.objects.select_for_update().get_or_create(
                    name=self.organization_name
                )
                self._ensure_default_project_exists(org)
                user, u_created = User.objects.get_or_create(
                    username=username, defaults={"email": email, "password": None}
                )
                if u_created or user.email != email:
                    user.email = email
                    user.save()
                membership, _ = Membership.objects.get_or_create(
                    user=user,
                    organization=org,
                    defaults={
                        "role": Membership.MEMBER,
                        "date_invited": now(),
                        "date_joined": now(),
                    },
                )
                self._handle_email_verification(user)
                login(request, user)

        except Exception as e:
            logger.exception("Proxy auth failed")

    def _ensure_default_project_exists(self, organization):
        if not Project.objects.filter(organization=organization).exists():
            Project.objects.create(
                name=self.default_project_name,
                organization=organization,
                description="Auto-created default project",
                subscriptions=get_default_subscriptions(),
            )
            logger.info(f"Created default project for {organization.name}")

    def _handle_email_verification(self, user):
        """
        Обрабатывает верификацию email для пользователя.
        Создает/обновляет запись EmailAddress в allauth.
        """
        try:
            email_address, created = EmailAddress.objects.get_or_create(
                user=user,
                email=user.email,
                defaults={"verified": True, "primary": True},
            )

            if not created:
                # Если email изменился или не верифицирован
                needs_update = False

                if email_address.email != user.email:
                    email_address.email = user.email
                    needs_update = True

                if not email_address.verified:
                    email_address.verified = True
                    needs_update = True

                if not email_address.primary:
                    email_address.primary = True
                    needs_update = True

                if needs_update:
                    email_address.save()
                    logger.info(f"Updated email verification for user {user.username}")

            logger.debug(
                f"Email {'created' if created else 'updated'} "
                f"for {user.username}: {user.email} (verified: True)"
            )

        except Exception as e:
            logger.error(
                f"Failed to handle email verification for {user.username}: {str(e)}",
                exc_info=True,
            )
            # Продолжаем работу даже при ошибке верификации email
