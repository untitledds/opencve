from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth import get_user_model
from django.db import transaction
from organizations.models import Organization, Membership
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

        logger.debug(
            f"Initializing ProxyHeaderAuthenticationMiddleware with settings: "
            f"username_header='{self.username_header}' (original: '{getattr(settings, 'PROXY_HEADER_USER', 'Remote-User')}'), "
            f"email_header='{self.email_header}' (original: '{getattr(settings, 'PROXY_HEADER_EMAIL', 'Remote-Email')}'), "
            f"organization_name='{self.organization_name}'"
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

        # Organization handling
        organization_name = self.organization_name
        logger.debug(f"Looking up organization: {organization_name}")

        organization, created = Organization.objects.get_or_create(
            name=organization_name
        )

        if created:
            logger.info(f"Created new organization: {organization_name}")
        else:
            logger.debug(f"Using existing organization: {organization_name}")

        # User handling
        user, user_created = User.objects.get_or_create(
            username=username, defaults={"email": email}
        )

        if user_created:
            logger.info(f"Creating new user: {username}")
            user.set_unusable_password()
            user.save()

            Membership.objects.create(
                user=user,
                organization=organization,
                role=Membership.MEMBER,
                date_invited=now(),
                date_joined=now(),
            )
            logger.info(
                f"Created membership for user {username} in organization {organization_name}"
            )
        else:
            logger.debug(f"Found existing user: {username}")
            if user.email != email:
                logger.info(
                    f"Updating email for user {username} from {user.email} to {email}"
                )
                user.email = email
                user.save()

        # Email verification handling (for allauth)
        logger.debug(f"Processing email verification for {email}")

        email_address, email_created = EmailAddress.objects.get_or_create(
            user=user, email=user.email, defaults={"verified": True, "primary": True}
        )

        if email_created:
            logger.info(f"Created new verified email address for {username}")
        else:
            if not email_address.verified:
                logger.info(f"Marking existing email as verified for {username}")
                email_address.verified = True
                email_address.primary = True
                email_address.save()
        user.backend = "django.contrib.auth.backends.ModelBackend"
        # Login user
        logger.debug(f"Logging in user {username}")
        login(request, user)
        logger.info(f"Successfully authenticated user {username} via proxy headers")
