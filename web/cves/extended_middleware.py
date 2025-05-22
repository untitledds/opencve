from django.conf import settings
from django.contrib.auth import login, authenticate
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

    def __call__(self, request):
        # Пробуем аутентификацию через заголовки, только если пользователь ещё не аутентифицирован
        if not request.user.is_authenticated:
            username = request.META.get(settings.PROXY_HEADER_USER)
            email = request.META.get(settings.PROXY_HEADER_EMAIL)

            if username and email:
                try:
                    with transaction.atomic():
                        self._process_proxy_auth(request, username, email)
                except Exception as e:
                    logger.error(f"Proxy auth failed: {e}", exc_info=True)
                    # Продолжаем цепочку middleware, даже если аутентификация не удалась

        # Если прокси-аутентификация не сработала, Django попробует другие методы (сессии, токены и т. д.)
        response = self.get_response(request)
        return response

    def _process_proxy_auth(self, request, username, email):
        """Обрабатывает аутентификацию через прокси-заголовки."""
        organization_name = settings.GLOBAL_ORGANIZATION_NAME
        organization, _ = Organization.objects.get_or_create(name=organization_name)

        user, created = User.objects.get_or_create(
            username=username,
            defaults={"email": email}
        )

        if created:
            user.set_unusable_password()
            user.save()
            Membership.objects.create(
                user=user,
                organization=organization,
                role=Membership.MEMBER,
                date_invited=now(),
                date_joined=now(),
            )
            logger.info(f"Created new user via proxy auth: {username}")
        elif user.email != email:
            user.email = email
            user.save()
            logger.info(f"Updated email for user {username}")

        # Подтверждаем email в AllAuth
        EmailAddress.objects.get_or_create(
            user=user,
            email=user.email,
            defaults={"verified": True, "primary": True}
        )

        # Логиним пользователя
        login(request, user)
