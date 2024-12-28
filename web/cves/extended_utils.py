from django.db.models import Q
from django.utils import timezone
from cves.utils import list_filtered_cves

def extended_list_filtered_cves(params, user):
    """
    Расширенная версия list_filtered_cves с добавлением фильтрации по дате.
    """
    queryset = list_filtered_cves(params, user)

    # Фильтрация по дате создания
    created_at = params.get("created_at")
    if created_at:
        queryset = queryset.filter(created_at__date=created_at)

    # Фильтрация по дате обновления
    updated_at = params.get("updated_at")
    if updated_at:
        queryset = queryset.filter(updated_at__date=updated_at)

    return queryset
