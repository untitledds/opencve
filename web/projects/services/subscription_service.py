# projects/services/subscription_service.py
from typing import Dict, Any
from rest_framework.exceptions import ValidationError
from projects.models import Project
from cves.models import Vendor, Product
from opencve.conf import settings
from django.db import transaction
from cves.extended_utils import get_user_organization


def update_subscription(
    user,
    obj_type: str,
    obj_id: str,
    action: str = None,
) -> Dict[str, Any]:
    organization = get_user_organization(user)
    if not organization:
        raise ValidationError("User is not a member of any organization.")

    project_name = getattr(settings, "GLOBAL_DEFAULT_PROJECT_NAME", "default")
    try:
        project = Project.objects.get(organization=organization, name=project_name)
    except Project.DoesNotExist:
        raise ValidationError(
            f"Project '{project_name}' not found for your organization."
        )

    config = {
        "vendor": {
            "model": Vendor,
            "name_attr": "name",
            "human_name_attr": "human_name",
            "key": "vendors",
        },
        "product": {
            "model": Product,
            "name_attr": "vendored_name",
            "human_name_attr": "human_name",
            "key": "products",
        },
    }.get(obj_type)

    if not config:
        raise ValidationError(f"Invalid obj_type: {obj_type}")

    try:
        obj = config["model"].objects.get(id=obj_id)
        technical_name = getattr(obj, config["name_attr"])
        display_name = getattr(obj, config["human_name_attr"])
    except config["model"].DoesNotExist:
        raise ValidationError(f"{obj_type.capitalize()} not found.")

    key = config["key"]
    current = set(project.subscriptions.get(key, []))
    is_subscribed = technical_name in current

    if action == "subscribe" and is_subscribed:
        result_action = "already_subscribed"
    elif action == "unsubscribe" and not is_subscribed:
        result_action = "already_unsubscribed"
    elif action == "subscribe":
        current.add(technical_name)
        result_action = "subscribed"
    elif action == "unsubscribe":
        current.discard(technical_name)
        result_action = "unsubscribed"
    else:
        result_action = "unsubscribed" if is_subscribed else "subscribed"
        if is_subscribed:
            current.discard(technical_name)
        else:
            current.add(technical_name)

    project.subscriptions[key] = list(current)
    with transaction.atomic():
        project.save(update_fields=["subscriptions", "updated_at"])

    return {
        "status": "success",
        "message": f"Successfully {result_action}: {display_name}",
        "action": result_action,
        "type": obj_type,
        "name": display_name,
        "technical_name": technical_name,
        "subscriptions": project.subscriptions,
    }
