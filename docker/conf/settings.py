"""
This file is used to override the `opencve/conf/base.py` settings.
"""

from opencve.conf.base import *  # noqa # pylint: disable=unused-import

MIDDLEWARE += [
"cves.extended_middleware.ProxyHeaderAuthenticationMiddleware",
]


# Proxy Headers Configuration
PROXY_HEADER_USER = env.str("PROXY_HEADER_USER", default="Remote-User")
PROXY_HEADER_EMAIL = env.str("PROXY_HEADER_EMAIL", default="Remote-Email")

# Global Organization Configuration
GLOBAL_ORGANIZATION_NAME = env.str("GLOBAL_ORGANIZATION_NAME", default="DefaultOrg")
