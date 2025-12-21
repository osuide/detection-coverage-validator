"""API dependencies."""

from app.api.deps.admin import (
    get_current_admin,
    require_permission,
    require_reauth,
    get_client_ip,
)
from app.api.deps.rate_limit import (
    init_rate_limiter,
    close_rate_limiter,
    auth_rate_limit,
    signup_rate_limit,
    password_reset_rate_limit,
    mfa_rate_limit,
)

__all__ = [
    # Admin auth
    "get_current_admin",
    "require_permission",
    "require_reauth",
    "get_client_ip",
    # Rate limiting
    "init_rate_limiter",
    "close_rate_limiter",
    "auth_rate_limit",
    "signup_rate_limit",
    "password_reset_rate_limit",
    "mfa_rate_limit",
]
