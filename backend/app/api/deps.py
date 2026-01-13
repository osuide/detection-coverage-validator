"""API dependencies for authentication and authorization."""

from functools import wraps
from typing import Any, Callable, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_token, get_client_ip
from app.models.admin import AdminUser, AdminSession, has_permission
from app.services.admin_auth_service import get_admin_auth_service

# Bearer token security scheme
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_admin(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> AdminUser:
    """Get current authenticated admin user.

    Validates:
    1. Bearer token is present and valid
    2. Token is for an admin user (type=admin)
    3. Session is still valid
    4. IP matches session IP (session binding)
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(credentials.credentials)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # SECURITY: Handle None payload from expired/invalid tokens (decode_token returns None, not raises)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify this is an admin token
    if payload.get("type") != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not an admin token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # SECURITY: Guard UUID parsing to return 401 instead of 500 on malformed tokens
    try:
        admin_id = UUID(payload["sub"])
        session_id = UUID(payload.get("session_id", ""))
    except (ValueError, TypeError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get admin user
    result = await db.execute(select(AdminUser).where(AdminUser.id == admin_id))
    admin = result.scalar_one_or_none()

    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not admin.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin account is disabled",
        )

    # Validate session
    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request) or "unknown"
    user_agent = request.headers.get("User-Agent")

    session = await auth_service.validate_session(
        session_id=session_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Store session ID in request state for logout
    request.state.admin_session_id = session_id

    return admin


def require_permission(permission: str) -> Callable:
    """Dependency factory that requires a specific permission.

    Usage:
        @router.get("/endpoint")
        async def endpoint(admin: AdminUser = Depends(require_permission("org:read"))):
            ...
    """

    async def permission_checker(
        admin: AdminUser = Depends(get_current_admin),
    ) -> AdminUser:
        if not has_permission(admin.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}",
            )
        return admin

    return permission_checker


def require_reauth(func: Callable) -> Callable:
    """Decorator requiring recent authentication for sensitive actions.

    The admin must have authenticated within the last 5 minutes.
    """

    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        request = kwargs.get("request")
        admin = kwargs.get("admin")

        if not request or not admin:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Invalid endpoint configuration",
            )

        # Get session
        session_id = getattr(request.state, "admin_session_id", None)
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found",
            )

        db = kwargs.get("db")
        if not db:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database session not found",
            )

        result = await db.execute(
            select(AdminSession).where(AdminSession.id == session_id)
        )
        session = result.scalar_one_or_none()

        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found",
            )

        # Check last auth time
        from datetime import datetime, timedelta, timezone

        if session.last_auth_at < datetime.now(timezone.utc) - timedelta(minutes=5):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Re-authentication required for this action",
                headers={"X-Require-Reauth": "true"},
            )

        return await func(*args, **kwargs)

    return wrapper
