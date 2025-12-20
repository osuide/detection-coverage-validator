"""Admin authentication routes."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser
from app.services.admin_auth_service import get_admin_auth_service
from app.api.deps import get_current_admin

router = APIRouter(prefix="/auth", tags=["Admin Auth"])


# Request/Response schemas
class AdminLoginRequest(BaseModel):
    """Admin login request."""

    email: EmailStr
    password: str


class AdminLoginResponse(BaseModel):
    """Admin login response."""

    requires_mfa: bool
    mfa_token: Optional[str] = None  # Temporary token for MFA flow
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None


class AdminMFARequest(BaseModel):
    """MFA verification request."""

    mfa_token: str
    totp_code: str


class AdminTokenResponse(BaseModel):
    """Token response."""

    access_token: str
    refresh_token: str
    expires_in: int
    admin: dict


class AdminRefreshRequest(BaseModel):
    """Token refresh request."""

    refresh_token: str


class AdminProfileResponse(BaseModel):
    """Admin profile response."""

    id: str
    email: str
    full_name: Optional[str]
    role: str
    mfa_enabled: bool
    requires_password_change: bool
    permissions: list[str]


class AdminSetupMFAResponse(BaseModel):
    """MFA setup response."""

    provisioning_uri: str
    secret: str  # For manual entry


class AdminEnableMFARequest(BaseModel):
    """Enable MFA request."""

    totp_code: str


def get_client_ip(request: Request) -> str:
    """Get client IP from request."""
    # Check for forwarded headers (behind proxy/load balancer)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=AdminLoginResponse)
async def admin_login(
    body: AdminLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Admin login endpoint.

    Step 1: Verify email/password
    Step 2: If MFA enabled, return mfa_token for verification
    Step 3: If MFA not enabled, return tokens directly (dev mode only)
    """
    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    # Check IP allowlist
    if not await auth_service.check_ip_allowed(ip_address):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: IP not in allowlist",
        )

    try:
        admin, requires_mfa = await auth_service.authenticate(
            email=body.email,
            password=body.password,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    if requires_mfa:
        # Generate temporary MFA token
        import secrets

        mfa_token = secrets.token_urlsafe(32)

        # Store in cache/session (in production, use Redis)
        # For now, we'll encode admin ID in the token (not secure for production)
        # TODO: Use Redis to store MFA session
        from app.core.security import create_access_token
        from datetime import timedelta

        mfa_token = create_access_token(
            data={"sub": str(admin.id), "type": "mfa_pending"},
            expires_delta=timedelta(minutes=5),
        )

        return AdminLoginResponse(
            requires_mfa=True,
            mfa_token=mfa_token,
        )

    # MFA not enabled - issue tokens directly (dev mode)
    access_token, refresh_token = await auth_service.create_session(
        admin=admin,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return AdminLoginResponse(
        requires_mfa=False,
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/mfa/verify", response_model=AdminTokenResponse)
async def verify_mfa(
    body: AdminMFARequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Verify MFA code and issue tokens."""
    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    # Decode MFA token to get admin ID
    from app.core.security import decode_token

    try:
        payload = decode_token(body.mfa_token)
        if payload.get("type") != "mfa_pending":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token"
            )
        admin_id = UUID(payload["sub"])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )

    # Get admin
    from sqlalchemy import select

    result = await db.execute(select(AdminUser).where(AdminUser.id == admin_id))
    admin = result.scalar_one_or_none()

    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token"
        )

    # Verify TOTP
    if not await auth_service.verify_totp(admin, body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code"
        )

    # Create session
    access_token, refresh_token = await auth_service.create_session(
        admin=admin,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return AdminTokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=auth_service.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        admin={
            "id": str(admin.id),
            "email": admin.email,
            "full_name": admin.full_name,
            "role": admin.role.value,
            "mfa_enabled": admin.mfa_enabled,
        },
    )


@router.post("/refresh", response_model=dict)
async def refresh_token(
    body: AdminRefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Refresh access token."""
    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request)

    access_token = await auth_service.refresh_access_token(
        refresh_token=body.refresh_token,
        ip_address=ip_address,
    )

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    return {
        "access_token": access_token,
        "expires_in": auth_service.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/logout")
async def logout(
    request: Request,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Logout and terminate session."""
    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    # Get session ID from token
    session_id = getattr(request.state, "admin_session_id", None)

    if session_id:
        await auth_service.logout(
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    return {"message": "Logged out successfully"}


@router.get("/me", response_model=AdminProfileResponse)
async def get_current_admin_profile(
    admin: AdminUser = Depends(get_current_admin),
):
    """Get current admin profile."""
    return AdminProfileResponse(
        id=str(admin.id),
        email=admin.email,
        full_name=admin.full_name,
        role=admin.role.value,
        mfa_enabled=admin.mfa_enabled,
        requires_password_change=admin.requires_password_change,
        permissions=admin.permissions,
    )


@router.post("/mfa/setup", response_model=AdminSetupMFAResponse)
async def setup_mfa(
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Setup MFA for admin account."""
    if admin.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is already enabled"
        )

    auth_service = get_admin_auth_service(db)
    provisioning_uri = await auth_service.setup_totp(admin)

    # Extract secret from URI for manual entry
    import re

    secret_match = re.search(r"secret=([A-Z2-7]+)", provisioning_uri)
    secret = secret_match.group(1) if secret_match else ""

    return AdminSetupMFAResponse(
        provisioning_uri=provisioning_uri,
        secret=secret,
    )


@router.post("/mfa/enable")
async def enable_mfa(
    body: AdminEnableMFARequest,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
):
    """Enable MFA after verifying TOTP code."""
    auth_service = get_admin_auth_service(db)

    if not await auth_service.enable_mfa(admin, body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code"
        )

    return {"message": "MFA enabled successfully"}
