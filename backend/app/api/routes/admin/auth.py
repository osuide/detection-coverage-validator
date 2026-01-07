"""Admin authentication routes.

Security: Uses httpOnly cookies for refresh tokens (immune to XSS).
CSRF protection via double-submit cookie pattern.
"""

import hmac
import secrets
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.database import get_db
from app.core.config import get_settings
from app.core.security import get_client_ip
from app.models.admin import AdminUser
from app.services.admin_auth_service import get_admin_auth_service
from app.api.deps import get_current_admin

settings = get_settings()

logger = structlog.get_logger()

router = APIRouter(prefix="/auth", tags=["Admin Auth"])


# === Secure Cookie Configuration ===
# httpOnly cookies for refresh tokens - immune to XSS

ADMIN_REFRESH_TOKEN_COOKIE_NAME = "dcv_admin_refresh_token"
ADMIN_CSRF_TOKEN_COOKIE_NAME = "dcv_admin_csrf_token"


def set_admin_auth_cookies(
    response: Response,
    refresh_token: str,
    csrf_token: str,
) -> None:
    """Set secure httpOnly cookies for admin authentication.

    Args:
        response: FastAPI response object
        refresh_token: The refresh token to store
        csrf_token: CSRF token for double-submit protection
    """
    # Admin sessions have shorter lifetime (8 hours vs 7 days for users)
    max_age = 8 * 60 * 60  # 8 hours

    # Cookie domain for cross-subdomain auth (e.g., ".a13e.com")
    cookie_domain = settings.cookie_domain

    # Refresh token - httpOnly (not accessible to JS)
    response.set_cookie(
        key=ADMIN_REFRESH_TOKEN_COOKIE_NAME,
        value=refresh_token,
        max_age=max_age,
        httponly=True,  # Critical: prevents XSS from stealing token
        secure=settings.environment != "development",  # HTTPS only in production
        samesite="lax",  # Protects against CSRF for most cases
        path="/api/v1/admin/auth",  # Only sent to admin auth endpoints
        domain=cookie_domain,
    )

    # CSRF token - NOT httpOnly (JS needs to read and send in header)
    response.set_cookie(
        key=ADMIN_CSRF_TOKEN_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age,
        httponly=False,  # JS must read this
        secure=settings.environment != "development",
        samesite="lax",
        path="/",
        domain=cookie_domain,
    )


def clear_admin_auth_cookies(response: Response) -> None:
    """Clear admin authentication cookies on logout."""
    cookie_domain = settings.cookie_domain

    response.delete_cookie(
        key=ADMIN_REFRESH_TOKEN_COOKIE_NAME,
        path="/api/v1/admin/auth",
        domain=cookie_domain,
    )
    response.delete_cookie(
        key=ADMIN_CSRF_TOKEN_COOKIE_NAME,
        path="/",
        domain=cookie_domain,
    )


def generate_admin_csrf_token() -> str:
    """Generate a CSRF token for double-submit cookie pattern."""
    return secrets.token_urlsafe(32)


async def validate_admin_csrf_token(request: Request) -> None:
    """Validate CSRF token using double-submit cookie pattern.

    Uses hmac.compare_digest for constant-time comparison to prevent timing attacks.

    Raises HTTPException 403 if validation fails.
    """
    # Get CSRF token from cookie
    cookie_token = request.cookies.get(ADMIN_CSRF_TOKEN_COOKIE_NAME)
    if not cookie_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing CSRF token cookie",
        )

    # Get CSRF token from header
    header_token = request.headers.get("X-Admin-CSRF-Token")
    if not header_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing CSRF token header",
        )

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(cookie_token, header_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid CSRF token",
        )


# Request/Response schemas
class AdminLoginRequest(BaseModel):
    """Admin login request."""

    email: EmailStr
    password: str


class AdminLoginResponse(BaseModel):
    """Admin login response.

    Note: refresh_token is no longer returned in the response body.
    It is set as an httpOnly cookie for security.
    """

    requires_mfa: bool
    mfa_setup_required: bool = False  # True if MFA needs to be set up first
    mfa_token: Optional[str] = None  # Temporary token for MFA flow
    setup_token: Optional[str] = None  # Token for MFA setup (when mfa_setup_required)
    access_token: Optional[str] = None
    csrf_token: Optional[str] = None  # CSRF token for double-submit pattern


class AdminMFARequest(BaseModel):
    """MFA verification request."""

    mfa_token: str
    totp_code: str


class AdminTokenResponse(BaseModel):
    """Token response.

    Note: refresh_token is set as an httpOnly cookie, not in response body.
    """

    access_token: str
    csrf_token: str  # CSRF token for double-submit pattern
    expires_in: int
    admin: dict


class AdminRefreshResponse(BaseModel):
    """Token refresh response."""

    access_token: str
    expires_in: int


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


@router.post("/login", response_model=AdminLoginResponse)
async def admin_login(
    body: AdminLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AdminLoginResponse:
    """Admin login endpoint.

    Step 1: Verify email/password
    Step 2: If MFA enabled, return mfa_token for verification
    Step 3: If MFA not enabled, return tokens directly (dev mode only)

    Security: Refresh token is set as httpOnly cookie (not in response body).
    """
    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request) or "unknown"
    user_agent = request.headers.get("User-Agent")

    # Check IP allowlist
    if not await auth_service.check_ip_allowed(ip_address):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: IP not in allowlist",
        )

    try:
        admin, requires_mfa, mfa_setup_required = await auth_service.authenticate(
            email=body.email,
            password=body.password,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except ValueError as e:
        logger.warning("admin_auth_failed", error=str(e), email=body.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    from app.core.security import create_access_token
    from datetime import timedelta

    # Case 1: MFA setup required (new admin in staging/production)
    if mfa_setup_required:
        # Generate a setup token that allows MFA setup
        setup_token = create_access_token(
            data={"sub": str(admin.id), "type": "mfa_setup"},
            expires_delta=timedelta(minutes=10),
        )
        return AdminLoginResponse(
            requires_mfa=False,
            mfa_setup_required=True,
            setup_token=setup_token,
        )

    # Case 2: MFA enabled, need verification
    if requires_mfa:
        mfa_token = create_access_token(
            data={"sub": str(admin.id), "type": "mfa_pending"},
            expires_delta=timedelta(minutes=5),
        )
        return AdminLoginResponse(
            requires_mfa=True,
            mfa_token=mfa_token,
        )

    # Case 3: MFA not enabled and not required (development only)
    access_token, refresh_token = await auth_service.create_session(
        admin=admin,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Set refresh token in httpOnly cookie (secure against XSS)
    csrf_token = generate_admin_csrf_token()
    set_admin_auth_cookies(response, refresh_token, csrf_token)

    return AdminLoginResponse(
        requires_mfa=False,
        access_token=access_token,
        csrf_token=csrf_token,
    )


@router.post("/mfa/verify", response_model=AdminTokenResponse)
async def verify_mfa(
    body: AdminMFARequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AdminTokenResponse:
    """Verify MFA code and issue tokens.

    Security: Refresh token is set as httpOnly cookie (not in response body).
    """
    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request) or "unknown"
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

    # Set refresh token in httpOnly cookie (secure against XSS)
    csrf_token = generate_admin_csrf_token()
    set_admin_auth_cookies(response, refresh_token, csrf_token)

    return AdminTokenResponse(
        access_token=access_token,
        csrf_token=csrf_token,
        expires_in=auth_service.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        admin={
            "id": str(admin.id),
            "email": admin.email,
            "full_name": admin.full_name,
            "role": admin.role.value,
            "mfa_enabled": admin.mfa_enabled,
        },
    )


@router.post("/refresh", response_model=AdminRefreshResponse)
async def refresh_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_refresh_token: Optional[str] = Cookie(
        None, alias=ADMIN_REFRESH_TOKEN_COOKIE_NAME
    ),
) -> AdminRefreshResponse:
    """Refresh access token.

    Security: Reads refresh token from httpOnly cookie.
    CSRF validation is performed to prevent cross-site token refresh attacks.
    """
    # Validate CSRF token (prevents cross-site token refresh)
    await validate_admin_csrf_token(request)

    if not admin_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token",
        )

    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request) or "unknown"

    access_token = await auth_service.refresh_access_token(
        refresh_token=admin_refresh_token,
        ip_address=ip_address,
    )

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    return AdminRefreshResponse(
        access_token=access_token,
        expires_in=auth_service.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Logout and terminate session.

    Clears httpOnly cookies and invalidates server-side session.
    """
    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request) or "unknown"
    user_agent = request.headers.get("User-Agent")

    # Get session ID from token
    session_id = getattr(request.state, "admin_session_id", None)

    if session_id:
        await auth_service.logout(
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    # Clear httpOnly cookies
    clear_admin_auth_cookies(response)

    return {"message": "Logged out successfully"}


@router.get("/me", response_model=AdminProfileResponse)
async def get_current_admin_profile(
    admin: AdminUser = Depends(get_current_admin),
) -> AdminProfileResponse:
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
) -> AdminSetupMFAResponse:
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
) -> dict:
    """Enable MFA after verifying TOTP code."""
    auth_service = get_admin_auth_service(db)

    if not await auth_service.enable_mfa(admin, body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code"
        )

    return {"message": "MFA enabled successfully"}


# ============================================================================
# First-Time MFA Setup Endpoints (using setup_token, not full auth)
# ============================================================================


class AdminSetupMFAWithTokenRequest(BaseModel):
    """Request to start MFA setup using setup token."""

    setup_token: str


class AdminEnableMFAWithTokenRequest(BaseModel):
    """Request to enable MFA using setup token and TOTP code."""

    setup_token: str
    totp_code: str


@router.post("/mfa/setup-with-token", response_model=AdminSetupMFAResponse)
async def setup_mfa_with_token(
    body: AdminSetupMFAWithTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> AdminSetupMFAResponse:
    """Setup MFA for admin who hasn't configured MFA yet.

    This endpoint uses the setup_token from login response (when mfa_setup_required=true)
    to allow first-time MFA setup without requiring full authentication.
    """
    from app.core.security import decode_token
    from sqlalchemy import select

    # Validate setup token
    try:
        payload = decode_token(body.setup_token)
        if payload.get("type") != "mfa_setup":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid setup token",
            )
        admin_id = UUID(payload["sub"])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired setup token",
        )

    # Get admin
    result = await db.execute(select(AdminUser).where(AdminUser.id == admin_id))
    admin = result.scalar_one_or_none()

    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid setup token",
        )

    if admin.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    # Generate TOTP secret
    auth_service = get_admin_auth_service(db)
    provisioning_uri = await auth_service.setup_totp(admin)

    # Extract secret for manual entry
    import re

    secret_match = re.search(r"secret=([A-Z2-7]+)", provisioning_uri)
    secret = secret_match.group(1) if secret_match else ""

    return AdminSetupMFAResponse(
        provisioning_uri=provisioning_uri,
        secret=secret,
    )


@router.post("/mfa/enable-with-token", response_model=AdminTokenResponse)
async def enable_mfa_with_token(
    body: AdminEnableMFAWithTokenRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AdminTokenResponse:
    """Enable MFA and complete login using setup token and TOTP code.

    After MFA is enabled, this endpoint returns access tokens and sets
    refresh token as httpOnly cookie to complete the login flow.

    Security: Refresh token is set as httpOnly cookie (not in response body).
    """
    from app.core.security import decode_token, get_client_ip
    from sqlalchemy import select

    # Validate setup token
    try:
        payload = decode_token(body.setup_token)
        if payload.get("type") != "mfa_setup":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid setup token",
            )
        admin_id = UUID(payload["sub"])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired setup token",
        )

    # Get admin
    result = await db.execute(select(AdminUser).where(AdminUser.id == admin_id))
    admin = result.scalar_one_or_none()

    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid setup token",
        )

    # Enable MFA
    auth_service = get_admin_auth_service(db)
    if not await auth_service.enable_mfa(admin, body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code. Please check your authenticator app.",
        )

    # Create session and return tokens
    ip_address = get_client_ip(request) or "unknown"
    user_agent = request.headers.get("User-Agent")

    access_token, refresh_token = await auth_service.create_session(
        admin=admin,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Set refresh token in httpOnly cookie (secure against XSS)
    csrf_token = generate_admin_csrf_token()
    set_admin_auth_cookies(response, refresh_token, csrf_token)

    return AdminTokenResponse(
        access_token=access_token,
        csrf_token=csrf_token,
        expires_in=auth_service.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        admin={
            "id": str(admin.id),
            "email": admin.email,
            "full_name": admin.full_name,
            "role": admin.role.value,
            "mfa_enabled": True,  # Now enabled
        },
    )


# ============================================================================
# WebAuthn/FIDO2 Authentication Endpoints
# ============================================================================


class WebAuthnAuthOptionsRequest(BaseModel):
    """Request WebAuthn authentication options."""

    email: EmailStr


class WebAuthnAuthOptionsResponse(BaseModel):
    """WebAuthn authentication options for the browser."""

    options: dict
    auth_token: str  # Temporary token for verification step


class WebAuthnAuthVerifyRequest(BaseModel):
    """WebAuthn authentication verification request."""

    auth_token: str
    credential: dict


@router.post("/webauthn/auth/options", response_model=WebAuthnAuthOptionsResponse)
async def get_webauthn_auth_options(
    body: WebAuthnAuthOptionsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> WebAuthnAuthOptionsResponse:
    """Get WebAuthn authentication options for an admin.

    This starts the WebAuthn authentication flow. The admin provides their email,
    and we return a challenge for their security key.
    """
    from sqlalchemy import select
    from app.services.webauthn_service import (
        get_webauthn_service,
        store_challenge_async,
    )
    from app.core.security import get_client_ip

    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request) or "unknown"

    # Check IP allowlist
    if not await auth_service.check_ip_allowed(ip_address):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: IP not in allowlist",
        )

    # Get admin by email
    result = await db.execute(
        select(AdminUser).where(AdminUser.email == body.email.lower())
    )
    admin = result.scalar_one_or_none()

    if not admin:
        # Don't reveal if user exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Check if admin has WebAuthn credentials
    credentials = admin.webauthn_credentials or []
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No security keys registered. Please use password + TOTP.",
        )

    # Check if account is active and not locked
    if not admin.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
        )

    if admin.is_locked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is locked. Please try again later.",
        )

    # Generate authentication options
    webauthn = get_webauthn_service()
    options_json, challenge = webauthn.generate_authentication_options_for_user(
        credentials=credentials
    )

    # Store challenge with admin ID (Redis-backed for multi-instance support)
    await store_challenge_async(f"admin_webauthn_auth_{admin.id}", challenge)

    # Create temporary auth token
    from app.core.security import create_access_token
    from datetime import timedelta

    auth_token = create_access_token(
        data={"sub": str(admin.id), "type": "webauthn_pending"},
        expires_delta=timedelta(minutes=5),
    )

    return WebAuthnAuthOptionsResponse(
        options=options_json,
        auth_token=auth_token,
    )


@router.post("/webauthn/auth/verify", response_model=AdminTokenResponse)
async def verify_webauthn_auth(
    body: WebAuthnAuthVerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AdminTokenResponse:
    """Complete WebAuthn authentication.

    Verifies the security key response and returns access tokens.
    Security: Refresh token is set as httpOnly cookie (not in response body).
    """
    import json
    from sqlalchemy import select
    from app.services.webauthn_service import get_webauthn_service, get_challenge_async
    from app.core.security import decode_token, get_client_ip
    from datetime import datetime, timezone

    # Validate auth token
    try:
        payload = decode_token(body.auth_token)
        if payload.get("type") != "webauthn_pending":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        admin_id = UUID(payload["sub"])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
        )

    # Get admin
    result = await db.execute(select(AdminUser).where(AdminUser.id == admin_id))
    admin = result.scalar_one_or_none()

    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    # Get stored challenge (Redis-backed for multi-instance support)
    challenge = await get_challenge_async(f"admin_webauthn_auth_{admin.id}")
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication session expired. Please try again.",
        )

    # Verify the authentication
    webauthn = get_webauthn_service()
    try:
        credential_id, new_sign_count = webauthn.verify_authentication(
            credential_json=json.dumps(body.credential),
            expected_challenge=challenge,
            stored_credentials=admin.webauthn_credentials or [],
        )
    except Exception as e:
        # Increment failed attempts
        admin.failed_login_attempts += 1
        if admin.failed_login_attempts >= 3:
            from datetime import timedelta

            admin.locked_until = datetime.now(timezone.utc) + timedelta(minutes=60)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}",
        )

    # Update credential sign count and last used
    credentials = admin.webauthn_credentials or []
    for cred in credentials:
        if cred["credential_id"] == credential_id:
            cred["sign_count"] = new_sign_count
            cred["last_used_at"] = datetime.now(timezone.utc).isoformat()
            break
    admin.webauthn_credentials = credentials

    # Reset failed attempts
    admin.failed_login_attempts = 0

    await db.commit()

    # Create session
    auth_service = get_admin_auth_service(db)
    ip_address = get_client_ip(request) or "unknown"
    user_agent = request.headers.get("User-Agent")

    access_token, refresh_token = await auth_service.create_session(
        admin=admin,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Set refresh token in httpOnly cookie (secure against XSS)
    csrf_token = generate_admin_csrf_token()
    set_admin_auth_cookies(response, refresh_token, csrf_token)

    return AdminTokenResponse(
        access_token=access_token,
        csrf_token=csrf_token,
        expires_in=auth_service.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        admin={
            "id": str(admin.id),
            "email": admin.email,
            "full_name": admin.full_name,
            "role": admin.role.value,
            "mfa_enabled": admin.mfa_enabled,
        },
    )
