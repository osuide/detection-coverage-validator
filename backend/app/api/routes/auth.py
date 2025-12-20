"""Authentication API endpoints."""

import re
import secrets
import time
from collections import defaultdict
from typing import Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context
from app.models.user import User, Organization, MembershipStatus
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    MFAVerifyRequest,
    RefreshRequest,
    RefreshResponse,
    CookieRefreshResponse,
    SignupRequest,
    SignupResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    ChangePasswordRequest,
    MFASetupRequest,
    MFASetupResponse,
    MFABackupCodesResponse,
    UserResponse,
    UserUpdateRequest,
    OrganizationResponse,
    OrganizationCreateRequest,
    SwitchOrganizationRequest,
    SwitchOrganizationResponse,
    SessionResponse,
)
from app.services.auth_service import AuthService
from app.services.hibp_service import check_password_breached

logger = structlog.get_logger()
settings = get_settings()
router = APIRouter()
security = HTTPBearer(auto_error=False)


# === Rate Limiting ===
# Simple in-memory rate limiter for authentication endpoints
# For production with multiple instances, use Redis-backed rate limiting


class RateLimiter:
    """Simple in-memory rate limiter for authentication endpoints."""

    def __init__(self):
        # Format: {ip: [(timestamp, endpoint), ...]}
        self._requests: dict[str, list[tuple[float, str]]] = defaultdict(list)
        self._cleanup_interval = 60  # seconds
        self._last_cleanup = time.time()

    def _cleanup_old_requests(self, max_age: int = 300):
        """Remove requests older than max_age seconds."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        cutoff = now - max_age
        for ip in list(self._requests.keys()):
            self._requests[ip] = [
                (ts, ep) for ts, ep in self._requests[ip] if ts > cutoff
            ]
            if not self._requests[ip]:
                del self._requests[ip]

    def is_rate_limited(
        self, ip: str, endpoint: str, max_requests: int, window_seconds: int
    ) -> bool:
        """Check if IP is rate limited for the given endpoint."""
        self._cleanup_old_requests()
        now = time.time()
        cutoff = now - window_seconds

        # Count recent requests for this endpoint
        recent_count = sum(
            1 for ts, ep in self._requests[ip] if ts > cutoff and ep == endpoint
        )

        if recent_count >= max_requests:
            return True

        # Record this request
        self._requests[ip].append((now, endpoint))
        return False


# Global rate limiter instance
_rate_limiter = RateLimiter()


def rate_limit_login(request: Request):
    """Rate limit dependency for login endpoint: 10 requests per minute per IP."""
    from app.core.security import get_client_ip

    ip = get_client_ip(request) or "unknown"
    if _rate_limiter.is_rate_limited(ip, "login", max_requests=10, window_seconds=60):
        logger.warning("rate_limit_exceeded", ip=ip, endpoint="login")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
            headers={"Retry-After": "60"},
        )


def rate_limit_signup(request: Request):
    """Rate limit dependency for signup endpoint: 5 requests per minute per IP."""
    from app.core.security import get_client_ip

    ip = get_client_ip(request) or "unknown"
    if _rate_limiter.is_rate_limited(ip, "signup", max_requests=5, window_seconds=60):
        logger.warning("rate_limit_exceeded", ip=ip, endpoint="signup")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many signup attempts. Please try again later.",
            headers={"Retry-After": "60"},
        )


def rate_limit_password_reset(request: Request):
    """Rate limit dependency for password reset: 3 requests per minute per IP."""
    from app.core.security import get_client_ip

    ip = get_client_ip(request) or "unknown"
    if _rate_limiter.is_rate_limited(
        ip, "password_reset", max_requests=3, window_seconds=60
    ):
        logger.warning("rate_limit_exceeded", ip=ip, endpoint="password_reset")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset attempts. Please try again later.",
            headers={"Retry-After": "60"},
        )


# === Secure Cookie Configuration ===
# httpOnly cookies for refresh tokens - immune to XSS

REFRESH_TOKEN_COOKIE_NAME = "dcv_refresh_token"
CSRF_TOKEN_COOKIE_NAME = "dcv_csrf_token"


def set_auth_cookies(
    response: Response,
    refresh_token: str,
    csrf_token: str,
    remember_me: bool = False,
) -> None:
    """Set secure httpOnly cookies for authentication.

    Args:
        response: FastAPI response object
        refresh_token: The refresh token to store
        csrf_token: CSRF token for double-submit protection
        remember_me: If True, use longer expiry (30 days vs 7 days)
    """
    max_age = (
        30 * 24 * 60 * 60
        if remember_me
        else settings.refresh_token_expire_days * 24 * 60 * 60
    )

    # Refresh token - httpOnly (not accessible to JS)
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        value=refresh_token,
        max_age=max_age,
        httponly=True,  # Critical: prevents XSS from stealing token
        secure=settings.environment != "development",  # HTTPS only in production
        samesite="lax",  # Protects against CSRF for most cases
        path="/api/v1/auth",  # Only sent to auth endpoints
    )

    # CSRF token - NOT httpOnly (JS needs to read and send in header)
    response.set_cookie(
        key=CSRF_TOKEN_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age,
        httponly=False,  # JS must read this
        secure=settings.environment != "development",
        samesite="lax",
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    """Clear authentication cookies on logout."""
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        path="/api/v1/auth",
    )
    response.delete_cookie(
        key=CSRF_TOKEN_COOKIE_NAME,
        path="/",
    )


def generate_csrf_token() -> str:
    """Generate a CSRF token for double-submit cookie pattern."""
    return secrets.token_urlsafe(32)


def get_client_ip(request: Request) -> Optional[str]:
    """Get client IP address from request."""
    # Check X-Forwarded-For header first (for proxies)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Get the current authenticated user from JWT token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    auth_service = AuthService(db)
    payload = auth_service.decode_token(credentials.credentials)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = UUID(payload.get("sub"))
    user = await auth_service.get_user_by_id(user_id)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Store org context if present
    if "org" in payload:
        request.state.organization_id = UUID(payload["org"])

    return user


async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Get current user if authenticated, None otherwise."""
    if not credentials:
        return None
    try:
        return await get_current_user(request, credentials, db)
    except HTTPException:
        return None


@router.post(
    "/login", response_model=LoginResponse, dependencies=[Depends(rate_limit_login)]
)
async def login(
    request: Request,
    response: Response,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user with email and password.

    Returns access and refresh tokens. If MFA is enabled,
    returns requires_mfa=True with a partial mfa_token.
    """
    auth_service = AuthService(db)
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    user, error = await auth_service.authenticate(
        email=body.email,
        password=body.password,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error or "Invalid credentials",
        )

    # Check if MFA is required
    if user.mfa_enabled:
        # Generate a short-lived MFA token
        mfa_token = auth_service.generate_access_token(user.id, expires_minutes=5)
        return LoginResponse(
            access_token="",
            refresh_token="",
            expires_in=0,
            user=UserResponse.model_validate(user),
            requires_mfa=True,
            mfa_token=mfa_token,
        )

    # Get user's organizations
    organizations = await auth_service.get_user_organizations(user.id)
    org = organizations[0] if organizations else None

    # Get user's role in the organization
    user_role = None
    if org:
        membership = await auth_service.get_user_membership(user.id, org.id)
        if membership:
            user_role = membership.role.value

    # Create session
    access_token, refresh_token = await auth_service.create_session(
        user=user,
        organization_id=org.id if org else None,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Create user response with role
    user_response = UserResponse.model_validate(user)
    user_response.role = user_role

    # Set httpOnly cookies for secure session management
    csrf_token = generate_csrf_token()
    set_auth_cookies(response, refresh_token, csrf_token, remember_me=body.remember_me)

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,  # Still in body for backwards compatibility
        expires_in=settings.access_token_expire_minutes * 60,
        user=user_response,
        organization=OrganizationResponse.model_validate(org) if org else None,
        requires_mfa=False,
    )


@router.post("/login/mfa", response_model=LoginResponse)
async def verify_mfa(
    request: Request,
    response: Response,
    body: MFAVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    """Verify MFA code and complete login."""
    auth_service = AuthService(db)
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    # Decode MFA token
    payload = auth_service.decode_token(body.mfa_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )

    user_id = UUID(payload.get("sub"))
    user = await auth_service.get_user_by_id(user_id)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    # Verify MFA code
    if not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA not configured",
        )

    # Check if it's a backup code (now hashed)
    if user.mfa_backup_codes:
        is_valid_backup, backup_index = auth_service.verify_backup_code(
            body.code, user.mfa_backup_codes
        )
        if is_valid_backup:
            # Remove used backup code
            user.mfa_backup_codes = [
                c for i, c in enumerate(user.mfa_backup_codes) if i != backup_index
            ]
        elif not auth_service.verify_mfa_code(user.mfa_secret, body.code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code",
            )
    elif not auth_service.verify_mfa_code(user.mfa_secret, body.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )

    # Get user's organizations
    organizations = await auth_service.get_user_organizations(user.id)
    org = organizations[0] if organizations else None

    # Get user's role in the organization
    user_role = None
    if org:
        membership = await auth_service.get_user_membership(user.id, org.id)
        if membership:
            user_role = membership.role.value

    # Create session
    access_token, refresh_token = await auth_service.create_session(
        user=user,
        organization_id=org.id if org else None,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Create user response with role
    user_response = UserResponse.model_validate(user)
    user_response.role = user_role

    # Set httpOnly cookies for secure session management
    csrf_token = generate_csrf_token()
    set_auth_cookies(response, refresh_token, csrf_token)

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        user=user_response,
        organization=OrganizationResponse.model_validate(org) if org else None,
        requires_mfa=False,
    )


@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_signup)],
)
async def signup(
    request: Request,
    response: Response,
    body: SignupRequest,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user and create their organization."""
    auth_service = AuthService(db)
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    # Check if email already exists
    existing_user = await auth_service.get_user_by_email(body.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Check if password has been exposed in data breaches (HIBP)
    if settings.hibp_password_check_enabled:
        breach_message = await check_password_breached(body.password)
        if breach_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=breach_message,
            )

    # Generate slug from organization name
    slug = re.sub(r"[^a-z0-9-]", "-", body.organization_name.lower())
    slug = re.sub(r"-+", "-", slug).strip("-")

    # Check if slug is available
    if not await auth_service.check_slug_available(slug):
        # Append random suffix (8 bytes = 16 hex chars for security)
        import secrets

        slug = f"{slug}-{secrets.token_hex(8)}"

    # Create user
    user = await auth_service.create_user(
        email=body.email,
        password=body.password,
        full_name=body.full_name,
        email_verified=False,  # Require email verification in production
    )

    # Create organization
    org = await auth_service.create_organization(
        name=body.organization_name,
        slug=slug,
        owner_user_id=user.id,
    )

    # Create session
    access_token, refresh_token = await auth_service.create_session(
        user=user,
        organization_id=org.id,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # User who signed up is always the owner
    user_response = UserResponse.model_validate(user)
    user_response.role = "owner"

    # Set httpOnly cookies for secure session management
    csrf_token = generate_csrf_token()
    set_auth_cookies(response, refresh_token, csrf_token)

    return SignupResponse(
        user=user_response,
        organization=OrganizationResponse.model_validate(org),
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=RefreshResponse)
async def refresh_token(
    request: Request,
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """Refresh access token using refresh token."""
    auth_service = AuthService(db)
    ip_address = get_client_ip(request)

    access_token, new_refresh_token = await auth_service.refresh_session(
        refresh_token=body.refresh_token,
        ip_address=ip_address,
    )

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    return RefreshResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/refresh-session", response_model=CookieRefreshResponse)
async def refresh_session_cookie(
    request: Request,
    response: Response,
    dcv_refresh_token: Optional[str] = Cookie(None),
    db: AsyncSession = Depends(get_db),
):
    """Refresh access token using httpOnly cookie.

    This is the secure version that reads the refresh token from an httpOnly
    cookie instead of the request body. Use this for browser-based clients.

    The refresh token is automatically rotated and a new cookie is set.
    """
    if not dcv_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token cookie found. Please log in again.",
        )

    # Validate CSRF token (double-submit cookie pattern)
    csrf_header = request.headers.get("X-CSRF-Token")
    csrf_cookie = request.cookies.get(CSRF_TOKEN_COOKIE_NAME)

    if not csrf_header or not csrf_cookie or csrf_header != csrf_cookie:
        logger.warning(
            "csrf_validation_failed",
            ip=get_client_ip(request),
            has_header=bool(csrf_header),
            has_cookie=bool(csrf_cookie),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token validation failed",
        )

    auth_service = AuthService(db)
    ip_address = get_client_ip(request)

    access_token, new_refresh_token = await auth_service.refresh_session(
        refresh_token=dcv_refresh_token,
        ip_address=ip_address,
    )

    if not access_token:
        # Clear invalid cookies
        clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again.",
        )

    # Generate new CSRF token and set cookies
    new_csrf_token = generate_csrf_token()
    set_auth_cookies(response, new_refresh_token, new_csrf_token)

    return CookieRefreshResponse(
        access_token=access_token,
        expires_in=settings.access_token_expire_minutes * 60,
        csrf_token=new_csrf_token,
    )


@router.post("/logout-session", status_code=status.HTTP_204_NO_CONTENT)
async def logout_session_cookie(
    request: Request,
    response: Response,
    dcv_refresh_token: Optional[str] = Cookie(None),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
):
    """Logout using httpOnly cookie-based session.

    Clears the httpOnly cookie and invalidates the session.
    """
    if dcv_refresh_token:
        auth_service = AuthService(db)
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent")

        await auth_service.logout(
            refresh_token=dcv_refresh_token,
            user_id=current_user.id if current_user else None,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    # Always clear cookies
    clear_auth_cookies(response)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    body: RefreshRequest,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db),
):
    """Logout and invalidate the refresh token."""
    auth_service = AuthService(db)
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    await auth_service.logout(
        refresh_token=body.refresh_token,
        user_id=current_user.id if current_user else None,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/forgot-password",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(rate_limit_password_reset)],
)
async def forgot_password(
    request: Request,
    body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Request password reset.

    Always returns 204 to prevent email enumeration.
    """
    from app.services.email_service import get_email_service

    auth_service = AuthService(db)
    token = await auth_service.initiate_password_reset(body.email)

    if token:
        # Send password reset email
        email_service = get_email_service()
        email_sent = email_service.send_password_reset_email(
            to_email=body.email,
            reset_token=token,
        )
        if not email_sent:
            logger.warning("password_reset_email_failed", email=body.email)
        else:
            logger.info("password_reset_email_sent", email=body.email)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    request: Request,
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """Reset password using reset token."""
    # Check if password has been exposed in data breaches (HIBP)
    if settings.hibp_password_check_enabled:
        breach_message = await check_password_breached(body.password)
        if breach_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=breach_message,
            )

    auth_service = AuthService(db)
    ip_address = get_client_ip(request)

    success, error = await auth_service.reset_password(
        token=body.token,
        new_password=body.password,
        ip_address=ip_address,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error or "Password reset failed",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserResponse)
async def get_me(
    auth: AuthContext = Depends(get_auth_context),
):
    """Get current user profile."""
    if not auth.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    user_response = UserResponse.model_validate(auth.user)
    # Populate role from membership context
    if auth.membership:
        user_response.role = auth.membership.role.value
    return user_response


@router.patch("/me", response_model=UserResponse)
async def update_me(
    body: UserUpdateRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Update current user profile."""
    if not auth.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    if body.full_name is not None:
        auth.user.full_name = body.full_name
    if body.timezone is not None:
        auth.user.timezone = body.timezone
    if body.avatar_url is not None:
        auth.user.avatar_url = body.avatar_url

    user_response = UserResponse.model_validate(auth.user)
    # Populate role from membership context
    if auth.membership:
        user_response.role = auth.membership.role.value
    return user_response


@router.post("/me/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    request: Request,
    body: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change current user's password."""
    auth_service = AuthService(db)

    # Verify current password
    if not auth_service.verify_password(
        body.current_password, current_user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Check if new password has been exposed in data breaches (HIBP)
    if settings.hibp_password_check_enabled:
        breach_message = await check_password_breached(body.new_password)
        if breach_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=breach_message,
            )

    # Update password
    current_user.password_hash = auth_service.hash_password(body.new_password)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/me/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Start MFA setup - returns secret and provisioning URI."""
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    auth_service = AuthService(db)
    secret = auth_service.generate_mfa_secret()
    provisioning_uri = auth_service.get_mfa_provisioning_uri(secret, current_user.email)

    # Store secret temporarily (not enabled until verified)
    current_user.mfa_secret = secret

    return MFASetupResponse(
        secret=secret,
        provisioning_uri=provisioning_uri,
    )


@router.post("/me/mfa/verify", response_model=MFABackupCodesResponse)
async def verify_mfa_setup(
    request: Request,
    body: MFASetupRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify MFA code and enable MFA."""
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Start MFA setup first",
        )

    auth_service = AuthService(db)

    # Verify the code
    if not auth_service.verify_mfa_code(current_user.mfa_secret, body.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code",
        )

    # Generate backup codes (display codes for user, hashed codes for storage)
    display_codes, hashed_codes = auth_service.generate_backup_codes()

    # Enable MFA - store hashed codes, return display codes to user ONCE
    current_user.mfa_enabled = True
    current_user.mfa_backup_codes = hashed_codes

    return MFABackupCodesResponse(backup_codes=display_codes)


@router.delete("/me/mfa", status_code=status.HTTP_204_NO_CONTENT)
async def disable_mfa(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable MFA for current user."""
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.mfa_backup_codes = None

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me/organizations", response_model=list[OrganizationResponse])
async def get_my_organizations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get organizations the current user belongs to."""
    auth_service = AuthService(db)
    organizations = await auth_service.get_user_organizations(current_user.id)
    return [OrganizationResponse.model_validate(org) for org in organizations]


@router.post("/me/organizations/switch", response_model=SwitchOrganizationResponse)
async def switch_organization(
    request: Request,
    body: SwitchOrganizationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Switch to a different organization."""
    auth_service = AuthService(db)

    # Verify membership
    membership = await auth_service.get_user_membership(
        user_id=current_user.id,
        organization_id=body.organization_id,
    )

    if not membership or membership.status != MembershipStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of this organization",
        )

    # Generate new access token with org context
    access_token = auth_service.generate_access_token(
        user_id=current_user.id,
        organization_id=body.organization_id,
    )

    # Get organization
    from sqlalchemy import select

    result = await db.execute(
        select(Organization).where(Organization.id == body.organization_id)
    )
    org = result.scalar_one()

    return SwitchOrganizationResponse(
        access_token=access_token,
        organization=OrganizationResponse.model_validate(org),
    )


@router.get("/me/sessions", response_model=list[SessionResponse])
async def get_my_sessions(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all active sessions for current user."""
    from sqlalchemy import select, and_
    from app.models.user import UserSession

    result = await db.execute(
        select(UserSession)
        .where(
            and_(
                UserSession.user_id == current_user.id,
                UserSession.is_active.is_(True),
            )
        )
        .order_by(UserSession.last_activity_at.desc())
    )
    sessions = result.scalars().all()

    responses = []
    for session in sessions:
        resp = SessionResponse.model_validate(session)
        # Mark current session (approximate - based on recent activity)
        responses.append(resp)

    return responses


@router.delete("/me/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke a specific session."""
    from sqlalchemy import select, and_
    from app.models.user import UserSession

    result = await db.execute(
        select(UserSession).where(
            and_(
                UserSession.id == session_id,
                UserSession.user_id == current_user.id,
            )
        )
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    session.is_active = False
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/me/sessions", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_all_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke all sessions except current."""
    auth_service = AuthService(db)
    await auth_service.logout_all_sessions(current_user.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/organizations",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_organization(
    body: OrganizationCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new organization."""
    auth_service = AuthService(db)

    # Check slug availability
    if not await auth_service.check_slug_available(body.slug):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization slug is already taken",
        )

    org = await auth_service.create_organization(
        name=body.name,
        slug=body.slug,
        owner_user_id=current_user.id,
    )

    return OrganizationResponse.model_validate(org)


@router.get("/organizations/check-slug")
async def check_slug_availability(
    slug: str,
    db: AsyncSession = Depends(get_db),
):
    """Check if an organization slug is available."""
    auth_service = AuthService(db)
    available = await auth_service.check_slug_available(slug)
    return {"available": available}
