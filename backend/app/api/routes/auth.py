"""Authentication API endpoints."""

import re
import secrets
from typing import Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps.rate_limit import (
    auth_rate_limit,
    signup_rate_limit,
    password_reset_rate_limit,
    mfa_rate_limit,
)
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    AuthContext,
    get_auth_context,
    get_client_ip as get_secure_client_ip,
)
from app.models.user import User, Organization, OrganizationMember, MembershipStatus
from app.models.security import OrganizationSecuritySettings
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
from app.services.email_quality_service import get_email_quality_service
from app.services.fingerprint_service import FingerprintService
from app.services.hibp_service import check_password_breached

logger = structlog.get_logger()
settings = get_settings()
router = APIRouter()
security = HTTPBearer(auto_error=False)


# === Rate Limiting ===
# Redis-backed rate limiting for multi-instance deployments
# See app/api/deps/rate_limit.py for implementation

# Create rate limit dependencies for use in endpoint decorators
rate_limit_login = auth_rate_limit()
rate_limit_signup = signup_rate_limit()
rate_limit_password_reset = password_reset_rate_limit()
rate_limit_mfa = mfa_rate_limit()


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

    # Cookie domain for cross-subdomain auth (e.g., ".a13e.com")
    # When set, cookies are accessible to all subdomains (frontend + API)
    cookie_domain = settings.cookie_domain

    # Refresh token - httpOnly (not accessible to JS)
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        value=refresh_token,
        max_age=max_age,
        httponly=True,  # Critical: prevents XSS from stealing token
        secure=settings.environment != "development",  # HTTPS only in production
        samesite="lax",  # Protects against CSRF for most cases
        path="/api/v1/auth",  # Only sent to auth endpoints
        domain=cookie_domain,  # Required for cross-subdomain setups
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
        domain=cookie_domain,  # Required for cross-subdomain setups
    )


def clear_auth_cookies(response: Response) -> None:
    """Clear authentication cookies on logout."""
    cookie_domain = settings.cookie_domain

    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        path="/api/v1/auth",
        domain=cookie_domain,
    )
    response.delete_cookie(
        key=CSRF_TOKEN_COOKIE_NAME,
        path="/",
        domain=cookie_domain,
    )


def generate_csrf_token() -> str:
    """Generate a CSRF token for double-submit cookie pattern."""
    return secrets.token_urlsafe(32)


async def validate_csrf_token(request: Request) -> None:
    """Validate CSRF token using double-submit cookie pattern.

    Security: Uses hmac.compare_digest for constant-time comparison
    to prevent timing attacks (fixes M2 from security audit).

    Raises HTTPException 403 if validation fails.
    """
    import hmac
    import structlog

    logger = structlog.get_logger()

    csrf_header = request.headers.get("X-CSRF-Token")
    csrf_cookie = request.cookies.get(CSRF_TOKEN_COOKIE_NAME)

    # Debug logging to diagnose CSRF issues
    logger.debug(
        "csrf_validation",
        has_header=bool(csrf_header),
        has_cookie=bool(csrf_cookie),
        header_len=len(csrf_header) if csrf_header else 0,
        cookie_len=len(csrf_cookie) if csrf_cookie else 0,
        cookies_received=list(request.cookies.keys()),
    )

    # Both must be present
    if not csrf_header or not csrf_cookie:
        logger.warning(
            "csrf_token_missing",
            has_header=bool(csrf_header),
            has_cookie=bool(csrf_cookie),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing",
        )

    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(csrf_header, csrf_cookie):
        logger.warning(
            "csrf_token_mismatch",
            header_prefix=csrf_header[:8] if csrf_header else None,
            cookie_prefix=csrf_cookie[:8] if csrf_cookie else None,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token validation failed",
        )


def get_client_ip(request: Request) -> Optional[str]:
    """Get client IP address from request.

    Uses the secure implementation from app.core.security that properly
    validates trusted proxies before accepting forwarded headers.
    """
    return get_secure_client_ip(request)


def validate_password_policy(
    password: str,
    security_settings: Optional[OrganizationSecuritySettings],
) -> Optional[str]:
    """Validate password against organisation security policy.

    Returns error message if validation fails, None if password is valid.
    """
    if not security_settings:
        # No org security settings - use sensible defaults
        min_length = 8
        require_uppercase = True
        require_lowercase = True
        require_number = True
        require_special = False
    else:
        min_length = security_settings.password_min_length
        require_uppercase = security_settings.password_require_uppercase
        require_lowercase = security_settings.password_require_lowercase
        require_number = security_settings.password_require_number
        require_special = security_settings.password_require_special

    errors = []

    if len(password) < min_length:
        errors.append(f"at least {min_length} characters")

    if require_uppercase and not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")

    if require_lowercase and not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")

    if require_number and not re.search(r"\d", password):
        errors.append("a number")

    if require_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("a special character")

    if errors:
        return f"Password must contain {', '.join(errors)}"

    return None


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

    # H2: Store org context only if user has active membership
    if "org" in payload:
        org_id = UUID(payload["org"])
        # Verify active membership before trusting the org claim
        membership = await db.execute(
            select(OrganizationMember).where(
                and_(
                    OrganizationMember.user_id == user_id,
                    OrganizationMember.organization_id == org_id,
                    OrganizationMember.status == MembershipStatus.ACTIVE,
                )
            )
        )
        if membership.scalar_one_or_none():
            request.state.organization_id = org_id
        # If not a member, silently ignore the org claim (user should switch orgs)

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

    Enforces organisation security policies:
    - IP allowlist (if configured)
    - Allowed authentication methods
    - MFA requirements
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

    # Get user's organizations first (needed for security policy checks)
    organizations = await auth_service.get_user_organizations(user.id)
    org = organizations[0] if organizations else None

    # Get organisation security settings and enforce policies
    org_requires_mfa = False
    org_security = None
    if org:
        result = await db.execute(
            select(OrganizationSecuritySettings).where(
                OrganizationSecuritySettings.organization_id == org.id
            )
        )
        org_security = result.scalar_one_or_none()

        if org_security:
            # Enforce IP allowlist (if configured)
            if org_security.ip_allowlist and ip_address:
                if not org_security.is_ip_allowed(ip_address):
                    logger.warning(
                        "login_blocked_ip_allowlist",
                        user_id=str(user.id),
                        ip_address=ip_address,
                        organization_id=str(org.id),
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied: Your IP address is not allowed by organisation policy",
                    )

            # Enforce allowed authentication methods
            if not org_security.is_auth_method_allowed("password"):
                logger.warning(
                    "login_blocked_auth_method",
                    user_id=str(user.id),
                    auth_method="password",
                    allowed_methods=org_security.allowed_auth_methods,
                    organization_id=str(org.id),
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Password authentication is not allowed for this organisation. Please use SSO.",
                )

            # Check MFA requirement
            if org_security.require_mfa:
                org_requires_mfa = True

    # Check if MFA is required (user has it enabled OR org requires it)
    if user.mfa_enabled:
        # User has MFA set up - require verification
        # Generate a short-lived MFA pending token
        # Security: Uses type='mfa_pending' which is rejected by auth middleware,
        # preventing this token from being used as an access token (MFA bypass fix)
        mfa_token = auth_service.generate_mfa_pending_token(user.id, expires_minutes=5)
        # M4: Don't leak user info before MFA verification - return minimal data
        return LoginResponse(
            access_token="",
            refresh_token="",
            expires_in=0,
            user=None,  # Don't return user details until MFA verified
            requires_mfa=True,
            mfa_token=mfa_token,
        )
    elif org_requires_mfa:
        # Org requires MFA but user hasn't set it up - block login
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your organisation requires MFA. Please set up MFA before logging in.",
        )

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


@router.post(
    "/login/mfa", response_model=LoginResponse, dependencies=[Depends(rate_limit_mfa)]
)
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

    # Security: Validate token type is 'mfa_pending'
    # This ensures only tokens from the login flow can be used here,
    # not regular access tokens or other token types
    token_type = payload.get("type")
    if token_type != "mfa_pending":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA token type",
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
    fingerprint_service = FingerprintService(db)
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    # Extract device fingerprint from header (optional)
    fingerprint_hash = request.headers.get("X-Device-Fingerprint")

    # Check registration rate limit from this device
    if fingerprint_hash:
        allowed, reason = await fingerprint_service.check_registration_allowed(
            fingerprint_hash=fingerprint_hash,
            ip_address=ip_address,
        )
        if not allowed:
            logger.warning(
                "signup_blocked_fingerprint",
                fingerprint_hash=(
                    fingerprint_hash[:16] + "..." if fingerprint_hash else None
                ),
                ip_address=ip_address,
                reason=reason,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=reason or "Too many registrations from this device",
            )

    # Validate email quality (async MX check - Pydantic already blocked disposable domains)
    email_service = get_email_quality_service()
    is_valid, email_error = await email_service.validate_email_quality(
        body.email,
        check_mx=settings.fraud_prevention_enabled,
    )
    if not is_valid:
        logger.warning(
            "signup_blocked_email_quality",
            email_domain=body.email.split("@")[1] if "@" in body.email else "unknown",
            error=email_error,
            ip_address=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=email_error,
        )

    # Check if email already exists
    # M10: Return generic message to prevent email enumeration
    existing_user = await auth_service.get_user_by_email(body.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to create account with this email address",
        )

    # Check if password has been exposed in data breaches (HIBP)
    if settings.hibp_password_check_enabled:
        breach_message = await check_password_breached(body.password)
        if breach_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=breach_message,
            )

    # Generate slug from organization name with guaranteed entropy
    # Always add random suffix to prevent timing attacks and ensure uniqueness
    import secrets

    slug_base = re.sub(r"[^a-z0-9-]", "-", body.organization_name.lower())
    slug_base = re.sub(r"-+", "-", slug_base).strip("-")[:40]  # Limit base length
    slug = f"{slug_base}-{secrets.token_hex(4)}"  # Always add 8 random chars

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

    # Record device fingerprint association (non-blocking)
    if fingerprint_hash:
        try:
            await fingerprint_service.record_fingerprint(
                fingerprint_hash=fingerprint_hash,
                user_id=user.id,
                organization_id=org.id,
                ip_address=ip_address,
            )
        except Exception as e:
            # Don't fail signup if fingerprint recording fails
            logger.error(
                "fingerprint_record_failed",
                user_id=str(user.id),
                error=str(e),
            )

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
    _csrf: None = Depends(
        validate_csrf_token
    ),  # CSRF validation with constant-time comparison
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
    _csrf: None = Depends(validate_csrf_token),  # CSRF validation
):
    """Logout using httpOnly cookie-based session.

    Clears the httpOnly cookie and invalidates the session.
    Requires CSRF token to prevent cross-site logout attacks.
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
    """Reset password using reset token.

    Enforces organisation password policy if the user belongs to an organisation
    with custom password requirements.
    """
    auth_service = AuthService(db)
    ip_address = get_client_ip(request)

    # First, get the user from the token to check their org's password policy
    # This is done before the HIBP check to ensure org policy takes precedence
    from datetime import datetime, timezone as tz

    token_hash = auth_service.hash_token(body.token)
    user_result = await db.execute(
        select(User).where(
            and_(
                User.password_reset_token == token_hash,
                User.password_reset_expires_at > datetime.now(tz.utc),
            )
        )
    )
    user = user_result.scalar_one_or_none()

    if not user:
        # Don't reveal if token was invalid vs expired - let auth_service handle it
        pass
    else:
        # Get user's primary organisation security settings for password policy
        orgs = await auth_service.get_user_organizations(user.id)
        if orgs:
            security_result = await db.execute(
                select(OrganizationSecuritySettings).where(
                    OrganizationSecuritySettings.organization_id == orgs[0].id
                )
            )
            org_security = security_result.scalar_one_or_none()

            # Validate password against organisation policy
            policy_error = validate_password_policy(body.password, org_security)
            if policy_error:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=policy_error,
                )

    # Check if password has been exposed in data breaches (HIBP)
    if settings.hibp_password_check_enabled:
        breach_message = await check_password_breached(body.password)
        if breach_message:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=breach_message,
            )

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
    """Change current user's password.

    Enforces organisation password policy if configured.
    """
    auth_service = AuthService(db)

    # Verify current password
    if not auth_service.verify_password(
        body.current_password, current_user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Get user's primary organisation security settings for password policy
    orgs = await auth_service.get_user_organizations(current_user.id)
    org_security = None
    if orgs:
        result = await db.execute(
            select(OrganizationSecuritySettings).where(
                OrganizationSecuritySettings.organization_id == orgs[0].id
            )
        )
        org_security = result.scalar_one_or_none()

    # Validate password against organisation policy
    policy_error = validate_password_policy(body.new_password, org_security)
    if policy_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=policy_error,
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
