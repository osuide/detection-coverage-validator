"""Authentication API endpoints."""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.models.user import User, Organization, OrganizationMember, UserRole, MembershipStatus
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    MFAVerifyRequest,
    RefreshRequest,
    RefreshResponse,
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

logger = structlog.get_logger()
settings = get_settings()
router = APIRouter()
security = HTTPBearer(auto_error=False)


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


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
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
        mfa_token = auth_service.generate_access_token(
            user.id, expires_minutes=5
        )
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

    # Create session
    access_token, refresh_token = await auth_service.create_session(
        user=user,
        organization_id=org.id if org else None,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserResponse.model_validate(user),
        organization=OrganizationResponse.model_validate(org) if org else None,
        requires_mfa=False,
    )


@router.post("/login/mfa", response_model=LoginResponse)
async def verify_mfa(
    request: Request,
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

    # Check if it's a backup code
    if user.mfa_backup_codes and body.code in user.mfa_backup_codes:
        # Remove used backup code
        user.mfa_backup_codes.remove(body.code)
    elif not auth_service.verify_mfa_code(user.mfa_secret, body.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )

    # Get user's organizations
    organizations = await auth_service.get_user_organizations(user.id)
    org = organizations[0] if organizations else None

    # Create session
    access_token, refresh_token = await auth_service.create_session(
        user=user,
        organization_id=org.id if org else None,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserResponse.model_validate(user),
        organization=OrganizationResponse.model_validate(org) if org else None,
        requires_mfa=False,
    )


@router.post("/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    request: Request,
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

    # Generate slug from organization name
    slug = re.sub(r'[^a-z0-9-]', '-', body.organization_name.lower())
    slug = re.sub(r'-+', '-', slug).strip('-')

    # Check if slug is available
    if not await auth_service.check_slug_available(slug):
        # Append random suffix
        import secrets
        slug = f"{slug}-{secrets.token_hex(3)}"

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

    return SignupResponse(
        user=UserResponse.model_validate(user),
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


@router.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT)
async def forgot_password(
    body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Request password reset.

    Always returns 204 to prevent email enumeration.
    """
    auth_service = AuthService(db)
    token = await auth_service.initiate_password_reset(body.email)

    if token:
        # TODO: Send email with reset link
        # In development, log the token
        logger.info("Password reset token generated", email=body.email, token=token)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(
    request: Request,
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """Reset password using reset token."""
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
    current_user: User = Depends(get_current_user),
):
    """Get current user profile."""
    return UserResponse.model_validate(current_user)


@router.patch("/me", response_model=UserResponse)
async def update_me(
    body: UserUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update current user profile."""
    if body.full_name is not None:
        current_user.full_name = body.full_name
    if body.timezone is not None:
        current_user.timezone = body.timezone
    if body.avatar_url is not None:
        current_user.avatar_url = body.avatar_url

    return UserResponse.model_validate(current_user)


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
    if not auth_service.verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
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

    # Generate backup codes
    backup_codes = auth_service.generate_backup_codes()

    # Enable MFA
    current_user.mfa_enabled = True
    current_user.mfa_backup_codes = backup_codes

    return MFABackupCodesResponse(backup_codes=backup_codes)


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
        select(UserSession).where(
            and_(
                UserSession.user_id == current_user.id,
                UserSession.is_active == True,
            )
        ).order_by(UserSession.last_activity_at.desc())
    )
    sessions = result.scalars().all()

    # Decode current token to identify current session
    auth_service = AuthService(db)
    current_payload = auth_service.decode_token(credentials.credentials)

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


@router.post("/organizations", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
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
