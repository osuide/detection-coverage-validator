"""User WebAuthn/FIDO2 routes for passkeys and hardware security keys.

These endpoints allow regular users (including SSO users) to register
and manage WebAuthn credentials for MFA.
"""

import json
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context
from app.models.user import User
from app.services.webauthn_service import (
    get_webauthn_service,
    store_challenge,
    get_challenge,
)

router = APIRouter(prefix="/me/webauthn", tags=["User WebAuthn"])


# Request/Response schemas
class WebAuthnRegistrationOptionsRequest(BaseModel):
    """Request to start credential registration."""

    device_name: str = "Security Key"
    authenticator_type: Optional[str] = None  # 'platform', 'cross-platform', or None


class WebAuthnRegistrationOptionsResponse(BaseModel):
    """Registration options for the browser."""

    options: dict  # PublicKeyCredentialCreationOptions JSON


class WebAuthnRegistrationVerifyRequest(BaseModel):
    """Credential registration response from the browser."""

    credential: dict  # RegistrationCredential JSON
    device_name: str = "Security Key"


class WebAuthnCredentialResponse(BaseModel):
    """Stored credential info."""

    credential_id: str
    device_name: str
    created_at: str
    last_used_at: Optional[str]


class WebAuthnCredentialsListResponse(BaseModel):
    """List of registered credentials."""

    credentials: list[WebAuthnCredentialResponse]
    has_totp: bool  # Whether user also has TOTP enabled


class WebAuthnDeleteRequest(BaseModel):
    """Request to delete a credential."""

    credential_id: str


@router.post("/register/options", response_model=WebAuthnRegistrationOptionsResponse)
async def get_registration_options(
    body: WebAuthnRegistrationOptionsRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> WebAuthnRegistrationOptionsResponse:
    """Start WebAuthn credential registration.

    Returns PublicKeyCredentialCreationOptions to pass to navigator.credentials.create()

    Works for both password-based and SSO users.
    """
    if not auth.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    user = auth.user
    webauthn = get_webauthn_service()

    # Get existing credentials
    existing_credentials = user.webauthn_credentials or []

    # Generate registration options
    options_json, challenge = webauthn.generate_registration_options_for_user(
        user_id=user.id,
        user_email=user.email,
        user_name=user.full_name or user.email,
        existing_credentials=existing_credentials,
        authenticator_type=body.authenticator_type,
    )

    # Store challenge for verification
    store_challenge(f"user_webauthn_reg_{user.id}", challenge)

    return WebAuthnRegistrationOptionsResponse(options=options_json)


@router.post("/register/verify")
async def verify_registration(
    body: WebAuthnRegistrationVerifyRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Complete WebAuthn credential registration.

    Verifies the credential and stores it for future authentication.
    Automatically enables MFA if not already enabled.
    """
    if not auth.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    user = auth.user
    webauthn = get_webauthn_service()

    # Get stored challenge
    challenge = get_challenge(f"user_webauthn_reg_{user.id}")
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration session expired. Please try again.",
        )

    try:
        # Verify the registration
        credential = webauthn.verify_registration(
            credential_json=json.dumps(body.credential),
            expected_challenge=challenge,
            device_name=body.device_name,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration verification failed: {str(e)}",
        )

    # Add to user's credentials
    credentials = user.webauthn_credentials or []
    credentials.append(credential.to_dict())
    user.webauthn_credentials = credentials

    # Enable MFA if not already enabled
    if not user.mfa_enabled:
        user.mfa_enabled = True

    await db.commit()

    return {
        "message": "Security key registered successfully",
        "device_name": body.device_name,
        "mfa_enabled": True,
    }


@router.get("/credentials", response_model=WebAuthnCredentialsListResponse)
async def list_credentials(
    auth: AuthContext = Depends(get_auth_context),
) -> WebAuthnCredentialsListResponse:
    """List registered WebAuthn credentials."""
    if not auth.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    user = auth.user
    credentials = user.webauthn_credentials or []

    return WebAuthnCredentialsListResponse(
        credentials=[
            WebAuthnCredentialResponse(
                credential_id=cred["credential_id"],
                device_name=cred.get("device_name", "Security Key"),
                created_at=cred.get("created_at", ""),
                last_used_at=cred.get("last_used_at"),
            )
            for cred in credentials
        ],
        has_totp=bool(user.mfa_secret),
    )


@router.post("/credentials/delete")
async def delete_credential(
    body: WebAuthnDeleteRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a registered WebAuthn credential."""
    if not auth.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    user = auth.user
    credentials = user.webauthn_credentials or []

    # Find and remove the credential
    new_credentials = [
        c for c in credentials if c["credential_id"] != body.credential_id
    ]

    if len(new_credentials) == len(credentials):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found",
        )

    # Check if user would have no MFA methods left
    has_totp = bool(user.mfa_secret)
    if not new_credentials and not has_totp:
        # Disable MFA since no methods remain
        user.mfa_enabled = False

    user.webauthn_credentials = new_credentials
    await db.commit()

    return {
        "message": "Security key removed successfully",
        "mfa_enabled": user.mfa_enabled,
    }


# ============================================================================
# WebAuthn Authentication Endpoints (for login flow)
# ============================================================================


class WebAuthnLoginOptionsRequest(BaseModel):
    """Request WebAuthn authentication options."""

    email: str


class WebAuthnLoginOptionsResponse(BaseModel):
    """WebAuthn authentication options for the browser."""

    options: dict
    auth_token: str  # Temporary token for verification step


class WebAuthnLoginVerifyRequest(BaseModel):
    """WebAuthn authentication verification request."""

    auth_token: str
    credential: dict


@router.post(
    "/login/options",
    response_model=WebAuthnLoginOptionsResponse,
    tags=["Authentication"],
)
async def get_webauthn_login_options(
    body: WebAuthnLoginOptionsRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get WebAuthn authentication options for a user.

    This starts the WebAuthn login flow. The user provides their email,
    and we return a challenge for their security key.
    """
    from app.core.security import create_access_token
    from datetime import timedelta

    # Get user by email
    result = await db.execute(select(User).where(User.email == body.email.lower()))
    user = result.scalar_one_or_none()

    if not user:
        # Don't reveal if user exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Check if user has WebAuthn credentials
    credentials = user.webauthn_credentials or []
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No security keys registered. Please use password login.",
        )

    # Check if account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
        )

    # Generate authentication options
    webauthn = get_webauthn_service()
    options_json, challenge = webauthn.generate_authentication_options_for_user(
        credentials=credentials
    )

    # Store challenge with user ID
    store_challenge(f"user_webauthn_auth_{user.id}", challenge)

    # Create temporary auth token
    auth_token = create_access_token(
        data={"sub": str(user.id), "type": "webauthn_pending"},
        expires_delta=timedelta(minutes=5),
    )

    return WebAuthnLoginOptionsResponse(
        options=options_json,
        auth_token=auth_token,
    )


@router.post("/login/verify", tags=["Authentication"])
async def verify_webauthn_login(
    body: WebAuthnLoginVerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Complete WebAuthn authentication and login.

    Verifies the security key response and returns access/refresh tokens.
    """
    from app.core.security import decode_token, get_client_ip
    from app.services.auth_service import AuthService
    from app.api.routes.auth import (
        generate_csrf_token,
        set_auth_cookies,
    )
    from app.schemas.auth import LoginResponse, UserResponse, OrganizationResponse
    from app.core.config import get_settings

    settings = get_settings()

    # Validate auth token
    try:
        payload = decode_token(body.auth_token)
        if payload.get("type") != "webauthn_pending":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
            )
        user_id = UUID(payload["sub"])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
        )

    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    # Get stored challenge
    challenge = get_challenge(f"user_webauthn_auth_{user.id}")
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
            stored_credentials=user.webauthn_credentials or [],
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}",
        )

    # Update credential sign count and last used
    credentials = user.webauthn_credentials or []
    for cred in credentials:
        if cred["credential_id"] == credential_id:
            cred["sign_count"] = new_sign_count
            cred["last_used_at"] = datetime.now(timezone.utc).isoformat()
            break
    user.webauthn_credentials = credentials
    await db.commit()

    # Create session
    auth_service = AuthService(db)
    ip_address = get_client_ip(request) or "unknown"
    user_agent = request.headers.get("User-Agent")

    # Get user's organizations
    organizations = await auth_service.get_user_organizations(user.id)
    org = organizations[0] if organizations else None

    # Get user's role in the organization
    user_role = None
    if org:
        membership = await auth_service.get_user_membership(user.id, org.id)
        if membership:
            user_role = membership.role.value

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
