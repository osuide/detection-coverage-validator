"""Admin WebAuthn/FIDO2 routes for passkeys and hardware security keys."""

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.admin import AdminUser
from app.api.deps import get_current_admin
from app.services.webauthn_service import (
    get_webauthn_service,
    store_challenge,
    get_challenge,
)

router = APIRouter(prefix="/webauthn", tags=["Admin WebAuthn"])


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


class WebAuthnDeleteRequest(BaseModel):
    """Request to delete a credential."""

    credential_id: str


@router.post("/register/options", response_model=WebAuthnRegistrationOptionsResponse)
async def get_registration_options(
    body: WebAuthnRegistrationOptionsRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> WebAuthnRegistrationOptionsResponse:
    """Start WebAuthn credential registration.

    Returns PublicKeyCredentialCreationOptions to pass to navigator.credentials.create()
    """
    webauthn = get_webauthn_service()

    # Get existing credentials
    existing_credentials = admin.webauthn_credentials or []

    # Generate registration options
    options_json, challenge = webauthn.generate_registration_options_for_user(
        user_id=admin.id,
        user_email=admin.email,
        user_name=admin.full_name or admin.email,
        existing_credentials=existing_credentials,
        authenticator_type=body.authenticator_type,
    )

    # Store challenge for verification
    store_challenge(f"admin_webauthn_reg_{admin.id}", challenge)

    return WebAuthnRegistrationOptionsResponse(options=options_json)


@router.post("/register/verify")
async def verify_registration(
    body: WebAuthnRegistrationVerifyRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Complete WebAuthn credential registration.

    Verifies the credential and stores it for future authentication.
    """
    webauthn = get_webauthn_service()

    # Get stored challenge
    challenge = get_challenge(f"admin_webauthn_reg_{admin.id}")
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

    # Add to admin's credentials
    credentials = admin.webauthn_credentials or []
    credentials.append(credential.to_dict())
    admin.webauthn_credentials = credentials

    # Enable MFA if not already enabled
    if not admin.mfa_enabled:
        admin.mfa_enabled = True

    await db.commit()

    return {
        "message": "Security key registered successfully",
        "device_name": body.device_name,
    }


@router.get("/credentials", response_model=WebAuthnCredentialsListResponse)
async def list_credentials(
    admin: AdminUser = Depends(get_current_admin),
) -> WebAuthnCredentialsListResponse:
    """List registered WebAuthn credentials."""
    credentials = admin.webauthn_credentials or []

    return WebAuthnCredentialsListResponse(
        credentials=[
            WebAuthnCredentialResponse(
                credential_id=cred["credential_id"],
                device_name=cred.get("device_name", "Security Key"),
                created_at=cred.get("created_at", ""),
                last_used_at=cred.get("last_used_at"),
            )
            for cred in credentials
        ]
    )


@router.post("/credentials/delete")
async def delete_credential(
    body: WebAuthnDeleteRequest,
    admin: AdminUser = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a registered WebAuthn credential."""
    credentials = admin.webauthn_credentials or []

    # Find and remove the credential
    new_credentials = [
        c for c in credentials if c["credential_id"] != body.credential_id
    ]

    if len(new_credentials) == len(credentials):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found",
        )

    # Don't allow removing last credential if MFA is required
    if not new_credentials and not admin.mfa_secret_encrypted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove last security key. Set up TOTP first or keep at least one key.",
        )

    admin.webauthn_credentials = new_credentials
    await db.commit()

    return {"message": "Security key removed successfully"}
