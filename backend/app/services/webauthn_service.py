"""WebAuthn/FIDO2 service for passkeys and hardware security keys.

Supports:
- Hardware keys (YubiKey, SoloKey, etc.)
- Platform authenticators (Touch ID, Face ID, Windows Hello)
- Passkeys (cross-device sync via iCloud, Google Password Manager, etc.)

References:
- py_webauthn: https://github.com/duo-labs/py_webauthn
- WebAuthn spec: https://www.w3.org/TR/webauthn-2/
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import structlog
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    AuthenticationCredential,
)

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class WebAuthnCredential:
    """Stored WebAuthn credential data."""

    def __init__(
        self,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        device_name: str = "Security Key",
        created_at: Optional[datetime] = None,
        last_used_at: Optional[datetime] = None,
        transports: Optional[list[str]] = None,
    ):
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count
        self.device_name = device_name
        self.created_at = created_at or datetime.now(timezone.utc)
        self.last_used_at = last_used_at
        self.transports = transports or []

    def to_dict(self) -> dict:
        """Serialise to dict for JSONB storage."""
        return {
            "credential_id": bytes_to_base64url(self.credential_id),
            "public_key": bytes_to_base64url(self.public_key),
            "sign_count": self.sign_count,
            "device_name": self.device_name,
            "created_at": self.created_at.isoformat(),
            "last_used_at": (
                self.last_used_at.isoformat() if self.last_used_at else None
            ),
            "transports": self.transports,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WebAuthnCredential":
        """Deserialise from dict."""
        return cls(
            credential_id=base64url_to_bytes(data["credential_id"]),
            public_key=base64url_to_bytes(data["public_key"]),
            sign_count=data["sign_count"],
            device_name=data.get("device_name", "Security Key"),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else None
            ),
            last_used_at=(
                datetime.fromisoformat(data["last_used_at"])
                if data.get("last_used_at")
                else None
            ),
            transports=data.get("transports", []),
        )


class WebAuthnService:
    """WebAuthn registration and authentication service."""

    def __init__(self, rp_id: Optional[str] = None, rp_name: Optional[str] = None):
        """Initialise WebAuthn service.

        Args:
            rp_id: Relying Party ID (domain name, e.g., 'a13e.com')
                   If not provided, uses WEBAUTHN_RP_ID from settings or localhost.
            rp_name: Relying Party name (displayed to user)
        """
        # RP ID should be the domain (without port or protocol)
        self.rp_id = rp_id or settings.webauthn_rp_id
        self.rp_name = rp_name or settings.webauthn_rp_name

        # Origin must match the RP ID
        # In production: https://staging.a13e.com or https://a13e.com
        # In development: http://localhost:3001
        if self.rp_id == "localhost":
            self.expected_origin = "http://localhost:3001"
        else:
            self.expected_origin = f"https://{self.rp_id}"

        self.logger = logger.bind(service="WebAuthnService", rp_id=self.rp_id)

    def generate_registration_options_for_user(
        self,
        user_id: UUID,
        user_email: str,
        user_name: str,
        existing_credentials: list[dict],
        authenticator_type: Optional[str] = None,
    ) -> tuple[dict, bytes]:
        """Generate registration options for a new credential.

        Args:
            user_id: User's UUID
            user_email: User's email (used as user handle)
            user_name: User's display name
            existing_credentials: List of existing credential dicts
            authenticator_type: Optional - 'platform' for Touch ID/Windows Hello,
                               'cross-platform' for hardware keys, None for any

        Returns:
            tuple of (options_json, challenge_bytes)
        """
        # Convert existing credentials to exclude list
        exclude_credentials = [
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(cred["credential_id"]),
                transports=cred.get("transports"),
            )
            for cred in existing_credentials
        ]

        # Set authenticator selection based on type
        authenticator_selection = AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        if authenticator_type == "platform":
            authenticator_selection = AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            )
        elif authenticator_type == "cross-platform":
            authenticator_selection = AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                resident_key=ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.PREFERRED,
            )

        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=str(user_id).encode(),
            user_name=user_email,
            user_display_name=user_name,
            exclude_credentials=exclude_credentials if exclude_credentials else None,
            authenticator_selection=authenticator_selection,
            timeout=60000,  # 60 seconds
        )

        self.logger.info(
            "webauthn_registration_options_generated",
            user_id=str(user_id),
            exclude_count=len(exclude_credentials),
        )

        return options_to_json(options), options.challenge

    def verify_registration(
        self,
        credential_json: dict,
        expected_challenge: bytes,
        device_name: str = "Security Key",
    ) -> WebAuthnCredential:
        """Verify registration response and return credential to store.

        Args:
            credential_json: The credential response from the browser
            expected_challenge: The challenge that was sent to the browser
            device_name: User-friendly name for this credential

        Returns:
            WebAuthnCredential to store

        Raises:
            Exception if verification fails
        """
        # Parse the credential response
        credential = RegistrationCredential.parse_raw(
            credential_json
            if isinstance(credential_json, str)
            else str(credential_json)
        )

        # Verify the registration
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.expected_origin,
            require_user_verification=False,  # Allow without UV for hardware keys
        )

        self.logger.info(
            "webauthn_registration_verified",
            credential_id=bytes_to_base64url(verification.credential_id)[:20],
            device_name=device_name,
        )

        return WebAuthnCredential(
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            device_name=device_name,
            transports=credential.response.transports or [],
        )

    def generate_authentication_options_for_user(
        self,
        credentials: list[dict],
    ) -> tuple[dict, bytes]:
        """Generate authentication options for existing credentials.

        Args:
            credentials: List of stored credential dicts

        Returns:
            tuple of (options_json, challenge_bytes)
        """
        if not credentials:
            raise ValueError("No credentials registered for this user")

        allow_credentials = [
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(cred["credential_id"]),
                transports=cred.get("transports"),
            )
            for cred in credentials
        ]

        options = generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
            timeout=60000,  # 60 seconds
        )

        self.logger.info(
            "webauthn_auth_options_generated",
            credential_count=len(allow_credentials),
        )

        return options_to_json(options), options.challenge

    def verify_authentication(
        self,
        credential_json: dict,
        expected_challenge: bytes,
        stored_credentials: list[dict],
    ) -> tuple[str, int]:
        """Verify authentication response.

        Args:
            credential_json: The credential response from the browser
            expected_challenge: The challenge that was sent to the browser
            stored_credentials: List of stored credential dicts to match against

        Returns:
            tuple of (credential_id_base64url, new_sign_count)

        Raises:
            Exception if verification fails
        """
        # Parse the credential response
        credential = AuthenticationCredential.parse_raw(
            credential_json
            if isinstance(credential_json, str)
            else str(credential_json)
        )

        # Find the matching stored credential
        credential_id_b64 = bytes_to_base64url(credential.raw_id)
        stored_cred = None
        for cred in stored_credentials:
            if cred["credential_id"] == credential_id_b64:
                stored_cred = cred
                break

        if not stored_cred:
            raise ValueError("Credential not found")

        # Verify the authentication
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.expected_origin,
            credential_public_key=base64url_to_bytes(stored_cred["public_key"]),
            credential_current_sign_count=stored_cred["sign_count"],
            require_user_verification=False,
        )

        self.logger.info(
            "webauthn_auth_verified",
            credential_id=credential_id_b64[:20],
            new_sign_count=verification.new_sign_count,
        )

        return credential_id_b64, verification.new_sign_count


# Challenge storage (in production, use Redis with TTL)
# For now, we store challenges in memory with expiration
_challenge_store: dict[str, tuple[bytes, datetime]] = {}
CHALLENGE_TTL_SECONDS = 120


def store_challenge(key: str, challenge: bytes) -> None:
    """Store a challenge temporarily."""
    _challenge_store[key] = (challenge, datetime.now(timezone.utc))
    # Clean up old challenges
    _cleanup_challenges()


def get_challenge(key: str) -> Optional[bytes]:
    """Get and remove a stored challenge."""
    data = _challenge_store.pop(key, None)
    if not data:
        return None
    challenge, created_at = data
    # Check if expired
    age = (datetime.now(timezone.utc) - created_at).total_seconds()
    if age > CHALLENGE_TTL_SECONDS:
        return None
    return challenge


def _cleanup_challenges() -> None:
    """Remove expired challenges."""
    now = datetime.now(timezone.utc)
    expired = [
        key
        for key, (_, created_at) in _challenge_store.items()
        if (now - created_at).total_seconds() > CHALLENGE_TTL_SECONDS
    ]
    for key in expired:
        _challenge_store.pop(key, None)


def get_webauthn_service(rp_id: Optional[str] = None) -> WebAuthnService:
    """Get WebAuthn service instance."""
    return WebAuthnService(rp_id=rp_id)
