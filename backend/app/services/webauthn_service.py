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
)
from webauthn.helpers.options_to_json_dict import options_to_json_dict
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorTransport,
)

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


def _str_to_transport(transport_str: str) -> AuthenticatorTransport | None:
    """Convert a transport string to AuthenticatorTransport enum.

    Args:
        transport_str: Transport string like 'usb', 'nfc', 'ble', etc.

    Returns:
        AuthenticatorTransport enum or None if not recognised
    """
    transport_map = {
        "usb": AuthenticatorTransport.USB,
        "nfc": AuthenticatorTransport.NFC,
        "ble": AuthenticatorTransport.BLE,
        "smart-card": AuthenticatorTransport.SMART_CARD,
        "internal": AuthenticatorTransport.INTERNAL,
        "cable": AuthenticatorTransport.CABLE,
        "hybrid": AuthenticatorTransport.HYBRID,
    }
    return transport_map.get(transport_str.lower())


def _parse_transports(
    transports: list[str] | None,
) -> list[AuthenticatorTransport] | None:
    """Parse a list of transport strings to AuthenticatorTransport enums.

    Args:
        transports: List of transport strings or None

    Returns:
        List of AuthenticatorTransport enums or None
    """
    if not transports:
        return None
    result = []
    for t in transports:
        parsed = _str_to_transport(t)
        if parsed:
            result.append(parsed)
    return result if result else None


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
                transports=_parse_transports(cred.get("transports")),
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

        return options_to_json_dict(options), options.challenge

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
                transports=_parse_transports(cred.get("transports")),
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

        return options_to_json_dict(options), options.challenge

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


# =============================================================================
# Challenge Storage (Redis-backed with in-memory fallback)
# =============================================================================
# CWE-384: Session Fixation prevention - challenges are single-use and time-limited.
# Production: Uses Redis for distributed challenge storage across ECS tasks.
# Development: Falls back to in-memory if Redis unavailable.

CHALLENGE_TTL_SECONDS = 120

# In-memory fallback for development (when Redis unavailable)
_challenge_store: dict[str, tuple[bytes, datetime]] = {}


async def store_challenge_async(key: str, challenge: bytes) -> bool:
    """Store a challenge in Redis (with in-memory fallback).

    Args:
        key: Unique key for this challenge (e.g., "user_webauthn_reg_{user_id}")
        challenge: The challenge bytes to store

    Returns:
        True if stored successfully

    Security:
        - Uses Redis for distributed storage across multiple ECS tasks
        - Falls back to in-memory for development environments
        - 2-minute TTL limits replay window
    """
    from app.core.cache import store_webauthn_challenge, is_redis_available

    if is_redis_available():
        stored = await store_webauthn_challenge(key, challenge)
        if stored:
            return True
        # Fall through to in-memory if Redis store failed

    # In-memory fallback (development or Redis failure)
    _challenge_store[key] = (challenge, datetime.now(timezone.utc))
    _cleanup_challenges()
    logger.debug("webauthn_challenge_stored_inmemory", key=key[:30])
    return True


async def get_challenge_async(key: str) -> Optional[bytes]:
    """Get and consume a stored challenge (single-use).

    Args:
        key: The challenge key used during storage

    Returns:
        Challenge bytes if found and valid, None otherwise

    Security:
        - Atomic get-and-delete prevents replay attacks
        - Expired challenges automatically rejected
        - Single-use enforcement
    """
    from app.core.cache import get_and_consume_webauthn_challenge, is_redis_available

    if is_redis_available():
        challenge = await get_and_consume_webauthn_challenge(key)
        if challenge is not None:
            return challenge
        # Don't fall through - if Redis is available but challenge not found,
        # it means the challenge expired or was already used

    # In-memory fallback (only if Redis unavailable)
    if not is_redis_available():
        data = _challenge_store.pop(key, None)
        if not data:
            return None
        challenge, created_at = data
        age = (datetime.now(timezone.utc) - created_at).total_seconds()
        if age > CHALLENGE_TTL_SECONDS:
            logger.warning("webauthn_challenge_expired_inmemory", key=key[:30])
            return None
        logger.debug("webauthn_challenge_consumed_inmemory", key=key[:30])
        return challenge

    return None


def _cleanup_challenges() -> None:
    """Remove expired challenges from in-memory store."""
    now = datetime.now(timezone.utc)
    expired = [
        key
        for key, (_, created_at) in _challenge_store.items()
        if (now - created_at).total_seconds() > CHALLENGE_TTL_SECONDS
    ]
    for key in expired:
        _challenge_store.pop(key, None)


# Legacy sync wrappers - DEPRECATED, use async versions
# Kept for backwards compatibility during migration
def store_challenge(key: str, challenge: bytes) -> None:
    """DEPRECATED: Use store_challenge_async instead."""
    _challenge_store[key] = (challenge, datetime.now(timezone.utc))
    _cleanup_challenges()


def get_challenge(key: str) -> Optional[bytes]:
    """DEPRECATED: Use get_challenge_async instead."""
    data = _challenge_store.pop(key, None)
    if not data:
        return None
    challenge, created_at = data
    age = (datetime.now(timezone.utc) - created_at).total_seconds()
    if age > CHALLENGE_TTL_SECONDS:
        return None
    return challenge


def get_webauthn_service(rp_id: Optional[str] = None) -> WebAuthnService:
    """Get WebAuthn service instance."""
    return WebAuthnService(rp_id=rp_id)
