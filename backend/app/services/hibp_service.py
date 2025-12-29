"""HaveIBeenPwned password checking service.

This service checks passwords against the HaveIBeenPwned database of breached
passwords using their k-anonymity API. This is privacy-preserving because:

1. The password is hashed with SHA-1 locally
2. Only the first 5 characters of the hash are sent to the API
3. The API returns all hash suffixes that match
4. We check locally if the full hash exists in the results

This means the full password or hash is never transmitted to HIBP.

API Documentation: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

import hashlib
from typing import Optional, Tuple

import httpx
import structlog

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class HIBPService:
    """Service for checking passwords against HaveIBeenPwned database."""

    PWNED_PASSWORDS_API = "https://api.pwnedpasswords.com/range/"

    # User-Agent as requested by HIBP API guidelines
    USER_AGENT = "A13E-Detection-Coverage-Validator"

    # Timeout for API requests
    TIMEOUT = 5.0

    def __init__(self) -> None:
        self._enabled = getattr(settings, "hibp_password_check_enabled", True)
        # Fail-closed mode: reject passwords when API is unavailable (more secure)
        self._fail_closed = getattr(settings, "hibp_fail_closed", False)

    def is_enabled(self) -> bool:
        """Check if HIBP password checking is enabled."""
        return self._enabled

    def _hash_password(self, password: str) -> str:
        """Hash password with SHA-1 (as required by HIBP API).

        Note: SHA-1 is used here only because HIBP requires it for their
        k-anonymity API. The actual password storage uses bcrypt.
        We use usedforsecurity=False because this is not for cryptographic
        security but for API compatibility with HaveIBeenPwned.
        """
        return (
            hashlib.sha1(password.encode("utf-8"), usedforsecurity=False)
            .hexdigest()
            .upper()
        )

    async def check_password(self, password: str) -> Tuple[bool, int]:
        """Check if a password has been exposed in data breaches.

        Uses the k-anonymity model to preserve privacy:
        - Only the first 5 characters of the SHA-1 hash are sent
        - The API returns all matching suffixes
        - We check locally for the full hash

        Args:
            password: The password to check

        Returns:
            Tuple of (is_breached, breach_count):
            - is_breached: True if password found in breaches
            - breach_count: Number of times seen in breaches (0 if not found)
        """
        if not self._enabled:
            logger.debug("hibp_check_disabled")
            return False, 0

        try:
            # Hash the password
            sha1_hash = self._hash_password(password)

            # Split into prefix (sent to API) and suffix (checked locally)
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            # Query the HIBP API
            async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
                response = await client.get(
                    f"{self.PWNED_PASSWORDS_API}{prefix}",
                    headers={
                        "User-Agent": self.USER_AGENT,
                        "Add-Padding": "true",  # Adds padding to prevent timing attacks
                    },
                )

                if response.status_code != 200:
                    logger.warning(
                        "hibp_api_error",
                        status_code=response.status_code,
                        fail_closed=self._fail_closed,
                    )
                    # Fail-closed: treat as breached when API fails (more secure)
                    # Fail-open: allow password when API fails (more available)
                    return self._fail_closed, -1 if self._fail_closed else 0

                # Parse response - each line is "SUFFIX:COUNT"
                for line in response.text.splitlines():
                    if ":" not in line:
                        continue

                    hash_suffix, count_str = line.split(":")

                    if hash_suffix.upper() == suffix:
                        breach_count = int(count_str)
                        logger.info(
                            "hibp_password_breached",
                            breach_count=breach_count,
                        )
                        return True, breach_count

                # Password not found in breaches
                return False, 0

        except httpx.TimeoutException:
            logger.warning("hibp_api_timeout", fail_closed=self._fail_closed)
            # Fail-closed: treat as breached on timeout (more secure)
            # Fail-open: allow password on timeout (more available)
            return self._fail_closed, -1 if self._fail_closed else 0
        except Exception as e:
            logger.error(
                "hibp_api_exception", error=str(e), fail_closed=self._fail_closed
            )
            # Fail-closed: treat as breached on error (more secure)
            # Fail-open: allow password on error (more available)
            return self._fail_closed, -1 if self._fail_closed else 0

    async def check_password_with_message(
        self, password: str, min_breach_count: int = 1
    ) -> Optional[str]:
        """Check password and return a user-friendly message if breached.

        Args:
            password: The password to check
            min_breach_count: Minimum breach count to consider as breached

        Returns:
            Error message if password is breached, None if safe
        """
        is_breached, breach_count = await self.check_password(password)

        if is_breached and breach_count >= min_breach_count:
            if breach_count > 1000000:
                return (
                    "This password has been exposed in over 1 million data breaches. "
                    "Please choose a different password."
                )
            elif breach_count > 100000:
                return (
                    "This password has been exposed in over 100,000 data breaches. "
                    "Please choose a different password."
                )
            elif breach_count > 10000:
                return (
                    "This password has been exposed in over 10,000 data breaches. "
                    "Please choose a different password."
                )
            elif breach_count > 1000:
                return (
                    "This password has been exposed in over 1,000 data breaches. "
                    "Please choose a different password."
                )
            else:
                return (
                    "This password has been exposed in data breaches. "
                    "Please choose a different password."
                )

        return None


# Singleton instance
hibp_service = HIBPService()


async def check_password_breached(password: str) -> Optional[str]:
    """Convenience function to check if a password is breached.

    Returns:
        Error message if breached, None if safe
    """
    return await hibp_service.check_password_with_message(password)
