"""AWS Cognito service for SSO authentication."""

import httpx
import hashlib
import base64
import secrets
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone
from jose import jwt, jwk, JWTError
import structlog

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


def generate_pkce() -> Tuple[str, str]:
    """Generate PKCE code verifier and challenge.

    Returns:
        Tuple of (code_verifier, code_challenge)
    """
    # Generate a random code verifier (43-128 characters)
    code_verifier = secrets.token_urlsafe(64)[:128]

    # Generate code challenge using S256 method
    code_challenge_bytes = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).rstrip(b'=').decode('ascii')

    return code_verifier, code_challenge


class CognitoService:
    """Service for AWS Cognito authentication."""

    def __init__(self):
        self.region = settings.aws_region or "us-east-1"
        self.user_pool_id = settings.cognito_user_pool_id
        self.client_id = settings.cognito_client_id
        self.domain = settings.cognito_domain
        self._jwks: Optional[Dict] = None
        self._jwks_fetched_at: Optional[datetime] = None

    @property
    def issuer(self) -> str:
        """Get the Cognito issuer URL."""
        return f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"

    @property
    def jwks_url(self) -> str:
        """Get the JWKS URL."""
        return f"{self.issuer}/.well-known/jwks.json"

    @property
    def base_url(self) -> str:
        """Get the Cognito hosted UI base URL."""
        # Handle both full URL and domain-only formats
        if self.domain and self.domain.startswith("https://"):
            return self.domain
        return f"https://{self.domain}.auth.{self.region}.amazoncognito.com"

    @property
    def authorization_url(self) -> str:
        """Get the OAuth authorization URL."""
        return f"{self.base_url}/oauth2/authorize"

    @property
    def token_url(self) -> str:
        """Get the OAuth token URL."""
        return f"{self.base_url}/oauth2/token"

    @property
    def userinfo_url(self) -> str:
        """Get the userinfo URL."""
        return f"{self.base_url}/oauth2/userInfo"

    async def get_jwks(self) -> Dict:
        """Fetch and cache JWKS from Cognito."""
        # Cache JWKS for 1 hour
        if self._jwks and self._jwks_fetched_at:
            age = (datetime.now(timezone.utc) - self._jwks_fetched_at).total_seconds()
            if age < 3600:
                return self._jwks

        async with httpx.AsyncClient() as client:
            response = await client.get(self.jwks_url)
            response.raise_for_status()
            self._jwks = response.json()
            self._jwks_fetched_at = datetime.now(timezone.utc)
            logger.info("jwks_fetched", url=self.jwks_url)
            return self._jwks

    def _get_signing_key(self, token: str, jwks: Dict) -> Optional[str]:
        """Get the signing key for a token from JWKS."""
        try:
            headers = jwt.get_unverified_headers(token)
            kid = headers.get("kid")

            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    return jwk.construct(key)
            return None
        except Exception as e:
            logger.error("get_signing_key_failed", error=str(e))
            return None

    async def verify_token(
        self, token: str, access_token: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Verify a Cognito JWT token and return claims.

        Args:
            token: The ID token to verify
            access_token: Optional access token for at_hash validation
        """
        try:
            jwks = await self.get_jwks()
            signing_key = self._get_signing_key(token, jwks)

            if not signing_key:
                logger.warning("signing_key_not_found")
                return None

            # Verify the token - pass access_token for at_hash validation
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.issuer,
                access_token=access_token,
            )

            # Check token expiration
            exp = claims.get("exp")
            if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
                logger.warning("token_expired")
                return None

            return claims

        except JWTError as e:
            logger.warning("jwt_verification_failed", error=str(e))
            return None
        except Exception as e:
            logger.error("token_verification_error", error=str(e))
            return None

    async def exchange_code_for_tokens(
        self,
        code: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for tokens with PKCE."""
        try:
            data = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "redirect_uri": redirect_uri,
            }

            # Include code_verifier for PKCE
            if code_verifier:
                data["code_verifier"] = code_verifier

            logger.info("token_exchange_starting", token_url=self.token_url, redirect_uri=redirect_uri, client_id=self.client_id)

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    self.token_url,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                logger.info("token_exchange_response", status=response.status_code)

                if response.status_code != 200:
                    logger.error("token_exchange_failed", status=response.status_code, body=response.text)
                    return None

                try:
                    return response.json()
                except Exception as json_error:
                    logger.error("token_exchange_json_parse_error", error=str(json_error), body=response.text[:500])
                    return None

        except httpx.HTTPStatusError as e:
            logger.error("token_exchange_http_error", error=str(e), status_code=e.response.status_code if e.response else None)
            return None
        except httpx.RequestError as e:
            logger.error("token_exchange_request_error", error=str(e), error_type=type(e).__name__)
            return None
        except Exception as e:
            logger.error("token_exchange_error", error=str(e), error_type=type(e).__name__, token_url=self.token_url)
            return None

    async def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user info from Cognito."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.userinfo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )

                if response.status_code != 200:
                    logger.error("userinfo_failed", status=response.status_code)
                    return None

                return response.json()

        except Exception as e:
            logger.error("userinfo_error", error=str(e))
            return None

    def build_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: str,
        identity_provider: Optional[str] = None,
    ) -> str:
        """Build the Cognito authorization URL with PKCE."""
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        if identity_provider:
            params["identity_provider"] = identity_provider

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{self.authorization_url}?{query}"

    def is_configured(self) -> bool:
        """Check if Cognito is configured."""
        return bool(self.user_pool_id and self.client_id)


# Singleton instance
cognito_service = CognitoService()
