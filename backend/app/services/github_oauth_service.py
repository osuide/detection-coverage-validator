"""GitHub OAuth service for direct authentication (bypassing Cognito)."""

import httpx
import secrets
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlencode
import structlog

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class GitHubOAuthService:
    """Service for direct GitHub OAuth authentication."""

    AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_URL = "https://api.github.com/user"
    EMAILS_URL = "https://api.github.com/user/emails"

    def __init__(self):
        self.client_id = settings.github_client_id
        self.client_secret = settings.github_client_secret

    def is_configured(self) -> bool:
        """Check if GitHub OAuth is configured."""
        return bool(self.client_id and self.client_secret)

    def generate_state(self) -> str:
        """Generate a random state for CSRF protection."""
        return secrets.token_urlsafe(32)

    def build_authorization_url(self, redirect_uri: str, state: str) -> str:
        """Build the GitHub authorization URL."""
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": "read:user user:email",
            "state": state,
        }
        return f"{self.AUTHORIZE_URL}?{urlencode(params)}"

    async def exchange_code_for_token(
        self, code: str, redirect_uri: str
    ) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access token.

        GitHub returns application/x-www-form-urlencoded by default,
        but we request JSON with Accept header.
        """
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    self.TOKEN_URL,
                    data={
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "code": code,
                        "redirect_uri": redirect_uri,
                    },
                    headers={
                        "Accept": "application/json",
                    },
                )

                logger.info(
                    "github_token_exchange",
                    status=response.status_code,
                )

                if response.status_code != 200:
                    logger.error(
                        "github_token_exchange_failed",
                        status=response.status_code,
                        body=response.text[:500],
                    )
                    return None

                data = response.json()

                # Check for error in response
                if "error" in data:
                    logger.error(
                        "github_token_exchange_error",
                        error=data.get("error"),
                        description=data.get("error_description"),
                    )
                    return None

                return data

        except Exception as e:
            logger.error("github_token_exchange_exception", error=str(e))
            return None

    async def get_user_info(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Get user info from GitHub API."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.USER_URL,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github+json",
                    },
                )

                if response.status_code != 200:
                    logger.error(
                        "github_user_info_failed",
                        status=response.status_code,
                    )
                    return None

                return response.json()

        except Exception as e:
            logger.error("github_user_info_exception", error=str(e))
            return None

    async def get_user_emails(self, access_token: str) -> Optional[list]:
        """Get user emails from GitHub API."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.EMAILS_URL,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/vnd.github+json",
                    },
                )

                if response.status_code != 200:
                    logger.error(
                        "github_emails_failed",
                        status=response.status_code,
                    )
                    return None

                return response.json()

        except Exception as e:
            logger.error("github_emails_exception", error=str(e))
            return None

    async def get_primary_email(self, access_token: str) -> Optional[str]:
        """Get the user's primary verified email."""
        emails = await self.get_user_emails(access_token)
        if not emails:
            return None

        # Find primary verified email
        for email in emails:
            if email.get("primary") and email.get("verified"):
                return email.get("email")

        # Fallback to any verified email
        for email in emails:
            if email.get("verified"):
                return email.get("email")

        return None


# Singleton instance
github_oauth_service = GitHubOAuthService()
