"""GCP Workload Identity Federation Service - AWS to GCP authentication.

This service implements secure, keyless authentication from A13E (running on AWS ECS)
to customer GCP projects using Workload Identity Federation (WIF).

Security Architecture:
1. A13E ECS task assumes AWS IAM role
2. AWS IAM role issues OIDC token with unique subject
3. Token exchanged at GCP STS for federated credential
4. Federated credential impersonates customer's service account
5. Short-lived (1h) GCP credentials returned - NEVER stored

Why WIF is Essential:
- A13E is a security tool that should detect credential mismanagement
- Using JSON service account keys would contradict our security mission
- WIF provides zero-trust, keyless authentication
- All credentials are short-lived and auto-rotating

MITRE ATT&CK Relevance:
- T1528: Steal Application Access Token - WIF prevents token theft (no stored tokens)
- T1078.004: Cloud Accounts - Federated identities reduce attack surface
- T1552: Unsecured Credentials - No credentials to be unsecured

Token Exchange Flow:
1. Get AWS OIDC token from ECS task metadata
2. Exchange at GCP STS endpoint for federated token
3. Use federated token to impersonate customer's service account
4. Return impersonated credentials to scanners

Customer Setup Requirements:
1. Create WIF Pool: projects/{project}/locations/global/workloadIdentityPools/a13e-pool
2. Create AWS Provider: .../providers/aws
3. Create Service Account: a13e-scanner@{project}.iam.gserviceaccount.com
4. Grant impersonation: serviceAccountTokenCreator to WIF identity
5. Grant scanner permissions: Custom role with read-only security access
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from typing import Any, Optional

import httpx
import structlog

# Google Cloud SDK imports
from google.auth import credentials as ga_credentials
from google.auth import impersonated_credentials

logger = structlog.get_logger()

# Thread pool for synchronous GCP SDK calls
_gcp_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="gcp-wif-")

# Token refresh buffer - refresh 5 minutes before expiry
TOKEN_REFRESH_BUFFER_SECONDS = 300

# Default token lifetime (1 hour - GCP maximum for impersonated credentials)
DEFAULT_TOKEN_LIFETIME_SECONDS = 3600


@dataclass
class WIFConfiguration:
    """Configuration for GCP Workload Identity Federation.

    This is stored per-customer in the database (gcp_workload_identity_config column).
    No secrets - all values are public identifiers.
    """

    # GCP project where the WIF pool lives (usually customer's project)
    project_id: str

    # WIF pool location (always 'global' for AWS federation)
    pool_location: str = "global"

    # WIF pool ID created by customer
    pool_id: str = "a13e-pool"

    # AWS provider ID within the pool
    provider_id: str = "aws"

    # Service account email to impersonate
    service_account_email: str = ""

    @property
    def pool_resource_name(self) -> str:
        """Full resource name of the WIF pool."""
        return (
            f"projects/{self.project_id}/locations/{self.pool_location}"
            f"/workloadIdentityPools/{self.pool_id}"
        )

    @property
    def provider_resource_name(self) -> str:
        """Full resource name of the AWS provider."""
        return f"{self.pool_resource_name}/providers/{self.provider_id}"

    @property
    def audience(self) -> str:
        """Audience value for token exchange (matches WIF provider config)."""
        return f"//iam.googleapis.com/{self.provider_resource_name}"

    def to_dict(self) -> dict[str, str]:
        """Serialise for database storage."""
        return {
            "project_id": self.project_id,
            "pool_location": self.pool_location,
            "pool_id": self.pool_id,
            "provider_id": self.provider_id,
            "service_account_email": self.service_account_email,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "WIFConfiguration":
        """Deserialise from database storage."""
        return cls(
            project_id=data["project_id"],
            pool_location=data.get("pool_location", "global"),
            pool_id=data.get("pool_id", "a13e-pool"),
            provider_id=data.get("provider_id", "aws"),
            service_account_email=data.get("service_account_email", ""),
        )


@dataclass
class GCPCredentialResult:
    """Result of obtaining GCP credentials via WIF.

    Contains the credentials object and metadata for caching decisions.
    """

    credentials: ga_credentials.Credentials
    project_id: str
    service_account_email: str
    expires_at: datetime
    obtained_at: datetime

    @property
    def is_valid(self) -> bool:
        """Check if credentials are still valid (with refresh buffer)."""
        buffer_time = (
            datetime.now(timezone.utc).timestamp() + TOKEN_REFRESH_BUFFER_SECONDS
        )
        return self.expires_at.timestamp() > buffer_time


class GCPWIFError(Exception):
    """Base exception for WIF-related errors."""

    pass


class WIFConfigurationError(GCPWIFError):
    """Error in WIF configuration (customer setup issue)."""

    pass


class WIFTokenExchangeError(GCPWIFError):
    """Error during AWS to GCP token exchange."""

    pass


class WIFImpersonationError(GCPWIFError):
    """Error during service account impersonation."""

    pass


class AWSTokenError(GCPWIFError):
    """Error obtaining AWS OIDC token."""

    pass


class GCPWIFCredentialService:
    """Service for obtaining GCP credentials via AWS-to-GCP Workload Identity Federation.

    This is the production-recommended authentication method for A13E.
    It eliminates the need for storing GCP service account keys.

    Architecture:
    - A13E runs on AWS ECS with an IAM role
    - AWS ECS task role can obtain OIDC tokens
    - GCP WIF pool trusts AWS OIDC provider
    - Token exchange yields federated identity
    - Federated identity impersonates customer's service account
    """

    # OAuth scopes for scanning operations (read-only)
    REQUIRED_SCOPES = [
        "https://www.googleapis.com/auth/cloud-platform.read-only",
        "https://www.googleapis.com/auth/logging.read",
        "https://www.googleapis.com/auth/monitoring.read",
    ]

    # GCP STS endpoint for token exchange
    GCP_STS_ENDPOINT = "https://sts.googleapis.com/v1/token"

    def __init__(self) -> None:
        """Initialise the WIF credential service."""
        self.logger = logger.bind(service="GCPWIFCredentialService")
        self._credential_cache: dict[str, GCPCredentialResult] = {}
        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def close(self) -> None:
        """Close the HTTP client and clean up resources."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
        self._credential_cache.clear()

    async def _run_sync(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        """Run a synchronous function without blocking the event loop."""
        loop = asyncio.get_event_loop()
        if kwargs:
            func = partial(func, **kwargs)
        return await loop.run_in_executor(_gcp_executor, func, *args)

    async def get_aws_oidc_token(self, audience: str) -> str:
        """Get AWS OIDC token from ECS task metadata.

        When running on ECS, the task can request OIDC tokens from the
        container metadata service. This token is used for federation.

        Args:
            audience: The audience for the token (GCP WIF audience)

        Returns:
            JWT token string

        Raises:
            AWSTokenError: If unable to obtain token
        """
        import os

        # Check if we're running on ECS (has metadata endpoint)
        # Container credential URI is set by ECS
        container_creds_uri = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        if not container_creds_uri:
            # Not running on ECS - check for local development token
            dev_token = os.environ.get("A13E_DEV_AWS_OIDC_TOKEN")
            if dev_token:
                self.logger.warning(
                    "using_dev_oidc_token",
                    message="Using development OIDC token - not for production",
                )
                return dev_token
            raise AWSTokenError(
                "Not running on ECS and no development token available. "
                "Set AWS_CONTAINER_CREDENTIALS_RELATIVE_URI (ECS) or "
                "A13E_DEV_AWS_OIDC_TOKEN (development)."
            )

        # ECS metadata endpoint for OIDC tokens
        # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
        metadata_uri = os.environ.get(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            f"http://169.254.170.2{container_creds_uri}",
        )

        # Request OIDC token with specific audience
        # This requires sts:AssumeRoleWithWebIdentity permission on the task role
        try:
            client = await self._get_http_client()

            # The token endpoint for ECS tasks
            # Note: ECS Anywhere uses different endpoint
            token_endpoint = f"{metadata_uri.rsplit('/', 1)[0]}/credential-provider"

            response = await client.get(
                token_endpoint,
                params={"audience": audience},
                headers={
                    "Authorization": os.environ.get(
                        "AWS_CONTAINER_AUTHORIZATION_TOKEN", ""
                    )
                },
            )

            if response.status_code != 200:
                raise AWSTokenError(
                    f"Failed to get OIDC token from ECS: {response.status_code} - {response.text}"
                )

            token_data = response.json()
            return token_data.get("token", token_data.get("Token", ""))

        except httpx.HTTPError as e:
            raise AWSTokenError(f"HTTP error getting ECS OIDC token: {e}")
        except Exception as e:
            raise AWSTokenError(f"Error getting ECS OIDC token: {e}")

    async def exchange_token_for_gcp_credentials(
        self,
        aws_token: str,
        wif_config: WIFConfiguration,
    ) -> ga_credentials.Credentials:
        """Exchange AWS OIDC token for GCP federated credentials.

        This performs the STS token exchange at GCP's endpoint.

        Args:
            aws_token: AWS OIDC JWT token
            wif_config: WIF configuration with pool details

        Returns:
            GCP Credentials object (federated)

        Raises:
            WIFTokenExchangeError: If token exchange fails
        """
        try:
            # Build the STS exchange request
            # https://cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token
            exchange_request = {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "audience": wif_config.audience,
                "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "subject_token": aws_token,
                "scope": " ".join(self.REQUIRED_SCOPES),
            }

            client = await self._get_http_client()
            response = await client.post(
                self.GCP_STS_ENDPOINT,
                data=exchange_request,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if response.status_code != 200:
                error_detail = response.json() if response.content else {}
                raise WIFTokenExchangeError(
                    f"GCP STS token exchange failed: {response.status_code} - "
                    f"{error_detail.get('error_description', response.text)}"
                )

            token_data = response.json()

            # Create credentials from the exchanged token
            # This is a federated identity, not yet impersonated
            from google.oauth2 import credentials as oauth2_creds

            federated_creds = oauth2_creds.Credentials(
                token=token_data["access_token"],
                expiry=datetime.fromtimestamp(
                    time.time() + token_data.get("expires_in", 3600),
                    tz=timezone.utc,
                ),
            )

            self.logger.info(
                "token_exchange_success",
                project_id=wif_config.project_id,
                expires_in=token_data.get("expires_in", 3600),
            )

            return federated_creds

        except WIFTokenExchangeError:
            raise
        except Exception as e:
            raise WIFTokenExchangeError(f"Token exchange error: {e}")

    async def impersonate_service_account(
        self,
        source_credentials: ga_credentials.Credentials,
        wif_config: WIFConfiguration,
        lifetime: int = DEFAULT_TOKEN_LIFETIME_SECONDS,
    ) -> ga_credentials.Credentials:
        """Impersonate customer's service account using federated credentials.

        The federated identity (from token exchange) impersonates the customer's
        service account to perform actual scanning operations.

        Args:
            source_credentials: Federated credentials from token exchange
            wif_config: WIF configuration with service account details
            lifetime: Token lifetime in seconds (max 3600)

        Returns:
            Impersonated credentials

        Raises:
            WIFImpersonationError: If impersonation fails
        """
        if not wif_config.service_account_email:
            raise WIFImpersonationError("Service account email not configured")

        try:
            # Use Google's impersonated_credentials to get SA credentials
            # This is a synchronous call - offload to thread pool
            def create_impersonated_creds() -> ga_credentials.Credentials:
                return impersonated_credentials.Credentials(
                    source_credentials=source_credentials,
                    target_principal=wif_config.service_account_email,
                    target_scopes=self.REQUIRED_SCOPES,
                    lifetime=min(lifetime, DEFAULT_TOKEN_LIFETIME_SECONDS),
                )

            impersonated = await self._run_sync(create_impersonated_creds)

            self.logger.info(
                "impersonation_success",
                service_account=wif_config.service_account_email,
                project_id=wif_config.project_id,
            )

            return impersonated

        except Exception as e:
            raise WIFImpersonationError(
                f"Failed to impersonate {wif_config.service_account_email}: {e}"
            )

    async def get_credentials(
        self,
        wif_config: WIFConfiguration,
        force_refresh: bool = False,
    ) -> GCPCredentialResult:
        """Get GCP credentials for scanning via WIF.

        This is the main entry point for obtaining credentials.
        It handles the full flow: AWS token -> GCP exchange -> impersonation.

        Credentials are cached per-project and automatically refreshed
        5 minutes before expiry.

        Args:
            wif_config: WIF configuration for the customer
            force_refresh: Force credential refresh even if cached

        Returns:
            GCPCredentialResult with credentials and metadata

        Raises:
            GCPWIFError: Various subclasses for different failure modes
        """
        cache_key = f"{wif_config.project_id}:{wif_config.service_account_email}"

        # Check cache (unless force refresh)
        if not force_refresh and cache_key in self._credential_cache:
            cached = self._credential_cache[cache_key]
            if cached.is_valid:
                self.logger.debug(
                    "using_cached_credentials",
                    project_id=wif_config.project_id,
                    expires_at=cached.expires_at.isoformat(),
                )
                return cached

        self.logger.info(
            "obtaining_wif_credentials",
            project_id=wif_config.project_id,
            service_account=wif_config.service_account_email,
        )

        # Step 1: Get AWS OIDC token
        aws_token = await self.get_aws_oidc_token(wif_config.audience)

        # Step 2: Exchange for GCP federated credentials
        federated_creds = await self.exchange_token_for_gcp_credentials(
            aws_token, wif_config
        )

        # Step 3: Impersonate customer's service account
        impersonated_creds = await self.impersonate_service_account(
            federated_creds, wif_config
        )

        # Calculate expiry (1 hour from now)
        expires_at = datetime.now(timezone.utc).replace(microsecond=0)
        expires_at = expires_at.replace(
            hour=expires_at.hour,
            minute=expires_at.minute + 60,
        )

        result = GCPCredentialResult(
            credentials=impersonated_creds,
            project_id=wif_config.project_id,
            service_account_email=wif_config.service_account_email,
            expires_at=expires_at,
            obtained_at=datetime.now(timezone.utc),
        )

        # Cache the result
        self._credential_cache[cache_key] = result

        self.logger.info(
            "wif_credentials_obtained",
            project_id=wif_config.project_id,
            service_account=wif_config.service_account_email,
            expires_at=expires_at.isoformat(),
        )

        return result

    async def validate_wif_configuration(
        self,
        wif_config: WIFConfiguration,
    ) -> dict[str, Any]:
        """Validate WIF configuration and test credential flow.

        Used during customer onboarding to verify their WIF setup.

        Args:
            wif_config: Configuration to validate

        Returns:
            Dict with validation results
        """
        result = {
            "valid": False,
            "message": "",
            "steps_completed": [],
            "steps_failed": [],
        }

        # Step 1: Validate configuration values
        if not wif_config.project_id:
            result["message"] = "Missing project_id"
            result["steps_failed"].append("configuration_check")
            return result
        if not wif_config.service_account_email:
            result["message"] = "Missing service_account_email"
            result["steps_failed"].append("configuration_check")
            return result

        result["steps_completed"].append("configuration_check")

        # Step 2: Try to get AWS OIDC token
        try:
            aws_token = await self.get_aws_oidc_token(wif_config.audience)
            result["steps_completed"].append("aws_oidc_token")
        except AWSTokenError as e:
            result["message"] = f"AWS token error: {e}"
            result["steps_failed"].append("aws_oidc_token")
            return result

        # Step 3: Try token exchange
        try:
            federated_creds = await self.exchange_token_for_gcp_credentials(
                aws_token, wif_config
            )
            result["steps_completed"].append("gcp_token_exchange")
        except WIFTokenExchangeError as e:
            result["message"] = (
                f"Token exchange failed. Check WIF pool configuration: {e}"
            )
            result["steps_failed"].append("gcp_token_exchange")
            return result

        # Step 4: Try impersonation
        try:
            await self.impersonate_service_account(federated_creds, wif_config)
            result["steps_completed"].append("service_account_impersonation")
        except WIFImpersonationError as e:
            result["message"] = (
                f"Impersonation failed. Check service account permissions: {e}"
            )
            result["steps_failed"].append("service_account_impersonation")
            return result

        result["valid"] = True
        result["message"] = "WIF configuration is valid and working"
        return result


# Singleton instance
gcp_wif_service = GCPWIFCredentialService()
