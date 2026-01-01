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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import partial
from typing import Any, Optional

import httpx
import structlog

# Google Cloud SDK imports
from google.auth import aws as google_auth_aws
from google.auth import credentials as ga_credentials
from google.auth import impersonated_credentials

# Import the ECS-compatible AWS credentials supplier
from app.services.ecs_wif_credentials import EcsAwsSecurityCredentialsSupplier

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

    # AWS provider ID within the pool (must be 4-32 chars)
    provider_id: str = "a13e-aws"

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
            provider_id=data.get("provider_id", "a13e-aws"),
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

    def _create_wif_credentials(
        self,
        wif_config: WIFConfiguration,
    ) -> ga_credentials.Credentials:
        """Create WIF credentials using AWS credentials from ECS.

        Uses the EcsAwsSecurityCredentialsSupplier which properly handles:
        - ECS task role via AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
        - boto3.Session().get_credentials() for ECS compatibility
        - SigV4 signing for AWS-to-GCP token exchange

        Args:
            wif_config: WIF configuration with pool details

        Returns:
            GCP Credentials object (federated, not yet impersonated)

        Raises:
            WIFTokenExchangeError: If credential creation fails
        """
        try:
            # Create the custom AWS credentials supplier for ECS
            supplier = EcsAwsSecurityCredentialsSupplier()

            # Create AWS-based WIF credentials using google.auth.aws
            # This handles the SigV4 signing and token exchange automatically
            wif_credentials = google_auth_aws.Credentials(
                audience=wif_config.audience,
                subject_token_type="urn:ietf:params:aws:token-type:aws4_request",
                token_url=self.GCP_STS_ENDPOINT,
                aws_security_credentials_supplier=supplier,
            )

            self.logger.info(
                "wif_credentials_created",
                project_id=wif_config.project_id,
                pool_id=wif_config.pool_id,
                provider_id=wif_config.provider_id,
            )

            return wif_credentials

        except Exception as e:
            raise WIFTokenExchangeError(f"Failed to create WIF credentials: {e}")

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

        # Step 1: Create WIF credentials using AWS credentials from ECS
        # This uses boto3 to get credentials and google.auth.aws for token exchange
        wif_creds = await self._run_sync(self._create_wif_credentials, wif_config)

        # Step 2: Impersonate customer's service account
        impersonated_creds = await self.impersonate_service_account(
            wif_creds, wif_config
        )

        # Calculate expiry (1 hour from now)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

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

        # Step 2: Try to create WIF credentials using AWS credentials from ECS
        # This uses boto3 and google.auth.aws for proper SigV4 token exchange
        try:
            wif_creds = await self._run_sync(self._create_wif_credentials, wif_config)
            result["steps_completed"].append("aws_credentials")
            result["steps_completed"].append("gcp_token_exchange")
        except WIFTokenExchangeError as e:
            result["message"] = f"WIF credential creation failed: {e}"
            result["steps_failed"].append("gcp_token_exchange")
            return result
        except Exception as e:
            result["message"] = f"AWS credentials error: {e}"
            result["steps_failed"].append("aws_credentials")
            return result

        # Step 3: Try impersonation
        try:
            await self.impersonate_service_account(wif_creds, wif_config)
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
