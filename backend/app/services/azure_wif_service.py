"""Azure Workload Identity Federation Service - AWS to Azure authentication.

Security Architecture:
1. A13E ECS task assumes AWS IAM role
2. AWS STS generates identity token
3. Azure AD validates AWS identity via federated credential
4. Short-lived (1h) Azure credentials - NEVER stored

MITRE ATT&CK Relevance:
- T1528: Steal Application Access Token - WIF prevents token theft
- T1078.004: Cloud Accounts - Federated identities reduce attack surface
- T1552: Unsecured Credentials - No credentials to be unsecured
"""

import asyncio
from dataclasses import dataclass

import structlog
from azure.identity.aio import ClientAssertionCredential

logger = structlog.get_logger()


@dataclass
class AzureWIFConfiguration:
    """Configuration for Azure Workload Identity Federation.

    Stored per-customer in database (azure_workload_identity_config column).
    No secrets - all values are public identifiers.
    """

    tenant_id: str  # Azure AD tenant
    client_id: str  # Azure AD application (federated credential)
    subscription_id: str  # Azure subscription to scan

    def to_dict(self) -> dict[str, str]:
        """Serialise for database storage."""
        return {
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "subscription_id": self.subscription_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "AzureWIFConfiguration":
        """Deserialise from database storage.

        CRITICAL: Use defensive dict access (JSONB returns dicts, not dataclasses).
        Following CLAUDE.md guidance on JSON column serialization.
        """
        if not data:
            raise ValueError("Azure WIF configuration is empty")

        required_keys = ["tenant_id", "client_id", "subscription_id"]
        missing = [k for k in required_keys if k not in data]
        if missing:
            raise ValueError(f"Missing required keys: {missing}")

        return cls(
            tenant_id=data.get("tenant_id", ""),
            client_id=data.get("client_id", ""),
            subscription_id=data.get("subscription_id", ""),
        )


class AzureWIFError(Exception):
    """Base exception for WIF-related errors."""

    pass


async def get_aws_sts_token() -> str:
    """Get AWS STS identity token that Azure can validate.

    CRITICAL FIX: Run boto3 in thread pool to avoid blocking event loop.
    Per CLAUDE.md: "boto3 blocks asyncio. Always use run_sync()."

    Returns:
        AWS identity token (session token from ECS task role)

    Raises:
        AzureWIFError: If token generation fails
    """

    def _get_token_sync() -> str:
        """Synchronous token generation (runs in thread pool)."""
        import boto3
        from botocore.exceptions import ClientError

        try:
            # Get ECS task credentials
            session = boto3.Session()
            credentials = session.get_credentials()

            if not credentials:
                raise AzureWIFError("No AWS credentials available from ECS task")

            # Get STS client with credentials
            sts = session.client("sts")

            # Get caller identity as proof of AWS identity
            # Azure validates this via federated credential trust
            response = sts.get_caller_identity()

            # For Azure WIF, we use the session token as identity proof
            frozen = credentials.get_frozen_credentials()

            if not frozen.token:
                raise AzureWIFError(
                    "No session token available (need IAM role, not static credentials)"
                )

            logger.debug(
                "aws_sts_token_obtained",
                account=response["Account"],
                arn=response["Arn"][:50] + "...",  # Truncate for logging
            )

            # Return the session token (this is the AWS identity proof)
            return frozen.token

        except ClientError as e:
            raise AzureWIFError(f"AWS STS error: {e}")
        except Exception as e:
            raise AzureWIFError(f"Failed to get AWS token: {e}")

    # Run in thread pool to avoid blocking event loop
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_token_sync)


async def get_azure_credential(
    wif_config: AzureWIFConfiguration,
) -> ClientAssertionCredential:
    """Get Azure credential using WIF.

    SIMPLIFIED: Let Azure SDK handle token caching and refresh.
    No custom cache needed - SDK automatically:
    - Caches the token
    - Refreshes before expiry
    - Handles errors and retries

    Args:
        wif_config: WIF configuration for the customer

    Returns:
        ClientAssertionCredential (Azure SDK manages token lifecycle)

    Raises:
        AzureWIFError: If credential creation fails
    """
    try:
        # Create credential with AWS token supplier
        # Azure SDK automatically manages token lifecycle
        credential = ClientAssertionCredential(
            tenant_id=wif_config.tenant_id,
            client_id=wif_config.client_id,
            func=get_aws_sts_token,  # Called by SDK when token needed
        )

        logger.info(
            "azure_credential_created",
            tenant_id=wif_config.tenant_id,
            subscription_id=wif_config.subscription_id,
        )

        return credential

    except Exception as e:
        raise AzureWIFError(f"Failed to create Azure credential: {e}")


async def validate_wif_configuration(wif_config: AzureWIFConfiguration) -> dict:
    """Validate Azure WIF configuration by attempting to authenticate.

    Tests the full WIF flow:
    1. Get AWS STS token from ECS task role
    2. Exchange for Azure credential via federated trust
    3. Verify we can list resources in the subscription

    Args:
        wif_config: WIF configuration to validate

    Returns:
        dict with keys:
            - valid: bool
            - message: str
            - steps_completed: list[str]
            - steps_failed: list[str]
    """
    steps_completed = []
    steps_failed = []

    try:
        # Step 1: Get AWS STS token
        try:
            await get_aws_sts_token()
            steps_completed.append("AWS STS token obtained")
        except AzureWIFError as e:
            steps_failed.append(f"AWS STS token: {e}")
            return {
                "valid": False,
                "message": f"Failed to get AWS identity token: {e}",
                "steps_completed": steps_completed,
                "steps_failed": steps_failed,
            }

        # Step 2: Get Azure credential via WIF
        try:
            credential = await get_azure_credential(wif_config)
            steps_completed.append("Azure credential created via WIF")
        except AzureWIFError as e:
            steps_failed.append(f"Azure WIF credential: {e}")
            return {
                "valid": False,
                "message": f"Failed to create Azure credential: {e}",
                "steps_completed": steps_completed,
                "steps_failed": steps_failed,
            }

        # Step 3: Test the credential by getting a token
        try:
            # Request a token for Azure Resource Manager
            token = await credential.get_token("https://management.azure.com/.default")
            if token and token.token:
                steps_completed.append("Azure access token obtained")
            else:
                steps_failed.append("Azure token was empty")
                return {
                    "valid": False,
                    "message": "Azure credential returned empty token",
                    "steps_completed": steps_completed,
                    "steps_failed": steps_failed,
                }
        except Exception as e:
            steps_failed.append(f"Azure token exchange: {e}")
            return {
                "valid": False,
                "message": f"Failed to exchange token with Azure: {e}",
                "steps_completed": steps_completed,
                "steps_failed": steps_failed,
            }

        # Step 4: Test subscription access with a lightweight API call
        try:
            from azure.mgmt.resource.subscriptions.aio import SubscriptionClient

            async with SubscriptionClient(credential) as sub_client:
                subscription = await sub_client.subscriptions.get(
                    wif_config.subscription_id
                )
                steps_completed.append(
                    f"Subscription access verified: {subscription.display_name}"
                )
        except Exception as e:
            steps_failed.append(f"Subscription access: {e}")
            return {
                "valid": False,
                "message": f"Cannot access subscription {wif_config.subscription_id}: {e}",
                "steps_completed": steps_completed,
                "steps_failed": steps_failed,
            }

        logger.info(
            "azure_wif_validation_success",
            tenant_id=wif_config.tenant_id,
            subscription_id=wif_config.subscription_id,
            steps_completed=steps_completed,
        )

        return {
            "valid": True,
            "message": "Azure WIF configuration is valid",
            "steps_completed": steps_completed,
            "steps_failed": steps_failed,
        }

    except Exception as e:
        logger.error(
            "azure_wif_validation_error",
            error=str(e),
            tenant_id=wif_config.tenant_id,
        )
        return {
            "valid": False,
            "message": f"Unexpected validation error: {e}",
            "steps_completed": steps_completed,
            "steps_failed": [str(e)],
        }


# Export public API
__all__ = [
    "AzureWIFConfiguration",
    "AzureWIFError",
    "get_azure_credential",
    "get_aws_sts_token",
    "validate_wif_configuration",
]
