"""Azure Workload Identity Federation Service - AWS to Azure authentication.

Security Architecture:
1. A13E ECS task calls Cognito GetOpenIdTokenForDeveloperIdentity
2. Cognito returns OIDC JWT with issuer=cognito-identity.amazonaws.com
3. Azure AD validates JWT via federated credential trust
4. Short-lived (1h) Azure credentials - NEVER stored

MITRE ATT&CK Relevance:
- T1528: Steal Application Access Token - WIF prevents token theft
- T1078.004: Cloud Accounts - Federated identities reduce attack surface
- T1552: Unsecured Credentials - No credentials to be unsecured
"""

import asyncio
from dataclasses import dataclass
from typing import Optional, Tuple

import structlog
from azure.identity.aio import ClientAssertionCredential

from app.core.config import get_settings

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


@dataclass
class CognitoJWTResult:
    """Result from Cognito GetOpenIdTokenForDeveloperIdentity.

    Contains the OIDC JWT token and the Cognito IdentityId.
    The IdentityId is stable per cloud_account_id and must be stored
    for use in Azure federated credential configuration.
    """

    token: str  # OIDC JWT for Azure WIF
    identity_id: str  # Cognito IdentityId (e.g., eu-west-2:abc123-...)


async def get_cognito_jwt(
    cloud_account_id: str,
    existing_identity_id: Optional[str] = None,
) -> CognitoJWTResult:
    """Get Cognito OIDC JWT for Azure WIF authentication.

    Uses GetOpenIdTokenForDeveloperIdentity to generate a proper OIDC JWT that:
    - Has issuer: https://cognito-identity.amazonaws.com
    - Has subject: The Cognito IdentityId (stable per cloud account)
    - Has audience: The Identity Pool ID

    CRITICAL: Runs boto3 in thread pool to avoid blocking asyncio event loop.
    Per CLAUDE.md: "boto3 blocks asyncio. Always use run_sync()."

    Args:
        cloud_account_id: The A13E cloud account ID (used as developer user identifier)
        existing_identity_id: If known, reuse existing Cognito Identity ID for consistency

    Returns:
        CognitoJWTResult with token and identity_id

    Raises:
        AzureWIFError: If token generation fails
    """
    settings = get_settings()

    if not settings.cognito_identity_pool_id:
        raise AzureWIFError(
            "Cognito Identity Pool not configured. "
            "Azure WIF requires COGNITO_IDENTITY_POOL_ID to be set."
        )

    def _get_token_sync() -> CognitoJWTResult:
        """Synchronous token generation (runs in thread pool)."""
        import boto3
        from botocore.exceptions import ClientError

        try:
            client = boto3.client(
                "cognito-identity",
                region_name=settings.aws_region,
            )

            # Build request parameters
            params = {
                "IdentityPoolId": settings.cognito_identity_pool_id,
                "Logins": {
                    # Developer provider name must match Terraform config
                    "a13e-azure-wif": cloud_account_id,
                },
                "TokenDuration": 3600,  # 1 hour (max allowed)
            }

            # If we have existing identity, reuse it for consistency
            # This ensures the same cloud account always gets the same IdentityId
            if existing_identity_id:
                params["IdentityId"] = existing_identity_id

            response = client.get_open_id_token_for_developer_identity(**params)

            token = response["Token"]
            identity_id = response["IdentityId"]

            logger.debug(
                "cognito_jwt_obtained",
                identity_id=identity_id[:20] + "...",
                cloud_account_id=cloud_account_id[:8] + "...",
            )

            return CognitoJWTResult(token=token, identity_id=identity_id)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))
            logger.error(
                "cognito_jwt_error",
                error_code=error_code,
                error_message=error_message,
                cloud_account_id=cloud_account_id[:8] + "...",
            )
            raise AzureWIFError(
                f"Cognito identity pool error ({error_code}): {error_message}"
            )
        except Exception as e:
            logger.error(
                "cognito_jwt_unexpected_error",
                error=str(e),
                cloud_account_id=cloud_account_id[:8] + "...",
            )
            raise AzureWIFError(f"Failed to get Cognito JWT: {e}")

    # Run in thread pool to avoid blocking event loop
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_token_sync)


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
    cloud_account_id: str,
    cognito_identity_id: Optional[str] = None,
) -> Tuple[ClientAssertionCredential, str]:
    """Get Azure credential using Cognito-based WIF.

    Uses Cognito Identity Pool to generate OIDC JWTs that Azure can validate.
    The Cognito IdentityId is stable per cloud_account_id and must be stored
    in the database for use in the customer's Azure federated credential config.

    Args:
        wif_config: WIF configuration for the customer
        cloud_account_id: A13E cloud account ID (used as developer identity)
        cognito_identity_id: Existing Cognito Identity ID (if known)

    Returns:
        Tuple of (ClientAssertionCredential, cognito_identity_id)
        The cognito_identity_id should be stored for future use

    Raises:
        AzureWIFError: If credential creation fails
    """
    try:
        # Get initial JWT to discover/confirm the Cognito Identity ID
        jwt_result = await get_cognito_jwt(
            cloud_account_id=cloud_account_id,
            existing_identity_id=cognito_identity_id,
        )

        # Create a token supplier that fetches fresh JWTs when needed
        # This is called by Azure SDK when it needs a new token
        async def token_supplier() -> str:
            result = await get_cognito_jwt(
                cloud_account_id=cloud_account_id,
                existing_identity_id=jwt_result.identity_id,
            )
            return result.token

        # Create credential with Cognito JWT supplier
        # Azure SDK automatically manages token lifecycle
        credential = ClientAssertionCredential(
            tenant_id=wif_config.tenant_id,
            client_id=wif_config.client_id,
            func=token_supplier,  # Called by SDK when token needed
        )

        logger.info(
            "azure_credential_created",
            tenant_id=wif_config.tenant_id,
            subscription_id=wif_config.subscription_id,
            cognito_identity_id=jwt_result.identity_id[:20] + "...",
        )

        return credential, jwt_result.identity_id

    except AzureWIFError:
        raise  # Re-raise WIF errors as-is
    except Exception as e:
        raise AzureWIFError(f"Failed to create Azure credential: {e}")


async def validate_wif_configuration(
    wif_config: AzureWIFConfiguration,
    cloud_account_id: str,
    existing_cognito_identity_id: Optional[str] = None,
) -> dict:
    """Validate Azure WIF configuration by attempting to authenticate.

    Tests the full WIF flow:
    1. Get Cognito OIDC JWT from Identity Pool
    2. Exchange for Azure credential via federated trust
    3. Verify we can access the subscription

    Args:
        wif_config: WIF configuration for the customer
        cloud_account_id: A13E cloud account ID
        existing_cognito_identity_id: Existing Cognito Identity ID (if known)

    Returns:
        dict with keys:
            - valid: bool
            - message: str
            - steps_completed: list[str]
            - steps_failed: list[str]
            - cognito_identity_id: str (if successful, for storage)
    """
    steps_completed = []
    steps_failed = []
    cognito_identity_id = None

    try:
        # Step 1: Get Cognito OIDC JWT
        try:
            jwt_result = await get_cognito_jwt(
                cloud_account_id=cloud_account_id,
                existing_identity_id=existing_cognito_identity_id,
            )
            cognito_identity_id = jwt_result.identity_id
            steps_completed.append("Cognito OIDC JWT obtained")
        except AzureWIFError as e:
            steps_failed.append(f"Cognito JWT: {e}")
            return {
                "valid": False,
                "message": f"Failed to get Cognito identity token: {e}",
                "steps_completed": steps_completed,
                "steps_failed": steps_failed,
                "cognito_identity_id": None,
            }

        # Step 2: Get Azure credential via WIF
        try:
            credential, _ = await get_azure_credential(
                wif_config,
                cloud_account_id=cloud_account_id,
                cognito_identity_id=cognito_identity_id,
            )
            steps_completed.append("Azure credential created via WIF")
        except AzureWIFError as e:
            steps_failed.append(f"Azure WIF credential: {e}")
            return {
                "valid": False,
                "message": f"Failed to create Azure credential: {e}",
                "steps_completed": steps_completed,
                "steps_failed": steps_failed,
                "cognito_identity_id": cognito_identity_id,
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
                    "cognito_identity_id": cognito_identity_id,
                }
        except Exception as e:
            steps_failed.append(f"Azure token exchange: {e}")
            return {
                "valid": False,
                "message": f"Failed to exchange token with Azure: {e}",
                "steps_completed": steps_completed,
                "steps_failed": steps_failed,
                "cognito_identity_id": cognito_identity_id,
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
                "cognito_identity_id": cognito_identity_id,
            }

        logger.info(
            "azure_wif_validation_success",
            tenant_id=wif_config.tenant_id,
            subscription_id=wif_config.subscription_id,
            cognito_identity_id=cognito_identity_id[:20] + "...",
            steps_completed=steps_completed,
        )

        return {
            "valid": True,
            "message": "Azure WIF configuration is valid",
            "steps_completed": steps_completed,
            "steps_failed": steps_failed,
            "cognito_identity_id": cognito_identity_id,
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
            "cognito_identity_id": cognito_identity_id,
        }


# Export public API
__all__ = [
    "AzureWIFConfiguration",
    "AzureWIFError",
    "CognitoJWTResult",
    "get_azure_credential",
    "get_aws_sts_token",  # Deprecated - kept for backwards compatibility
    "get_cognito_jwt",
    "validate_wif_configuration",
]
