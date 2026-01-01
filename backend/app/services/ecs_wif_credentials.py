"""
ECS Workload Identity Federation Credentials with Domain-Wide Delegation

This module provides WIF credentials that work on AWS ECS Fargate and support
Google Workspace domain-wide delegation.

The standard google-auth library has two limitations:
1. It doesn't support ECS Fargate's credential mechanism (uses EC2 IMDS)
2. It doesn't support the `subject` parameter for domain-wide delegation with WIF

This module solves both by:
1. Using boto3 to get AWS credentials (works on ECS via AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
2. Using custom JWT signing to add the `sub` claim for domain-wide delegation

Architecture:
    ECS Task Role → boto3.Session().get_credentials()
                 → aws.Credentials (WIF)
                 → impersonated_credentials (impersonate GCP SA)
                 → Custom JWT with sub claim
                 → Token exchange with Google
                 → Workspace API calls

References:
- https://github.com/agarabhishek/GCP-WIF-AwsSecurityCredentialsSupplier
- https://blog.salrashid.dev/articles/2021/impersonation_and_domain_delegation/
- https://github.com/googleapis/google-auth-library-python/issues/1785
"""

import base64
import os
import time
from typing import Any, Optional

import boto3
import google.auth
import google.auth.transport
import google.oauth2.credentials
import requests
import structlog
from google.auth import aws, exceptions, impersonated_credentials

logger = structlog.get_logger()


class EcsAwsSecurityCredentialsSupplier(aws.AwsSecurityCredentialsSupplier):
    """
    Custom AWS Security Credentials Supplier for ECS Fargate.

    Uses boto3.Session().get_credentials() which automatically handles:
    - ECS task role via AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
    - EC2 instance profiles via IMDS
    - Environment variables (AWS_ACCESS_KEY_ID, etc.)
    - Shared credentials file
    """

    def get_aws_security_credentials(
        self,
        context: Any,  # SupplierContext - contains audience and subject token type
        request: google.auth.transport.Request,
    ) -> aws.AwsSecurityCredentials:
        """
        Fetch AWS security credentials via boto3.

        Args:
            context: Supplier context with audience and token type
            request: HTTP request object for making calls

        Returns:
            AwsSecurityCredentials with access key, secret key, and session token
        """
        try:
            session = boto3.Session()
            credentials = session.get_credentials()

            if credentials is None:
                raise ValueError("No AWS credentials available")

            # Get frozen credentials to ensure we have the current values
            frozen = credentials.get_frozen_credentials()

            logger.debug(
                "ecs_aws_credentials_obtained",
                access_key_prefix=frozen.access_key[:8] + "...",
                has_token=bool(frozen.token),
            )

            return aws.AwsSecurityCredentials(
                frozen.access_key,
                frozen.secret_key,
                frozen.token,
            )

        except Exception as e:
            logger.error("ecs_aws_credentials_failed", error=str(e))
            raise exceptions.RefreshError(e, retryable=True)

    def get_aws_region(
        self,
        context: Any,  # SupplierContext
        request: google.auth.transport.Request,
    ) -> str:
        """
        Get the AWS region from environment variables.

        ECS Fargate sets AWS_REGION automatically.

        Args:
            context: Supplier context
            request: HTTP request object

        Returns:
            AWS region string (e.g., 'eu-west-2')
        """
        try:
            region = os.environ.get("AWS_REGION") or os.environ.get(
                "AWS_DEFAULT_REGION"
            )

            if not region:
                raise ValueError(
                    "AWS_REGION or AWS_DEFAULT_REGION environment variable not set"
                )

            logger.debug("ecs_aws_region_obtained", region=region)
            return region

        except Exception as e:
            logger.error("ecs_aws_region_failed", error=str(e))
            raise exceptions.RefreshError(e, retryable=True)


def get_wif_delegated_credentials(
    gcp_project_number: str,
    wif_pool_id: str,
    wif_provider_id: str,
    service_account_email: str,
    scopes: list[str],
    delegated_user: Optional[str] = None,
) -> google.oauth2.credentials.Credentials:
    """
    Get WIF credentials with domain-wide delegation support.

    This function:
    1. Uses the custom ECS credentials supplier to get AWS credentials
    2. Creates WIF credentials to authenticate to GCP
    3. Impersonates the target service account
    4. Signs a custom JWT with the `sub` claim for domain-wide delegation
    5. Exchanges the JWT for an access token

    Args:
        gcp_project_number: GCP project number (numeric)
        wif_pool_id: Workload Identity Pool ID
        wif_provider_id: Workload Identity Provider ID
        service_account_email: GCP service account to impersonate
        scopes: OAuth scopes for the final credentials
        delegated_user: Email of user to impersonate via domain-wide delegation

    Returns:
        Credentials object that can be used with Google API clients
    """
    # Step 1: Create the custom AWS credentials supplier
    supplier = EcsAwsSecurityCredentialsSupplier()

    # Step 2: Build the WIF audience
    audience = (
        f"//iam.googleapis.com/projects/{gcp_project_number}"
        f"/locations/global/workloadIdentityPools/{wif_pool_id}"
        f"/providers/{wif_provider_id}"
    )

    # Step 3: Create AWS-based WIF credentials
    wif_credentials = aws.Credentials(
        audience=audience,
        subject_token_type="urn:ietf:params:aws:token-type:aws4_request",
        token_url="https://sts.googleapis.com/v1/token",
        aws_security_credentials_supplier=supplier,
        # Note: We don't set service_account_impersonation_url here
        # because we'll handle impersonation manually for domain-wide delegation
    )

    logger.info(
        "wif_credentials_created",
        pool_id=wif_pool_id,
        provider_id=wif_provider_id,
    )

    # Step 4: Create impersonated credentials
    # This gives us the ability to sign JWTs as the service account
    impersonated = impersonated_credentials.Credentials(
        source_credentials=wif_credentials,
        target_principal=service_account_email,
        target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
        delegates=[],
    )

    logger.info(
        "impersonated_credentials_created",
        service_account=service_account_email,
    )

    # If no delegated user, return the impersonated credentials with proper scopes
    if not delegated_user:
        # Re-create with the actual scopes we need
        return impersonated_credentials.Credentials(
            source_credentials=wif_credentials,
            target_principal=service_account_email,
            target_scopes=scopes,
            delegates=[],
        )

    # Step 5: Create JWT with sub claim for domain-wide delegation
    now = int(time.time())
    exp_time = now + 3600  # 1 hour

    # Build the JWT claims
    scope_string = " ".join(scopes)
    claims = {
        "iss": service_account_email,
        "sub": delegated_user,
        "scope": scope_string,
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": exp_time,
    }

    # Encode claims as JSON
    import json

    claims_json = json.dumps(claims, separators=(",", ":"))

    # Build the JWT header
    header = {"alg": "RS256", "typ": "JWT"}
    header_json = json.dumps(header, separators=(",", ":"))

    # Base64url encode header and claims
    header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip("=")
    claims_b64 = base64.urlsafe_b64encode(claims_json.encode()).decode().rstrip("=")

    # Create the signing input
    signing_input = f"{header_b64}.{claims_b64}"

    # Step 6: Sign the JWT using the impersonated credentials
    # The sign_bytes method uses the IAM signBlob API
    signature = impersonated.sign_bytes(signing_input.encode())
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    # Assemble the complete JWT
    assertion = f"{signing_input}.{signature_b64}"

    logger.debug(
        "jwt_created_for_delegation",
        delegated_user=delegated_user,
        scopes_count=len(scopes),
    )

    # Step 7: Exchange the JWT for an access token
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion,
    }

    response = requests.post(token_url, data=data, timeout=30)

    if response.status_code != 200:
        logger.error(
            "jwt_token_exchange_failed",
            status_code=response.status_code,
            response=response.text,
        )
        raise exceptions.RefreshError(
            f"Token exchange failed: {response.status_code} - {response.text}"
        )

    token_data = response.json()
    access_token = token_data["access_token"]
    expires_in = token_data.get("expires_in", 3600)

    logger.info(
        "delegated_credentials_obtained",
        delegated_user=delegated_user,
        expires_in=expires_in,
    )

    # Step 8: Create credentials object with the access token
    # Note: These credentials will expire and need to be refreshed
    # The expiry is set based on the token response
    from datetime import datetime, timezone

    expiry = datetime.now(timezone.utc).replace(tzinfo=None) + __import__(
        "datetime"
    ).timedelta(seconds=expires_in)

    credentials = google.oauth2.credentials.Credentials(
        token=access_token,
        expiry=expiry,
    )

    return credentials
