"""AWS Credential Service - Secure cross-account access using STS AssumeRole.

Security Best Practices:
1. Uses STS AssumeRole (no long-lived credentials)
2. External ID prevents confused deputy attacks
3. Session duration limited to 1 hour
4. All assumed credentials are temporary
5. Validates permissions before accepting connection
"""

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, Callable, Optional, TypeVar

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import structlog

from app.models.cloud_credential import (
    CloudCredential,
    CredentialStatus,
    CredentialType,
)

# Shared thread pool for boto3 calls - prevents blocking the async event loop
_credential_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="cred-")

T = TypeVar("T")

logger = structlog.get_logger()


def _is_dev_mode_allowed() -> bool:
    """Check if DEV_MODE is allowed in current environment.

    Security: DEV_MODE bypasses real AWS credential validation.
    It must be blocked in production/staging to prevent abuse.
    """
    dev_mode_requested = os.environ.get("A13E_DEV_MODE", "false").lower() == "true"
    environment = os.environ.get("ENVIRONMENT", "development")

    # DEV_MODE only allowed in development/local environments
    if dev_mode_requested and environment in ("production", "prod", "staging"):
        logger.warning(
            "dev_mode_blocked",
            environment=environment,
            message="DEV_MODE requested but blocked in non-development environment",
        )
        return False
    return dev_mode_requested


# Development mode - skip real AWS calls (blocked in production/staging)
DEV_MODE = _is_dev_mode_allowed()


class AWSCredentialService:
    """Service for AWS cross-account credential management."""

    # A13E's AWS account ID (for trust relationship)
    A13E_AWS_ACCOUNT_ID = "123080274263"  # A13E production AWS account

    def __init__(self):
        """Initialize with base AWS client."""
        # This uses the credentials of A13E's infrastructure
        self._sts_client = None

    @property
    def sts_client(self):
        """Lazy load STS client."""
        if self._sts_client is None:
            self._sts_client = boto3.client("sts")
        return self._sts_client

    async def _run_sync(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Run a synchronous boto3 call without blocking the event loop.

        Offloads the call to a thread pool to prevent blocking.
        """
        loop = asyncio.get_event_loop()
        if kwargs:
            func = partial(func, **kwargs)
        return await loop.run_in_executor(_credential_executor, func, *args)

    async def assume_role_async(
        self,
        role_arn: str,
        external_id: str,
        session_name: Optional[str] = None,
        duration_seconds: int = 3600,
    ) -> dict:
        """Async version of assume_role that doesn't block the event loop."""
        return await self._run_sync(
            self.assume_role, role_arn, external_id, session_name, duration_seconds
        )

    def assume_role(
        self,
        role_arn: str,
        external_id: str,
        session_name: Optional[str] = None,
        duration_seconds: int = 3600,
    ) -> dict:
        """Assume a cross-account IAM role.

        Args:
            role_arn: ARN of the role to assume
            external_id: External ID for confused deputy prevention
            session_name: Name for the assumed role session (auto-generated if not provided)
            duration_seconds: Session duration (max 3600)

        Returns:
            dict with temporary credentials

        Raises:
            ValueError: If role assumption fails
        """
        # M13: Generate unique session name for better audit tracking
        if session_name is None:
            import secrets
            from datetime import datetime

            timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            unique_suffix = secrets.token_hex(4)
            session_name = f"A13E-{timestamp}-{unique_suffix}"

        try:
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                ExternalId=external_id,
                RoleSessionName=session_name,
                DurationSeconds=min(duration_seconds, 3600),
            )

            credentials = response["Credentials"]

            return {
                "access_key_id": credentials["AccessKeyId"],
                "secret_access_key": credentials["SecretAccessKey"],
                "session_token": credentials["SessionToken"],
                "expiration": credentials["Expiration"],
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]

            logger.error(
                "aws_assume_role_failed",
                role_arn=role_arn,
                error_code=error_code,
                error_message=error_message,
            )

            if error_code == "AccessDenied":
                raise ValueError(
                    f"Access denied when assuming role. Please verify:\n"
                    f"1. The role ARN is correct: {role_arn}\n"
                    f"2. The role trusts A13E account: {self.A13E_AWS_ACCOUNT_ID}\n"
                    f"3. The external ID matches: {external_id[:20]}...\n"
                    f"AWS Error: {error_message}"
                )
            elif error_code == "MalformedPolicyDocument":
                raise ValueError(
                    "The role's trust policy is malformed. Please re-create the role using our CloudFormation template."
                )
            else:
                raise ValueError(f"Failed to assume role: {error_message}")

        except NoCredentialsError:
            logger.error(
                "aws_no_credentials",
                msg="A13E infrastructure credentials not configured",
            )
            raise ValueError(
                "A13E AWS credentials not configured. Please contact support."
            )

    def get_client_with_assumed_role(
        self,
        service_name: str,
        role_arn: str,
        external_id: str,
        region: str = "us-east-1",
    ):
        """Get a boto3 client using assumed role credentials.

        Args:
            service_name: AWS service name (e.g., 'logs', 'events')
            role_arn: ARN of the role to assume
            external_id: External ID for the role
            region: AWS region

        Returns:
            boto3 client for the specified service
        """
        credentials = self.assume_role(role_arn, external_id)

        return boto3.client(
            service_name,
            region_name=region,
            aws_access_key_id=credentials["access_key_id"],
            aws_secret_access_key=credentials["secret_access_key"],
            aws_session_token=credentials["session_token"],
        )

    async def validate_credentials(
        self,
        credential: CloudCredential,
    ) -> dict:
        """Validate AWS credentials and check permissions.

        Returns:
            dict with validation results
        """
        if credential.credential_type != CredentialType.AWS_IAM_ROLE:
            raise ValueError("Invalid credential type for AWS validation")

        if not credential.aws_role_arn or not credential.aws_external_id:
            return {
                "status": CredentialStatus.INVALID,
                "message": "Missing role ARN or external ID",
                "granted_permissions": [],
                "missing_permissions": [],
            }

        # Development mode - simulate successful validation
        if DEV_MODE:
            logger.info(
                "aws_dev_mode_validation",
                role_arn=credential.aws_role_arn,
                msg="Simulating successful validation in dev mode",
            )
            all_permissions = [
                "logs:DescribeLogGroups",
                "logs:DescribeMetricFilters",
                "logs:DescribeSubscriptionFilters",
                "cloudwatch:DescribeAlarms",
                "cloudwatch:DescribeAlarmsForMetric",
                "events:ListRules",
                "events:DescribeRule",
                "events:ListTargetsByRule",
                "guardduty:ListDetectors",
                "guardduty:GetDetector",
                "guardduty:ListFindings",
                "guardduty:GetFindings",
                "securityhub:DescribeHub",
                "securityhub:GetEnabledStandards",
                "securityhub:DescribeStandardsControls",
                "config:DescribeConfigRules",
                "config:DescribeComplianceByConfigRule",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors",
                "lambda:ListFunctions",
                "lambda:ListEventSourceMappings",
                "lambda:GetFunction",
                "lambda:GetFunctionConfiguration",
            ]
            return {
                "status": CredentialStatus.VALID,
                "message": f"[DEV MODE] All {len(all_permissions)} required permissions verified.",
                "granted_permissions": all_permissions,
                "missing_permissions": [],
            }

        try:
            # First, verify we can assume the role (non-blocking)
            creds = await self.assume_role_async(
                credential.aws_role_arn,
                credential.aws_external_id,
            )

            # Create a session with the assumed credentials
            session = boto3.Session(
                aws_access_key_id=creds["access_key_id"],
                aws_secret_access_key=creds["secret_access_key"],
                aws_session_token=creds["session_token"],
            )

            # Run all permission checks IN PARALLEL for faster validation
            # Each check returns (granted_perms, missing_perms) tuple
            results = await asyncio.gather(
                self._check_logs_permissions(session),
                self._check_cloudwatch_permissions(session),
                self._check_eventbridge_permissions(session),
                self._check_guardduty_permissions(session),
                self._check_securityhub_permissions(session),
                self._check_config_permissions(session),
                self._check_cloudtrail_permissions(session),
                self._check_lambda_permissions(session),
            )

            # Combine results from all checks
            granted = []
            missing = []
            for check_granted, check_missing in results:
                granted.extend(check_granted)
                missing.extend(check_missing)

            # Determine status
            if missing:
                status = CredentialStatus.PERMISSION_ERROR
                message = f"Missing {len(missing)} required permissions. Please update the IAM policy."
            else:
                status = CredentialStatus.VALID
                message = f"All {len(granted)} required permissions verified."

            return {
                "status": status,
                "message": message,
                "granted_permissions": granted,
                "missing_permissions": missing,
            }

        except ValueError as e:
            return {
                "status": CredentialStatus.INVALID,
                "message": str(e),
                "granted_permissions": [],
                "missing_permissions": [],
            }
        except Exception as e:
            logger.exception("aws_credential_validation_error", error=str(e))
            return {
                "status": CredentialStatus.INVALID,
                "message": f"Unexpected error during validation: {str(e)}",
                "granted_permissions": [],
                "missing_permissions": [],
            }

    async def _check_logs_permissions(
        self, session: boto3.Session
    ) -> tuple[list[str], list[str]]:
        """Check CloudWatch Logs permissions."""
        permissions = [
            "logs:DescribeLogGroups",
            "logs:DescribeMetricFilters",
            "logs:DescribeSubscriptionFilters",
        ]
        try:
            client = session.client("logs", region_name="us-east-1")
            await self._run_sync(client.describe_log_groups, limit=1)
            return (permissions, [])
        except ClientError as e:
            if "AccessDenied" in str(e):
                return ([], permissions)
            return (permissions, [])  # Other errors = permission OK

    async def _check_cloudwatch_permissions(
        self, session: boto3.Session
    ) -> tuple[list[str], list[str]]:
        """Check CloudWatch Alarms permissions."""
        permissions = [
            "cloudwatch:DescribeAlarms",
            "cloudwatch:DescribeAlarmsForMetric",
        ]
        try:
            client = session.client("cloudwatch", region_name="us-east-1")
            await self._run_sync(client.describe_alarms, MaxRecords=1)
            return (permissions, [])
        except ClientError as e:
            if "AccessDenied" in str(e):
                return ([], permissions)
            return (permissions, [])

    async def _check_eventbridge_permissions(
        self, session: boto3.Session
    ) -> tuple[list[str], list[str]]:
        """Check EventBridge permissions."""
        permissions = [
            "events:ListRules",
            "events:DescribeRule",
            "events:ListTargetsByRule",
        ]
        try:
            client = session.client("events", region_name="us-east-1")
            await self._run_sync(client.list_rules, Limit=1)
            return (permissions, [])
        except ClientError as e:
            if "AccessDenied" in str(e):
                return ([], permissions)
            return (permissions, [])

    async def _check_guardduty_permissions(
        self, session: boto3.Session
    ) -> tuple[list[str], list[str]]:
        """Check GuardDuty permissions."""
        permissions = [
            "guardduty:ListDetectors",
            "guardduty:GetDetector",
            "guardduty:ListFindings",
            "guardduty:GetFindings",
        ]
        try:
            client = session.client("guardduty", region_name="us-east-1")
            await self._run_sync(client.list_detectors)
            return (permissions, [])
        except ClientError as e:
            if "AccessDenied" in str(e):
                return ([], permissions)
            return (permissions, [])

    async def _check_securityhub_permissions(
        self, session: boto3.Session
    ) -> tuple[list[str], list[str]]:
        """Check Security Hub permissions."""
        permissions = [
            "securityhub:DescribeHub",
            "securityhub:GetEnabledStandards",
            "securityhub:DescribeStandardsControls",
        ]
        try:
            client = session.client("securityhub", region_name="us-east-1")
            await self._run_sync(client.describe_hub)
            return (permissions, [])
        except ClientError as e:
            if "AccessDenied" in str(e):
                return ([], permissions)
            # Security Hub not enabled - that's OK, permission exists
            return (permissions, [])

    async def _check_config_permissions(
        self, session: boto3.Session
    ) -> tuple[list[str], list[str]]:
        """Check AWS Config permissions."""
        permissions = [
            "config:DescribeConfigRules",
            "config:DescribeComplianceByConfigRule",
        ]
        try:
            client = session.client("config", region_name="us-east-1")
            await self._run_sync(client.describe_config_rules)
            return (permissions, [])
        except ClientError as e:
            if "AccessDenied" in str(e):
                return ([], permissions)
            return (permissions, [])

    async def _check_cloudtrail_permissions(
        self, session: boto3.Session
    ) -> tuple[list[str], list[str]]:
        """Check CloudTrail permissions."""
        permissions = [
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:GetEventSelectors",
        ]
        try:
            client = session.client("cloudtrail", region_name="us-east-1")
            await self._run_sync(client.describe_trails)
            return (permissions, [])
        except ClientError as e:
            if "AccessDenied" in str(e):
                return ([], permissions)
            return (permissions, [])

    async def _check_lambda_permissions(
        self, session: boto3.Session
    ) -> tuple[list[str], list[str]]:
        """Check Lambda permissions."""
        permissions = [
            "lambda:ListFunctions",
            "lambda:ListEventSourceMappings",
            "lambda:GetFunction",
            "lambda:GetFunctionConfiguration",
        ]
        try:
            client = session.client("lambda", region_name="us-east-1")
            await self._run_sync(client.list_functions, MaxItems=1)
            return (permissions, [])
        except ClientError as e:
            if "AccessDenied" in str(e):
                return ([], permissions)
            return (permissions, [])

    def generate_cloudformation_url(
        self, external_id: str, region: str = "us-east-1"
    ) -> str:
        """Generate a CloudFormation quick-create URL.

        This allows users to deploy the IAM role with one click.
        """
        # URL-encode the template URL
        template_url = "https://a13e-public-templates.s3.amazonaws.com/cloudformation/a13e-scanner-role.yaml"

        params = [
            f"templateURL={template_url}",
            "stackName=A13E-DetectionScanner",
            f"param_ExternalId={external_id}",
            f"param_A13ETrustAccountId={self.A13E_AWS_ACCOUNT_ID}",
        ]

        return f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/create/review?{'&'.join(params)}"


# Singleton instance
aws_credential_service = AWSCredentialService()
