"""Cloud credential models for secure AWS/GCP access.

Security Best Practices Implemented:
1. Credentials encrypted at rest using Fernet (AES-128-CBC)
2. External ID for AWS to prevent confused deputy attacks
3. No storage of long-lived access keys (use IAM roles/service accounts)
4. Audit logging of credential access
5. Credential validation before storage
6. Automatic credential rotation reminders
"""

import enum
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

from cryptography.fernet import Fernet
from sqlalchemy import DateTime, Enum as SQLEnum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.config import get_settings


class CredentialType(str, enum.Enum):
    """Type of cloud credential."""

    # AWS: Cross-account IAM role (RECOMMENDED)
    AWS_IAM_ROLE = "aws_iam_role"

    # GCP: Workload Identity Federation (RECOMMENDED)
    GCP_WORKLOAD_IDENTITY = "gcp_workload_identity"

    # GCP: Service Account Key (less secure, but simpler)
    GCP_SERVICE_ACCOUNT_KEY = "gcp_service_account_key"


class CredentialStatus(str, enum.Enum):
    """Status of credential validation."""

    PENDING = "pending"  # Not yet validated
    VALID = "valid"  # Successfully validated
    INVALID = "invalid"  # Validation failed
    EXPIRED = "expired"  # Credential expired
    PERMISSION_ERROR = "permission_error"  # Missing required permissions


class CloudCredential(Base):
    """Secure storage for cloud provider credentials.

    For AWS: Stores Role ARN and External ID (no secrets)
    For GCP: Stores Service Account email or encrypted key
    """

    __tablename__ = "cloud_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Credential type
    credential_type: Mapped[CredentialType] = mapped_column(
        SQLEnum(
            CredentialType,
            name="credential_type",
            create_type=False,
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )

    # Status tracking
    status: Mapped[CredentialStatus] = mapped_column(
        SQLEnum(
            CredentialStatus,
            name="credential_status",
            create_type=False,
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=CredentialStatus.PENDING,
    )
    status_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_validated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # AWS IAM Role fields (not encrypted - these are not secrets)
    aws_role_arn: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    aws_external_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # GCP Workload Identity fields (not encrypted - these are not secrets)
    gcp_project_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    gcp_service_account_email: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    gcp_workload_identity_pool: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )

    # GCP Service Account Key (ENCRYPTED - this IS a secret)
    # Only used for gcp_service_account_key type
    _encrypted_key: Mapped[Optional[str]] = mapped_column(
        "encrypted_key", Text, nullable=True
    )

    # Permission tracking
    granted_permissions: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    missing_permissions: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Metadata
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # M14: Key rotation tracking for audit trail
    key_rotated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    key_rotation_count: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    cloud_account = relationship("CloudAccount", backref="credential")
    organization = relationship("Organization")

    @staticmethod
    def generate_external_id() -> str:
        """Generate a secure external ID for AWS cross-account role.

        External ID prevents confused deputy attacks where a malicious
        actor could trick us into accessing their account using another
        customer's role ARN.

        Format: a13e-{random_hex}
        """
        return f"a13e-{secrets.token_hex(16)}"

    @staticmethod
    def _get_encryption_key() -> bytes:
        """Get encryption key from settings.

        Validates the key by attempting to create a Fernet instance,
        which ensures the key is properly formatted base64.
        """
        settings = get_settings()
        key = settings.credential_encryption_key
        if not key:
            raise ValueError("CREDENTIAL_ENCRYPTION_KEY not configured")
        try:
            # Validate key by creating Fernet instance
            key_value = key.get_secret_value()
            Fernet(key_value.encode())
            return key_value.encode()
        except Exception as e:
            raise ValueError(f"Invalid encryption key: {e}")

    def set_gcp_service_account_key(self, key_json: str) -> None:
        """Encrypt and store GCP service account key.

        WARNING: Service account keys are a security risk.
        Workload Identity Federation is preferred.

        M14: Tracks key rotation for audit trail.
        """
        if self.credential_type != CredentialType.GCP_SERVICE_ACCOUNT_KEY:
            raise ValueError(
                "This credential type does not support service account keys"
            )

        # M14: Track rotation if key already exists
        if self._encrypted_key is not None:
            self.key_rotated_at = datetime.now(timezone.utc)
            self.key_rotation_count = (self.key_rotation_count or 0) + 1

        fernet = Fernet(self._get_encryption_key())
        self._encrypted_key = fernet.encrypt(key_json.encode()).decode()

    def get_gcp_service_account_key(self) -> Optional[str]:
        """Decrypt and retrieve GCP service account key."""
        if not self._encrypted_key:
            return None

        fernet = Fernet(self._get_encryption_key())
        return fernet.decrypt(self._encrypted_key.encode()).decode()

    def clear_sensitive_data(self) -> None:
        """Clear any sensitive data (for credential rotation)."""
        self._encrypted_key = None

    @property
    def is_valid(self) -> bool:
        """Check if credential is currently valid."""
        return self.status == CredentialStatus.VALID

    @property
    def needs_validation(self) -> bool:
        """Check if credential needs re-validation."""
        if self.status == CredentialStatus.PENDING:
            return True
        if not self.last_validated_at:
            return True
        # Re-validate if last check was more than 24 hours ago
        age = datetime.now(timezone.utc) - self.last_validated_at
        return age.total_seconds() > 86400

    def __repr__(self) -> str:
        return (
            f"<CloudCredential {self.credential_type.value} status={self.status.value}>"
        )


# AWS IAM Policy - Exact minimum permissions required
AWS_IAM_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "A13ECloudWatchLogsAccess",
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:DescribeMetricFilters",
                "logs:DescribeSubscriptionFilters",
                "logs:DescribeQueryDefinitions",
            ],
            "Resource": "*",
        },
        {
            "Sid": "A13ECloudWatchAlarmsAccess",
            "Effect": "Allow",
            "Action": [
                "cloudwatch:DescribeAlarms",
                "cloudwatch:DescribeAlarmsForMetric",
            ],
            "Resource": "*",
        },
        {
            "Sid": "A13EEventBridgeAccess",
            "Effect": "Allow",
            "Action": [
                "events:ListRules",
                "events:DescribeRule",
                "events:ListTargetsByRule",
            ],
            "Resource": "*",
        },
        {
            "Sid": "A13EGuardDutyAccess",
            "Effect": "Allow",
            "Action": [
                "guardduty:ListDetectors",
                "guardduty:GetDetector",
                "guardduty:ListFindings",
                "guardduty:GetFindings",
            ],
            "Resource": "*",
        },
        {
            "Sid": "A13ESecurityHubAccess",
            "Effect": "Allow",
            "Action": [
                "securityhub:DescribeHub",
                "securityhub:GetEnabledStandards",
                "securityhub:DescribeStandardsControls",
            ],
            "Resource": "*",
        },
        {
            "Sid": "A13EConfigAccess",
            "Effect": "Allow",
            "Action": [
                "config:DescribeConfigRules",
                "config:DescribeComplianceByConfigRule",
            ],
            "Resource": "*",
        },
        {
            "Sid": "A13ECloudTrailAccess",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors",
            ],
            "Resource": "*",
        },
        {
            "Sid": "A13ELambdaAccess",
            "Effect": "Allow",
            "Action": [
                "lambda:ListFunctions",
                "lambda:ListEventSourceMappings",
                "lambda:GetFunction",
                "lambda:GetFunctionConfiguration",
            ],
            "Resource": "*",
        },
    ],
}

# List of all AWS permissions we request (for UI display)
AWS_REQUIRED_PERMISSIONS = [
    # CloudWatch Logs
    {
        "action": "logs:DescribeLogGroups",
        "service": "CloudWatch Logs",
        "purpose": "List log groups to find metric filters",
    },
    {
        "action": "logs:DescribeMetricFilters",
        "service": "CloudWatch Logs",
        "purpose": "Find detection rules based on log patterns",
    },
    {
        "action": "logs:DescribeSubscriptionFilters",
        "service": "CloudWatch Logs",
        "purpose": "Find log forwarding configurations",
    },
    {
        "action": "logs:DescribeQueryDefinitions",
        "service": "CloudWatch Logs",
        "purpose": "Find saved CloudWatch Logs Insights queries for security monitoring",
    },
    # CloudWatch Alarms
    {
        "action": "cloudwatch:DescribeAlarms",
        "service": "CloudWatch",
        "purpose": "List alerting rules",
    },
    {
        "action": "cloudwatch:DescribeAlarmsForMetric",
        "service": "CloudWatch",
        "purpose": "Find alarms for specific metrics",
    },
    # EventBridge
    {
        "action": "events:ListRules",
        "service": "EventBridge",
        "purpose": "List event-driven detection rules",
    },
    {
        "action": "events:DescribeRule",
        "service": "EventBridge",
        "purpose": "Get rule details and patterns",
    },
    {
        "action": "events:ListTargetsByRule",
        "service": "EventBridge",
        "purpose": "See what actions rules trigger",
    },
    # GuardDuty
    {
        "action": "guardduty:ListDetectors",
        "service": "GuardDuty",
        "purpose": "Check if GuardDuty is enabled",
    },
    {
        "action": "guardduty:GetDetector",
        "service": "GuardDuty",
        "purpose": "Get detector configuration",
    },
    {
        "action": "guardduty:ListFindings",
        "service": "GuardDuty",
        "purpose": "List finding types (not finding details)",
    },
    {
        "action": "guardduty:GetFindings",
        "service": "GuardDuty",
        "purpose": "Get finding metadata for MITRE mapping",
    },
    # Security Hub
    {
        "action": "securityhub:DescribeHub",
        "service": "Security Hub",
        "purpose": "Check if Security Hub is enabled",
    },
    {
        "action": "securityhub:GetEnabledStandards",
        "service": "Security Hub",
        "purpose": "List enabled compliance standards",
    },
    {
        "action": "securityhub:DescribeStandardsControls",
        "service": "Security Hub",
        "purpose": "Get control details",
    },
    # Config
    {
        "action": "config:DescribeConfigRules",
        "service": "AWS Config",
        "purpose": "List compliance rules",
    },
    {
        "action": "config:DescribeComplianceByConfigRule",
        "service": "AWS Config",
        "purpose": "Get rule compliance status",
    },
    # CloudTrail
    {
        "action": "cloudtrail:DescribeTrails",
        "service": "CloudTrail",
        "purpose": "Check audit logging configuration",
    },
    {
        "action": "cloudtrail:GetTrailStatus",
        "service": "CloudTrail",
        "purpose": "Verify trails are active",
    },
    {
        "action": "cloudtrail:GetEventSelectors",
        "service": "CloudTrail",
        "purpose": "Check what events are logged",
    },
    # Lambda
    {
        "action": "lambda:ListFunctions",
        "service": "Lambda",
        "purpose": "Find serverless detection functions",
    },
    {
        "action": "lambda:ListEventSourceMappings",
        "service": "Lambda",
        "purpose": "See function triggers",
    },
    {
        "action": "lambda:GetFunction",
        "service": "Lambda",
        "purpose": "Get function configuration",
    },
    {
        "action": "lambda:GetFunctionConfiguration",
        "service": "Lambda",
        "purpose": "Get runtime settings",
    },
]

# GCP Custom Role Definition
GCP_CUSTOM_ROLE = {
    "title": "A13E Detection Scanner",
    "description": "Minimum permissions for A13E to scan security detection configurations. Read-only access to logging, monitoring, security, and SecOps services.",
    "stage": "GA",
    "includedPermissions": [
        # Cloud Logging - for log-based metrics and sinks
        "logging.logMetrics.list",
        "logging.logMetrics.get",
        "logging.sinks.list",
        "logging.sinks.get",
        # Cloud Monitoring - for alerting policies
        "monitoring.alertPolicies.list",
        "monitoring.alertPolicies.get",
        "monitoring.notificationChannels.list",
        "monitoring.notificationChannels.get",
        # Security Command Center - for findings
        "securitycenter.findings.list",
        "securitycenter.findings.get",
        "securitycenter.sources.list",
        "securitycenter.sources.get",
        # Google SecOps / Chronicle SIEM - for YARA-L detection rules
        # https://cloud.google.com/chronicle/docs/reference/feature-rbac-permissions-roles
        "chronicle.rules.list",
        "chronicle.rules.get",
        "chronicle.detections.list",
        "chronicle.detections.get",
        "chronicle.curatedRuleSets.list",
        "chronicle.curatedRuleSets.get",
        "chronicle.alertGroupingRules.list",
        "chronicle.alertGroupingRules.get",
        "chronicle.referenceLists.list",
        "chronicle.referenceLists.get",
        # Eventarc - for event triggers
        "eventarc.triggers.list",
        "eventarc.triggers.get",
        # Cloud Functions - for function-based detections
        "cloudfunctions.functions.list",
        "cloudfunctions.functions.get",
        # Cloud Run - for containerized detections
        "run.services.list",
        "run.services.get",
        # Required for project info
        "resourcemanager.projects.get",
    ],
}

# List of GCP permissions for UI display
GCP_REQUIRED_PERMISSIONS = [
    # Cloud Logging
    {
        "permission": "logging.logMetrics.list",
        "service": "Cloud Logging",
        "purpose": "List log-based metrics (detection rules)",
    },
    {
        "permission": "logging.logMetrics.get",
        "service": "Cloud Logging",
        "purpose": "Get metric filter details",
    },
    {
        "permission": "logging.sinks.list",
        "service": "Cloud Logging",
        "purpose": "List log export destinations",
    },
    {
        "permission": "logging.sinks.get",
        "service": "Cloud Logging",
        "purpose": "Get sink configuration",
    },
    # Cloud Monitoring
    {
        "permission": "monitoring.alertPolicies.list",
        "service": "Cloud Monitoring",
        "purpose": "List alerting policies",
    },
    {
        "permission": "monitoring.alertPolicies.get",
        "service": "Cloud Monitoring",
        "purpose": "Get alert policy details",
    },
    {
        "permission": "monitoring.notificationChannels.list",
        "service": "Cloud Monitoring",
        "purpose": "List notification channels",
    },
    {
        "permission": "monitoring.notificationChannels.get",
        "service": "Cloud Monitoring",
        "purpose": "Get channel configuration",
    },
    # Security Command Center
    {
        "permission": "securitycenter.findings.list",
        "service": "Security Command Center",
        "purpose": "List security findings",
    },
    {
        "permission": "securitycenter.findings.get",
        "service": "Security Command Center",
        "purpose": "Get finding details for MITRE mapping",
    },
    {
        "permission": "securitycenter.sources.list",
        "service": "Security Command Center",
        "purpose": "List finding sources",
    },
    {
        "permission": "securitycenter.sources.get",
        "service": "Security Command Center",
        "purpose": "Get source configuration",
    },
    # Google SecOps / Chronicle SIEM
    {
        "permission": "chronicle.rules.list",
        "service": "Google SecOps",
        "purpose": "List YARA-L detection rules",
    },
    {
        "permission": "chronicle.rules.get",
        "service": "Google SecOps",
        "purpose": "Get detection rule details",
    },
    {
        "permission": "chronicle.detections.list",
        "service": "Google SecOps",
        "purpose": "List detection alerts",
    },
    {
        "permission": "chronicle.detections.get",
        "service": "Google SecOps",
        "purpose": "Get detection alert details",
    },
    {
        "permission": "chronicle.curatedRuleSets.list",
        "service": "Google SecOps",
        "purpose": "List curated detection rule sets",
    },
    {
        "permission": "chronicle.curatedRuleSets.get",
        "service": "Google SecOps",
        "purpose": "Get curated rule set details",
    },
    {
        "permission": "chronicle.alertGroupingRules.list",
        "service": "Google SecOps",
        "purpose": "List alert grouping rules",
    },
    {
        "permission": "chronicle.alertGroupingRules.get",
        "service": "Google SecOps",
        "purpose": "Get alert grouping rule details",
    },
    {
        "permission": "chronicle.referenceLists.list",
        "service": "Google SecOps",
        "purpose": "List reference data for rules",
    },
    {
        "permission": "chronicle.referenceLists.get",
        "service": "Google SecOps",
        "purpose": "Get reference list details",
    },
    # Eventarc
    {
        "permission": "eventarc.triggers.list",
        "service": "Eventarc",
        "purpose": "List event-driven triggers",
    },
    {
        "permission": "eventarc.triggers.get",
        "service": "Eventarc",
        "purpose": "Get trigger configuration",
    },
    # Cloud Functions
    {
        "permission": "cloudfunctions.functions.list",
        "service": "Cloud Functions",
        "purpose": "List serverless functions",
    },
    {
        "permission": "cloudfunctions.functions.get",
        "service": "Cloud Functions",
        "purpose": "Get function configuration",
    },
    # Cloud Run
    {
        "permission": "run.services.list",
        "service": "Cloud Run",
        "purpose": "List Cloud Run services",
    },
    {
        "permission": "run.services.get",
        "service": "Cloud Run",
        "purpose": "Get service configuration",
    },
    # Resource Manager
    {
        "permission": "resourcemanager.projects.get",
        "service": "Resource Manager",
        "purpose": "Get project metadata",
    },
]

# What we DON'T access (for transparency)
PERMISSIONS_NOT_REQUESTED = {
    "aws": [
        "S3 bucket contents or object data",
        "RDS/DynamoDB database contents",
        "Secrets Manager or Parameter Store values",
        "IAM user credentials or access keys",
        "EC2 instance data or SSH keys",
        "VPC traffic or network logs contents",
        "KMS key material",
        "Any write or modify operations",
    ],
    "gcp": [
        "Cloud Storage bucket contents",
        "BigQuery or Cloud SQL data",
        "Secret Manager secret values",
        "IAM service account keys",
        "Compute Engine instance data or SSH keys",
        "VPC flow log contents",
        "Cloud KMS key material",
        "Any write or modify operations",
    ],
}
