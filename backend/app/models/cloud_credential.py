"""Cloud credential models for secure AWS/GCP access.

Security Best Practices Implemented:
1. No stored secrets - AWS uses IAM role assumption, GCP uses WIF
2. External ID for AWS to prevent confused deputy attacks
3. Audit logging of credential access
4. Credential validation before use
5. Short-lived credentials (1 hour max for GCP WIF)
"""

import enum
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import DateTime, Enum as SQLEnum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class CredentialType(str, enum.Enum):
    """Type of cloud credential."""

    # AWS: Cross-account IAM role
    AWS_IAM_ROLE = "aws_iam_role"

    # GCP: Workload Identity Federation (keyless, secure)
    GCP_WORKLOAD_IDENTITY = "gcp_workload_identity"


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
    For GCP: Stores WIF configuration (no secrets - keyless authentication)

    Security: No long-lived secrets are stored. AWS uses IAM role assumption,
    GCP uses Workload Identity Federation for short-lived credentials.
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
    # WIF pool name - stores pool ID (e.g., "a13e-pool")
    gcp_workload_identity_pool: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True
    )
    # WIF provider ID within the pool (e.g., "aws" for AWS federation)
    gcp_wif_provider_id: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, default="aws"
    )
    # WIF pool location (always "global" for AWS federation)
    gcp_wif_pool_location: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, default="global"
    )

    # Legacy encrypted key column - kept for schema compatibility
    # Not used: GCP uses WIF (no stored secrets)
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

    def clear_sensitive_data(self) -> None:
        """Clear any sensitive data (legacy - no secrets stored with WIF)."""
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

    @property
    def is_gcp_wif(self) -> bool:
        """Check if this credential uses GCP Workload Identity Federation."""
        return self.credential_type == CredentialType.GCP_WORKLOAD_IDENTITY

    def get_wif_configuration(self) -> Optional[Any]:
        """Get WIF configuration for this credential.

        Returns:
            WIFConfiguration object if this is a WIF credential, None otherwise
        """
        if not self.is_gcp_wif:
            return None

        if not self.gcp_project_id or not self.gcp_service_account_email:
            return None

        # Import here to avoid circular imports
        from app.services.gcp_wif_service import WIFConfiguration

        return WIFConfiguration(
            project_id=self.gcp_project_id,
            pool_location=self.gcp_wif_pool_location or "global",
            pool_id=self.gcp_workload_identity_pool or "a13e-pool",
            provider_id=self.gcp_wif_provider_id or "aws",
            service_account_email=self.gcp_service_account_email,
        )

    def set_wif_configuration(
        self,
        project_id: str,
        service_account_email: str,
        pool_id: str = "a13e-pool",
        provider_id: str = "aws",
        pool_location: str = "global",
    ) -> None:
        """Set WIF configuration fields.

        Args:
            project_id: GCP project ID
            service_account_email: Service account to impersonate
            pool_id: WIF pool ID
            provider_id: WIF provider ID (default: aws)
            pool_location: WIF pool location (default: global)
        """
        self.credential_type = CredentialType.GCP_WORKLOAD_IDENTITY
        self.gcp_project_id = project_id
        self.gcp_service_account_email = service_account_email
        self.gcp_workload_identity_pool = pool_id
        self.gcp_wif_provider_id = provider_id
        self.gcp_wif_pool_location = pool_location
        # Clear any encrypted key since WIF doesn't use it
        self._encrypted_key = None

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
                # Core Security Hub APIs
                "securityhub:DescribeHub",
                "securityhub:GetEnabledStandards",
                "securityhub:GetInsights",
                "securityhub:GetFindings",  # Required for compliance posture data
                # Legacy standards-based API (for backward compatibility)
                "securityhub:DescribeStandardsControls",
                # New CSPM consolidated controls APIs
                "securityhub:ListSecurityControlDefinitions",
                "securityhub:BatchGetSecurityControls",
                "securityhub:ListStandardsControlAssociations",
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
        "action": "securityhub:GetInsights",
        "service": "Security Hub",
        "purpose": "List Security Hub insights",
    },
    {
        "action": "securityhub:GetFindings",
        "service": "Security Hub",
        "purpose": "Get compliance findings for Security Posture data",
    },
    {
        "action": "securityhub:DescribeStandardsControls",
        "service": "Security Hub",
        "purpose": "Get control details (legacy API)",
    },
    {
        "action": "securityhub:ListSecurityControlDefinitions",
        "service": "Security Hub CSPM",
        "purpose": "List all security control definitions",
    },
    {
        "action": "securityhub:BatchGetSecurityControls",
        "service": "Security Hub CSPM",
        "purpose": "Get control details and status",
    },
    {
        "action": "securityhub:ListStandardsControlAssociations",
        "service": "Security Hub CSPM",
        "purpose": "Check control enablement per standard",
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
        # Google SecOps / Chronicle SIEM - for YARA-L detection rules (read-only)
        # Requires Chronicle API Viewer role (roles/chronicle.viewer)
        # https://cloud.google.com/iam/docs/roles-permissions/chronicle
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
