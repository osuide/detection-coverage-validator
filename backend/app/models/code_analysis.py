"""Code analysis consent and configuration models.

This feature allows paying customers to opt-in to deeper code analysis
of their Lambda functions and IaC templates for more accurate MITRE mappings.

IMPORTANT: This feature requires explicit user consent due to:
- Access to actual source code
- Potential exposure of business logic
- Security considerations around code handling
"""

import enum
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class CodeAnalysisScope(str, enum.Enum):
    """Scope of code analysis consent."""
    LAMBDA_FUNCTIONS = "lambda_functions"
    CLOUDFORMATION = "cloudformation"
    TERRAFORM = "terraform"
    ALL = "all"


class CodeAnalysisConsent(Base):
    """Tracks user consent for code analysis feature.

    This model ensures we have explicit, auditable consent before
    accessing any user source code.
    """

    __tablename__ = "code_analysis_consents"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    organization_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False
    )
    cloud_account_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        nullable=False
    )

    # Consent details
    consent_given: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    consent_given_by: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    consent_given_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Scope of consent
    scope: Mapped[CodeAnalysisScope] = mapped_column(
        Enum(CodeAnalysisScope, name='code_analysis_scope', create_type=False),
        nullable=False, default=CodeAnalysisScope.ALL
    )

    # What they acknowledged
    acknowledged_risks: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    acknowledged_data_handling: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Revocation
    consent_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    consent_revoked_by: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    consent_revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revocation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    organization = relationship("Organization")
    cloud_account = relationship("CloudAccount")
    consenter = relationship("User", foreign_keys=[consent_given_by])
    revoker = relationship("User", foreign_keys=[consent_revoked_by])

    @property
    def is_active(self) -> bool:
        """Check if consent is currently active (given and not revoked)."""
        return self.consent_given and not self.consent_revoked

    def __repr__(self) -> str:
        status = "active" if self.is_active else "inactive"
        return f"<CodeAnalysisConsent {self.cloud_account_id} ({status})>"


# Disclosure text for UI
CODE_ANALYSIS_DISCLOSURE = {
    "title": "Enhanced Detection Analysis",
    "summary": "Opt-in to deeper code analysis for more accurate MITRE ATT&CK mappings.",
    "benefits": [
        "Up to 40% more accurate technique mappings",
        "Detection of security logic in Lambda functions",
        "IaC template analysis (CloudFormation, Terraform)",
        "SDK call pattern recognition for precise coverage assessment",
    ],
    "what_we_access": [
        "Lambda function source code (Python, Node.js, Go)",
        "CloudFormation and Terraform templates",
        "Function environment variables (secrets are redacted)",
        "IAM roles and policies attached to functions",
    ],
    "what_we_dont_do": [
        "We never execute your code",
        "We never store raw source code beyond analysis",
        "We never share code with third parties",
        "We never access production data or databases",
    ],
    "data_handling": {
        "processing": "Code is analyzed in-memory during scans",
        "storage": "Only extracted patterns and mappings are stored",
        "retention": "No source code is retained after analysis",
        "encryption": "All transfers use TLS 1.3 encryption",
    },
    "risks": [
        "Requires additional IAM permissions (lambda:GetFunction)",
        "Analysis may reveal business logic patterns in mappings",
        "Increased scan duration due to code download and parsing",
    ],
    "can_revoke": True,
    "revoke_effect": "Future scans will use metadata-only analysis. Existing mappings from code analysis will be marked as 'legacy'.",
}


# Additional IAM permissions required for code analysis
CODE_ANALYSIS_IAM_PERMISSIONS = {
    "lambda": [
        "lambda:GetFunction",  # Download function code
        "lambda:GetFunctionConfiguration",
        "lambda:ListFunctions",
    ],
    "cloudformation": [
        "cloudformation:GetTemplate",  # Get CFN templates
        "cloudformation:ListStacks",
        "cloudformation:DescribeStacks",
    ],
    "s3": [
        "s3:GetObject",  # For Terraform state files (optional)
    ],
}
