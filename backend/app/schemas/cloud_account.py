"""Cloud account schemas."""

import re
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.models.cloud_account import CloudProvider


# AWS account IDs are exactly 12 digits
AWS_ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")

# GCP project IDs: 6-30 chars, lowercase letters, digits, hyphens
# Must start with a letter, cannot end with hyphen
GCP_PROJECT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


class CloudAccountBase(BaseModel):
    """Base cloud account schema."""

    name: str = Field(..., min_length=1, max_length=255)
    provider: CloudProvider
    account_id: str = Field(..., min_length=1, max_length=64)
    regions: list[str] = Field(default_factory=list)
    description: Optional[str] = None


class CloudAccountCreate(CloudAccountBase):
    """Schema for creating a cloud account."""

    credentials_arn: Optional[str] = None

    @model_validator(mode="after")
    def validate_account_id_format(self) -> "CloudAccountCreate":
        """Validate account_id format based on provider."""
        if self.provider == CloudProvider.AWS:
            if not AWS_ACCOUNT_ID_PATTERN.match(self.account_id):
                raise ValueError(
                    "AWS account ID must be exactly 12 digits (e.g., 123456789012)"
                )
        elif self.provider == CloudProvider.GCP:
            if not GCP_PROJECT_ID_PATTERN.match(self.account_id):
                raise ValueError(
                    "GCP project ID must be 6-30 characters, start with a letter, "
                    "contain only lowercase letters, digits, and hyphens, "
                    "and cannot end with a hyphen (e.g., my-project-123)"
                )
        return self


class CloudAccountUpdate(BaseModel):
    """Schema for updating a cloud account."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    regions: Optional[list[str]] = None
    description: Optional[str] = None
    credentials_arn: Optional[str] = None
    is_active: Optional[bool] = None


class CloudAccountResponse(CloudAccountBase):
    """Schema for cloud account response."""

    id: UUID
    is_active: bool
    last_scan_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
