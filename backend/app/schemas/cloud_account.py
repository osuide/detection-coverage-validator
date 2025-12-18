"""Cloud account schemas."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.cloud_account import CloudProvider


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
