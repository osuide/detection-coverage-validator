"""Cloud organisation schemas."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.cloud_account import CloudProvider
from app.models.cloud_organization import (
    CloudOrganizationStatus,
    CloudOrganizationMemberStatus,
)


# ============================================================================
# CloudOrganization Schemas
# ============================================================================


class CloudOrganizationBase(BaseModel):
    """Base cloud organisation schema."""

    provider: CloudProvider
    cloud_org_id: str = Field(..., min_length=1, max_length=128)
    name: str = Field(..., min_length=1, max_length=255)


class CloudOrganizationCreate(CloudOrganizationBase):
    """Schema for initiating a cloud organisation connection."""

    credentials_arn: Optional[str] = None
    master_account_id: Optional[str] = None


class CloudOrganizationUpdate(BaseModel):
    """Schema for updating a cloud organisation."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    credentials_arn: Optional[str] = None
    status: Optional[CloudOrganizationStatus] = None


class CloudOrganizationResponse(CloudOrganizationBase):
    """Schema for cloud organisation response."""

    id: UUID
    organization_id: UUID
    root_email: Optional[str] = None
    master_account_id: Optional[str] = None
    status: CloudOrganizationStatus
    delegated_admins: Optional[dict] = None
    total_accounts_discovered: int
    total_accounts_connected: int
    discovered_at: datetime
    connected_at: Optional[datetime] = None
    last_sync_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CloudOrganizationSummary(BaseModel):
    """Summary view of a cloud organisation."""

    id: UUID
    provider: CloudProvider
    name: str
    status: CloudOrganizationStatus
    total_accounts_discovered: int
    total_accounts_connected: int
    last_sync_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ============================================================================
# CloudOrganizationMember Schemas
# ============================================================================


class CloudOrganizationMemberBase(BaseModel):
    """Base cloud organisation member schema."""

    member_account_id: str = Field(..., min_length=1, max_length=64)
    member_name: str = Field(..., min_length=1, max_length=255)
    member_email: Optional[str] = None
    hierarchy_path: Optional[str] = None


class CloudOrganizationMemberResponse(CloudOrganizationMemberBase):
    """Schema for cloud organisation member response."""

    id: UUID
    cloud_organization_id: UUID
    cloud_account_id: Optional[UUID] = None
    parent_id: Optional[str] = None
    status: CloudOrganizationMemberStatus
    join_method: Optional[str] = None
    joined_at: Optional[datetime] = None
    lifecycle_state: Optional[str] = None
    error_message: Optional[str] = None
    discovered_at: datetime
    connected_at: Optional[datetime] = None
    updated_at: datetime

    class Config:
        from_attributes = True


class CloudOrganizationMemberSummary(BaseModel):
    """Summary view of an organisation member."""

    id: UUID
    member_account_id: str
    member_name: str
    status: CloudOrganizationMemberStatus
    hierarchy_path: Optional[str] = None
    is_connected: bool = False

    class Config:
        from_attributes = True


# ============================================================================
# Discovery Request/Response Schemas
# ============================================================================


class DiscoverOrganizationRequest(BaseModel):
    """Request to discover accounts in a cloud organisation.

    For AWS: Provide credentials_arn (IAM role ARN)
    For GCP: Provide gcp_org_id and gcp_service_account_email
    """

    provider: CloudProvider

    # AWS-specific fields
    credentials_arn: Optional[str] = Field(
        None,
        min_length=1,
        description="ARN of the IAM role to assume (AWS)",
    )

    # GCP-specific fields
    gcp_org_id: Optional[str] = Field(
        None,
        min_length=1,
        description="GCP organisation ID (numeric)",
    )
    gcp_service_account_email: Optional[str] = Field(
        None,
        description="GCP service account email for impersonation",
    )
    gcp_project_id: Optional[str] = Field(
        None,
        description="GCP project ID linked to the service account",
    )


class DiscoverOrganizationResponse(BaseModel):
    """Response from organisation discovery."""

    cloud_organization: CloudOrganizationResponse
    members: list[CloudOrganizationMemberSummary]
    total_discovered: int


class ConnectMembersRequest(BaseModel):
    """Request to connect selected member accounts."""

    member_ids: list[UUID] = Field(
        ..., min_items=1, description="IDs of members to connect"
    )


class ConnectMembersResponse(BaseModel):
    """Response from connecting member accounts."""

    connected: int
    failed: int
    errors: list[dict] = []
