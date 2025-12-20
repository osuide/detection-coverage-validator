"""Pydantic schemas for API request/response validation."""

from app.schemas.cloud_account import (
    CloudAccountCreate,
    CloudAccountUpdate,
    CloudAccountResponse,
)
from app.schemas.cloud_organization import (
    CloudOrganizationCreate,
    CloudOrganizationUpdate,
    CloudOrganizationResponse,
    CloudOrganizationSummary,
    CloudOrganizationMemberResponse,
    CloudOrganizationMemberSummary,
    DiscoverOrganizationRequest,
    DiscoverOrganizationResponse,
    ConnectMembersRequest,
    ConnectMembersResponse,
)
from app.schemas.detection import DetectionResponse
from app.schemas.scan import ScanCreate, ScanResponse
from app.schemas.coverage import CoverageResponse, TacticCoverage, GapItem
from app.schemas.mapping import MappingResponse

__all__ = [
    # Cloud accounts
    "CloudAccountCreate",
    "CloudAccountUpdate",
    "CloudAccountResponse",
    # Cloud organisations
    "CloudOrganizationCreate",
    "CloudOrganizationUpdate",
    "CloudOrganizationResponse",
    "CloudOrganizationSummary",
    "CloudOrganizationMemberResponse",
    "CloudOrganizationMemberSummary",
    "DiscoverOrganizationRequest",
    "DiscoverOrganizationResponse",
    "ConnectMembersRequest",
    "ConnectMembersResponse",
    # Detections
    "DetectionResponse",
    # Scans
    "ScanCreate",
    "ScanResponse",
    # Coverage
    "CoverageResponse",
    "TacticCoverage",
    "GapItem",
    # Mappings
    "MappingResponse",
]
