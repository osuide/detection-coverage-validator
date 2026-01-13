"""Custom detection upload and management endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context, require_scope, require_role
from app.models.user import UserRole
from app.models.custom_detection import (
    CustomDetectionFormat,
    CustomDetectionStatus,
)
from app.services.custom_detection_service import CustomDetectionService


router = APIRouter()


# Request/Response Models


class CustomDetectionCreate(BaseModel):
    """Request to create a custom detection."""

    name: str
    rule_content: str
    format: CustomDetectionFormat
    description: Optional[str] = None
    cloud_account_id: Optional[UUID] = None
    tags: Optional[list[str]] = None
    severity: Optional[str] = None


class MappingUpdate(BaseModel):
    """Request to update technique mapping."""

    techniques: list[str]
    notes: Optional[str] = None


class CustomDetectionResponse(BaseModel):
    """Custom detection response."""

    id: str
    name: str
    description: Optional[str]
    format: str
    status: str
    cloud_account_id: Optional[str]
    mapped_techniques: Optional[list[str]]
    mapping_confidence: Optional[float]
    mapping_notes: Optional[str]
    tags: Optional[list[str]]
    severity: Optional[str]
    created_at: str
    processed_at: Optional[str]


class CustomDetectionDetailResponse(CustomDetectionResponse):
    """Detailed custom detection response including rule content."""

    rule_content: str
    rule_metadata: Optional[dict]
    processing_error: Optional[str]
    data_sources: Optional[list[str]]


class CustomDetectionListResponse(BaseModel):
    """List of custom detections."""

    items: list[CustomDetectionResponse]
    total: int
    limit: int
    offset: int


class BatchUploadResponse(BaseModel):
    """Response after batch upload."""

    batch_id: str
    filename: str
    status: str
    total_rules: int
    processed_rules: int
    successful_rules: int
    failed_rules: int


class MappingSummaryResponse(BaseModel):
    """Custom detection mapping summary."""

    total_detections: int
    by_status: dict
    by_format: dict
    unique_techniques_mapped: int


# Endpoints


@router.post(
    "",
    response_model=CustomDetectionResponse,
    dependencies=[
        Depends(require_scope("write:detections")),
        Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    ],
)
async def create_custom_detection(
    request: CustomDetectionCreate,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Upload a single custom detection rule.

    The detection will be automatically mapped to MITRE ATT&CK techniques
    based on rule content analysis. Supported formats include SIGMA, YARA,
    SPL (Splunk), KQL (Kusto), and CloudWatch.

    API keys require 'write:detections' scope.
    """
    if not auth.organization_id or not auth.user_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    service = CustomDetectionService(db)
    detection = await service.upload_detection(
        organization_id=auth.organization_id,
        user_id=auth.user_id,
        name=request.name,
        rule_content=request.rule_content,
        format=request.format,
        description=request.description,
        cloud_account_id=request.cloud_account_id,
        tags=request.tags,
        severity=request.severity,
    )

    return CustomDetectionResponse(
        id=str(detection.id),
        name=detection.name,
        description=detection.description,
        format=detection.format.value,
        status=detection.status.value,
        cloud_account_id=(
            str(detection.cloud_account_id) if detection.cloud_account_id else None
        ),
        mapped_techniques=detection.mapped_techniques,
        mapping_confidence=detection.mapping_confidence,
        mapping_notes=detection.mapping_notes,
        tags=detection.tags,
        severity=detection.severity,
        created_at=detection.created_at.isoformat(),
        processed_at=(
            detection.processed_at.isoformat() if detection.processed_at else None
        ),
    )


@router.post(
    "/batch",
    response_model=BatchUploadResponse,
    dependencies=[
        Depends(require_scope("write:detections")),
        Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    ],
)
async def upload_batch(
    file: UploadFile = File(...),
    format: CustomDetectionFormat = Form(...),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Upload a batch of detection rules from a file.

    Supports SIGMA YAML files (multiple documents), YARA files
    (multiple rules), or line-separated query files.
    """
    if not auth.organization_id or not auth.user_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Security: Check file size BEFORE reading full content to prevent memory exhaustion
    max_size = 1024 * 1024  # 1MB limit
    chunks = []
    total_size = 0

    # Read in chunks and check size incrementally
    while True:
        chunk = await file.read(8192)  # 8KB chunks
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > max_size:
            raise HTTPException(
                status_code=400,
                detail="File too large. Maximum size is 1MB.",
            )
        chunks.append(chunk)

    content = b"".join(chunks)

    try:
        content_str = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="File must be UTF-8 encoded text",
        )

    service = CustomDetectionService(db)
    batch = await service.upload_batch(
        organization_id=auth.organization_id,
        user_id=auth.user_id,
        filename=file.filename or "uploaded_file",
        content=content_str,
        format=format,
    )

    return BatchUploadResponse(
        batch_id=str(batch.id),
        filename=batch.filename,
        status=batch.status.value,
        total_rules=batch.total_rules,
        processed_rules=batch.processed_rules,
        successful_rules=batch.successful_rules,
        failed_rules=batch.failed_rules,
    )


@router.get("", response_model=CustomDetectionListResponse)
async def list_custom_detections(
    cloud_account_id: Optional[UUID] = None,
    status: Optional[CustomDetectionStatus] = None,
    format: Optional[CustomDetectionFormat] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> CustomDetectionListResponse:
    """List custom detections with optional filtering."""
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    # SECURITY: Check allowed_account_ids ACL when filtering by account
    if cloud_account_id and not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    service = CustomDetectionService(db)
    detections, total = await service.list_detections(
        organization_id=auth.organization_id,
        cloud_account_id=cloud_account_id,
        status=status,
        format=format,
        limit=limit,
        offset=offset,
    )

    items = [
        CustomDetectionResponse(
            id=str(d.id),
            name=d.name,
            description=d.description,
            format=d.format.value,
            status=d.status.value,
            cloud_account_id=str(d.cloud_account_id) if d.cloud_account_id else None,
            mapped_techniques=d.mapped_techniques,
            mapping_confidence=d.mapping_confidence,
            mapping_notes=d.mapping_notes,
            tags=d.tags,
            severity=d.severity,
            created_at=d.created_at.isoformat(),
            processed_at=d.processed_at.isoformat() if d.processed_at else None,
        )
        for d in detections
    ]

    return CustomDetectionListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/summary", response_model=MappingSummaryResponse)
async def get_mapping_summary(
    cloud_account_id: Optional[UUID] = None,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> MappingSummaryResponse:
    """Get summary statistics for custom detection mappings."""
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    # SECURITY: Check allowed_account_ids ACL when filtering by account
    if cloud_account_id and not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    service = CustomDetectionService(db)
    summary = await service.get_mapping_summary(auth.organization_id, cloud_account_id)

    return MappingSummaryResponse(**summary)


@router.get("/{detection_id}", response_model=CustomDetectionDetailResponse)
async def get_custom_detection(
    detection_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> CustomDetectionDetailResponse:
    """Get details of a specific custom detection."""
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = CustomDetectionService(db)
    detection = await service.get_detection(detection_id, auth.organization_id)

    if not detection:
        raise HTTPException(status_code=404, detail="Custom detection not found")

    return CustomDetectionDetailResponse(
        id=str(detection.id),
        name=detection.name,
        description=detection.description,
        format=detection.format.value,
        status=detection.status.value,
        cloud_account_id=(
            str(detection.cloud_account_id) if detection.cloud_account_id else None
        ),
        mapped_techniques=detection.mapped_techniques,
        mapping_confidence=detection.mapping_confidence,
        mapping_notes=detection.mapping_notes,
        tags=detection.tags,
        severity=detection.severity,
        created_at=detection.created_at.isoformat(),
        processed_at=(
            detection.processed_at.isoformat() if detection.processed_at else None
        ),
        rule_content=detection.rule_content,
        rule_metadata=detection.rule_metadata,
        processing_error=detection.processing_error,
        data_sources=detection.data_sources,
    )


@router.patch(
    "/{detection_id}/mapping",
    response_model=CustomDetectionResponse,
    dependencies=[Depends(require_scope("write:detections"))],
)
async def update_mapping(
    detection_id: UUID,
    request: MappingUpdate,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Manually update the MITRE technique mapping for a detection.

    Use this when automatic mapping was unsuccessful or needs refinement.

    API keys require 'write:detections' scope.
    """
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = CustomDetectionService(db)
    detection = await service.update_mapping(
        detection_id=detection_id,
        organization_id=auth.organization_id,
        techniques=request.techniques,
        notes=request.notes,
    )

    if not detection:
        raise HTTPException(status_code=404, detail="Custom detection not found")

    return CustomDetectionResponse(
        id=str(detection.id),
        name=detection.name,
        description=detection.description,
        format=detection.format.value,
        status=detection.status.value,
        cloud_account_id=(
            str(detection.cloud_account_id) if detection.cloud_account_id else None
        ),
        mapped_techniques=detection.mapped_techniques,
        mapping_confidence=detection.mapping_confidence,
        mapping_notes=detection.mapping_notes,
        tags=detection.tags,
        severity=detection.severity,
        created_at=detection.created_at.isoformat(),
        processed_at=(
            detection.processed_at.isoformat() if detection.processed_at else None
        ),
    )


@router.delete(
    "/{detection_id}",
    dependencies=[
        Depends(require_scope("write:detections")),
        Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    ],
)
async def delete_custom_detection(
    detection_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a custom detection.

    API keys require 'write:detections' scope.
    """
    if not auth.organization_id:
        raise HTTPException(status_code=401, detail="Organisation context required")

    service = CustomDetectionService(db)
    success = await service.delete_detection(detection_id, auth.organization_id)

    if not success:
        raise HTTPException(status_code=404, detail="Custom detection not found")

    return {"message": "Custom detection deleted"}


@router.get("/formats/supported")
async def get_supported_formats() -> dict:
    """Get list of supported detection rule formats."""
    return {
        "formats": [
            {
                "id": CustomDetectionFormat.SIGMA.value,
                "name": "SIGMA",
                "description": "Generic signature format for SIEM systems",
                "file_extensions": [".yml", ".yaml"],
            },
            {
                "id": CustomDetectionFormat.YARA.value,
                "name": "YARA",
                "description": "Pattern matching rules for malware research",
                "file_extensions": [".yar", ".yara"],
            },
            {
                "id": CustomDetectionFormat.SPL.value,
                "name": "SPL",
                "description": "Splunk Processing Language queries",
                "file_extensions": [".spl", ".txt"],
            },
            {
                "id": CustomDetectionFormat.KQL.value,
                "name": "KQL",
                "description": "Kusto Query Language (Microsoft Sentinel)",
                "file_extensions": [".kql", ".txt"],
            },
            {
                "id": CustomDetectionFormat.CLOUDWATCH.value,
                "name": "CloudWatch",
                "description": "AWS CloudWatch Logs Insights queries",
                "file_extensions": [".txt"],
            },
            {
                "id": CustomDetectionFormat.ELASTICSEARCH.value,
                "name": "Elasticsearch",
                "description": "Elasticsearch DSL queries",
                "file_extensions": [".json"],
            },
            {
                "id": CustomDetectionFormat.SNORT.value,
                "name": "Snort",
                "description": "Snort IDS/IPS rules",
                "file_extensions": [".rules"],
            },
            {
                "id": CustomDetectionFormat.SURICATA.value,
                "name": "Suricata",
                "description": "Suricata IDS/IPS rules",
                "file_extensions": [".rules"],
            },
            {
                "id": CustomDetectionFormat.CUSTOM.value,
                "name": "Custom",
                "description": "Custom detection format",
                "file_extensions": [".txt"],
            },
        ]
    }
