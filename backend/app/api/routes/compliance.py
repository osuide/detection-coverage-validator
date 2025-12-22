"""Compliance framework API endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.security import AuthContext, require_role
from app.models.user import UserRole
from app.models.cloud_account import CloudAccount
from app.models.compliance import (
    ComplianceFramework,
    ComplianceControl,
    ControlTechniqueMapping,
)
from app.schemas.compliance import (
    ComplianceFrameworkResponse,
    ControlResponse,
    TechniqueMappingResponse,
    ComplianceCoverageSummary,
    ComplianceCoverageResponse,
    FamilyCoverageItem,
    ControlGapItem,
    CloudCoverageMetricsResponse,
    MissingTechniqueDetail,
    ControlStatusItem,
    ControlsByStatus,
    ControlsByCloudCategory,
)
from app.services.compliance_service import ComplianceService

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/frameworks", response_model=list[ComplianceFrameworkResponse])
async def list_frameworks(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
) -> list[ComplianceFrameworkResponse]:
    """List all active compliance frameworks."""
    # Get frameworks with control counts
    result = await db.execute(
        select(
            ComplianceFramework,
            func.count(ComplianceControl.id).label("control_count"),
        )
        .outerjoin(ComplianceControl)
        .where(ComplianceFramework.is_active.is_(True))
        .group_by(ComplianceFramework.id)
        .order_by(ComplianceFramework.name)
    )

    frameworks = []
    for row in result.fetchall():
        framework = row[0]
        control_count = row[1]
        frameworks.append(
            ComplianceFrameworkResponse(
                id=framework.id,
                framework_id=framework.framework_id,
                name=framework.name,
                version=framework.version,
                description=framework.description,
                source_url=framework.source_url,
                total_controls=control_count,
                is_active=framework.is_active,
            )
        )

    return frameworks


@router.get("/frameworks/{framework_id}", response_model=ComplianceFrameworkResponse)
async def get_framework(
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
) -> ComplianceFrameworkResponse:
    """Get a specific compliance framework."""
    result = await db.execute(
        select(
            ComplianceFramework,
            func.count(ComplianceControl.id).label("control_count"),
        )
        .outerjoin(ComplianceControl)
        .where(ComplianceFramework.framework_id == framework_id)
        .group_by(ComplianceFramework.id)
    )

    row = result.fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Framework '{framework_id}' not found",
        )

    framework = row[0]
    control_count = row[1]

    return ComplianceFrameworkResponse(
        id=framework.id,
        framework_id=framework.framework_id,
        name=framework.name,
        version=framework.version,
        description=framework.description,
        source_url=framework.source_url,
        total_controls=control_count,
        is_active=framework.is_active,
    )


@router.get("/frameworks/{framework_id}/controls", response_model=list[ControlResponse])
async def list_controls(
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
) -> list[ControlResponse]:
    """List all controls in a framework."""
    # Get framework first
    framework_result = await db.execute(
        select(ComplianceFramework).where(
            ComplianceFramework.framework_id == framework_id
        )
    )
    framework = framework_result.scalar_one_or_none()
    if not framework:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Framework '{framework_id}' not found",
        )

    # Get controls with technique mapping counts
    result = await db.execute(
        select(
            ComplianceControl,
            func.count(ControlTechniqueMapping.id).label("mapping_count"),
        )
        .outerjoin(ControlTechniqueMapping)
        .where(ComplianceControl.framework_id == framework.id)
        .group_by(ComplianceControl.id)
        .order_by(ComplianceControl.display_order)
    )

    controls = []
    for row in result.fetchall():
        control = row[0]
        mapping_count = row[1]
        controls.append(
            ControlResponse(
                id=control.id,
                control_id=control.control_id,
                control_family=control.control_family,
                name=control.name,
                description=control.description,
                priority=control.priority,
                is_enhancement=control.is_enhancement,
                mapped_technique_count=mapping_count,
                cloud_applicability=control.cloud_applicability,
                cloud_context=control.cloud_context,
            )
        )

    return controls


@router.get(
    "/controls/{control_id}/techniques", response_model=list[TechniqueMappingResponse]
)
async def get_control_techniques(
    control_id: UUID,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
) -> list[TechniqueMappingResponse]:
    """Get MITRE techniques mapped to a control."""
    result = await db.execute(
        select(ControlTechniqueMapping)
        .where(ControlTechniqueMapping.control_id == control_id)
        .options(selectinload(ControlTechniqueMapping.technique))
    )

    mappings = result.scalars().all()

    return [
        TechniqueMappingResponse(
            technique_id=m.technique.technique_id,
            technique_name=m.technique.name,
            mapping_type=m.mapping_type,
            mapping_source=m.mapping_source,
        )
        for m in mappings
    ]


@router.get(
    "/coverage/{cloud_account_id}", response_model=list[ComplianceCoverageSummary]
)
async def get_compliance_summary(
    cloud_account_id: UUID,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
) -> list[ComplianceCoverageSummary]:
    """Get compliance coverage summary for all frameworks."""
    # Verify access to account
    account = await db.get(CloudAccount, cloud_account_id)
    if not account or account.organization_id != auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found",
        )

    service = ComplianceService(db)
    summaries = await service.get_compliance_summary(cloud_account_id)

    return [ComplianceCoverageSummary(**s) for s in summaries]


@router.get(
    "/coverage/{cloud_account_id}/{framework_id}",
    response_model=ComplianceCoverageResponse,
)
async def get_framework_coverage(
    cloud_account_id: UUID,
    framework_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.VIEWER, UserRole.ADMIN, UserRole.OWNER)
    ),
) -> ComplianceCoverageResponse:
    """Get detailed compliance coverage for a specific framework."""
    # Verify access to account
    account = await db.get(CloudAccount, cloud_account_id)
    if not account or account.organization_id != auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found",
        )

    service = ComplianceService(db)
    snapshot = await service.get_framework_coverage(cloud_account_id, framework_id)

    if not snapshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No coverage data found for framework '{framework_id}'",
        )

    # Get control count for framework response
    control_count_result = await db.execute(
        select(func.count(ComplianceControl.id)).where(
            ComplianceControl.framework_id == snapshot.framework_id
        )
    )
    control_count = control_count_result.scalar() or 0

    # Build response
    family_coverage = [
        FamilyCoverageItem(**fc) for fc in snapshot.family_coverage.values()
    ]

    # Enrich gaps with technique details and template availability
    top_gaps = []
    for gap in snapshot.top_gaps:
        missing_techniques = gap.get("missing_techniques", [])
        enriched_techniques = await service.enrich_gap_techniques(missing_techniques)

        top_gaps.append(
            ControlGapItem(
                control_id=gap.get("control_id", ""),
                control_name=gap.get("control_name", ""),
                control_family=gap.get("control_family", ""),
                priority=gap.get("priority"),
                coverage_percent=gap.get("coverage_percent", 0.0),
                missing_techniques=missing_techniques,
                missing_technique_details=[
                    MissingTechniqueDetail(**t) for t in enriched_techniques
                ],
                cloud_applicability=gap.get("cloud_applicability"),
                cloud_context=gap.get("cloud_context"),
            )
        )

    # Build cloud metrics response if available
    cloud_metrics = None
    if snapshot.cloud_metrics:
        cloud_metrics = CloudCoverageMetricsResponse(**snapshot.cloud_metrics)

    # Get controls grouped by status and cloud category for clickable cards
    by_status, by_cloud = await service.get_controls_by_status(
        cloud_account_id, framework_id
    )

    controls_by_status = ControlsByStatus(
        covered=[ControlStatusItem(**c) for c in by_status.get("covered", [])],
        partial=[ControlStatusItem(**c) for c in by_status.get("partial", [])],
        uncovered=[ControlStatusItem(**c) for c in by_status.get("uncovered", [])],
        not_assessable=[
            ControlStatusItem(**c) for c in by_status.get("not_assessable", [])
        ],
    )

    controls_by_cloud_category = ControlsByCloudCategory(
        cloud_detectable=[
            ControlStatusItem(**c) for c in by_cloud.get("cloud_detectable", [])
        ],
        customer_responsibility=[
            ControlStatusItem(**c) for c in by_cloud.get("customer_responsibility", [])
        ],
        provider_managed=[
            ControlStatusItem(**c) for c in by_cloud.get("provider_managed", [])
        ],
        not_assessable=[
            ControlStatusItem(**c) for c in by_cloud.get("not_assessable", [])
        ],
    )

    return ComplianceCoverageResponse(
        id=snapshot.id,
        cloud_account_id=snapshot.cloud_account_id,
        framework=ComplianceFrameworkResponse(
            id=snapshot.framework.id,
            framework_id=snapshot.framework.framework_id,
            name=snapshot.framework.name,
            version=snapshot.framework.version,
            description=snapshot.framework.description,
            source_url=snapshot.framework.source_url,
            total_controls=control_count,
            is_active=snapshot.framework.is_active,
        ),
        total_controls=snapshot.total_controls,
        covered_controls=snapshot.covered_controls,
        partial_controls=snapshot.partial_controls,
        uncovered_controls=snapshot.uncovered_controls,
        coverage_percent=snapshot.coverage_percent,
        cloud_metrics=cloud_metrics,
        family_coverage=family_coverage,
        top_gaps=top_gaps,
        controls_by_status=controls_by_status,
        controls_by_cloud_category=controls_by_cloud_category,
        created_at=snapshot.created_at,
    )
