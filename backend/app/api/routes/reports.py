"""Report generation endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import io

from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context
from app.models.cloud_account import CloudAccount
from app.services.report_service import ReportService

router = APIRouter()


@router.get("/coverage/csv")
async def download_coverage_csv(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Download coverage report as CSV."""
    # Verify account exists and belongs to user's organization
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    service = ReportService(db)
    csv_content = await service.generate_csv_report(cloud_account_id, "coverage")

    return StreamingResponse(
        io.StringIO(csv_content),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=coverage_report_{account.name}.csv"
        },
    )


@router.get("/gaps/csv")
async def download_gaps_csv(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Download gaps report as CSV."""
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    service = ReportService(db)
    csv_content = await service.generate_csv_report(cloud_account_id, "gaps")

    return StreamingResponse(
        io.StringIO(csv_content),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=gaps_report_{account.name}.csv"
        },
    )


@router.get("/detections/csv")
async def download_detections_csv(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Download detections report as CSV."""
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    service = ReportService(db)
    csv_content = await service.generate_csv_report(cloud_account_id, "detections")

    return StreamingResponse(
        io.StringIO(csv_content),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=detections_report_{account.name}.csv"
        },
    )


@router.get("/executive/pdf")
async def download_executive_pdf(
    cloud_account_id: UUID,
    include_gaps: bool = Query(True, description="Include gap analysis section"),
    include_detections: bool = Query(False, description="Include detection details"),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Download executive summary PDF report."""
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    try:
        service = ReportService(db)
        pdf_content = await service.generate_pdf_report(
            cloud_account_id,
            include_executive_summary=True,
            include_gap_analysis=include_gaps,
            include_detection_details=include_detections,
        )

        return StreamingResponse(
            io.BytesIO(pdf_content),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=executive_report_{account.name}.pdf"
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")


@router.get("/full/pdf")
async def download_full_pdf(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Download full coverage PDF report with all sections."""
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    try:
        service = ReportService(db)
        pdf_content = await service.generate_pdf_report(
            cloud_account_id,
            include_executive_summary=True,
            include_gap_analysis=True,
            include_detection_details=True,
        )

        return StreamingResponse(
            io.BytesIO(pdf_content),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=full_report_{account.name}.pdf"
            },
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")
