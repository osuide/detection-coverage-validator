"""Report generation endpoints."""

import io
import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context, require_scope
from app.models.cloud_account import CloudAccount
from app.models.billing import Subscription, AccountTier
from app.services.report_service import ReportService

logger = structlog.get_logger()

router = APIRouter()


def sanitize_filename(name: str) -> str:
    """Sanitise a string for use in Content-Disposition filename.

    Security: Prevents header injection and path traversal by:
    - Removing all characters except alphanumeric, underscore, hyphen
    - Limiting length to 100 characters
    - Providing fallback for empty results
    """
    # Remove all characters except alphanumeric, underscore, hyphen
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
    # Collapse multiple underscores
    safe_name = re.sub(r"_+", "_", safe_name)
    # Strip leading/trailing underscores
    safe_name = safe_name.strip("_")
    # Limit length
    safe_name = safe_name[:100]
    # Fallback if empty
    return safe_name or "report"


async def _require_paid_subscription(db: AsyncSession, organization_id: UUID) -> None:
    """Require a paid subscription to access reports.

    Raises HTTPException 403 if on free tier.
    Reports are a premium feature - free tier users should upgrade.
    """
    result = await db.execute(
        select(Subscription).where(Subscription.organization_id == organization_id)
    )
    subscription = result.scalar_one_or_none()

    is_free = not subscription or subscription.tier in (
        AccountTier.FREE,
        AccountTier.FREE_SCAN,
    )

    if is_free:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "subscription_required",
                "message": "Reports are available on paid plans only. Upgrade to Individual or higher to export reports.",
                "upgrade_url": "/settings/billing",
            },
        )


@router.get(
    "/coverage/csv",
    dependencies=[Depends(require_scope("read:reports"))],
)
async def download_coverage_csv(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Download coverage report as CSV.

    Requires paid subscription (Individual tier or higher).
    """
    # Require paid subscription for reports
    await _require_paid_subscription(db, auth.organization_id)

    # Security: Check account-level ACL
    if not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

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
            "Content-Disposition": f"attachment; filename=coverage_report_{sanitize_filename(account.name)}.csv"
        },
    )


@router.get(
    "/gaps/csv",
    dependencies=[Depends(require_scope("read:reports"))],
)
async def download_gaps_csv(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Download gaps report as CSV.

    Requires paid subscription (Individual tier or higher).
    """
    # Require paid subscription for reports
    await _require_paid_subscription(db, auth.organization_id)

    # Security: Check account-level ACL
    if not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

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
            "Content-Disposition": f"attachment; filename=gaps_report_{sanitize_filename(account.name)}.csv"
        },
    )


@router.get(
    "/detections/csv",
    dependencies=[Depends(require_scope("read:reports"))],
)
async def download_detections_csv(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Download detections report as CSV.

    Requires paid subscription (Individual tier or higher).
    """
    # Require paid subscription for reports
    await _require_paid_subscription(db, auth.organization_id)

    # Security: Check account-level ACL
    if not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

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
            "Content-Disposition": f"attachment; filename=detections_report_{sanitize_filename(account.name)}.csv"
        },
    )


@router.get(
    "/executive/pdf",
    dependencies=[Depends(require_scope("read:reports"))],
)
async def download_executive_pdf(
    cloud_account_id: UUID,
    include_gaps: bool = Query(True, description="Include gap analysis section"),
    include_detections: bool = Query(False, description="Include detection details"),
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Download executive summary PDF report.

    Requires paid subscription (Individual tier or higher).
    """
    # Require paid subscription for reports
    await _require_paid_subscription(db, auth.organization_id)

    # Security: Check account-level ACL
    if not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

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
            add_watermark=False,  # No watermark for paid subscribers
        )

        return StreamingResponse(
            io.BytesIO(pdf_content),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=executive_report_{sanitize_filename(account.name)}.pdf"
            },
        )
    except Exception as e:
        logger.error("pdf_generation_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate PDF report")


@router.get(
    "/full/pdf",
    dependencies=[Depends(require_scope("read:reports"))],
)
async def download_full_pdf(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Download full coverage PDF report with all sections.

    Requires paid subscription (Individual tier or higher).
    """
    # Require paid subscription for reports
    await _require_paid_subscription(db, auth.organization_id)

    # Security: Check account-level ACL
    if not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

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
            add_watermark=False,  # No watermark for paid subscribers
        )

        return StreamingResponse(
            io.BytesIO(pdf_content),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=full_report_{sanitize_filename(account.name)}.pdf"
            },
        )
    except Exception as e:
        logger.error("pdf_generation_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate PDF report")
