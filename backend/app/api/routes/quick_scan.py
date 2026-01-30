"""Quick scan API endpoint — public, no authentication.

Security controls:
- Rate limited: 5 requests per 5 minutes per IP
- Content size: 250 KB maximum
- Parse timeout: 10 seconds
- No database writes
- Request body logged to SENSITIVE_PATHS (no content logged)
- CORS: Allow all origins via per-path middleware (public endpoint)
- Error logging sanitised — no user content in logs
"""

import asyncio

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.deps.rate_limit import quick_scan_rate_limit
from app.core.security import get_client_ip
from app.services.quick_scan_service import run_quick_scan

logger = structlog.get_logger()

router = APIRouter(tags=["Quick Scan"])


class QuickScanRequest(BaseModel):
    """Request body for quick scan endpoint.

    v1 is Terraform-only — no format field (YAGNI).
    """

    content: str = Field(
        ...,
        min_length=1,
        max_length=256_000,
        description="Terraform HCL configuration content",
    )


class QuickScanSummary(BaseModel):
    """Coverage summary."""

    total_techniques: int
    covered_techniques: int
    coverage_percentage: float
    detections_found: int
    resources_parsed: int
    truncated: bool


class QuickScanDetection(BaseModel):
    """Detected security control."""

    name: str
    source_arn: str
    detection_type: str


class QuickScanGap(BaseModel):
    """Coverage gap."""

    technique_id: str
    technique_name: str
    tactic_name: str
    priority: str


class QuickScanResponse(BaseModel):
    """Response from quick scan endpoint."""

    summary: QuickScanSummary
    tactic_coverage: dict
    top_gaps: list[QuickScanGap]
    detections: list[QuickScanDetection]
    error: str | None = None


@router.post(
    "/analyse",
    response_model=QuickScanResponse,
    dependencies=[Depends(quick_scan_rate_limit())],
    summary="Analyse Terraform configuration for MITRE ATT&CK coverage",
    description="Public endpoint — no authentication required. "
    "Paste Terraform HCL content to get instant coverage analysis.",
)
async def analyse_quick_scan(
    request: Request,
    body: QuickScanRequest,
) -> QuickScanResponse:
    """Analyse Terraform HCL content for detection coverage."""
    client_ip = get_client_ip(request)
    logger.info(
        "quick_scan_request",
        client_ip=client_ip,
        content_length=len(body.content),
    )

    try:
        result = await run_quick_scan(body.content)
    except ValueError as e:
        logger.warning(
            "quick_scan_validation_error",
            client_ip=client_ip,
            error=str(e),
        )
        raise HTTPException(status_code=422, detail=str(e))
    except asyncio.TimeoutError:
        logger.warning(
            "quick_scan_timeout",
            client_ip=client_ip,
            content_length=len(body.content),
        )
        raise HTTPException(
            status_code=408,
            detail="Parse timeout — content too complex. Try a smaller configuration.",
        )
    except Exception:
        # SANITISED: Do NOT log str(e) — parser errors may contain user content
        logger.error(
            "quick_scan_error",
            client_ip=client_ip,
            error_type="parse_failure",
        )
        raise HTTPException(
            status_code=422,
            detail="Failed to parse Terraform content. Ensure valid HCL syntax.",
        )

    logger.info(
        "quick_scan_complete",
        client_ip=client_ip,
        detections_found=result["summary"]["detections_found"],
        coverage_pct=result["summary"]["coverage_percentage"],
    )

    return QuickScanResponse(**result)
