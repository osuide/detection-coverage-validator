"""Quick scan API endpoint — public, no authentication.

Security controls:
- Rate limited: 5 requests per 5 minutes per IP
- Content size: 128K chars (128 KB for ASCII HCL)
- Concurrency: max 5 concurrent scans (semaphore with 5s acquire timeout)
- Pipeline timeout: 30 seconds via asyncio.wait_for
- Parse timeout: 10 seconds (HCL parser level)
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

# Limit concurrent scans to prevent resource exhaustion
_scan_semaphore = asyncio.Semaphore(5)


class QuickScanRequest(BaseModel):
    """Request body for quick scan endpoint.

    v1 is Terraform-only — no format field (YAGNI).
    """

    content: str = Field(
        ...,
        min_length=1,
        max_length=128_000,
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


class QuickScanTechnique(BaseModel):
    """Per-technique coverage info for the MITRE ATT&CK heatmap."""

    technique_id: str
    technique_name: str
    tactic_id: str
    detection_count: int
    max_confidence: float
    status: str


class QuickScanResponse(BaseModel):
    """Response from quick scan endpoint."""

    summary: QuickScanSummary
    tactic_coverage: dict
    technique_coverage: list[QuickScanTechnique] = []
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

    # Acquire concurrency semaphore (with timeout to avoid indefinite queueing)
    try:
        async with asyncio.timeout(5):
            await _scan_semaphore.acquire()
    except TimeoutError:
        raise HTTPException(
            status_code=429,
            detail="Service busy — too many concurrent scans. Try again shortly.",
        )

    try:
        result = await asyncio.wait_for(run_quick_scan(body.content), timeout=30)
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
    except Exception as exc:
        logger.error(
            "quick_scan_error",
            client_ip=client_ip,
            error_type="parse_failure",
            exc_class=type(exc).__qualname__,
        )
        raise HTTPException(
            status_code=422,
            detail="Failed to parse Terraform content. Ensure valid HCL syntax.",
        )
    finally:
        _scan_semaphore.release()  # Always release — acquire succeeded before try block

    logger.info(
        "quick_scan_complete",
        client_ip=client_ip,
        detections_found=result["summary"]["detections_found"],
        coverage_pct=result["summary"]["coverage_percentage"],
    )

    return QuickScanResponse(**result)
