"""Public API v1 routes.

External API endpoints for integrations and automation.
Requires API key authentication with tier-based rate limiting.
"""

from fastapi import APIRouter

from app.api.v1.public.coverage import router as coverage_router
from app.api.v1.public.detections import router as detections_router
from app.api.v1.public.scans import router as scans_router

router = APIRouter(prefix="/public", tags=["Public API"])

router.include_router(coverage_router)
router.include_router(detections_router)
router.include_router(scans_router)

__all__ = ["router"]
