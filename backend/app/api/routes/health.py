"""Health check endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import structlog

from app.core.database import get_db
from app.core.config import get_settings

router = APIRouter()
settings = get_settings()
logger = structlog.get_logger()


@router.get("/health")
async def health_check():
    """Basic health check."""
    return {"status": "healthy", "version": settings.app_version}


@router.get("/health/ready")
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """Readiness check including database connectivity."""
    try:
        await db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        # Log full error server-side but return generic status
        logger.error("database_health_check_failed", error=str(e))
        db_status = "unavailable"

    return {
        "status": "ready" if db_status == "connected" else "not_ready",
        "database": db_status,
        "version": settings.app_version,
    }
