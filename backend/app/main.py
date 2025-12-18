"""Main FastAPI application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from app.core.config import get_settings
from app.api.routes import accounts, scans, detections, coverage, mappings, health, schedules, alerts, reports
from app.services.scheduler_service import scheduler_service

settings = get_settings()
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("starting_application")
    try:
        await scheduler_service.start()
    except Exception as e:
        logger.error("scheduler_start_failed", error=str(e))
    yield
    # Shutdown
    logger.info("shutting_down_application")
    try:
        await scheduler_service.stop()
    except Exception as e:
        logger.error("scheduler_stop_failed", error=str(e))


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Multi-cloud security detection coverage analysis platform",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(accounts.router, prefix="/api/v1/accounts", tags=["Cloud Accounts"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(detections.router, prefix="/api/v1/detections", tags=["Detections"])
app.include_router(coverage.router, prefix="/api/v1/coverage", tags=["Coverage"])
app.include_router(mappings.router, prefix="/api/v1/mappings", tags=["Mappings"])
app.include_router(schedules.router, prefix="/api/v1/schedules", tags=["Schedules"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
    }
