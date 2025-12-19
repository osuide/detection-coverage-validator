"""Admin portal API routes."""

from fastapi import APIRouter

from app.api.routes.admin.auth import router as auth_router
from app.api.routes.admin.organizations import router as org_router
from app.api.routes.admin.metrics import router as metrics_router
from app.api.routes.admin.settings import router as settings_router
from app.api.routes.admin.users import router as users_router
from app.api.routes.admin.audit_logs import router as audit_logs_router
from app.api.routes.admin.billing import router as billing_router
from app.api.routes.admin.admins import router as admins_router

# Create admin router - note: prefix is set in main.py as /api/v1/admin
router = APIRouter(tags=["Admin Portal"])

# Include sub-routers
router.include_router(auth_router)
router.include_router(org_router)
router.include_router(metrics_router)
router.include_router(settings_router)
router.include_router(users_router)
router.include_router(audit_logs_router)
router.include_router(billing_router)
router.include_router(admins_router)

__all__ = ["router"]
