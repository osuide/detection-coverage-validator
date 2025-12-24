"""Admin portal API routes."""

import logging

from fastapi import APIRouter

from app.api.routes.admin.auth import router as auth_router
from app.api.routes.admin.organizations import router as org_router
from app.api.routes.admin.metrics import router as metrics_router
from app.api.routes.admin.settings import router as settings_router
from app.api.routes.admin.users import router as users_router
from app.api.routes.admin.audit_logs import router as audit_logs_router
from app.api.routes.admin.billing import router as billing_router
from app.api.routes.admin.admins import router as admins_router
from app.api.routes.admin.fingerprints import router as fingerprints_router
from app.api.routes.admin.fraud import router as fraud_router

# MITRE router requires optional mitreattack-python package
try:
    from app.api.routes.admin.mitre import router as mitre_router

    MITRE_AVAILABLE = True
except ImportError:
    logging.warning("mitreattack-python not installed - MITRE admin routes disabled")
    mitre_router = None
    MITRE_AVAILABLE = False

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
router.include_router(fingerprints_router)
router.include_router(fraud_router)
if MITRE_AVAILABLE:
    router.include_router(mitre_router)

__all__ = ["router"]
