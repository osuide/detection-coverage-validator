"""Main FastAPI application."""

import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

from app.core.config import get_settings
from app.api.routes import (
    accounts,
    scans,
    detections,
    coverage,
    mappings,
    health,
    schedules,
    alerts,
    reports,
    auth,
    teams,
    api_keys,
    audit,
    cognito,
    org_security,
    billing,
    code_analysis,
    credentials,
    github_oauth,
    recommendations,
    cloud_organizations,
    analytics,
    custom_detections,
    compliance,
)
from app.api.routes.admin import router as admin_router
from app.api.v1.public import router as public_api_router
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.services.scheduler_service import scheduler_service


# === Security: Request Logging Middleware ===
# Excludes sensitive endpoints from body logging


class SecureLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs requests while protecting sensitive data."""

    # Endpoints where request/response bodies should NOT be logged
    SENSITIVE_PATHS = {
        "/api/v1/auth/login",
        "/api/v1/auth/signup",
        "/api/v1/auth/login/mfa",
        "/api/v1/auth/reset-password",
        "/api/v1/auth/change-password",
        "/api/v1/credentials/gcp",  # Contains service account keys
        "/api/v1/credentials/aws",  # Contains role ARNs
    }

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        logger = structlog.get_logger()

        # Determine if this is a sensitive endpoint
        is_sensitive = any(
            request.url.path.startswith(path) for path in self.SENSITIVE_PATHS
        )

        # Log request (without body for sensitive endpoints)
        log_data = {
            "method": request.method,
            "path": request.url.path,
            "client_ip": request.headers.get(
                "X-Forwarded-For", request.client.host if request.client else "unknown"
            ),
        }

        if is_sensitive:
            log_data["body"] = "[REDACTED - sensitive endpoint]"

        response = await call_next(request)

        # Log response
        duration_ms = (time.time() - start_time) * 1000
        log_data["status_code"] = response.status_code
        log_data["duration_ms"] = round(duration_ms, 2)

        if response.status_code >= 400:
            logger.warning("http_request", **log_data)
        else:
            logger.info("http_request", **log_data)

        return response


settings = get_settings()
logger = structlog.get_logger()


def run_migrations():
    """Run database migrations on startup using subprocess."""
    import subprocess

    try:
        result = subprocess.run(
            ["alembic", "upgrade", "head"],
            cwd="/app",
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            logger.info(
                "migrations_completed",
                output=result.stdout[-500:] if result.stdout else "",
            )
        else:
            logger.warning(
                "migrations_failed",
                stderr=result.stderr[-500:] if result.stderr else "",
            )
    except Exception as e:
        logger.warning("migrations_failed", error=str(e))


def seed_mitre_data():
    """Seed MITRE ATT&CK data if not already present."""
    import json
    from uuid import uuid4
    from datetime import datetime, timezone
    from sqlalchemy import create_engine, text
    from app.scripts.seed_mitre import TACTICS, TECHNIQUES

    database_url = os.environ.get("DATABASE_URL", "").replace("+asyncpg", "")
    if not database_url:
        logger.warning("mitre_seed_skipped", reason="DATABASE_URL not set")
        return

    try:
        engine = create_engine(database_url)
        with engine.connect() as conn:
            # Check if techniques already exist
            result = conn.execute(text("SELECT COUNT(*) FROM techniques"))
            count = result.scalar()
            if count > 0:
                logger.info(
                    "mitre_seed_skipped", reason=f"{count} techniques already exist"
                )
                return

            now = datetime.now(timezone.utc)

            # Get existing tactics (may have been partially inserted)
            existing_tactics = {}
            result = conn.execute(text("SELECT tactic_id, id FROM tactics"))
            for row in result:
                existing_tactics[row[0]] = str(row[1])

            # Insert missing tactics
            tactics_added = 0
            for tactic_id, name, short_name, display_order in TACTICS:
                if tactic_id not in existing_tactics:
                    tactic_uuid = str(uuid4())
                    conn.execute(
                        text(
                            """
                            INSERT INTO tactics (id, tactic_id, name, short_name, display_order, mitre_version, created_at)
                            VALUES (:id, :tactic_id, :name, :short_name, :display_order, :mitre_version, :created_at)
                            ON CONFLICT (tactic_id) DO NOTHING
                        """
                        ),
                        {
                            "id": tactic_uuid,
                            "tactic_id": tactic_id,
                            "name": name,
                            "short_name": short_name,
                            "display_order": display_order,
                            "mitre_version": "14.1",
                            "created_at": now,
                        },
                    )
                    existing_tactics[tactic_id] = tactic_uuid
                    tactics_added += 1
            conn.commit()

            # Refresh tactics to get any that were inserted by conflict
            result = conn.execute(text("SELECT tactic_id, id FROM tactics"))
            existing_tactics = {row[0]: str(row[1]) for row in result}

            # Insert techniques (skip duplicates - same technique can appear under multiple tactics)
            seen_techniques = set()
            techniques_added = 0
            for technique_id, name, tactic_id, description in TECHNIQUES:
                if technique_id in seen_techniques:
                    continue
                seen_techniques.add(technique_id)

                tactic_uuid = existing_tactics.get(tactic_id)
                if not tactic_uuid:
                    continue

                is_subtechnique = "." in technique_id
                parent_id = None
                if is_subtechnique:
                    parent_tech_id = technique_id.split(".")[0]
                    # Look up parent in DB
                    parent_result = conn.execute(
                        text("SELECT id FROM techniques WHERE technique_id = :tid"),
                        {"tid": parent_tech_id},
                    )
                    parent_row = parent_result.fetchone()
                    if parent_row:
                        parent_id = str(parent_row[0])

                tech_uuid = str(uuid4())
                conn.execute(
                    text(
                        """
                        INSERT INTO techniques (
                            id, technique_id, name, description, tactic_id, parent_technique_id,
                            platforms, mitre_version, is_subtechnique, created_at, updated_at
                        )
                        VALUES (
                            :id, :technique_id, :name, :description, :tactic_id, :parent_id,
                            CAST(:platforms AS jsonb), :mitre_version, :is_subtechnique, :created_at, :updated_at
                        )
                        ON CONFLICT (technique_id) DO NOTHING
                    """
                    ),
                    {
                        "id": tech_uuid,
                        "technique_id": technique_id,
                        "name": name,
                        "description": description,
                        "tactic_id": tactic_uuid,
                        "parent_id": parent_id,
                        "platforms": json.dumps(["AWS", "Azure", "GCP", "IaaS"]),
                        "mitre_version": "14.1",
                        "is_subtechnique": is_subtechnique,
                        "created_at": now,
                        "updated_at": now,
                    },
                )
                techniques_added += 1
            conn.commit()

            logger.info(
                "mitre_seeded",
                tactics_added=tactics_added,
                techniques_added=techniques_added,
            )
    except Exception as e:
        logger.warning("mitre_seed_failed", error=str(e))


def seed_admin_user():
    """Seed initial admin user for staging/production if not exists."""
    import secrets
    import bcrypt
    from sqlalchemy import create_engine, text

    env = os.environ.get("ENVIRONMENT", "development")
    if env == "development":
        logger.info("Skipping admin seed in development environment")
        return

    try:
        database_url = settings.database_url.replace("+asyncpg", "")
        engine = create_engine(database_url)

        with engine.connect() as conn:
            result = conn.execute(
                text("SELECT id FROM admin_users WHERE email = :email"),
                {"email": "admin@a13e.com"},
            )
            existing = result.fetchone()

            if existing:
                logger.info("admin_user_exists", email="admin@a13e.com")
                return

            # Check for environment variable first, otherwise generate random password
            admin_password = os.environ.get("INITIAL_ADMIN_PASSWORD")

            if not admin_password:
                # Generate cryptographically secure password
                admin_password = secrets.token_urlsafe(16)
                # Log once for operator to save - this is the only time it will be shown
                logger.critical(
                    "generated_initial_admin_password",
                    password=admin_password,
                    email="admin@a13e.com",
                    message="SAVE THIS PASSWORD IMMEDIATELY - it will not be shown again",
                )

            # Hash the password with bcrypt
            password_hash = bcrypt.hashpw(
                admin_password.encode(), bcrypt.gensalt(12)
            ).decode()

            from uuid import uuid4

            admin_id = uuid4()
            conn.execute(
                text(
                    """
                    INSERT INTO admin_users (
                        id, email, password_hash, role, full_name,
                        mfa_enabled, is_active, failed_login_attempts,
                        requires_password_change
                    ) VALUES (
                        :id, :email, :password_hash, 'super_admin', :full_name,
                        false, true, 0, true
                    )
                """
                ),
                {
                    "id": admin_id,
                    "email": "admin@a13e.com",
                    "password_hash": password_hash,
                    "full_name": "Platform Admin",
                },
            )
            conn.commit()

            logger.info(
                "admin_user_created",
                email="admin@a13e.com",
                admin_id=str(admin_id),
                password_from_env=bool(os.environ.get("INITIAL_ADMIN_PASSWORD")),
            )
    except Exception as e:
        logger.warning("admin_seed_failed", error=str(e))


async def seed_compliance_data():
    """Seed compliance framework data if not present."""
    from app.core.database import AsyncSessionLocal
    from app.data.compliance_mappings.loader import ComplianceMappingLoader

    try:
        async with AsyncSessionLocal() as db:
            loader = ComplianceMappingLoader(db)
            result = await loader.load_all()
            # Commit the loaded data
            await db.commit()
            if result.get("frameworks_loaded", 0) > 0:
                logger.info(
                    "compliance_data_seeded",
                    frameworks=result.get("frameworks_loaded"),
                    controls=result.get("total_controls"),
                    mappings=result.get("total_mappings"),
                )
            else:
                logger.debug("compliance_data_already_present")
    except Exception as e:
        logger.warning("compliance_seed_failed", error=str(e))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("starting_application")

    # Run migrations on startup
    run_migrations()

    # Seed MITRE data if not present
    seed_mitre_data()

    # Seed admin user for staging/production
    seed_admin_user()

    # Seed compliance framework data if not present
    await seed_compliance_data()

    # Initialise Redis-backed rate limiter
    from app.api.deps.rate_limit import init_rate_limiter, close_rate_limiter

    try:
        await init_rate_limiter()
    except Exception as e:
        logger.error("rate_limiter_init_failed", error=str(e))

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
    try:
        await close_rate_limiter()
    except Exception as e:
        logger.error("rate_limiter_close_failed", error=str(e))


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Multi-cloud security detection coverage analysis platform",
    lifespan=lifespan,
)

# CORS middleware - origins from environment or defaults for local dev
cors_origins_str = os.environ.get(
    "CORS_ORIGINS", "http://localhost:3000,http://localhost:3001,http://localhost:5173"
)
cors_origins = [origin.strip() for origin in cors_origins_str.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    # Explicitly list allowed methods and headers for security
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Request-ID",
        "X-Correlation-ID",
        "Accept",
        "Accept-Language",
        "Cache-Control",
    ],
    expose_headers=["X-Total-Count", "X-Page-Count", "X-Request-ID"],
)

# Add secure logging middleware (excludes sensitive endpoint bodies from logs)
app.add_middleware(SecureLoggingMiddleware)

# Add security headers middleware (X-Frame-Options, HSTS, CSP, etc.)
app.add_middleware(SecurityHeadersMiddleware)

# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(accounts.router, prefix="/api/v1/accounts", tags=["Cloud Accounts"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(detections.router, prefix="/api/v1/detections", tags=["Detections"])
app.include_router(coverage.router, prefix="/api/v1/coverage", tags=["Coverage"])
app.include_router(mappings.router, prefix="/api/v1/mappings", tags=["Mappings"])
app.include_router(schedules.router, prefix="/api/v1/schedules", tags=["Schedules"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(teams.router, prefix="/api/v1/teams", tags=["Team Management"])
app.include_router(api_keys.router, prefix="/api/v1/api-keys", tags=["API Keys"])
app.include_router(audit.router, prefix="/api/v1/audit-logs", tags=["Audit Logs"])
app.include_router(cognito.router, prefix="/api/v1/auth/cognito", tags=["Cognito SSO"])
app.include_router(github_oauth.router, prefix="/api/v1/auth", tags=["GitHub OAuth"])
app.include_router(
    org_security.router, prefix="/api/v1/org", tags=["Organization Security"]
)
app.include_router(billing.router, prefix="/api/v1/billing", tags=["Billing"])
app.include_router(
    code_analysis.router, prefix="/api/v1/code-analysis", tags=["Code Analysis"]
)
app.include_router(
    credentials.router, prefix="/api/v1/credentials", tags=["Cloud Credentials"]
)
app.include_router(
    recommendations.router, prefix="/api/v1/recommendations", tags=["Recommendations"]
)
app.include_router(
    cloud_organizations.router,
    prefix="/api/v1/cloud-organizations",
    tags=["Cloud Organisations"],
)
app.include_router(analytics.router, prefix="/api/v1/analytics", tags=["Analytics"])
app.include_router(
    custom_detections.router,
    prefix="/api/v1/custom-detections",
    tags=["Custom Detections"],
)
app.include_router(
    compliance.router,
    prefix="/api/v1",
    tags=["Compliance"],
)

# Admin Portal routes (separate from user routes)
app.include_router(admin_router, prefix="/api/v1/admin")

# Public API routes (API key authentication)
app.include_router(public_api_router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
    }
