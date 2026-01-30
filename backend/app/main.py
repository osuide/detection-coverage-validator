"""Main FastAPI application."""

import os
import time
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager

import uuid

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
import structlog
from prometheus_fastapi_instrumentator import Instrumentator

from app.core.config import get_settings
from app.core.security import get_client_ip
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
    techniques,
    gaps,
    evaluation_history,
    webauthn,
    support,
    workspace_setup,
)
from app.api.routes.admin import router as admin_router
from app.api.routes.quick_scan import router as quick_scan_router
from app.api.v1.public import router as public_api_router
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.services.scheduler_service import scheduler_service
from app.core.metrics import record_request

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
        "/api/v1/quick-scan",  # Untrusted user content — do not log body
    }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
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
            "client_ip": get_client_ip(request) or "unknown",
        }

        if is_sensitive:
            log_data["body"] = "[REDACTED - sensitive endpoint]"

        response = await call_next(request)

        # Log response
        duration_ms = (time.time() - start_time) * 1000
        log_data["status_code"] = response.status_code
        log_data["duration_ms"] = round(duration_ms, 2)

        # Record metrics for admin dashboard
        record_request(duration_ms, response.status_code, request.url.path)

        if response.status_code >= 400:
            logger.warning("http_request", **log_data)
        else:
            logger.info("http_request", **log_data)

        return response


settings = get_settings()
logger = structlog.get_logger()


def run_migrations() -> None:
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


def seed_mitre_data() -> None:
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
                        text("""
                            INSERT INTO tactics (id, tactic_id, name, short_name, display_order, mitre_version, created_at)
                            VALUES (:id, :tactic_id, :name, :short_name, :display_order, :mitre_version, :created_at)
                            ON CONFLICT (tactic_id) DO NOTHING
                        """),
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

                # Assign platforms based on tactic
                # Reconnaissance (TA0043) and Resource Development (TA0042) are PRE-compromise
                # and not part of the MITRE ATT&CK Cloud Matrix
                if tactic_id in ("TA0043", "TA0042"):
                    platforms = ["PRE"]
                else:
                    platforms = ["AWS", "Azure", "GCP", "IaaS"]

                conn.execute(
                    text("""
                        INSERT INTO techniques (
                            id, technique_id, name, description, tactic_id, parent_technique_id,
                            platforms, mitre_version, is_subtechnique, created_at, updated_at
                        )
                        VALUES (
                            :id, :technique_id, :name, :description, :tactic_id, :parent_id,
                            CAST(:platforms AS jsonb), :mitre_version, :is_subtechnique, :created_at, :updated_at
                        )
                        ON CONFLICT (technique_id) DO NOTHING
                    """),
                    {
                        "id": tech_uuid,
                        "technique_id": technique_id,
                        "name": name,
                        "description": description,
                        "tactic_id": tactic_uuid,
                        "parent_id": parent_id,
                        "platforms": json.dumps(platforms),
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


def seed_admin_user() -> None:
    """Seed initial admin user for staging/production if not exists."""
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

            # SECURITY: Require password from environment variable - never generate/print
            admin_password = os.environ.get("INITIAL_ADMIN_PASSWORD")

            if not admin_password:
                logger.error(
                    "admin_seed_failed",
                    error="INITIAL_ADMIN_PASSWORD environment variable is required",
                    message="Set via Secrets Manager or Terraform variables",
                )
                return  # Don't fail startup, just skip seeding

            if len(admin_password) < 16:
                logger.error(
                    "admin_seed_failed",
                    error="INITIAL_ADMIN_PASSWORD must be at least 16 characters",
                )
                return

            # Hash the password with bcrypt
            password_hash = bcrypt.hashpw(
                admin_password.encode(), bcrypt.gensalt(12)
            ).decode()

            from uuid import uuid4

            admin_id = uuid4()
            conn.execute(
                text("""
                    INSERT INTO admin_users (
                        id, email, password_hash, role, full_name,
                        mfa_enabled, is_active, failed_login_attempts,
                        requires_password_change
                    ) VALUES (
                        :id, :email, :password_hash, 'super_admin', :full_name,
                        false, true, 0, true
                    )
                """),
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
            )
    except Exception as e:
        logger.warning("admin_seed_failed", error=str(e))


async def seed_compliance_data() -> None:
    """Seed compliance framework data if not present.

    Set FORCE_RELOAD_COMPLIANCE=true to clear and reload all compliance data.
    This is useful when the JSON source files have been updated.
    """
    from app.core.database import AsyncSessionLocal
    from app.data.compliance_mappings.loader import ComplianceMappingLoader

    force_reload = os.environ.get("FORCE_RELOAD_COMPLIANCE", "").lower() == "true"

    try:
        async with AsyncSessionLocal() as db:
            loader = ComplianceMappingLoader(db)

            if force_reload:
                logger.info("force_reloading_compliance_data")
                await loader.clear_all()
                await db.commit()

            result = await loader.load_all()
            # Commit the loaded data
            await db.commit()
            if result.get("frameworks_loaded", 0) > 0:
                logger.info(
                    "compliance_data_seeded",
                    frameworks=result.get("frameworks_loaded"),
                    controls=result.get("total_controls"),
                    mappings=result.get("total_mappings"),
                    force_reload=force_reload,
                )
            else:
                logger.debug("compliance_data_already_present")
    except Exception as e:
        logger.warning("compliance_seed_failed", error=str(e))


def _verify_production_security() -> None:
    """
    Verify security-critical configuration at startup.
    Fails fast if dangerous configuration detected.

    SECURITY: DEV_MODE bypasses AWS credential validation entirely.
    This must NEVER be enabled in production or staging environments.
    """
    env = os.getenv("ENVIRONMENT", "development").lower()
    dev_mode = os.getenv("A13E_DEV_MODE", "").lower() == "true"

    if dev_mode and env in ("production", "prod", "staging"):
        logger.critical(
            "security_violation_blocked",
            reason="DEV_MODE cannot be enabled in production/staging",
            environment=env,
            alert="CRITICAL_SECURITY",
        )
        raise RuntimeError(
            f"FATAL: A13E_DEV_MODE=true is not allowed in {env} environment. "
            "This bypasses credential validation and is a security risk."
        )

    if dev_mode:
        logger.warning(
            "dev_mode_active",
            environment=env,
            warning="AWS credential validation is bypassed - for development only",
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan events."""
    # Startup
    logger.info("starting_application")

    # SECURITY: Verify production security configuration first
    _verify_production_security()

    # Run migrations on startup
    run_migrations()

    # Seed MITRE data if not present
    seed_mitre_data()

    # Seed admin user for staging/production
    seed_admin_user()

    # Seed compliance framework data if not present
    await seed_compliance_data()

    # Initialise Redis-backed rate limiter and cache
    from app.api.deps.rate_limit import init_rate_limiter, close_rate_limiter
    from app.core.cache import init_cache, close_cache

    try:
        await init_rate_limiter()
    except Exception as e:
        logger.error("rate_limiter_init_failed", error=str(e))
        # SECURITY: In staging/production, rate limiting is required
        if settings.environment not in ("development",):
            raise RuntimeError(
                f"Rate limiter initialisation failed: {e}. "
                "Cannot start without rate limiting in staging/production."
            )

    try:
        await init_cache()
    except Exception as e:
        logger.warning("cache_init_failed", error=str(e))

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
    try:
        await close_cache()
    except Exception as e:
        logger.warning("cache_close_failed", error=str(e))


# SECURITY: Disable internal API documentation in production
# /docs (Swagger) and /openapi.json (full internal spec) are only for development/staging
# /redoc uses /public/openapi.json (public API only) and is available in all environments
docs_url = "/docs" if settings.environment in ("development", "staging") else None
openapi_url = (
    "/openapi.json" if settings.environment in ("development", "staging") else None
)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Multi-cloud security detection coverage analysis platform",
    lifespan=lifespan,
    docs_url=docs_url,
    redoc_url=None,  # Disabled - using custom dark theme endpoint below
    openapi_url=openapi_url,
)

# Mount static files for self-hosted ReDoc (CSP-compliant)
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# === Per-path CORS for public quick-scan endpoint ===
# The main CORSMiddleware uses allow_credentials=True with an origin
# allowlist, so we cannot add wildcard '*' there. This class-based
# middleware is registered via add_middleware() AFTER CORSMiddleware,
# which makes it run BEFORE CORSMiddleware in the request chain
# (Starlette processes last-added middleware outermost). This ensures
# quick-scan requests are handled with open CORS headers before the
# restrictive CORSMiddleware can reject unknown origins.


class QuickScanCORSMiddleware(BaseHTTPMiddleware):
    """Per-path CORS for the public quick-scan endpoint.

    Must be added AFTER CORSMiddleware via add_middleware() so it
    wraps CORSMiddleware and intercepts requests first.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path.startswith("/api/v1/quick-scan"):
            if request.method == "OPTIONS":
                return Response(
                    status_code=200,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type",
                        "Access-Control-Max-Age": "3600",
                    },
                )
            response = await call_next(request)
            # Remove credentials header — `allow-credentials: true` +
            # `allow-origin: *` is invalid per the CORS spec and browsers
            # silently reject the response.  The quick-scan endpoint is
            # public and never uses credentials.
            if "access-control-allow-credentials" in response.headers:
                del response.headers["access-control-allow-credentials"]
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
            return response
        return await call_next(request)


# === Public API Documentation ===
# Serves ONLY the Public API spec (not internal endpoints)
# The spec is pre-generated by scripts/generate_public_openapi.py

# Path to the public OpenAPI spec (in static folder for Docker compatibility)
PUBLIC_OPENAPI_PATH = Path(__file__).parent / "static" / "docs" / "public-openapi.json"


@app.get("/public/openapi.json", include_in_schema=False)
async def get_public_openapi() -> JSONResponse:
    """Serve the Public API OpenAPI specification.

    SECURITY: This serves ONLY the public API endpoints (/api/v1/public/*).
    Internal, admin, and user-facing endpoints are NOT included.
    The spec is pre-generated by scripts/generate_public_openapi.py.
    """
    if not PUBLIC_OPENAPI_PATH.exists():
        return JSONResponse(
            status_code=404,
            content={
                "detail": "Public API spec not found. Run generate_public_openapi.py"
            },
        )

    import json

    with open(PUBLIC_OPENAPI_PATH) as f:
        spec = json.load(f)

    return JSONResponse(content=spec)


# Custom ReDoc endpoint with dark theme to match app styling
# NOTE: /redoc is available in ALL environments because it serves the PUBLIC API spec only
# (via /public/openapi.json). No internal endpoints are exposed. This is intentional
# for external API integrators who need documentation in production.


@app.get("/redoc", include_in_schema=False)
async def custom_redoc_html() -> HTMLResponse:
    """Serve ReDoc API documentation with dark theme.

    SECURITY: Uses the PUBLIC API spec only - no internal endpoints exposed.
    Uses self-hosted ReDoc bundle for strict CSP compliance.
    No external CDN dependencies.
    """
    return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <title>A13E Public API Reference</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            margin: 0;
            padding: 0;
        }
    </style>
</head>
<body>
    <redoc
        spec-url='/public/openapi.json'
        theme='{
            "colors": {
                "primary": { "main": "#22d3ee" },
                "success": { "main": "#10b981" },
                "warning": { "main": "#f59e0b" },
                "error": { "main": "#ef4444" },
                "text": { "primary": "#1f2937", "secondary": "#4b5563" },
                "http": {
                    "get": "#22d3ee",
                    "post": "#10b981",
                    "put": "#f59e0b",
                    "delete": "#ef4444",
                    "patch": "#a855f7"
                },
                "responses": {
                    "success": { "color": "#10b981", "backgroundColor": "#064e3b" },
                    "error": { "color": "#ef4444", "backgroundColor": "#7f1d1d" },
                    "redirect": { "color": "#f59e0b", "backgroundColor": "#78350f" },
                    "info": { "color": "#3b82f6", "backgroundColor": "#1e3a5f" }
                }
            },
            "typography": {
                "fontSize": "15px",
                "fontFamily": "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif",
                "headings": { "fontFamily": "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, sans-serif" },
                "code": { "fontFamily": "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace", "fontSize": "13px", "backgroundColor": "#1e293b" }
            },
            "sidebar": {
                "backgroundColor": "#0f172a",
                "textColor": "#9ca3af",
                "activeTextColor": "#22d3ee"
            },
            "rightPanel": {
                "backgroundColor": "#1e293b",
                "textColor": "#e2e8f0"
            },
            "schema": {
                "nestedBackground": "#f1f5f9"
            }
        }'
        hide-hostname="true"
        hide-download-button="false"
        native-scrollbars="true"
    ></redoc>
    <script src="/static/docs/redoc.standalone.js"></script>
</body>
</html>
        """)


# === Global Exception Handler ===
# Catches unhandled exceptions and returns generic error messages
# to prevent information disclosure while logging full details server-side
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch unhandled exceptions and return generic error.

    Security: Prevents internal error details from being exposed to clients.
    Full details are logged server-side with request ID for correlation.
    """
    # Get or generate request ID for correlation
    request_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())

    # Log full error server-side for debugging
    logger.error(
        "unhandled_exception",
        request_id=request_id,
        path=request.url.path,
        method=request.method,
        error_type=type(exc).__name__,
        error=str(exc),
        exc_info=True,
    )

    # Return generic error to client with request ID for support reference
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal error occurred. Please try again later.",
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id},
    )


# CORS middleware - origins from environment or defaults for local dev
cors_origins_str = os.environ.get(
    "CORS_ORIGINS", "http://localhost:3000,http://localhost:3001,http://localhost:5173"
)
cors_origins = [
    origin.strip() for origin in cors_origins_str.split(",") if origin.strip()
]


def validate_cors_origins(origins: list[str], environment: str) -> list[str]:
    """Validate CORS origins on startup.

    Security checks:
    - No wildcards (*) allowed
    - Valid URL format required
    - HTTPS required in production (except localhost)
    """
    from urllib.parse import urlparse

    validated = []
    for origin in origins:
        # Reject wildcards
        if origin == "*" or "*" in origin:
            logger.error(
                "cors_wildcard_rejected",
                origin=origin,
                message="Wildcard CORS origins are not allowed",
            )
            continue

        # Parse and validate URL
        try:
            parsed = urlparse(origin)
            if not parsed.scheme or not parsed.netloc:
                logger.error(
                    "cors_invalid_origin",
                    origin=origin,
                    message="Invalid URL format",
                )
                continue

            # Require HTTPS in production (except for localhost)
            is_localhost = parsed.netloc.startswith(
                "localhost"
            ) or parsed.netloc.startswith("127.0.0.1")
            if (
                environment not in ("development", "test")
                and parsed.scheme != "https"
                and not is_localhost
            ):
                logger.error(
                    "cors_insecure_origin",
                    origin=origin,
                    environment=environment,
                    message="HTTPS required for CORS origins in production",
                )
                continue

            validated.append(origin)

        except Exception as e:
            logger.error("cors_parse_error", origin=origin, error=str(e))
            continue

    if not validated:
        logger.warning(
            "cors_no_valid_origins",
            message="No valid CORS origins configured - CORS will block all cross-origin requests",
        )

    return validated


# Validate CORS origins on startup
cors_origins = validate_cors_origins(
    cors_origins, os.environ.get("ENVIRONMENT", "development")
)
logger.info("cors_origins_configured", origins=cors_origins)

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
        "X-CSRF-Token",  # Required for cookie-based auth refresh
        "Accept",
        "Accept-Language",
        "Cache-Control",
    ],
    expose_headers=["X-Total-Count", "X-Page-Count", "X-Request-ID"],
)

# Per-path CORS for quick-scan — MUST be after CORSMiddleware so it runs
# before it in the request chain (last added = outermost in Starlette).
app.add_middleware(QuickScanCORSMiddleware)

# Add secure logging middleware (excludes sensitive endpoint bodies from logs)
app.add_middleware(SecureLoggingMiddleware)

# Add security headers middleware (X-Frame-Options, HSTS, CSP, etc.)
app.add_middleware(SecurityHeadersMiddleware)

# Add request ID correlation middleware (enables log correlation)
app.add_middleware(RequestIDMiddleware)

# Initialize Prometheus instrumentation
# Exposes /metrics endpoint for scraping
Instrumentator().instrument(app).expose(app)

# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(webauthn.router, prefix="/api/v1/auth", tags=["WebAuthn"])
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
app.include_router(gaps.router, prefix="/api/v1/gaps", tags=["Coverage Gaps"])
app.include_router(
    evaluation_history.router,
    prefix="/api/v1/evaluation-history",
    tags=["Evaluation History"],
)
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
app.include_router(
    techniques.router,
    prefix="/api/v1",
    tags=["Techniques"],
)

# Admin Portal routes (separate from user routes)
app.include_router(admin_router, prefix="/api/v1/admin")

# Public API routes (API key authentication)
app.include_router(public_api_router, prefix="/api/v1")

# Support system integration (dedicated API key auth)
app.include_router(support.router, prefix="/api/v1", tags=["Support Integration"])

# Google Workspace setup (admin only)
app.include_router(workspace_setup.router, prefix="/api/v1", tags=["Workspace Setup"])

# Quick Scan — public, no authentication
app.include_router(quick_scan_router, prefix="/api/v1/quick-scan", tags=["Quick Scan"])


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
    }
