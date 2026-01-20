"""Security headers middleware for API responses.

This middleware adds security headers to all API responses to prevent
common web vulnerabilities like clickjacking, XSS, and MIME-sniffing.

CSP Strategy:
- /redoc: Self-hosted ReDoc bundle, strictest feasible policy
- /docs: FastAPI's Swagger UI uses CDN, slightly relaxed for development
- /openapi.json: Pure JSON, strictest policy
- All other endpoints: Strictest policy (default-src 'none')
"""

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# === CSP Policies (ordered from most to least restrictive) ===

# Strictest CSP for API endpoints - they return JSON, not HTML
# No resources should ever be loaded in context of API responses
API_CSP = "default-src 'none'; " "frame-ancestors 'none'"

# Strict CSP for self-hosted ReDoc documentation
# Uses self-hosted redoc.standalone.js - no external CDN dependencies
# Only allows: self-hosted scripts, inline styles (ReDoc requirement), data: images
REDOC_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "object-src 'none'"
)

# CSP for Swagger UI (/docs) - requires CDN access for FastAPI's built-in UI
# Less restrictive due to CDN dependencies, but still locked down
# Consider self-hosting Swagger UI for stricter CSP in future
SWAGGER_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://cdn.jsdelivr.net; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "object-src 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses.

    Headers added:
    - X-Frame-Options: Prevents clickjacking
    - X-Content-Type-Options: Prevents MIME-sniffing
    - X-XSS-Protection: Legacy XSS protection (still useful for older browsers)
    - Strict-Transport-Security: Enforces HTTPS (HSTS)
    - Content-Security-Policy: Restricts resource loading
    - Referrer-Policy: Controls referrer information
    - Permissions-Policy: Restricts browser features
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response = await call_next(request)

        # Prevent clickjacking - deny all framing
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # XSS protection (legacy but still useful for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # HSTS - enforce HTTPS for 1 year, including subdomains
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Content Security Policy - apply appropriate policy per endpoint type
        path = request.url.path
        if path == "/redoc":
            # Self-hosted ReDoc - strict CSP, no external dependencies
            response.headers["Content-Security-Policy"] = REDOC_CSP
        elif path == "/docs":
            # Swagger UI - needs CDN access for FastAPI's built-in UI
            response.headers["Content-Security-Policy"] = SWAGGER_CSP
        elif path.startswith("/static/"):
            # Static files - use ReDoc CSP (same origin, no external deps)
            response.headers["Content-Security-Policy"] = REDOC_CSP
        else:
            # All API endpoints and /openapi.json - strictest policy
            response.headers["Content-Security-Policy"] = API_CSP

        # Referrer policy - only send origin for cross-origin requests
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy - disable unnecessary browser features
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )

        return response
