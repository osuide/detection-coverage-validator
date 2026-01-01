"""Security headers middleware for API responses.

This middleware adds security headers to all API responses to prevent
common web vulnerabilities like clickjacking, XSS, and MIME-sniffing.
"""

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# CSP for API documentation pages (ReDoc, Swagger)
# Allows external resources needed for docs rendering
DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.redoc.ly https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: https://cdn.redoc.ly; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)

# Restrictive CSP for API endpoints
API_CSP = "default-src 'none'; frame-ancestors 'none'"


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

        # Content Security Policy - use relaxed policy for docs pages
        path = request.url.path
        if path in ("/redoc", "/docs", "/openapi.json"):
            response.headers["Content-Security-Policy"] = DOCS_CSP
        else:
            response.headers["Content-Security-Policy"] = API_CSP

        # Referrer policy - only send origin for cross-origin requests
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy - disable unnecessary browser features
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )

        return response
