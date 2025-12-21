"""Request ID correlation middleware.

Security benefit: Enables correlation of logs across services for
incident investigation and debugging without exposing internal details.
"""

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import structlog

logger = structlog.get_logger()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add request ID to all requests for log correlation.

    This middleware:
    1. Accepts incoming X-Request-ID header if present
    2. Generates a new UUID if no header provided
    3. Binds the request ID to structlog context for all logs
    4. Returns X-Request-ID header in the response
    """

    async def dispatch(self, request: Request, call_next):
        # Get existing request ID or generate new one
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Store in request state for access by other components
        request.state.request_id = request_id

        # Bind to structlog context for all subsequent logs in this request
        with structlog.contextvars.bound_contextvars(request_id=request_id):
            response = await call_next(request)
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            return response
