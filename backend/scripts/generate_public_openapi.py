#!/usr/bin/env python3
"""Generate sanitised OpenAPI spec for public API documentation.

This script extracts the OpenAPI schema from the FastAPI app and filters out
internal/admin endpoints to produce a spec suitable for public documentation.

SECURITY: This script is a critical security control. Any changes must be
reviewed carefully to ensure no internal endpoints are exposed.

Usage:
    python scripts/generate_public_openapi.py

Output:
    docs/api/openapi.json
"""

import json
import os
import sys
from copy import deepcopy
from pathlib import Path

# Add backend to Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

# Set minimal environment for app import
os.environ.setdefault("SECRET_KEY", "docs-generation-key-not-for-production")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
os.environ.setdefault("ENVIRONMENT", "development")


def get_openapi_schema() -> dict:
    """Import FastAPI app and extract OpenAPI schema."""
    from app.main import app

    return app.openapi()


# =============================================================================
# SECURITY: Path and Tag Exclusion Rules
# =============================================================================

# Paths that MUST be excluded (admin, internal OAuth, health probes)
EXCLUDED_PATH_PREFIXES = [
    "/api/v1/admin",  # Admin portal - NEVER expose
    "/api/v1/auth/cognito",  # Internal OAuth flow
    "/api/v1/auth/github",  # Internal OAuth callbacks
    "/health/ready",  # Internal Kubernetes probe
    "/health/live",  # Internal Kubernetes probe
]

# Exact paths to exclude
EXCLUDED_PATHS_EXACT = [
    "/",  # Root redirect
    "/health",  # Internal health check (keep /api/v1/health if exists)
]

# Tags that indicate internal/admin endpoints
EXCLUDED_TAGS = [
    "Admin",
    "Admin Auth",
    "Admin Users",
    "Admin Organizations",
    "Admin Billing",
    "Admin Audit",
    "Admin Settings",
    "Admin Metrics",
    "Admin Fingerprints",
    "Admin MITRE",
    "Admin Fraud",
    "Cognito SSO",  # Internal OAuth
    "GitHub OAuth",  # Internal OAuth
    "WebAuthn",  # Browser-only, not API
]

# Paths to INCLUDE (whitelist approach for safety)
# Only these prefixes will be included in the public docs
INCLUDED_PATH_PREFIXES = [
    "/api/v1/accounts",
    "/api/v1/scans",
    "/api/v1/detections",
    "/api/v1/coverage",
    "/api/v1/mappings",
    "/api/v1/schedules",
    "/api/v1/alerts",
    "/api/v1/reports",
    "/api/v1/api-keys",
    "/api/v1/gaps",
    "/api/v1/techniques",
    "/api/v1/compliance",
    "/api/v1/custom-detections",
    "/api/v1/recommendations",
    "/api/v1/analytics",
    "/api/v1/evaluation-history",
    "/api/v1/cloud-organizations",
    "/api/v1/public",  # Public API routes
    "/api/v1/teams",  # Team management
    "/api/v1/credentials",  # Cloud credentials (API key users need this)
    "/api/v1/billing",  # Billing info (read operations)
    "/api/v1/org",  # Organisation settings
    "/api/v1/audit-logs",  # Audit logs
    "/api/v1/code-analysis",  # IaC analysis
]


def should_exclude_path(path: str) -> bool:
    """Check if a path should be excluded from public docs."""
    # Check exact exclusions first
    if path in EXCLUDED_PATHS_EXACT:
        return True

    # Check prefix exclusions (admin, internal OAuth)
    for prefix in EXCLUDED_PATH_PREFIXES:
        if path.startswith(prefix):
            return True

    # Whitelist approach: only include known-safe prefixes
    for prefix in INCLUDED_PATH_PREFIXES:
        if path.startswith(prefix):
            return False

    # Default: exclude anything not explicitly whitelisted
    return True


def should_exclude_by_tags(operation: dict) -> bool:
    """Check if an operation should be excluded based on its tags."""
    operation_tags = operation.get("tags", [])
    for tag in operation_tags:
        if tag in EXCLUDED_TAGS:
            return True
    return False


def sanitise_schema(schema: dict) -> dict:
    """Remove internal endpoints and sensitive information from OpenAPI schema."""
    sanitised = deepcopy(schema)

    # Update metadata for public docs
    sanitised["info"]["title"] = "A13E Detection Coverage Validator API"
    sanitised["info"]["description"] = (
        "API for programmatic access to A13E Detection Coverage Validator.\n\n"
        "## Authentication\n\n"
        "All API requests require authentication using an API key.\n"
        "Include your API key in the Authorization header:\n\n"
        "```\n"
        "Authorization: Bearer dcv_live_xxxxxxxxxx\n"
        "```\n\n"
        "API keys can be created in the A13E dashboard under Settings → API Keys.\n\n"
        "## Rate Limiting\n\n"
        "API requests are rate-limited based on your subscription tier:\n\n"
        "| Tier | Requests/Hour |\n"
        "|------|---------------|\n"
        "| Free | 100 |\n"
        "| Individual (£29/mo) | 1,000 |\n"
        "| Pro (£250/mo) | 10,000 |\n"
        "| Enterprise | 100,000 |\n\n"
        "Rate limit headers are included in all responses:\n"
        "- `X-RateLimit-Limit`: Maximum requests per hour\n"
        "- `X-RateLimit-Remaining`: Requests remaining\n"
        "- `X-RateLimit-Reset`: Unix timestamp when limit resets\n"
    )

    # Filter paths
    paths_to_remove = []
    for path, path_item in sanitised.get("paths", {}).items():
        if should_exclude_path(path):
            paths_to_remove.append(path)
            continue

        # Check each HTTP method
        methods_to_remove = []
        for method in ["get", "post", "put", "patch", "delete", "options", "head"]:
            if method in path_item:
                operation = path_item[method]
                if should_exclude_by_tags(operation):
                    methods_to_remove.append(method)

        # Remove excluded methods
        for method in methods_to_remove:
            del path_item[method]

        # If all methods removed, mark path for removal
        if not any(m in path_item for m in ["get", "post", "put", "patch", "delete"]):
            paths_to_remove.append(path)

    # Remove excluded paths
    for path in paths_to_remove:
        if path in sanitised["paths"]:
            del sanitised["paths"][path]

    # Filter tags list
    if "tags" in sanitised:
        sanitised["tags"] = [
            tag for tag in sanitised["tags"] if tag.get("name") not in EXCLUDED_TAGS
        ]

    # Update security schemes - only document Bearer token
    if "components" in sanitised and "securitySchemes" in sanitised["components"]:
        sanitised["components"]["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "API Key",
                "description": (
                    "API key authentication. Get your API key from the A13E dashboard.\n"
                    "Format: `dcv_live_xxxxxxxxxx`"
                ),
            }
        }

    # Set global security requirement
    sanitised["security"] = [{"BearerAuth": []}]

    # Clean up unused schema definitions
    sanitised = remove_unused_schemas(sanitised)

    # Add servers
    sanitised["servers"] = [
        {
            "url": "https://api.a13e.com",
            "description": "Production API",
        },
        {
            "url": "https://api.staging.a13e.com",
            "description": "Staging API (for testing)",
        },
    ]

    # Add contact and license info
    sanitised["info"]["contact"] = {
        "name": "A13E Support",
        "email": "support@a13e.com",
        "url": "https://a13e.com",
    }
    sanitised["info"]["license"] = {
        "name": "Proprietary",
        "url": "https://a13e.com/terms",
    }

    # Add external docs link
    sanitised["externalDocs"] = {
        "description": "Full documentation",
        "url": "https://docs.a13e.com",
    }

    return sanitised


def remove_unused_schemas(schema: dict) -> dict:
    """Remove schema definitions not referenced by remaining paths."""
    if "components" not in schema or "schemas" not in schema["components"]:
        return schema

    # Find all referenced schemas
    schema_json = json.dumps(schema["paths"])
    referenced = set()

    for schema_name in schema["components"]["schemas"]:
        ref_pattern = f'"$ref": "#/components/schemas/{schema_name}"'
        if ref_pattern in schema_json:
            referenced.add(schema_name)

    # Also check for nested references within schemas
    changed = True
    while changed:
        changed = False
        schemas_json = json.dumps(
            {
                k: v
                for k, v in schema["components"]["schemas"].items()
                if k in referenced
            }
        )
        for schema_name in schema["components"]["schemas"]:
            if schema_name not in referenced:
                ref_pattern = f'"$ref": "#/components/schemas/{schema_name}"'
                if ref_pattern in schemas_json:
                    referenced.add(schema_name)
                    changed = True

    # Remove unreferenced schemas
    schema["components"]["schemas"] = {
        k: v for k, v in schema["components"]["schemas"].items() if k in referenced
    }

    return schema


def main():
    """Generate and save the sanitised OpenAPI spec."""
    print("Generating public OpenAPI specification...")

    # Get the raw schema
    raw_schema = get_openapi_schema()
    print(f"  Raw schema: {len(raw_schema.get('paths', {}))} paths")

    # Sanitise for public docs
    public_schema = sanitise_schema(raw_schema)
    print(f"  Public schema: {len(public_schema.get('paths', {}))} paths")

    # Calculate what was removed
    removed_count = len(raw_schema.get("paths", {})) - len(
        public_schema.get("paths", {})
    )
    print(f"  Removed: {removed_count} internal/admin paths")

    # Ensure output directory exists
    output_dir = backend_dir.parent / "docs" / "api"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write the sanitised schema
    output_path = output_dir / "openapi.json"
    with open(output_path, "w") as f:
        json.dump(public_schema, f, indent=2)

    print(f"  Output: {output_path}")
    print("Done!")

    # Print summary of included tags
    included_tags = [tag["name"] for tag in public_schema.get("tags", [])]
    print(f"\nIncluded API sections: {', '.join(included_tags)}")


if __name__ == "__main__":
    main()
