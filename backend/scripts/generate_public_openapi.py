#!/usr/bin/env python3
"""Generate sanitised OpenAPI spec for public API documentation.

This script extracts the OpenAPI schema from the FastAPI app and produces
a spec containing ONLY the Public API endpoints (/api/v1/public/*).

These are the external-facing endpoints designed for third-party integrations
and automation, authenticated via API keys (X-API-Key header).

SECURITY: This script is a critical security control. Only Public API
endpoints should be exposed. All internal, admin, and user-facing
endpoints are excluded.

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
# SECURITY: Strict Public API Whitelist
# =============================================================================
# ONLY the Public API endpoints are included. Everything else is excluded.
# The Public API is designed for external integrations and uses API key auth.

# Paths to INCLUDE - ONLY the Public API
# These are the ONLY endpoints that will appear in the public documentation
INCLUDED_PATH_PREFIXES = [
    "/api/v1/public/",  # Public API routes ONLY
]


def should_include_path(path: str) -> bool:
    """Check if a path should be included in public docs.

    Uses strict whitelist - only /api/v1/public/* paths are included.
    """
    for prefix in INCLUDED_PATH_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def sanitise_schema(schema: dict) -> dict:
    """Filter schema to include ONLY Public API endpoints."""
    sanitised = deepcopy(schema)

    # Update metadata for public API docs
    sanitised["info"]["title"] = "A13E Public API"
    sanitised["info"]["version"] = "1.0.0"
    sanitised["info"][
        "description"
    ] = """
# A13E Detection Coverage Validator - Public API

Programmatic access to your cloud security detection coverage data.

## Overview

The A13E Public API enables you to integrate detection coverage data into your security workflows, dashboards, and automation pipelines. Use it to:

- **Monitor coverage** - Track your MITRE ATT&CK coverage across cloud accounts
- **Trigger scans** - Initiate detection discovery scans programmatically
- **Query detections** - List and inspect discovered security detections
- **Identify gaps** - Find uncovered techniques prioritised by risk

## Authentication

All requests require an API key passed in the `X-API-Key` header:

```bash
curl -H "X-API-Key: dcv_live_xxxxxxxxxx" \\
  https://api.a13e.com/api/v1/public/accounts/{id}/coverage
```

### Getting an API Key

1. Sign in to the [A13E Dashboard](https://app.a13e.com)
2. Navigate to **Settings** → **API Keys**
3. Click **Create API Key**
4. Copy the key immediately (it won't be shown again)

API keys begin with `dcv_live_`.

## Rate Limiting

Requests are rate-limited based on your subscription tier:

| Tier | Rate Limit | Price |
|------|------------|-------|
| Individual | 100 requests/minute | £29/mo |
| Pro | 500 requests/minute | £250/mo |
| Enterprise | Custom limits | Custom |

> **Note:** API access requires a paid subscription. The Free tier does not include API access.

Rate limit headers are included in all responses:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |

When rate limited, you'll receive a `429 Too Many Requests` response. Use exponential backoff when retrying.

## Error Handling

The API uses standard HTTP status codes:

| Code | Meaning |
|------|---------|
| `200` | Success |
| `400` | Bad request (invalid parameters) |
| `401` | Unauthorised (invalid or missing API key) |
| `403` | Forbidden (insufficient permissions) |
| `404` | Resource not found |
| `409` | Conflict (e.g., scan already running) |
| `429` | Rate limit exceeded |
| `500` | Internal server error |

Error responses include a JSON body with details:

```json
{
  "detail": "Cloud account not found"
}
```

## Code Examples

### Python

```python
import requests

API_KEY = "dcv_live_xxxxxxxxxx"
BASE_URL = "https://api.a13e.com/api/v1/public"

headers = {"X-API-Key": API_KEY}

# Get coverage for an account
response = requests.get(
    f"{BASE_URL}/accounts/{account_id}/coverage",
    headers=headers
)
coverage = response.json()
print(f"Coverage: {coverage['coverage_percent']:.1f}%")
```

### JavaScript

```javascript
const API_KEY = 'dcv_live_xxxxxxxxxx';
const BASE_URL = 'https://api.a13e.com/api/v1/public';

const response = await fetch(
  `${BASE_URL}/accounts/${accountId}/coverage`,
  { headers: { 'X-API-Key': API_KEY } }
);
const coverage = await response.json();
console.log(`Coverage: ${coverage.coverage_percent.toFixed(1)}%`);
```

### cURL

```bash
# Get coverage summary
curl -H "X-API-Key: dcv_live_xxx" \\
  "https://api.a13e.com/api/v1/public/accounts/{account_id}/coverage"

# Trigger a scan
curl -X POST -H "X-API-Key: dcv_live_xxx" \\
  -H "Content-Type: application/json" \\
  -d '{"regions": ["eu-west-2"]}' \\
  "https://api.a13e.com/api/v1/public/accounts/{account_id}/scans"
```
"""

    # Filter to include ONLY Public API paths
    public_paths = {}
    for path, path_item in sanitised.get("paths", {}).items():
        if should_include_path(path):
            public_paths[path] = path_item

    sanitised["paths"] = public_paths

    # Define tags for Public API sections with descriptions
    sanitised["tags"] = [
        {
            "name": "Coverage",
            "description": "Coverage metrics and gap analysis for cloud accounts. "
            "Get overall coverage percentages, per-technique breakdown, and "
            "prioritised gaps with remediation guidance.",
        },
        {
            "name": "Detections",
            "description": "Discovered security detections in your cloud accounts. "
            "List detections by account with filtering, and get detailed "
            "information including MITRE ATT&CK technique mappings.",
        },
        {
            "name": "Scans",
            "description": "Detection discovery scans. Trigger new scans to discover "
            "security detections, monitor scan progress, and retrieve scan results.",
        },
    ]

    # Rename tags in operations for cleaner grouping
    tag_mapping = {
        "Public API - Coverage": "Coverage",
        "Public API - Detections": "Detections",
        "Public API - Scans": "Scans",
        "Public API": "Coverage",  # Fallback
    }

    for path_item in sanitised["paths"].values():
        for method in ["get", "post", "put", "patch", "delete"]:
            if method in path_item:
                operation = path_item[method]
                if "tags" in operation:
                    # Map tags and deduplicate
                    mapped_tags = [
                        tag_mapping.get(tag, tag) for tag in operation["tags"]
                    ]
                    operation["tags"] = list(dict.fromkeys(mapped_tags))

                # Update security to use our ApiKeyAuth scheme
                if "security" in operation:
                    operation["security"] = [{"ApiKeyAuth": []}]

    # Update security scheme to use X-API-Key header
    sanitised["components"] = sanitised.get("components", {})
    sanitised["components"]["securitySchemes"] = {
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": (
                "API key for authentication. Create keys in the A13E Dashboard "
                "under Settings → API Keys.\n\n"
                "Format: `dcv_live_xxxxxxxxxx`"
            ),
        }
    }

    # Set global security requirement
    sanitised["security"] = [{"ApiKeyAuth": []}]

    # Clean up unused schema definitions
    sanitised = remove_unused_schemas(sanitised)

    # Add servers - production only (no staging exposed)
    sanitised["servers"] = [
        {
            "url": "https://api.a13e.com",
            "description": "Production API",
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
        "description": "A13E Documentation",
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
    """Generate and save the Public API OpenAPI spec."""
    print("=" * 60)
    print("Generating A13E Public API OpenAPI Specification")
    print("=" * 60)

    # Get the raw schema
    raw_schema = get_openapi_schema()
    total_paths = len(raw_schema.get("paths", {}))
    print(f"\nTotal API paths in application: {total_paths}")

    # Sanitise for public docs
    public_schema = sanitise_schema(raw_schema)
    public_paths = len(public_schema.get("paths", {}))
    print(f"Public API paths included: {public_paths}")

    # Show included paths
    print("\nIncluded endpoints:")
    for path in sorted(public_schema.get("paths", {}).keys()):
        methods = [
            m.upper()
            for m in ["get", "post", "put", "patch", "delete"]
            if m in public_schema["paths"][path]
        ]
        print(f"  {', '.join(methods):12} {path}")

    # Ensure output directory exists
    output_dir = backend_dir.parent / "docs" / "api"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write the sanitised schema
    output_path = output_dir / "openapi.json"
    with open(output_path, "w") as f:
        json.dump(public_schema, f, indent=2)

    print(f"\nOutput: {output_path}")

    # Print summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    included_tags = [tag["name"] for tag in public_schema.get("tags", [])]
    print(f"API sections: {', '.join(included_tags)}")
    print(f"Total endpoints: {public_paths}")
    excluded_count = total_paths - public_paths
    print(f"Internal endpoints excluded: {excluded_count}")
    print("\nDone!")


if __name__ == "__main__":
    main()
