#!/usr/bin/env python3
"""Verify OpenAPI spec does not expose sensitive endpoints.

SECURITY: This script is a CI security gate. It MUST fail the build if any
internal, admin, or sensitive endpoints are present in the public OpenAPI spec.

This script should be run AFTER generate_public_openapi.py and BEFORE deployment.

Usage:
    python scripts/verify_openapi_security.py [path_to_openapi.json]

Exit codes:
    0 - Verification passed (safe to deploy)
    1 - Verification FAILED (DO NOT DEPLOY)
"""

import json
import re
import sys
from pathlib import Path
from typing import NamedTuple


class Violation(NamedTuple):
    """Security violation found in OpenAPI spec."""

    category: str
    location: str
    details: str


# =============================================================================
# SECURITY: Forbidden Patterns
# These patterns MUST NOT appear in the public API documentation
# =============================================================================

# Paths that MUST NOT be present
FORBIDDEN_PATH_PATTERNS = [
    r"/admin",  # Admin portal
    r"/cognito",  # Internal OAuth
    r"/github/callback",  # Internal OAuth callback
    r"/auth/github/authorize",  # Internal OAuth
    r"/health/ready",  # Internal probe
    r"/health/live",  # Internal probe
    r"/webauthn",  # Browser-only auth
]

# Tags that MUST NOT be present
FORBIDDEN_TAGS = [
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
    "Cognito SSO",
    "GitHub OAuth",
    "WebAuthn",
]

# Words that should NOT appear in public documentation
# (case-insensitive check)
FORBIDDEN_DESCRIPTION_PATTERNS = [
    r"\badmin\s+portal\b",
    r"\binternal\s+use\s+only\b",
    r"\bdo\s+not\s+expose\b",
    r"\bsuperuser\b",
    r"\bsuperadmin\b",
    r"\broot\s+access\b",
]

# Schema names that indicate internal/admin functionality
FORBIDDEN_SCHEMA_PATTERNS = [
    r"^Admin",
    r"^SuperUser",
    r"^Internal",
]


def verify_spec(spec_path: str) -> list[Violation]:
    """Verify OpenAPI spec for security violations.

    Returns:
        List of Violation objects. Empty list means verification passed.
    """
    violations: list[Violation] = []

    with open(spec_path) as f:
        spec = json.load(f)

    # Check paths
    for path in spec.get("paths", {}):
        for pattern in FORBIDDEN_PATH_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                violations.append(
                    Violation(
                        category="FORBIDDEN_PATH",
                        location=f"paths.{path}",
                        details=f"Path matches forbidden pattern: {pattern}",
                    )
                )

    # Check tags
    for tag in spec.get("tags", []):
        tag_name = tag.get("name", "")
        if tag_name in FORBIDDEN_TAGS:
            violations.append(
                Violation(
                    category="FORBIDDEN_TAG",
                    location=f"tags.{tag_name}",
                    details=f"Tag is in forbidden list: {tag_name}",
                )
            )

    # Check operation tags
    for path, path_item in spec.get("paths", {}).items():
        for method in ["get", "post", "put", "patch", "delete"]:
            if method in path_item:
                operation = path_item[method]
                for tag in operation.get("tags", []):
                    if tag in FORBIDDEN_TAGS:
                        violations.append(
                            Violation(
                                category="FORBIDDEN_OPERATION_TAG",
                                location=f"paths.{path}.{method}",
                                details=f"Operation has forbidden tag: {tag}",
                            )
                        )

    # Check descriptions for sensitive keywords
    spec_text = json.dumps(spec)
    for pattern in FORBIDDEN_DESCRIPTION_PATTERNS:
        matches = re.findall(pattern, spec_text, re.IGNORECASE)
        if matches:
            violations.append(
                Violation(
                    category="FORBIDDEN_CONTENT",
                    location="(various)",
                    details=f"Spec contains forbidden content pattern: {pattern}",
                )
            )

    # Check schema names
    if "components" in spec and "schemas" in spec["components"]:
        for schema_name in spec["components"]["schemas"]:
            for pattern in FORBIDDEN_SCHEMA_PATTERNS:
                if re.match(pattern, schema_name, re.IGNORECASE):
                    violations.append(
                        Violation(
                            category="FORBIDDEN_SCHEMA",
                            location=f"components.schemas.{schema_name}",
                            details=f"Schema name matches forbidden pattern: {pattern}",
                        )
                    )

    # Check for exposed internal security schemes
    if "components" in spec and "securitySchemes" in spec["components"]:
        schemes = spec["components"]["securitySchemes"]
        for scheme_name in schemes:
            if "admin" in scheme_name.lower():
                violations.append(
                    Violation(
                        category="FORBIDDEN_SECURITY_SCHEME",
                        location=f"components.securitySchemes.{scheme_name}",
                        details="Admin security scheme exposed in public docs",
                    )
                )

    return violations


def main():
    """Run security verification and exit with appropriate code."""
    # Determine spec path
    if len(sys.argv) > 1:
        spec_path = sys.argv[1]
    else:
        # Default path
        backend_dir = Path(__file__).parent.parent
        spec_path = backend_dir.parent / "docs" / "api" / "openapi.json"

    if not Path(spec_path).exists():
        print(f"ERROR: OpenAPI spec not found at {spec_path}")
        print("Run generate_public_openapi.py first.")
        sys.exit(1)

    print(f"Verifying OpenAPI spec: {spec_path}")
    print("-" * 60)

    violations = verify_spec(str(spec_path))

    if violations:
        print("\n🚨 SECURITY VERIFICATION FAILED 🚨\n")
        print("The following security violations were detected:\n")

        for v in violations:
            print(f"  [{v.category}]")
            print(f"    Location: {v.location}")
            print(f"    Details:  {v.details}")
            print()

        print(f"Total violations: {len(violations)}")
        print("\n⛔ DO NOT DEPLOY - Fix the spec generation script first!")
        sys.exit(1)
    else:
        print("\n✅ Security verification PASSED\n")
        print("No forbidden paths, tags, or content detected.")
        print("The OpenAPI spec is safe for public documentation.")
        sys.exit(0)


if __name__ == "__main__":
    main()
