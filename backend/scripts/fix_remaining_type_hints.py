#!/usr/bin/env python3
"""Fix remaining type hint issues found by mypy.

This script fixes:
1. __init__ and __post_init__ methods missing -> None
2. Nested functions missing return types
3. Missing argument type annotations (adds Any where needed)
4. Missing return statements
"""

import re
from pathlib import Path

# Specific fixes needed based on mypy output
FIXES = {
    "app/parsers/sdk_pattern_library.py": [
        (538, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/data/remediation_templates/template_loader.py": [
        (155, "def __post_init__(self):", "def __post_init__(self) -> None:"),
    ],
    "app/data/remediation_templates/validation/fix_unclosed_strings.py": [
        (
            26,
            "def add_closing_quote(match) -> Any:",
            "def add_closing_quote(match: re.Match[str]) -> str:",
        ),
        (
            36,
            "def add_closing_quote2(match) -> Any:",
            "def add_closing_quote2(match: re.Match[str]) -> str:",
        ),
    ],
    "app/data/remediation_templates/validation/template_validator.py": [
        (132, "def validate_hcl(content):", "def validate_hcl(content: str) -> bool:"),
    ],
    "app/validators/base_validator.py": [
        (84, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/services/region_discovery_service.py": [
        (21, "def __init__(self):", "def __init__(self) -> None:"),
        (257, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/parsers/lambda_code_parser.py": [
        (
            120,
            "def __init__(self, session=None):",
            "def __init__(self, session: Any = None) -> None:",
        ),
    ],
    "app/parsers/cloudformation_parser.py": [
        (
            150,
            "def __init__(self, session=None):",
            "def __init__(self, session: Any = None) -> None:",
        ),
    ],
    "app/middleware/security_headers.py": [
        (
            25,
            "def __init__(self, app, config: SecurityHeadersConfig = None):",
            "def __init__(self, app: ASGIApp, config: SecurityHeadersConfig = None) -> None:",
        ),
    ],
    "app/services/email_quality_service.py": [
        (192, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/core/config.py": [
        (87, "def __init__(self, **data):", "def __init__(self, **data: Any) -> None:"),
    ],
    "app/services/hibp_service.py": [
        (39, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/services/github_oauth_service.py": [
        (23, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/services/email_service.py": [
        (111, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/services/cognito_service.py": [
        (40, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/core/rate_limiter.py": [
        (49, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/services/mitre_threat_service.py": [
        (69, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/services/gcp_credential_service.py": [
        (55, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/services/aws_credential_service.py": [
        (65, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/validators/health_calculator.py": [
        (46, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/mappers/pattern_mapper.py": [
        (52, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/analyzers/gap_analyzer.py": [
        (83, "def __init__(self):", "def __init__(self) -> None:"),
    ],
    "app/services/scheduler_service.py": [
        (
            32,
            "def __init__(self, scan_service):",
            "def __init__(self, scan_service: Any) -> None:",
        ),
        (39, "def start(self):", "def start(self) -> None:"),
    ],
}


def fix_file(filepath: Path, fixes: list) -> int:
    """Apply fixes to a file.

    Returns number of fixes applied.
    """
    content = filepath.read_text()
    lines = content.split("\n")
    fixed_count = 0

    for line_no, old_pattern, new_pattern in fixes:
        # Line numbers are 1-indexed
        idx = line_no - 1
        if idx < len(lines):
            if old_pattern in lines[idx]:
                lines[idx] = lines[idx].replace(old_pattern, new_pattern)
                fixed_count += 1
                print(f"  Fixed line {line_no}: {old_pattern[:50]}...")

    if fixed_count > 0:
        filepath.write_text("\n".join(lines))

    return fixed_count


def add_any_import(filepath: Path) -> bool:
    """Add 'from typing import Any' if needed."""
    content = filepath.read_text()

    # Check if Any is used but not imported
    if "Any" in content and "from typing import" in content:
        if "Any" not in content.split("from typing import")[1].split("\n")[0]:
            # Need to add Any to existing import
            content = re.sub(
                r"from typing import ([^;\n]+)",
                lambda m: (
                    f"from typing import Any, {m.group(1)}"
                    if "Any" not in m.group(1)
                    else m.group(0)
                ),
                content,
                count=1,
            )
            filepath.write_text(content)
            return True
    elif "Any" in content and "from typing import" not in content:
        # Need to add new import
        lines = content.split("\n")
        # Find first import line
        for i, line in enumerate(lines):
            if line.startswith("import ") or line.startswith("from "):
                lines.insert(i, "from typing import Any")
                break
        filepath.write_text("\n".join(lines))
        return True

    return False


def main() -> None:
    base_dir = Path(__file__).parent.parent
    total_fixed = 0

    for rel_path, fixes in FIXES.items():
        filepath = base_dir / rel_path
        if filepath.exists():
            print(f"Fixing {rel_path}...")
            fixed = fix_file(filepath, fixes)
            total_fixed += fixed
            add_any_import(filepath)
        else:
            print(f"WARNING: File not found: {rel_path}")

    print(f"\nTotal fixes applied: {total_fixed}")


if __name__ == "__main__":
    main()
