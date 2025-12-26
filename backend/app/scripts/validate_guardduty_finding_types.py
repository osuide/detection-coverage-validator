#!/usr/bin/env python3
"""Validate GuardDuty finding types in remediation templates.

This script scans all remediation templates and validates that the GuardDuty
finding types referenced are valid according to AWS documentation.

Usage:
    python validate_guardduty_finding_types.py [--fix]

Options:
    --fix    Automatically fix invalid finding types where corrections exist
"""

import re
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.data.guardduty_finding_types import (
    is_valid_finding_type,
    get_correction,
)


def extract_finding_types_from_file(filepath: Path) -> list[tuple[int, str]]:
    """Extract GuardDuty finding types from a template file.

    Args:
        filepath: Path to the template file.

    Returns:
        List of (line_number, finding_type) tuples.
    """
    finding_types = []
    content = filepath.read_text()

    # Pattern to match finding types in guardduty_finding_types arrays
    # Look for lines within guardduty_finding_types=[ ... ] blocks
    in_finding_types_block = False

    # Also match finding types in event_pattern jsonencode blocks
    in_event_pattern = False

    # Pattern to match finding types
    # Matches strings like "Backdoor:EC2/C&CActivity.B" or "CredentialAccess:IAMUser/*"
    pattern = r'"([A-Za-z]+:[A-Za-z0-9]+/[^"]*)"'

    for i, line in enumerate(content.split("\n"), 1):
        # Skip comment lines
        if line.strip().startswith("#"):
            continue

        # Track if we're in a guardduty_finding_types block
        if "guardduty_finding_types=" in line or "guardduty_finding_types =" in line:
            in_finding_types_block = True
        if in_finding_types_block and "]," in line:
            in_finding_types_block = False

        # Track if we're in an event_pattern with GuardDuty types
        if "event_pattern" in line and "jsonencode" in line:
            in_event_pattern = True
        if in_event_pattern and "})" in line:
            in_event_pattern = False

        # Only extract from relevant blocks
        if (
            in_finding_types_block
            or in_event_pattern
            or "type = [" in line
            or "type:" in line
        ):
            matches = re.findall(pattern, line)
            for match in matches:
                # Filter to only GuardDuty-style finding types
                # Must have format ThreatPurpose:Resource/Family
                if ":" in match and "/" in match:
                    # Skip if it contains explanation text
                    if " and " in match or " detects " in match or " via " in match:
                        continue
                    finding_types.append((i, match))

    return finding_types


def validate_template(filepath: Path) -> dict:
    """Validate a single template file.

    Args:
        filepath: Path to the template file.

    Returns:
        Dict with validation results.
    """
    finding_types = extract_finding_types_from_file(filepath)

    valid = []
    invalid = []
    correctable = []

    for line_num, ft in finding_types:
        if is_valid_finding_type(ft):
            valid.append((line_num, ft))
        else:
            correction = get_correction(ft)
            if correction:
                correctable.append((line_num, ft, correction))
            else:
                invalid.append((line_num, ft))

    return {
        "file": filepath.name,
        "valid": valid,
        "invalid": invalid,
        "correctable": correctable,
        "total": len(finding_types),
    }


def fix_template(filepath: Path, corrections: list[tuple[int, str, str]]) -> int:
    """Fix invalid finding types in a template.

    Args:
        filepath: Path to the template file.
        corrections: List of (line_num, old_type, new_type) tuples.

    Returns:
        Number of corrections made.
    """
    content = filepath.read_text()
    fixed_count = 0

    for _, old_type, new_type in corrections:
        if old_type in content:
            content = content.replace(f'"{old_type}"', f'"{new_type}"')
            fixed_count += 1

    if fixed_count > 0:
        filepath.write_text(content)

    return fixed_count


def main():
    """Main entry point."""
    fix_mode = "--fix" in sys.argv

    # Find templates directory
    script_dir = Path(__file__).parent
    templates_dir = script_dir.parent / "data" / "remediation_templates"

    if not templates_dir.exists():
        print(f"Error: Templates directory not found: {templates_dir}")
        sys.exit(1)

    # Validate all templates
    results = []
    for filepath in sorted(templates_dir.glob("t*.py")):
        result = validate_template(filepath)
        if result["invalid"] or result["correctable"]:
            results.append(result)

    # Print report
    print("=" * 80)
    print("GuardDuty Finding Types Validation Report")
    print("=" * 80)
    print()

    total_invalid = 0
    total_correctable = 0
    total_fixed = 0

    for result in results:
        if result["invalid"] or result["correctable"]:
            print(f"\n📁 {result['file']}")

            if result["correctable"]:
                print("  Correctable:")
                for line_num, old_type, new_type in result["correctable"]:
                    print(f"    Line {line_num}: {old_type}")
                    print(f"      → Suggest: {new_type}")
                total_correctable += len(result["correctable"])

                if fix_mode:
                    filepath = templates_dir / result["file"]
                    fixed = fix_template(filepath, result["correctable"])
                    total_fixed += fixed
                    print(f"    ✓ Fixed {fixed} finding types")

            if result["invalid"]:
                print("  Invalid (no correction available):")
                for line_num, ft in result["invalid"]:
                    print(f"    Line {line_num}: {ft}")
                total_invalid += len(result["invalid"])

    # Summary
    print("\n" + "=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"Templates with issues: {len(results)}")
    print(f"Total correctable finding types: {total_correctable}")
    print(f"Total invalid finding types (no correction): {total_invalid}")

    if fix_mode:
        print(f"Total fixed: {total_fixed}")
    else:
        if total_correctable > 0:
            print("\nRun with --fix to automatically correct finding types")

    # Exit with error code if there are unfixable invalid types
    if total_invalid > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
