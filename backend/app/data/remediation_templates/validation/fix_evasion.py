#!/usr/bin/env python3
"""Fix missing evasion_considerations in GuardDuty detection strategies."""

import re
from pathlib import Path

# Templates that need fixing and their evasion considerations
EVASION_FIXES = {
    "t1485_data_destruction.py": "Slow deletion over time, using legitimate admin tools, deleting from approved automation accounts",
    "t1486_data_encrypted_for_impact.py": "Using legitimate encryption tools, encrypting during maintenance windows, mimicking backup operations",
    "t1087_account_discovery.py": "Slow enumeration over time, using service accounts, staying within normal API usage patterns",
    "t1136_create_account.py": "Creating accounts during business hours, using naming conventions that match legitimate accounts",
    "t1498_network_dos.py": "Low-rate attacks, using legitimate traffic patterns, distributed sources",
    "t1070_indicator_removal.py": "Disabling logging during low-activity periods, using legitimate admin accounts",
    "t1568_002_domain_generation_algorithms.py": "Using legitimate-looking domains, low query frequency, blending with normal DNS traffic",
    "t1548_abuse_elevation.py": "Gradual privilege escalation, using legitimate automation, mimicking normal admin operations",
    "t1048_exfil_alt_protocol.py": "Low bandwidth exfiltration, using encrypted protocols, mimicking legitimate backup traffic",
}


def fix_template(template_path: Path, evasion_text: str) -> bool:
    """Add missing evasion_considerations to a template."""
    content = template_path.read_text()

    # Pattern: detection_coverage followed by implementation_effort (missing evasion_considerations)
    pattern = r'(detection_coverage="[^"]+",)\n(\s+implementation_effort=EffortLevel\.LOW,\n\s+implementation_time="30 minutes",)'

    if not re.search(pattern, content):
        print(f"  Pattern not found in {template_path.name}")
        return False

    replacement = rf'\1\n            evasion_considerations="{evasion_text}",\n\2'
    new_content = re.sub(pattern, replacement, content)

    if new_content != content:
        template_path.write_text(new_content)
        return True
    return False


def main():
    templates_dir = Path(__file__).parent.parent

    for template_name, evasion_text in EVASION_FIXES.items():
        template_path = templates_dir / template_name
        if template_path.exists():
            print(f"Processing: {template_name}")
            if fix_template(template_path, evasion_text):
                print("  Fixed")
            else:
                print("  Skipped (already fixed or pattern not found)")
        else:
            print(f"  Not found: {template_name}")


if __name__ == "__main__":
    main()
