#!/usr/bin/env python3
"""
Fix duplicate attributes in remediation templates.

This script removes duplicate TreatMissingData and treat_missing_data
attributes from CloudFormation and Terraform templates.
"""

import re
from pathlib import Path


def fix_cloudformation_duplicates(content: str) -> str:
    """Remove duplicate TreatMissingData in CloudFormation templates."""
    # Pattern to find CloudWatch Alarm resources with duplicate TreatMissingData
    # We need to remove the second occurrence within the same resource

    lines = content.split("\n")
    result_lines = []
    in_alarm_resource = False
    seen_treat_missing = False
    alarm_indent = 0

    for i, line in enumerate(lines):
        # Detect start of CloudWatch Alarm resource
        if "Type: AWS::CloudWatch::Alarm" in line:
            in_alarm_resource = True
            seen_treat_missing = False
            # Find the indent level of Properties
            alarm_indent = len(line) - len(line.lstrip())
            result_lines.append(line)
            continue

        # Detect end of resource (line with same or less indentation that's not empty)
        if in_alarm_resource and line.strip() and not line.strip().startswith("#"):
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= alarm_indent and "Properties:" not in line:
                in_alarm_resource = False
                seen_treat_missing = False

        # Check for TreatMissingData
        if in_alarm_resource and "TreatMissingData:" in line:
            if seen_treat_missing:
                # Skip this duplicate line
                continue
            seen_treat_missing = True

        result_lines.append(line)

    return "\n".join(result_lines)


def fix_terraform_duplicates(content: str) -> str:
    """Remove duplicate treat_missing_data in Terraform templates."""
    # Pattern to find resources with duplicate treat_missing_data
    lines = content.split("\n")
    result_lines = []
    in_resource = False
    seen_treat_missing = False
    resource_brace_count = 0

    for line in lines:
        # Detect start of resource block
        if re.match(r'\s*resource\s+"aws_cloudwatch_metric_alarm"', line):
            in_resource = True
            seen_treat_missing = False
            resource_brace_count = 0

        # Track brace depth
        if in_resource:
            resource_brace_count += line.count("{")
            resource_brace_count -= line.count("}")
            if resource_brace_count <= 0:
                in_resource = False
                seen_treat_missing = False

        # Check for treat_missing_data
        if in_resource and "treat_missing_data" in line and "=" in line:
            if seen_treat_missing:
                # Skip this duplicate line
                continue
            seen_treat_missing = True

        result_lines.append(line)

    return "\n".join(result_lines)


def fix_template(template_path: Path) -> bool:
    """Fix duplicates in a single template. Returns True if changes were made."""
    content = template_path.read_text()
    original = content

    # Fix CloudFormation duplicates
    content = fix_cloudformation_duplicates(content)

    # Fix Terraform duplicates
    content = fix_terraform_duplicates(content)

    if content != original:
        template_path.write_text(content)
        return True
    return False


def main():
    """Fix all templates with duplicate issues."""
    templates_dir = Path(__file__).parent.parent

    templates_to_fix = [
        "t1052_exfil_physical_medium.py",
        "t1091_removable_media.py",
        "t1102_002_bidirectional_communication.py",
        "t1102_web_service.py",
        "t1104_multi_stage_channels.py",
        "t1124_system_time_discovery.py",
        "t1127_trusted_dev_utils.py",
        "t1137_office_app_startup.py",
        "t1195_003_compromise_hardware.py",
        "t1200_hardware_additions.py",
        "t1202_indirect_command_exec.py",
        "t1204_002_malicious_file.py",
        "t1210_exploitation_remote_services.py",
        "t1219_remote_access_software.py",
        "t1491_002_external_defacement.py",
        "t1499_003_application_exhaustion_flood.py",
        "t1499_endpoint_dos.py",
        "t1529_system_shutdown_reboot.py",
        "t1535_unused_cloud_regions_main.py",
        "t1542_pre_os_boot.py",
        "t1554_compromise_host_software.py",
        "t1556_009_conditional_access_policies.py",
        "t1558_kerberos_tickets.py",
        "t1570_lateral_tool_transfer.py",
        "t1586_003_cloud_accounts.py",
        "t1588_002_tool.py",
        "t1614_system_location_discovery.py",
        "t1654_log_enumeration.py",
    ]

    fixed_count = 0
    for template_name in templates_to_fix:
        template_path = templates_dir / template_name
        if template_path.exists():
            if fix_template(template_path):
                print(f"✅ Fixed: {template_name}")
                fixed_count += 1
            else:
                print(f"⏭️  No changes needed: {template_name}")
        else:
            print(f"❌ Not found: {template_name}")

    print(f"\nFixed {fixed_count} templates")


if __name__ == "__main__":
    main()
