#!/usr/bin/env python3
"""
Remediation Template Validator.

This script validates remediation templates for:
1. Structural correctness (required fields, valid types)
2. Detection logic issues (flawed approaches that won't work)
3. GuardDuty finding type validity
4. Anti-patterns (duplicate attributes, missing DLQ, etc.)
5. CloudTrail event pattern validity

Usage:
    python template_validator.py                    # Validate all templates
    python template_validator.py t1078_valid_accounts.py  # Validate specific template
    python template_validator.py --report           # Generate full report
"""

import ast
import re
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Set
from enum import Enum

# Import GuardDuty findings database
try:
    from guardduty_findings import (
        validate_finding_type,
        technique_has_guardduty_coverage,
        get_recommended_guardduty_findings,
    )
except ImportError:
    # Running from different directory
    import os

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from guardduty_findings import (
        validate_finding_type,
        technique_has_guardduty_coverage,
        get_recommended_guardduty_findings,
    )


class Severity(Enum):
    ERROR = "ERROR"  # Detection will not work
    WARNING = "WARNING"  # Detection may not work as expected
    INFO = "INFO"  # Suggestion for improvement


@dataclass
class ValidationIssue:
    """A single validation issue."""

    severity: Severity
    category: str
    message: str
    line_number: Optional[int] = None
    suggestion: Optional[str] = None


@dataclass
class TemplateValidationResult:
    """Result of validating a single template."""

    template_name: str
    technique_id: str
    issues: List[ValidationIssue] = field(default_factory=list)
    detection_types: Set[str] = field(default_factory=set)
    guardduty_findings: Set[str] = field(default_factory=set)

    @property
    def has_errors(self) -> bool:
        return any(i.severity == Severity.ERROR for i in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(i.severity == Severity.WARNING for i in self.issues)

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.WARNING)


class TemplateValidator:
    """Validates remediation templates for correctness and effectiveness."""

    # Patterns that indicate flawed detection logic
    FLAWED_DETECTION_PATTERNS = {
        # "Impossible travel" that just counts logins
        r"pattern\s*=.*ConsoleLogin.*Success.*\n.*metric_transformation": {
            "description": "CloudWatch metric filter counting logins doesn't detect impossible travel",
            "affected_techniques": ["T1078"],
            "suggestion": "Use GuardDuty UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B which has ML-based impossible travel detection with geolocation",
        },
        # Trying to detect data exfiltration by just counting S3 GetObject
        r"pattern\s*=.*GetObject.*\n.*metric.*Exfiltration": {
            "description": "Counting GetObject calls doesn't effectively detect exfiltration",
            "affected_techniques": ["T1530"],
            "suggestion": "Use GuardDuty Exfiltration:S3/ObjectRead.Unusual for anomaly-based detection or S3 Access Analyzer for data perimeter",
        },
        # Detecting brute force by just counting failed logins without rate analysis
        r"threshold\s*=\s*[0-5]\s*\n.*failed.*login": {
            "description": "Very low threshold for failed logins will cause alert fatigue",
            "affected_techniques": ["T1110"],
            "suggestion": "Use GuardDuty UnauthorizedAccess:EC2/SSHBruteForce or set threshold >= 10 with shorter period",
        },
    }

    # CloudTrail event names that don't exist or are commonly mistyped
    INVALID_CLOUDTRAIL_EVENTS = {
        "DeleteSecretKey": "Use DeleteAccessKey instead",
        "CreateIAMUser": "Use CreateUser instead",
        "DeleteIAMUser": "Use DeleteUser instead",
        "ModifySecurityGroup": "Use AuthorizeSecurityGroupIngress/Egress or RevokeSecurityGroupIngress/Egress",
        "UpdateBucketPolicy": "Use PutBucketPolicy instead",
        "CreateEC2Instance": "Use RunInstances instead",
        "DeleteEC2Instance": "Use TerminateInstances instead",
    }

    # Required fields for a valid template (check both uppercase constants and object attributes)
    REQUIRED_FIELDS = [
        ("technique_id", "TECHNIQUE_ID"),  # (object attribute, constant name)
        ("technique_name", "TECHNIQUE_NAME"),
        ("detection_strategies", "DETECTION_STRATEGIES"),
    ]

    def __init__(self):
        self.results: List[TemplateValidationResult] = []

    def validate_template(self, template_path: Path) -> TemplateValidationResult:
        """Validate a single template file."""
        template_name = template_path.name
        technique_id = self._extract_technique_id(template_name)

        result = TemplateValidationResult(
            template_name=template_name,
            technique_id=technique_id,
        )

        try:
            content = template_path.read_text()
        except Exception as e:
            result.issues.append(
                ValidationIssue(
                    severity=Severity.ERROR,
                    category="file_read",
                    message=f"Failed to read template: {e}",
                )
            )
            return result

        # Run all validations
        self._validate_python_syntax(content, result)
        self._validate_required_fields(content, result)
        self._validate_guardduty_findings(content, result)
        self._validate_cloudtrail_events(content, result)
        self._validate_detection_logic(content, result, technique_id)
        self._validate_terraform_patterns(content, result)
        self._validate_cloudformation_patterns(content, result)
        self._check_guardduty_coverage(technique_id, content, result)

        self.results.append(result)
        return result

    def _extract_technique_id(self, filename: str) -> str:
        """Extract MITRE technique ID from filename."""
        # Handle patterns like t1078_valid_accounts.py, t1078_004_cloud_accounts.py
        match = re.match(r"t(\d+)(?:_(\d+))?", filename.lower())
        if match:
            technique = f"T{match.group(1)}"
            if match.group(2):
                technique += f".{match.group(2).zfill(3)}"
            return technique
        return "UNKNOWN"

    def _validate_python_syntax(self, content: str, result: TemplateValidationResult):
        """Check Python syntax is valid."""
        try:
            ast.parse(content)
        except SyntaxError as e:
            result.issues.append(
                ValidationIssue(
                    severity=Severity.ERROR,
                    category="python_syntax",
                    message=f"Python syntax error: {e.msg}",
                    line_number=e.lineno,
                )
            )

    def _validate_required_fields(self, content: str, result: TemplateValidationResult):
        """Check required fields are present."""
        for field_tuple in self.REQUIRED_FIELDS:
            attr_name, const_name = field_tuple
            # Check for either object attribute (technique_id=) or constant (TECHNIQUE_ID =)
            has_attr = f"{attr_name}=" in content or f"{attr_name} =" in content
            has_const = f"{const_name}" in content
            if not has_attr and not has_const:
                result.issues.append(
                    ValidationIssue(
                        severity=Severity.ERROR,
                        category="missing_field",
                        message=f"Missing required field: {attr_name} or {const_name}",
                    )
                )

    def _validate_guardduty_findings(
        self, content: str, result: TemplateValidationResult
    ):
        """Validate GuardDuty finding types referenced in template."""
        # Find all GuardDuty finding types in guardduty_finding_types lists
        # Pattern handles special chars like & in C&CActivity
        finding_list_pattern = r"guardduty_finding_types\s*=\s*\[(.*?)\]"
        list_matches = re.findall(finding_list_pattern, content, re.DOTALL)

        findings_found = set()
        for list_content in list_matches:
            # Extract quoted strings from the list
            quoted_findings = re.findall(r'"([^"]+)"', list_content)
            findings_found.update(quoted_findings)

        # Also check for individual finding type references
        # Pattern: Category:Resource/FindingName.Suffix
        individual_pattern = r'"([A-Z][a-zA-Z]+:[A-Z][a-zA-Z0-9&]+/[A-Za-z0-9.!]+)"'
        individual_matches = re.findall(individual_pattern, content)
        findings_found.update(individual_matches)

        result.guardduty_findings = findings_found

        for finding_type in findings_found:
            if not validate_finding_type(finding_type):
                result.issues.append(
                    ValidationIssue(
                        severity=Severity.WARNING,
                        category="invalid_guardduty_finding",
                        message=f"GuardDuty finding type may not exist: {finding_type}",
                        suggestion="Verify against https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html",
                    )
                )

    def _validate_cloudtrail_events(
        self, content: str, result: TemplateValidationResult
    ):
        """Validate CloudTrail event names."""
        # Find event names in patterns
        event_pattern = r'eventName\s*[=:]\s*["\']?(\w+)["\']?'
        events = re.findall(event_pattern, content)

        for event in events:
            if event in self.INVALID_CLOUDTRAIL_EVENTS:
                result.issues.append(
                    ValidationIssue(
                        severity=Severity.ERROR,
                        category="invalid_cloudtrail_event",
                        message=f"Invalid CloudTrail event name: {event}",
                        suggestion=self.INVALID_CLOUDTRAIL_EVENTS[event],
                    )
                )

    def _validate_detection_logic(
        self, content: str, result: TemplateValidationResult, technique_id: str
    ):
        """Check for flawed detection logic patterns."""
        for pattern, info in self.FLAWED_DETECTION_PATTERNS.items():
            if technique_id in info.get("affected_techniques", []):
                if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                    result.issues.append(
                        ValidationIssue(
                            severity=Severity.ERROR,
                            category="flawed_detection_logic",
                            message=info["description"],
                            suggestion=info["suggestion"],
                        )
                    )

    def _validate_terraform_patterns(
        self, content: str, result: TemplateValidationResult
    ):
        """Validate Terraform resource patterns."""
        # Check for duplicate attributes (common mistake)
        duplicate_attrs = [
            (
                r"treat_missing_data\s*=.*\n.*treat_missing_data\s*=",
                "Duplicate treat_missing_data attribute",
            ),
            (
                r"alarm_actions\s*=.*\n.*alarm_actions\s*=",
                "Duplicate alarm_actions attribute",
            ),
            (r"threshold\s*=.*\n.*threshold\s*=", "Duplicate threshold attribute"),
        ]

        for pattern, message in duplicate_attrs:
            if re.search(pattern, content, re.MULTILINE):
                result.issues.append(
                    ValidationIssue(
                        severity=Severity.ERROR,
                        category="terraform_duplicate",
                        message=message,
                    )
                )

        # Check for missing best practices
        if (
            "aws_cloudwatch_event_rule" in content
            or "aws_cloudwatch_event_target" in content
        ):
            # Should have DLQ
            if "dead_letter" not in content.lower() and "dlq" not in content.lower():
                result.issues.append(
                    ValidationIssue(
                        severity=Severity.WARNING,
                        category="missing_dlq",
                        message="EventBridge rule has no dead-letter queue configured",
                        suggestion="Add dead_letter_config to aws_cloudwatch_event_target for reliability",
                    )
                )

            # Should have retry policy
            if "retry_policy" not in content.lower():
                result.issues.append(
                    ValidationIssue(
                        severity=Severity.WARNING,
                        category="missing_retry",
                        message="EventBridge rule has no retry policy configured",
                        suggestion="Add retry_policy with maximum_retry_attempts = 8",
                    )
                )

        # Check SNS topic encryption
        if "aws_sns_topic" in content:
            if "kms_master_key_id" not in content:
                result.issues.append(
                    ValidationIssue(
                        severity=Severity.WARNING,
                        category="unencrypted_sns",
                        message="SNS topic is not encrypted",
                        suggestion='Add kms_master_key_id = "alias/aws/sns" for encryption at rest',
                    )
                )

    def _validate_cloudformation_patterns(
        self, content: str, result: TemplateValidationResult
    ):
        """Validate CloudFormation resource patterns."""
        # Check for duplicate properties within the same CloudWatch Alarm resource
        # Split by alarm resource declarations and check each one
        alarm_pattern = (
            r"Type:\s*AWS::CloudWatch::Alarm\s*\n\s*Properties:(.*?)(?=\n\s*\w+:|$)"
        )
        alarm_matches = re.findall(alarm_pattern, content, re.DOTALL)

        for alarm_content in alarm_matches:
            treat_missing_count = alarm_content.count("TreatMissingData:")
            if treat_missing_count > 1:
                result.issues.append(
                    ValidationIssue(
                        severity=Severity.ERROR,
                        category="cloudformation_duplicate",
                        message="Duplicate TreatMissingData property in CloudWatch Alarm",
                    )
                )

    def _check_guardduty_coverage(
        self, technique_id: str, content: str, result: TemplateValidationResult
    ):
        """Check if technique has GuardDuty coverage we should use."""
        if technique_has_guardduty_coverage(technique_id):
            recommended = get_recommended_guardduty_findings(technique_id)

            # Check if template uses GuardDuty
            uses_guardduty = (
                any(f in content for f in recommended) or "GuardDuty" in content
            )

            if not uses_guardduty:
                result.issues.append(
                    ValidationIssue(
                        severity=Severity.WARNING,
                        category="guardduty_underutilized",
                        message=f"Technique {technique_id} has GuardDuty coverage but template doesn't use it",
                        suggestion=f"Consider using GuardDuty findings: {', '.join(recommended[:3])}",
                    )
                )

    def validate_all_templates(
        self, templates_dir: Path
    ) -> List[TemplateValidationResult]:
        """Validate all templates in directory."""
        self.results = []

        for template_path in templates_dir.glob("t*.py"):
            if template_path.name.startswith("__"):
                continue
            if "validation" in str(template_path):
                continue
            if template_path.name == "template_loader.py":
                continue  # Utility module, not a template

            self.validate_template(template_path)

        return self.results

    def generate_report(self) -> str:
        """Generate a validation report."""
        lines = [
            "# Remediation Template Validation Report",
            "",
            f"Templates validated: {len(self.results)}",
            f"Templates with errors: {sum(1 for r in self.results if r.has_errors)}",
            f"Templates with warnings: {sum(1 for r in self.results if r.has_warnings)}",
            "",
        ]

        # Group by category
        errors_by_category = {}
        for result in self.results:
            for issue in result.issues:
                if issue.category not in errors_by_category:
                    errors_by_category[issue.category] = []
                errors_by_category[issue.category].append((result.template_name, issue))

        if errors_by_category:
            lines.append("## Issues by Category")
            lines.append("")

            for category, issues in sorted(errors_by_category.items()):
                error_count = sum(1 for _, i in issues if i.severity == Severity.ERROR)
                warning_count = sum(
                    1 for _, i in issues if i.severity == Severity.WARNING
                )

                lines.append(
                    f"### {category} ({error_count} errors, {warning_count} warnings)"
                )
                lines.append("")

                for template_name, issue in issues:
                    severity_icon = "🔴" if issue.severity == Severity.ERROR else "🟡"
                    lines.append(
                        f"- {severity_icon} **{template_name}**: {issue.message}"
                    )
                    if issue.suggestion:
                        lines.append(f"  - 💡 {issue.suggestion}")

                lines.append("")

        # Templates with critical issues
        critical = [r for r in self.results if r.has_errors]
        if critical:
            lines.append("## Templates Requiring Immediate Attention")
            lines.append("")
            for result in critical:
                lines.append(
                    f"- **{result.template_name}** ({result.technique_id}): {result.error_count} errors"
                )

        return "\n".join(lines)


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Validate remediation templates")
    parser.add_argument("template", nargs="?", help="Specific template to validate")
    parser.add_argument("--report", action="store_true", help="Generate full report")
    parser.add_argument("--dir", default=".", help="Templates directory")
    args = parser.parse_args()

    validator = TemplateValidator()
    templates_dir = Path(args.dir)

    if args.template:
        template_path = templates_dir / args.template
        if not template_path.exists():
            print(f"Template not found: {template_path}")
            sys.exit(1)

        result = validator.validate_template(template_path)

        print(f"\n{'='*60}")
        print(f"Validation: {result.template_name} ({result.technique_id})")
        print(f"{'='*60}")

        if not result.issues:
            print("✅ No issues found")
        else:
            for issue in result.issues:
                icon = (
                    "🔴"
                    if issue.severity == Severity.ERROR
                    else "🟡" if issue.severity == Severity.WARNING else "ℹ️"
                )
                print(f"\n{icon} [{issue.category}] {issue.message}")
                if issue.line_number:
                    print(f"   Line: {issue.line_number}")
                if issue.suggestion:
                    print(f"   💡 {issue.suggestion}")

        sys.exit(1 if result.has_errors else 0)

    else:
        # Validate all templates
        results = validator.validate_all_templates(templates_dir)

        if args.report:
            print(validator.generate_report())
        else:
            errors = sum(r.error_count for r in results)
            warnings = sum(r.warning_count for r in results)
            print(
                f"\nValidated {len(results)} templates: {errors} errors, {warnings} warnings"
            )

            if errors > 0:
                print("\nTemplates with errors:")
                for r in results:
                    if r.has_errors:
                        print(f"  - {r.template_name}: {r.error_count} errors")

        sys.exit(1 if errors > 0 else 0)


if __name__ == "__main__":
    main()
