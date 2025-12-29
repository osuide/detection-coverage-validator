"""SDK call pattern library for MITRE technique mapping.

Maps AWS SDK calls to MITRE ATT&CK techniques for accurate
detection coverage assessment from code analysis.
"""

from dataclasses import dataclass, field


@dataclass
class SDKPattern:
    """Represents an SDK call pattern mapped to MITRE techniques."""

    # SDK call identification
    service: str  # e.g., "iam", "ec2", "s3"
    method_pattern: str  # e.g., "create_access_key", "describe_*"

    # MITRE mapping
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str

    # Mapping quality
    confidence: float = 0.85
    is_detection: bool = (
        True  # True if this indicates detection, False if it's the attack itself
    )

    # Context
    description: str = ""
    requires_context: list[str] = field(
        default_factory=list
    )  # Other calls that boost confidence


class SDKPatternLibrary:
    """Library of SDK call patterns mapped to MITRE ATT&CK techniques.

    This library enables code analysis to identify:
    1. What security events a Lambda function is monitoring (detection logic)
    2. What AWS APIs the function calls that could indicate attack patterns
    """

    # AWS SDK patterns for Python (boto3) and JavaScript (aws-sdk)
    PATTERNS: list[SDKPattern] = [
        # === IAM Operations ===
        SDKPattern(
            service="iam",
            method_pattern="create_access_key",
            technique_id="T1098.001",
            technique_name="Account Manipulation: Additional Cloud Credentials",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.9,
            description="Creating access keys for persistence",
        ),
        SDKPattern(
            service="iam",
            method_pattern="create_user",
            technique_id="T1136.003",
            technique_name="Create Account: Cloud Account",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.85,
        ),
        SDKPattern(
            service="iam",
            method_pattern="attach_user_policy",
            technique_id="T1098",
            technique_name="Account Manipulation",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.8,
        ),
        SDKPattern(
            service="iam",
            method_pattern="attach_role_policy",
            technique_id="T1098",
            technique_name="Account Manipulation",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.8,
        ),
        SDKPattern(
            service="iam",
            method_pattern="put_user_policy",
            technique_id="T1098",
            technique_name="Account Manipulation",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.8,
        ),
        SDKPattern(
            service="iam",
            method_pattern="create_login_profile",
            technique_id="T1098.001",
            technique_name="Account Manipulation: Additional Cloud Credentials",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.9,
        ),
        SDKPattern(
            service="iam",
            method_pattern="update_assume_role_policy",
            technique_id="T1098",
            technique_name="Account Manipulation",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.85,
            description="Modifying trust policies for privilege escalation",
        ),
        SDKPattern(
            service="iam",
            method_pattern="list_access_keys",
            technique_id="T1087.004",
            technique_name="Account Discovery: Cloud Account",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.7,
            is_detection=True,
        ),
        SDKPattern(
            service="iam",
            method_pattern="list_users",
            technique_id="T1087.004",
            technique_name="Account Discovery: Cloud Account",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.7,
            is_detection=True,
        ),
        SDKPattern(
            service="iam",
            method_pattern="get_account_authorization_details",
            technique_id="T1087.004",
            technique_name="Account Discovery: Cloud Account",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.8,
            is_detection=True,
        ),
        # === STS Operations ===
        SDKPattern(
            service="sts",
            method_pattern="assume_role",
            technique_id="T1550.001",
            technique_name="Use Alternate Authentication Material: Application Access Token",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.6,  # Lower confidence - legitimate use is common
        ),
        SDKPattern(
            service="sts",
            method_pattern="get_session_token",
            technique_id="T1550.001",
            technique_name="Use Alternate Authentication Material: Application Access Token",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.5,
        ),
        SDKPattern(
            service="sts",
            method_pattern="get_caller_identity",
            technique_id="T1087.004",
            technique_name="Account Discovery: Cloud Account",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.6,
            is_detection=True,
        ),
        # === EC2 Operations ===
        SDKPattern(
            service="ec2",
            method_pattern="describe_instances",
            technique_id="T1580",
            technique_name="Cloud Infrastructure Discovery",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.7,
            is_detection=True,
        ),
        SDKPattern(
            service="ec2",
            method_pattern="describe_security_groups",
            technique_id="T1580",
            technique_name="Cloud Infrastructure Discovery",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.7,
            is_detection=True,
        ),
        SDKPattern(
            service="ec2",
            method_pattern="authorize_security_group_ingress",
            technique_id="T1562.007",
            technique_name="Impair Defenses: Disable or Modify Cloud Firewall",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.85,
        ),
        SDKPattern(
            service="ec2",
            method_pattern="authorize_security_group_egress",
            technique_id="T1562.007",
            technique_name="Impair Defenses: Disable or Modify Cloud Firewall",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.85,
        ),
        SDKPattern(
            service="ec2",
            method_pattern="modify_instance_attribute",
            technique_id="T1578",
            technique_name="Modify Cloud Compute Infrastructure",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.75,
        ),
        SDKPattern(
            service="ec2",
            method_pattern="create_snapshot",
            technique_id="T1578.001",
            technique_name="Modify Cloud Compute Infrastructure: Create Snapshot",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.7,
        ),
        SDKPattern(
            service="ec2",
            method_pattern="copy_snapshot",
            technique_id="T1537",
            technique_name="Transfer Data to Cloud Account",
            tactic_id="TA0010",
            tactic_name="Exfiltration",
            confidence=0.75,
        ),
        SDKPattern(
            service="ec2",
            method_pattern="modify_snapshot_attribute",
            technique_id="T1537",
            technique_name="Transfer Data to Cloud Account",
            tactic_id="TA0010",
            tactic_name="Exfiltration",
            confidence=0.8,
            description="Sharing snapshots with external accounts",
        ),
        SDKPattern(
            service="ec2",
            method_pattern="run_instances",
            technique_id="T1578.002",
            technique_name="Modify Cloud Compute Infrastructure: Create Cloud Instance",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.6,
        ),
        # === S3 Operations ===
        SDKPattern(
            service="s3",
            method_pattern="put_bucket_policy",
            technique_id="T1562.008",
            technique_name="Impair Defenses: Disable Cloud Logs",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.7,
        ),
        SDKPattern(
            service="s3",
            method_pattern="delete_bucket_policy",
            technique_id="T1562.008",
            technique_name="Impair Defenses: Disable Cloud Logs",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.75,
        ),
        SDKPattern(
            service="s3",
            method_pattern="put_bucket_acl",
            technique_id="T1530",
            technique_name="Data from Cloud Storage Object",
            tactic_id="TA0009",
            tactic_name="Collection",
            confidence=0.7,
        ),
        SDKPattern(
            service="s3",
            method_pattern="put_object_acl",
            technique_id="T1530",
            technique_name="Data from Cloud Storage Object",
            tactic_id="TA0009",
            tactic_name="Collection",
            confidence=0.7,
        ),
        SDKPattern(
            service="s3",
            method_pattern="get_object",
            technique_id="T1530",
            technique_name="Data from Cloud Storage Object",
            tactic_id="TA0009",
            tactic_name="Collection",
            confidence=0.5,
            is_detection=True,
        ),
        SDKPattern(
            service="s3",
            method_pattern="list_buckets",
            technique_id="T1580",
            technique_name="Cloud Infrastructure Discovery",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.6,
            is_detection=True,
        ),
        SDKPattern(
            service="s3",
            method_pattern="put_bucket_versioning",
            technique_id="T1485",
            technique_name="Data Destruction",
            tactic_id="TA0040",
            tactic_name="Impact",
            confidence=0.6,
            description="Disabling versioning before deletion",
        ),
        # === CloudTrail Operations ===
        SDKPattern(
            service="cloudtrail",
            method_pattern="stop_logging",
            technique_id="T1562.008",
            technique_name="Impair Defenses: Disable Cloud Logs",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.95,
        ),
        SDKPattern(
            service="cloudtrail",
            method_pattern="delete_trail",
            technique_id="T1562.008",
            technique_name="Impair Defenses: Disable Cloud Logs",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.95,
        ),
        SDKPattern(
            service="cloudtrail",
            method_pattern="update_trail",
            technique_id="T1562.008",
            technique_name="Impair Defenses: Disable Cloud Logs",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.7,
        ),
        SDKPattern(
            service="cloudtrail",
            method_pattern="lookup_events",
            technique_id="T1538",
            technique_name="Cloud Service Dashboard",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.8,
            is_detection=True,
        ),
        # === Lambda Operations ===
        SDKPattern(
            service="lambda",
            method_pattern="update_function_code",
            technique_id="T1525",
            technique_name="Implant Internal Image",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.7,
        ),
        SDKPattern(
            service="lambda",
            method_pattern="add_permission",
            technique_id="T1098",
            technique_name="Account Manipulation",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.7,
        ),
        SDKPattern(
            service="lambda",
            method_pattern="create_function",
            technique_id="T1525",
            technique_name="Implant Internal Image",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.6,
        ),
        SDKPattern(
            service="lambda",
            method_pattern="update_function_configuration",
            technique_id="T1525",
            technique_name="Implant Internal Image",
            tactic_id="TA0003",
            tactic_name="Persistence",
            confidence=0.65,
        ),
        # === Secrets Manager / SSM ===
        SDKPattern(
            service="secretsmanager",
            method_pattern="get_secret_value",
            technique_id="T1552.005",
            technique_name="Unsecured Credentials: Cloud Instance Metadata API",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            confidence=0.7,
        ),
        SDKPattern(
            service="ssm",
            method_pattern="get_parameter",
            technique_id="T1552.005",
            technique_name="Unsecured Credentials: Cloud Instance Metadata API",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            confidence=0.65,
        ),
        SDKPattern(
            service="ssm",
            method_pattern="get_parameters_by_path",
            technique_id="T1552.005",
            technique_name="Unsecured Credentials: Cloud Instance Metadata API",
            tactic_id="TA0006",
            tactic_name="Credential Access",
            confidence=0.7,
        ),
        SDKPattern(
            service="ssm",
            method_pattern="send_command",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic_id="TA0002",
            tactic_name="Execution",
            confidence=0.8,
        ),
        # === Organizations ===
        SDKPattern(
            service="organizations",
            method_pattern="describe_organization",
            technique_id="T1580",
            technique_name="Cloud Infrastructure Discovery",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.7,
            is_detection=True,
        ),
        SDKPattern(
            service="organizations",
            method_pattern="list_accounts",
            technique_id="T1087.004",
            technique_name="Account Discovery: Cloud Account",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.8,
            is_detection=True,
        ),
        # === KMS ===
        SDKPattern(
            service="kms",
            method_pattern="schedule_key_deletion",
            technique_id="T1485",
            technique_name="Data Destruction",
            tactic_id="TA0040",
            tactic_name="Impact",
            confidence=0.85,
        ),
        SDKPattern(
            service="kms",
            method_pattern="disable_key",
            technique_id="T1485",
            technique_name="Data Destruction",
            tactic_id="TA0040",
            tactic_name="Impact",
            confidence=0.8,
        ),
        # === RDS ===
        SDKPattern(
            service="rds",
            method_pattern="modify_db_instance",
            technique_id="T1578",
            technique_name="Modify Cloud Compute Infrastructure",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.6,
        ),
        SDKPattern(
            service="rds",
            method_pattern="create_db_snapshot",
            technique_id="T1530",
            technique_name="Data from Cloud Storage Object",
            tactic_id="TA0009",
            tactic_name="Collection",
            confidence=0.7,
        ),
        SDKPattern(
            service="rds",
            method_pattern="modify_db_snapshot_attribute",
            technique_id="T1537",
            technique_name="Transfer Data to Cloud Account",
            tactic_id="TA0010",
            tactic_name="Exfiltration",
            confidence=0.85,
            description="Sharing RDS snapshots externally",
        ),
        # === GuardDuty / Security Hub (Detection indicators) ===
        SDKPattern(
            service="guardduty",
            method_pattern="get_findings",
            technique_id="T1538",
            technique_name="Cloud Service Dashboard",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.9,
            is_detection=True,
            description="Retrieving GuardDuty findings for security monitoring",
        ),
        SDKPattern(
            service="securityhub",
            method_pattern="get_findings",
            technique_id="T1538",
            technique_name="Cloud Service Dashboard",
            tactic_id="TA0007",
            tactic_name="Discovery",
            confidence=0.9,
            is_detection=True,
        ),
        SDKPattern(
            service="guardduty",
            method_pattern="update_detector",
            technique_id="T1562.008",
            technique_name="Impair Defenses: Disable Cloud Logs",
            tactic_id="TA0005",
            tactic_name="Defense Evasion",
            confidence=0.8,
        ),
    ]

    def __init__(self) -> None:
        # Build lookup index by service
        self._by_service: dict[str, list[SDKPattern]] = {}
        for pattern in self.PATTERNS:
            if pattern.service not in self._by_service:
                self._by_service[pattern.service] = []
            self._by_service[pattern.service].append(pattern)

    def find_patterns(self, service: str, method: str) -> list[SDKPattern]:
        """Find matching patterns for an SDK call."""
        matches = []
        service_patterns = self._by_service.get(service.lower(), [])

        for pattern in service_patterns:
            # Check for exact match or wildcard
            if pattern.method_pattern == method.lower():
                matches.append(pattern)
            elif pattern.method_pattern.endswith("*"):
                prefix = pattern.method_pattern[:-1]
                if method.lower().startswith(prefix):
                    matches.append(pattern)

        return matches

    def get_detection_patterns(self) -> list[SDKPattern]:
        """Get patterns that indicate detection logic (not attacks)."""
        return [p for p in self.PATTERNS if p.is_detection]

    def get_attack_patterns(self) -> list[SDKPattern]:
        """Get patterns that indicate potential attack behavior."""
        return [p for p in self.PATTERNS if not p.is_detection]

    def get_patterns_by_technique(self, technique_id: str) -> list[SDKPattern]:
        """Get all patterns mapping to a specific technique."""
        return [p for p in self.PATTERNS if p.technique_id == technique_id]

    def get_all_techniques(self) -> set[str]:
        """Get all unique technique IDs in the library."""
        return {p.technique_id for p in self.PATTERNS}
