"""MITRE ATT&CK technique indicator library following 05-MAPPING-AGENT.md design.

This library maps CloudTrail events, keywords, and patterns to MITRE techniques.
Based on MITRE ATT&CK v14.1 Cloud Matrix.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class TechniqueIndicator:
    """Indicators for a MITRE technique."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str

    # CloudTrail event names that indicate this technique
    cloudtrail_events: list[str]

    # Keywords in detection names/descriptions
    keywords: list[str]

    # AWS services relevant to this technique
    aws_services: list[str]

    # Log group patterns (regex)
    log_patterns: list[str]

    # Base confidence for pattern match
    base_confidence: float = 0.7

    # Priority for gap analysis (1=critical, 4=low)
    priority: int = 2


# Reconnaissance - TA0043
RECON_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1526",
        technique_name="Cloud Service Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        cloudtrail_events=[
            "DescribeInstances",
            "ListBuckets",
            "DescribeDBInstances",
            "ListFunctions",
            "DescribeVpcs",
            "ListRoles",
            "GetAccountAuthorizationDetails",
        ],
        keywords=["discovery", "enumerate", "list", "describe", "inventory"],
        aws_services=["ec2", "s3", "rds", "lambda", "iam"],
        log_patterns=[r"describe", r"list", r"get.*config"],
        base_confidence=0.65,
        priority=3,
    ),
]

# Initial Access - TA0001
INITIAL_ACCESS_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1078.004",
        technique_name="Valid Accounts: Cloud Accounts",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        cloudtrail_events=[
            "ConsoleLogin",
            "AssumeRole",
            "GetSessionToken",
            "AssumeRoleWithSAML",
            "AssumeRoleWithWebIdentity",
        ],
        keywords=[
            "login",
            "signin",
            "authentication",
            "console",
            "assume",
            "credential",
            "mfa",
        ],
        aws_services=["sts", "signin", "iam"],
        log_patterns=[r"login", r"signin", r"console", r"assume.*role"],
        base_confidence=0.75,
        priority=1,
    ),
    TechniqueIndicator(
        technique_id="T1199",
        technique_name="Trusted Relationship",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        cloudtrail_events=[
            "AssumeRole",
            "CreateRole",
            "UpdateAssumeRolePolicy",
            "PutRolePolicy",
        ],
        keywords=["cross-account", "trust", "external", "third-party", "partner"],
        aws_services=["sts", "iam", "organizations"],
        log_patterns=[r"cross.?account", r"trust", r"external"],
        base_confidence=0.7,
        priority=2,
    ),
]

# Persistence - TA0003
PERSISTENCE_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1098.001",
        technique_name="Account Manipulation: Additional Cloud Credentials",
        tactic_id="TA0003",
        tactic_name="Persistence",
        cloudtrail_events=[
            "CreateAccessKey",
            "CreateLoginProfile",
            "UpdateLoginProfile",
            "CreateServiceSpecificCredential",
            "UploadSSHPublicKey",
        ],
        keywords=[
            "access key",
            "credential",
            "api key",
            "new key",
            "create key",
            "password",
        ],
        aws_services=["iam"],
        log_patterns=[r"create.*key", r"access.?key", r"credential"],
        base_confidence=0.8,
        priority=1,
    ),
    TechniqueIndicator(
        technique_id="T1098.003",
        technique_name="Account Manipulation: Additional Cloud Roles",
        tactic_id="TA0003",
        tactic_name="Persistence",
        cloudtrail_events=[
            "CreateRole",
            "AttachRolePolicy",
            "PutRolePolicy",
            "UpdateAssumeRolePolicy",
            "AttachUserPolicy",
        ],
        keywords=["role", "policy", "permission", "attach", "privilege"],
        aws_services=["iam"],
        log_patterns=[r"role", r"policy", r"permission"],
        base_confidence=0.75,
        priority=1,
    ),
    TechniqueIndicator(
        technique_id="T1136.003",
        technique_name="Create Account: Cloud Account",
        tactic_id="TA0003",
        tactic_name="Persistence",
        cloudtrail_events=[
            "CreateUser",
            "CreateGroup",
            "AddUserToGroup",
            "InviteAccountToOrganization",
        ],
        keywords=["create user", "new user", "add user", "user creation"],
        aws_services=["iam", "organizations"],
        log_patterns=[r"create.*user", r"new.*account"],
        base_confidence=0.8,
        priority=1,
    ),
    TechniqueIndicator(
        technique_id="T1525",
        technique_name="Implant Internal Image",
        tactic_id="TA0003",
        tactic_name="Persistence",
        cloudtrail_events=[
            "CreateImage",
            "RegisterImage",
            "ModifyImageAttribute",
            "CopyImage",
            "PutImage",
        ],
        keywords=["ami", "image", "container", "ecr", "registry"],
        aws_services=["ec2", "ecr"],
        log_patterns=[r"image", r"ami", r"container", r"registry"],
        base_confidence=0.7,
        priority=2,
    ),
]

# Privilege Escalation - TA0004
PRIVILEGE_ESCALATION_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1548.005",
        technique_name="Abuse Elevation Control: Temporary Elevated Cloud Access",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        cloudtrail_events=[
            "AssumeRole",
            "GetSessionToken",
            "GetFederationToken",
        ],
        keywords=["elevate", "escalate", "privilege", "admin", "temporary"],
        aws_services=["sts", "iam"],
        log_patterns=[r"escalat", r"privilege", r"elevat"],
        base_confidence=0.7,
        priority=1,
    ),
]

# Defense Evasion - TA0005
DEFENSE_EVASION_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable Cloud Logs",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        cloudtrail_events=[
            "StopLogging",
            "DeleteTrail",
            "UpdateTrail",
            "PutEventSelectors",
            "DeleteFlowLogs",
            "DeleteDeliveryChannel",
        ],
        keywords=["disable", "stop", "delete", "logging", "trail", "audit"],
        aws_services=["cloudtrail", "config", "vpc"],
        log_patterns=[r"stop.*log", r"delete.*trail", r"disable.*log"],
        base_confidence=0.85,
        priority=1,
    ),
    TechniqueIndicator(
        technique_id="T1578.002",
        technique_name="Modify Cloud Compute Infrastructure: Create Snapshot",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        cloudtrail_events=[
            "CreateSnapshot",
            "CopySnapshot",
            "ModifySnapshotAttribute",
            "CreateDBSnapshot",
        ],
        keywords=["snapshot", "backup", "copy"],
        aws_services=["ec2", "rds", "ebs"],
        log_patterns=[r"snapshot", r"backup"],
        base_confidence=0.6,
        priority=3,
    ),
    TechniqueIndicator(
        technique_id="T1535",
        technique_name="Unused/Unsupported Cloud Regions",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        cloudtrail_events=[],
        keywords=["region", "geographic", "unused", "uncommon"],
        aws_services=["ec2", "lambda"],
        log_patterns=[r"region"],
        base_confidence=0.5,
        priority=3,
    ),
]

# Credential Access - TA0006
CREDENTIAL_ACCESS_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1552.005",
        technique_name="Unsecured Credentials: Cloud Instance Metadata API",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        cloudtrail_events=[],
        keywords=["metadata", "imds", "169.254.169.254", "instance identity"],
        aws_services=["ec2"],
        log_patterns=[r"metadata", r"169\.254", r"imds"],
        base_confidence=0.75,
        priority=1,
    ),
    TechniqueIndicator(
        technique_id="T1528",
        technique_name="Steal Application Access Token",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        cloudtrail_events=[
            "GetSecretValue",
            "GetParameter",
            "GetParameters",
            "DescribeSecret",
        ],
        keywords=["secret", "token", "parameter store", "ssm", "credential"],
        aws_services=["secretsmanager", "ssm"],
        log_patterns=[r"secret", r"token", r"ssm"],
        base_confidence=0.7,
        priority=1,
    ),
]

# Discovery - TA0007
DISCOVERY_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1580",
        technique_name="Cloud Infrastructure Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        cloudtrail_events=[
            "DescribeInstances",
            "DescribeSecurityGroups",
            "DescribeSubnets",
            "DescribeVpcs",
            "DescribeVolumes",
        ],
        keywords=["infrastructure", "network", "vpc", "security group", "subnet"],
        aws_services=["ec2", "vpc"],
        log_patterns=[r"describe", r"infrastructure"],
        base_confidence=0.65,
        priority=3,
    ),
    TechniqueIndicator(
        technique_id="T1619",
        technique_name="Cloud Storage Object Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        cloudtrail_events=[
            "ListBuckets",
            "ListObjects",
            "ListObjectsV2",
            "GetBucketLocation",
            "GetBucketPolicy",
        ],
        keywords=["s3", "bucket", "storage", "object", "list"],
        aws_services=["s3"],
        log_patterns=[r"bucket", r"s3", r"storage"],
        base_confidence=0.65,
        priority=2,
    ),
]

# Lateral Movement - TA0008
LATERAL_MOVEMENT_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1550.001",
        technique_name="Use Alternate Authentication Material: Application Access Token",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        cloudtrail_events=[
            "AssumeRole",
            "AssumeRoleWithSAML",
            "AssumeRoleWithWebIdentity",
        ],
        keywords=["cross-account", "assume", "lateral", "token"],
        aws_services=["sts"],
        log_patterns=[r"assume", r"lateral", r"cross"],
        base_confidence=0.7,
        priority=2,
    ),
]

# Collection - TA0009
COLLECTION_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1530",
        technique_name="Data from Cloud Storage",
        tactic_id="TA0009",
        tactic_name="Collection",
        cloudtrail_events=[
            "GetObject",
            "CopyObject",
            "HeadObject",
            "GetBucketAcl",
        ],
        keywords=["download", "exfil", "copy", "data", "s3"],
        aws_services=["s3"],
        log_patterns=[r"get.*object", r"download", r"copy"],
        base_confidence=0.6,
        priority=2,
    ),
]

# Exfiltration - TA0010
EXFILTRATION_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1537",
        technique_name="Transfer Data to Cloud Account",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        cloudtrail_events=[
            "PutBucketPolicy",
            "PutBucketAcl",
            "CopyObject",
            "ModifySnapshotAttribute",
        ],
        keywords=["public", "share", "external", "transfer", "exfil"],
        aws_services=["s3", "ec2", "rds"],
        log_patterns=[r"public", r"share", r"external", r"transfer"],
        base_confidence=0.75,
        priority=1,
    ),
]

# Impact - TA0040
IMPACT_TECHNIQUES = [
    TechniqueIndicator(
        technique_id="T1485",
        technique_name="Data Destruction",
        tactic_id="TA0040",
        tactic_name="Impact",
        cloudtrail_events=[
            "DeleteBucket",
            "DeleteObject",
            "DeleteObjects",
            "DeleteVolume",
            "DeleteDBInstance",
            "TerminateInstances",
        ],
        keywords=["delete", "destroy", "terminate", "remove", "wipe"],
        aws_services=["s3", "ec2", "rds"],
        log_patterns=[r"delete", r"destroy", r"terminate"],
        base_confidence=0.75,
        priority=1,
    ),
    TechniqueIndicator(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic_id="TA0040",
        tactic_name="Impact",
        cloudtrail_events=[
            "PutBucketEncryption",
            "CreateKey",
            "Encrypt",
            "ScheduleKeyDeletion",
        ],
        keywords=["encrypt", "ransom", "kms", "key"],
        aws_services=["kms", "s3"],
        log_patterns=[r"encrypt", r"kms", r"key"],
        base_confidence=0.6,
        priority=2,
    ),
    TechniqueIndicator(
        technique_id="T1496",
        technique_name="Resource Hijacking",
        tactic_id="TA0040",
        tactic_name="Impact",
        cloudtrail_events=[
            "RunInstances",
            "CreateFunction",
            "UpdateFunctionConfiguration",
        ],
        keywords=["crypto", "mining", "hijack", "resource", "compute"],
        aws_services=["ec2", "lambda"],
        log_patterns=[r"crypto", r"mining", r"unusual.*compute"],
        base_confidence=0.7,
        priority=2,
    ),
]

# Combine all technique indicators
TECHNIQUE_INDICATORS: list[TechniqueIndicator] = [
    *RECON_TECHNIQUES,
    *INITIAL_ACCESS_TECHNIQUES,
    *PERSISTENCE_TECHNIQUES,
    *PRIVILEGE_ESCALATION_TECHNIQUES,
    *DEFENSE_EVASION_TECHNIQUES,
    *CREDENTIAL_ACCESS_TECHNIQUES,
    *DISCOVERY_TECHNIQUES,
    *LATERAL_MOVEMENT_TECHNIQUES,
    *COLLECTION_TECHNIQUES,
    *EXFILTRATION_TECHNIQUES,
    *IMPACT_TECHNIQUES,
]

# Create lookup dictionaries for efficient access
TECHNIQUE_BY_ID: dict[str, TechniqueIndicator] = {
    t.technique_id: t for t in TECHNIQUE_INDICATORS
}

TECHNIQUES_BY_TACTIC: dict[str, list[TechniqueIndicator]] = {}
for t in TECHNIQUE_INDICATORS:
    if t.tactic_id not in TECHNIQUES_BY_TACTIC:
        TECHNIQUES_BY_TACTIC[t.tactic_id] = []
    TECHNIQUES_BY_TACTIC[t.tactic_id].append(t)

CLOUDTRAIL_EVENT_TO_TECHNIQUES: dict[str, list[str]] = {}
for t in TECHNIQUE_INDICATORS:
    for event in t.cloudtrail_events:
        if event not in CLOUDTRAIL_EVENT_TO_TECHNIQUES:
            CLOUDTRAIL_EVENT_TO_TECHNIQUES[event] = []
        CLOUDTRAIL_EVENT_TO_TECHNIQUES[event].append(t.technique_id)
