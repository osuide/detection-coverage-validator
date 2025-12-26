"""AWS GuardDuty Finding Types Reference.

This module provides the authoritative list of valid GuardDuty finding types
based on official AWS documentation. Use this to validate finding types in
remediation templates.

Sources:
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
- https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html

Last updated: 26 December 2025
"""

from enum import Enum
from typing import NamedTuple


class GuardDutyFeature(Enum):
    """GuardDuty features that must be enabled for specific finding types."""

    BASE = "base"  # Core GuardDuty (CloudTrail, VPC Flow Logs, DNS)
    S3_PROTECTION = "s3_protection"
    EKS_AUDIT_LOG = "eks_audit_log"
    EKS_RUNTIME = "eks_runtime"
    EC2_RUNTIME = "ec2_runtime"
    ECS_RUNTIME = "ecs_runtime"
    LAMBDA_PROTECTION = "lambda_protection"
    MALWARE_PROTECTION = "malware_protection"
    RDS_PROTECTION = "rds_protection"
    EXTENDED_THREAT_DETECTION = "extended_threat_detection"


class FindingTypeInfo(NamedTuple):
    """Information about a GuardDuty finding type."""

    finding_type: str
    required_feature: GuardDutyFeature
    description: str = ""


# =============================================================================
# EC2 Finding Types (Base GuardDuty)
# =============================================================================
EC2_FINDING_TYPES: frozenset[str] = frozenset(
    {
        # Backdoor
        "Backdoor:EC2/C&CActivity.B",
        "Backdoor:EC2/C&CActivity.B!DNS",
        "Backdoor:EC2/DenialOfService.Dns",
        "Backdoor:EC2/DenialOfService.Tcp",
        "Backdoor:EC2/DenialOfService.Udp",
        "Backdoor:EC2/DenialOfService.UdpOnTcpPorts",
        "Backdoor:EC2/DenialOfService.UnusualProtocol",
        "Backdoor:EC2/Spambot",
        # Behavior
        "Behavior:EC2/NetworkPortUnusual",
        "Behavior:EC2/TrafficVolumeUnusual",
        # CryptoCurrency
        "CryptoCurrency:EC2/BitcoinTool.B",
        "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        # DefenseEvasion
        "DefenseEvasion:EC2/UnusualDNSResolver",
        "DefenseEvasion:EC2/UnusualDoHActivity",
        "DefenseEvasion:EC2/UnusualDoTActivity",
        # Impact
        "Impact:EC2/AbusedDomainRequest.Reputation",
        "Impact:EC2/BitcoinDomainRequest.Reputation",
        "Impact:EC2/MaliciousDomainRequest.Custom",
        "Impact:EC2/MaliciousDomainRequest.Reputation",
        "Impact:EC2/PortSweep",
        "Impact:EC2/SuspiciousDomainRequest.Reputation",
        "Impact:EC2/WinRMBruteForce",
        # Recon
        "Recon:EC2/PortProbeEMRUnprotectedPort",
        "Recon:EC2/PortProbeUnprotectedPort",
        "Recon:EC2/Portscan",
        # Trojan
        "Trojan:EC2/BlackholeTraffic",
        "Trojan:EC2/BlackholeTraffic!DNS",
        "Trojan:EC2/DGADomainRequest.B",
        "Trojan:EC2/DGADomainRequest.C!DNS",
        "Trojan:EC2/DNSDataExfiltration",
        "Trojan:EC2/DriveBySourceTraffic!DNS",
        "Trojan:EC2/DropPoint",
        "Trojan:EC2/DropPoint!DNS",
        "Trojan:EC2/PhishingDomainRequest!DNS",
        # UnauthorizedAccess
        "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
        "UnauthorizedAccess:EC2/MetadataDNSRebind",
        "UnauthorizedAccess:EC2/RDPBruteForce",
        "UnauthorizedAccess:EC2/SSHBruteForce",
        "UnauthorizedAccess:EC2/TorClient",
        "UnauthorizedAccess:EC2/TorRelay",
    }
)

# =============================================================================
# IAM Finding Types (Base GuardDuty)
# =============================================================================
IAM_FINDING_TYPES: frozenset[str] = frozenset(
    {
        # CredentialAccess
        "CredentialAccess:IAMUser/AnomalousBehavior",
        # DefenseEvasion
        "DefenseEvasion:IAMUser/AnomalousBehavior",
        "DefenseEvasion:IAMUser/BedrockLoggingDisabled",
        # Discovery
        "Discovery:IAMUser/AnomalousBehavior",
        # Exfiltration
        "Exfiltration:IAMUser/AnomalousBehavior",
        # Impact
        "Impact:IAMUser/AnomalousBehavior",
        # InitialAccess
        "InitialAccess:IAMUser/AnomalousBehavior",
        # PenTest
        "PenTest:IAMUser/KaliLinux",
        "PenTest:IAMUser/ParrotLinux",
        "PenTest:IAMUser/PentooLinux",
        # Persistence
        "Persistence:IAMUser/AnomalousBehavior",
        # Policy
        "Policy:IAMUser/RootCredentialUsage",
        "Policy:IAMUser/ShortTermRootCredentialUsage",
        # PrivilegeEscalation
        "PrivilegeEscalation:IAMUser/AnomalousBehavior",
        # Recon
        "Recon:IAMUser/MaliciousIPCaller",
        "Recon:IAMUser/MaliciousIPCaller.Custom",
        "Recon:IAMUser/TorIPCaller",
        # Stealth
        "Stealth:IAMUser/CloudTrailLoggingDisabled",
        "Stealth:IAMUser/PasswordPolicyChange",
        # UnauthorizedAccess
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
        "UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.OutsideAWS",
        "UnauthorizedAccess:IAMUser/TorIPCaller",
    }
)

# =============================================================================
# S3 Protection Finding Types
# =============================================================================
S3_FINDING_TYPES: frozenset[str] = frozenset(
    {
        # Discovery
        "Discovery:S3/AnomalousBehavior",
        "Discovery:S3/MaliciousIPCaller",
        "Discovery:S3/MaliciousIPCaller.Custom",
        "Discovery:S3/TorIPCaller",
        # Exfiltration
        "Exfiltration:S3/AnomalousBehavior",
        "Exfiltration:S3/MaliciousIPCaller",
        # Impact
        "Impact:S3/AnomalousBehavior.Delete",
        "Impact:S3/AnomalousBehavior.Permission",
        "Impact:S3/AnomalousBehavior.Write",
        "Impact:S3/MaliciousIPCaller",
        # Object (Malware Protection for S3)
        "Object:S3/MaliciousFile",
        # PenTest
        "PenTest:S3/KaliLinux",
        "PenTest:S3/ParrotLinux",
        "PenTest:S3/PentooLinux",
        # Policy
        "Policy:S3/AccountBlockPublicAccessDisabled",
        "Policy:S3/BucketAnonymousAccessGranted",
        "Policy:S3/BucketBlockPublicAccessDisabled",
        "Policy:S3/BucketPublicAccessGranted",
        # Stealth
        "Stealth:S3/ServerAccessLoggingDisabled",
        # UnauthorizedAccess
        "UnauthorizedAccess:S3/MaliciousIPCaller.Custom",
        "UnauthorizedAccess:S3/TorIPCaller",
    }
)

# =============================================================================
# Lambda Protection Finding Types
# =============================================================================
LAMBDA_FINDING_TYPES: frozenset[str] = frozenset(
    {
        "Backdoor:Lambda/C&CActivity.B",
        "CryptoCurrency:Lambda/BitcoinTool.B",
        "Trojan:Lambda/BlackholeTraffic",
        "Trojan:Lambda/DropPoint",
        "UnauthorizedAccess:Lambda/MaliciousIPCaller.Custom",
        "UnauthorizedAccess:Lambda/TorClient",
        "UnauthorizedAccess:Lambda/TorRelay",
    }
)

# =============================================================================
# Runtime Monitoring Finding Types (EC2/ECS/EKS)
# =============================================================================
RUNTIME_FINDING_TYPES: frozenset[str] = frozenset(
    {
        # Backdoor
        "Backdoor:Runtime/C&CActivity.B",
        "Backdoor:Runtime/C&CActivity.B!DNS",
        # CryptoCurrency
        "CryptoCurrency:Runtime/BitcoinTool.B",
        "CryptoCurrency:Runtime/BitcoinTool.B!DNS",
        # DefenseEvasion
        "DefenseEvasion:Runtime/FilelessExecution",
        "DefenseEvasion:Runtime/KernelModuleLoaded",
        "DefenseEvasion:Runtime/ProcessInjection.Proc",
        "DefenseEvasion:Runtime/ProcessInjection.Ptrace",
        "DefenseEvasion:Runtime/ProcessInjection.VirtualMemoryWrite",
        "DefenseEvasion:Runtime/PtraceAntiDebugging",
        "DefenseEvasion:Runtime/SuspiciousCommand",
        # Discovery
        "Discovery:Runtime/SuspiciousCommand",
        # Execution
        "Execution:Runtime/MaliciousFileExecuted",
        "Execution:Runtime/NewBinaryExecuted",
        "Execution:Runtime/NewLibraryLoaded",
        "Execution:Runtime/ReverseShell",
        "Execution:Runtime/SuspiciousCommand",
        "Execution:Runtime/SuspiciousShellCreated",
        "Execution:Runtime/SuspiciousTool",
        # Impact
        "Impact:Runtime/AbusedDomainRequest.Reputation",
        "Impact:Runtime/BitcoinDomainRequest.Reputation",
        "Impact:Runtime/CryptoMinerExecuted",
        "Impact:Runtime/MaliciousDomainRequest.Reputation",
        "Impact:Runtime/SuspiciousDomainRequest.Reputation",
        # Persistence
        "Persistence:Runtime/SuspiciousCommand",
        # PrivilegeEscalation
        "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified",
        "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
        "PrivilegeEscalation:Runtime/DockerSocketAccessed",
        "PrivilegeEscalation:Runtime/ElevationToRoot",
        "PrivilegeEscalation:Runtime/RuncContainerEscape",
        "PrivilegeEscalation:Runtime/SuspiciousCommand",
        "PrivilegeEscalation:Runtime/UserfaultfdUsage",
        # Trojan
        "Trojan:Runtime/BlackholeTraffic",
        "Trojan:Runtime/BlackholeTraffic!DNS",
        "Trojan:Runtime/DGADomainRequest.C!DNS",
        "Trojan:Runtime/DriveBySourceTraffic!DNS",
        "Trojan:Runtime/DropPoint",
        "Trojan:Runtime/DropPoint!DNS",
        "Trojan:Runtime/PhishingDomainRequest!DNS",
        # UnauthorizedAccess
        "UnauthorizedAccess:Runtime/MetadataDNSRebind",
        "UnauthorizedAccess:Runtime/TorClient",
        "UnauthorizedAccess:Runtime/TorRelay",
    }
)

# =============================================================================
# Kubernetes/EKS Finding Types
# =============================================================================
KUBERNETES_FINDING_TYPES: frozenset[str] = frozenset(
    {
        # CredentialAccess
        "CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed",
        "CredentialAccess:Kubernetes/MaliciousIPCaller",
        "CredentialAccess:Kubernetes/MaliciousIPCaller.Custom",
        "CredentialAccess:Kubernetes/SuccessfulAnonymousAccess",
        "CredentialAccess:Kubernetes/TorIPCaller",
        # DefenseEvasion
        "DefenseEvasion:Kubernetes/MaliciousIPCaller",
        "DefenseEvasion:Kubernetes/MaliciousIPCaller.Custom",
        "DefenseEvasion:Kubernetes/SuccessfulAnonymousAccess",
        "DefenseEvasion:Kubernetes/TorIPCaller",
        # Discovery
        "Discovery:Kubernetes/AnomalousBehavior.PermissionChecked",
        "Discovery:Kubernetes/MaliciousIPCaller",
        "Discovery:Kubernetes/MaliciousIPCaller.Custom",
        "Discovery:Kubernetes/SuccessfulAnonymousAccess",
        "Discovery:Kubernetes/TorIPCaller",
        # Execution
        "Execution:Kubernetes/AnomalousBehavior.ExecInPod",
        "Execution:Kubernetes/AnomalousBehavior.WorkloadDeployed",
        "Execution:Kubernetes/ExecInKubeSystemPod",
        # Impact
        "Impact:Kubernetes/MaliciousIPCaller",
        "Impact:Kubernetes/MaliciousIPCaller.Custom",
        "Impact:Kubernetes/SuccessfulAnonymousAccess",
        "Impact:Kubernetes/TorIPCaller",
        # Persistence
        "Persistence:Kubernetes/AnomalousBehavior.WorkloadDeployed!ContainerWithSensitiveMount",
        "Persistence:Kubernetes/ContainerWithSensitiveMount",
        "Persistence:Kubernetes/MaliciousIPCaller",
        "Persistence:Kubernetes/MaliciousIPCaller.Custom",
        "Persistence:Kubernetes/SuccessfulAnonymousAccess",
        "Persistence:Kubernetes/TorIPCaller",
        # Policy
        "Policy:Kubernetes/AdminAccessToDefaultServiceAccount",
        "Policy:Kubernetes/AnonymousAccessGranted",
        "Policy:Kubernetes/ExposedDashboard",
        "Policy:Kubernetes/KubeflowDashboardExposed",
        # PrivilegeEscalation
        "PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleBindingCreated",
        "PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleCreated",
        "PrivilegeEscalation:Kubernetes/AnomalousBehavior.WorkloadDeployed!PrivilegedContainer",
        "PrivilegeEscalation:Kubernetes/PrivilegedContainer",
    }
)

# =============================================================================
# Malware Protection Finding Types
# =============================================================================
MALWARE_FINDING_TYPES: frozenset[str] = frozenset(
    {
        "Execution:Container/MaliciousFile",
        "Execution:Container/SuspiciousFile",
        "Execution:EC2/MaliciousFile",
        "Execution:EC2/MaliciousFile!AMI",
        "Execution:EC2/MaliciousFile!Snapshot",
        "Execution:EC2/SuspiciousFile",
        "Execution:ECS/MaliciousFile",
        "Execution:ECS/SuspiciousFile",
        "Execution:Kubernetes/MaliciousFile",
        "Execution:Kubernetes/SuspiciousFile",
        "Execution:EC2/MaliciousFile!RecoveryPoint",
        "Execution:S3/MaliciousFile!RecoveryPoint",
    }
)

# =============================================================================
# RDS Protection Finding Types
# =============================================================================
RDS_FINDING_TYPES: frozenset[str] = frozenset(
    {
        "CredentialAccess:RDS/AnomalousBehavior.FailedLogin",
        "CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce",
        "CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin",
        "CredentialAccess:RDS/MaliciousIPCaller.FailedLogin",
        "CredentialAccess:RDS/MaliciousIPCaller.SuccessfulLogin",
        "CredentialAccess:RDS/TorIPCaller.FailedLogin",
        "CredentialAccess:RDS/TorIPCaller.SuccessfulLogin",
        "Discovery:RDS/MaliciousIPCaller",
        "Discovery:RDS/TorIPCaller",
    }
)

# =============================================================================
# Attack Sequence Finding Types (Extended Threat Detection)
# =============================================================================
ATTACK_SEQUENCE_FINDING_TYPES: frozenset[str] = frozenset(
    {
        "AttackSequence:EC2/CompromisedInstanceGroup",
        "AttackSequence:ECS/CompromisedCluster",
        "AttackSequence:EKS/CompromisedCluster",
        "AttackSequence:IAM/CompromisedCredentials",
        "AttackSequence:S3/CompromisedData",
    }
)

# =============================================================================
# All Valid Finding Types (Combined)
# =============================================================================
ALL_VALID_FINDING_TYPES: frozenset[str] = (
    EC2_FINDING_TYPES
    | IAM_FINDING_TYPES
    | S3_FINDING_TYPES
    | LAMBDA_FINDING_TYPES
    | RUNTIME_FINDING_TYPES
    | KUBERNETES_FINDING_TYPES
    | MALWARE_FINDING_TYPES
    | RDS_FINDING_TYPES
    | ATTACK_SEQUENCE_FINDING_TYPES
)

# =============================================================================
# Valid Prefixes for Wildcard Matching
# =============================================================================
VALID_PREFIXES: frozenset[str] = frozenset(
    {
        # EC2
        "Backdoor:EC2/",
        "Behavior:EC2/",
        "CryptoCurrency:EC2/",
        "DefenseEvasion:EC2/",
        "Impact:EC2/",
        "Recon:EC2/",
        "Trojan:EC2/",
        "UnauthorizedAccess:EC2/",
        # IAMUser
        "CredentialAccess:IAMUser/",
        "DefenseEvasion:IAMUser/",
        "Discovery:IAMUser/",
        "Exfiltration:IAMUser/",
        "Impact:IAMUser/",
        "InitialAccess:IAMUser/",
        "PenTest:IAMUser/",
        "Persistence:IAMUser/",
        "Policy:IAMUser/",
        "PrivilegeEscalation:IAMUser/",
        "Recon:IAMUser/",
        "Stealth:IAMUser/",
        "UnauthorizedAccess:IAMUser/",
        # S3
        "Discovery:S3/",
        "Exfiltration:S3/",
        "Impact:S3/",
        "Object:S3/",
        "PenTest:S3/",
        "Policy:S3/",
        "Stealth:S3/",
        "UnauthorizedAccess:S3/",
        # Lambda
        "Backdoor:Lambda/",
        "CryptoCurrency:Lambda/",
        "Trojan:Lambda/",
        "UnauthorizedAccess:Lambda/",
        # Runtime
        "Backdoor:Runtime/",
        "CryptoCurrency:Runtime/",
        "DefenseEvasion:Runtime/",
        "Discovery:Runtime/",
        "Execution:Runtime/",
        "Impact:Runtime/",
        "Persistence:Runtime/",
        "PrivilegeEscalation:Runtime/",
        "Trojan:Runtime/",
        "UnauthorizedAccess:Runtime/",
        # Kubernetes
        "CredentialAccess:Kubernetes/",
        "DefenseEvasion:Kubernetes/",
        "Discovery:Kubernetes/",
        "Execution:Kubernetes/",
        "Impact:Kubernetes/",
        "Persistence:Kubernetes/",
        "Policy:Kubernetes/",
        "PrivilegeEscalation:Kubernetes/",
        # Malware
        "Execution:Container/",
        "Execution:ECS/",
        # RDS
        "CredentialAccess:RDS/",
        "Discovery:RDS/",
        # Attack Sequence
        "AttackSequence:EC2/",
        "AttackSequence:ECS/",
        "AttackSequence:EKS/",
        "AttackSequence:IAM/",
        "AttackSequence:S3/",
    }
)

# =============================================================================
# Feature Requirements Mapping
# =============================================================================
FEATURE_REQUIREMENTS: dict[str, GuardDutyFeature] = {
    # Base GuardDuty
    "EC2": GuardDutyFeature.BASE,
    "IAMUser": GuardDutyFeature.BASE,
    # S3 Protection
    "S3": GuardDutyFeature.S3_PROTECTION,
    # Lambda Protection
    "Lambda": GuardDutyFeature.LAMBDA_PROTECTION,
    # Runtime Monitoring
    "Runtime": GuardDutyFeature.EC2_RUNTIME,  # Also ECS_RUNTIME or EKS_RUNTIME
    # Kubernetes
    "Kubernetes": GuardDutyFeature.EKS_AUDIT_LOG,
    # Malware Protection
    "Container": GuardDutyFeature.MALWARE_PROTECTION,
    "ECS": GuardDutyFeature.MALWARE_PROTECTION,
    # RDS Protection
    "RDS": GuardDutyFeature.RDS_PROTECTION,
}


def is_valid_finding_type(finding_type: str) -> bool:
    """Check if a GuardDuty finding type is valid.

    Args:
        finding_type: The finding type string to validate.

    Returns:
        True if the finding type is valid or matches a valid prefix pattern.
    """
    # Exact match
    if finding_type in ALL_VALID_FINDING_TYPES:
        return True

    # Check for wildcard patterns (e.g., "CredentialAccess:IAMUser/*")
    if finding_type.endswith("*"):
        base = finding_type[:-1]  # Remove trailing *
        # Check if it matches a valid prefix
        for prefix in VALID_PREFIXES:
            if base == prefix or base.startswith(prefix):
                return True

    # Check if it's a valid prefix pattern
    for prefix in VALID_PREFIXES:
        if finding_type == prefix or finding_type == prefix.rstrip("/"):
            return True

    return False


def get_required_feature(finding_type: str) -> GuardDutyFeature | None:
    """Get the GuardDuty feature required for a finding type.

    Args:
        finding_type: The finding type string.

    Returns:
        The required GuardDutyFeature, or None if invalid.
    """
    # Extract resource type (e.g., "EC2" from "Backdoor:EC2/C&CActivity.B")
    if ":" not in finding_type:
        return None

    parts = finding_type.split(":")
    if len(parts) < 2:
        return None

    resource_part = parts[1].split("/")[0]
    return FEATURE_REQUIREMENTS.get(resource_part)


def validate_finding_types(
    finding_types: list[str],
) -> tuple[list[str], list[str]]:
    """Validate a list of GuardDuty finding types.

    Args:
        finding_types: List of finding type strings to validate.

    Returns:
        Tuple of (valid_types, invalid_types).
    """
    valid = []
    invalid = []

    for ft in finding_types:
        if is_valid_finding_type(ft):
            valid.append(ft)
        else:
            invalid.append(ft)

    return valid, invalid


# =============================================================================
# Invalid Finding Type Corrections
# =============================================================================
# Map of common invalid finding types to their correct equivalents
FINDING_TYPE_CORRECTIONS: dict[str, str | None] = {
    # Invalid EC2 types - missing variant suffix
    "Backdoor:EC2/C&CActivity": "Backdoor:EC2/C&CActivity.B",
    "Backdoor:EC2/DenialOfService": "Backdoor:EC2/DenialOfService.Tcp",
    "DefenseEvasion:EC2/InstanceConfigModified": None,  # No equivalent
    "DefenseEvasion:EC2/UnusualNetworkPortActivity": None,
    "DefenseEvasion:EC2/UnusualProcessName": None,
    "Stealth:EC2/AnomalousBehavior": None,
    "Trojan:EC2/DGADomainRequest": "Trojan:EC2/DGADomainRequest.B",
    "UnauthorizedAccess:EC2/MaliciousFile": "Execution:EC2/MaliciousFile",
    "UnauthorizedAccess:EC2/MaliciousIPCaller": "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
    "UnauthorizedAccess:EC2/Tor": "UnauthorizedAccess:EC2/TorClient",
    "UnauthorizedAccess:EC2/TorIPCaller": "UnauthorizedAccess:EC2/TorClient",
    # Invalid IAM types - missing variant suffix
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess": "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    "UnauthorizedAccess:IAMUser/AnomalousBehavior": "InitialAccess:IAMUser/AnomalousBehavior",
    "CredentialAccess:IAMUser/AnomalousCloudAccessUsed": "CredentialAccess:IAMUser/AnomalousBehavior",
    "Persistence:IAMUser/ResourceCreation.OutsideNormalRegions": "Persistence:IAMUser/AnomalousBehavior",
    "Stealth:IAMUser/LoggingConfigurationModified": "Stealth:IAMUser/CloudTrailLoggingDisabled",
    "Stealth:IAMUser/S3ServerAccessLoggingDisabled": "Stealth:S3/ServerAccessLoggingDisabled",
    # Invalid S3 types
    "Backdoor:S3/MalwareFile": "Object:S3/MaliciousFile",
    "Execution:S3/MaliciousFile": "Object:S3/MaliciousFile",  # S3 uses Object: prefix
    "Execution:S3/SuspiciousFile": "Object:S3/MaliciousFile",
    "Exfiltration:S3/ObjectRead.Unusual": "Exfiltration:S3/AnomalousBehavior",
    "Impact:S3/MaliciousFile": "Object:S3/MaliciousFile",
    "Trojan:S3/MalwareFile": "Object:S3/MaliciousFile",
    # Invalid Runtime types
    "CredentialAccess:Runtime/MemoryDumpCreated": None,  # Not a real finding
    "DefenseEvasion:Runtime/ProcessInjection": "DefenseEvasion:Runtime/ProcessInjection.Proc",
    "DefenseEvasion:Runtime/ProcessInjectionAttempt": "DefenseEvasion:Runtime/ProcessInjection.Proc",
    "Discovery:Runtime/ProcessDiscovery": "Discovery:Runtime/SuspiciousCommand",
    "Discovery:Runtime/RegistryDiscovery": None,  # No equivalent (Registry is Windows)
    "Execution:Runtime/AnomalousProcessCommunication": "Execution:Runtime/SuspiciousCommand",
    "Execution:Runtime/MaliciousFile": "Execution:Runtime/MaliciousFileExecuted",
    "Execution:Runtime/ModifiedBinary": "Execution:Runtime/NewBinaryExecuted",
    "Execution:Runtime/ProcessInjection": "DefenseEvasion:Runtime/ProcessInjection.Proc",
    "Execution:Runtime/SuspiciousCommandExecuted": "Execution:Runtime/SuspiciousCommand",
    "Execution:Runtime/SuspiciousProcess": "Execution:Runtime/SuspiciousCommand",
    "Exfiltration:Runtime/SuspiciousDataTransfer": None,  # Not a real finding
    "Impact:Runtime/MaliciousCommand": "Execution:Runtime/SuspiciousCommand",
    "Persistence:Runtime/NewBinaryExecuted": "Execution:Runtime/NewBinaryExecuted",
    "PrivilegeEscalation:Runtime/AnomalousBehavior": "PrivilegeEscalation:Runtime/SuspiciousCommand",
    "PrivilegeEscalation:Runtime/ContainerMountsHost": "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
    "PrivilegeEscalation:Runtime/ContainerMountsWithShadowFile": "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
    "PrivilegeEscalation:Runtime/NewUserCreated": "PrivilegeEscalation:Runtime/SuspiciousCommand",
    "PrivilegeEscalation:Runtime/UsersAndGroupsModified": "PrivilegeEscalation:Runtime/SuspiciousCommand",
    "Trojan:Runtime/SuspiciousFile": "Execution:Runtime/MaliciousFileExecuted",
    # Invalid Container types
    "Execution:Container/SuspiciousProcess": "Execution:Container/SuspiciousFile",
}


def get_correction(invalid_type: str) -> str | None:
    """Get the corrected finding type for an invalid one.

    Args:
        invalid_type: The invalid finding type.

    Returns:
        The corrected finding type, or None if no correction exists.
    """
    return FINDING_TYPE_CORRECTIONS.get(invalid_type)
