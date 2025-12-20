"""GuardDuty finding type to MITRE ATT&CK technique mappings.

Based on AWS GuardDuty documentation and MITRE ATT&CK framework.
These are vendor-provided mappings with high confidence.
"""

# GuardDuty finding type prefix to MITRE technique mappings
# Format: finding_type_prefix -> [(technique_id, confidence)]
GUARDDUTY_MITRE_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # Reconnaissance findings
    "Recon:EC2/PortProbeUnprotectedPort": [
        ("T1595.001", 0.9),  # Active Scanning: Scanning IP Blocks
        ("T1046", 0.85),  # Network Service Discovery
    ],
    "Recon:EC2/Portscan": [
        ("T1595.001", 0.9),
        ("T1046", 0.85),
    ],
    "Recon:IAMUser/NetworkPermissions": [
        ("T1526", 0.85),  # Cloud Service Discovery
    ],
    "Recon:IAMUser/ResourcePermissions": [
        ("T1526", 0.85),
    ],
    "Recon:IAMUser/UserPermissions": [
        ("T1526", 0.85),
    ],
    # Unauthorized Access findings
    "UnauthorizedAccess:EC2/SSHBruteForce": [
        ("T1110.001", 0.95),  # Brute Force: Password Guessing
        ("T1078.004", 0.8),  # Valid Accounts: Cloud Accounts
    ],
    "UnauthorizedAccess:EC2/RDPBruteForce": [
        ("T1110.001", 0.95),
        ("T1078.004", 0.8),
    ],
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B": [
        ("T1078.004", 0.9),  # Valid Accounts: Cloud Accounts
    ],
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS": [
        ("T1552.005", 0.95),  # Unsecured Credentials: Cloud Instance Metadata API
        ("T1078.004", 0.85),
    ],
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS": [
        ("T1552.005", 0.95),
        ("T1537", 0.85),  # Transfer Data to Cloud Account
    ],
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller": [
        ("T1078.004", 0.85),
    ],
    "UnauthorizedAccess:IAMUser/TorIPCaller": [
        ("T1078.004", 0.85),
        ("T1090.003", 0.8),  # Proxy: Multi-hop Proxy
    ],
    # Persistence findings
    "Persistence:IAMUser/NetworkPermissions": [
        ("T1098", 0.9),  # Account Manipulation
        ("T1098.003", 0.85),  # Account Manipulation: Additional Cloud Roles
    ],
    "Persistence:IAMUser/ResourcePermissions": [
        ("T1098", 0.9),
        ("T1098.003", 0.85),
    ],
    "Persistence:IAMUser/UserPermissions": [
        ("T1098", 0.9),
        ("T1098.001", 0.85),  # Account Manipulation: Additional Cloud Credentials
    ],
    # Privilege Escalation findings
    "PrivilegeEscalation:IAMUser/AdministrativePermissions": [
        ("T1548.005", 0.9),  # Abuse Elevation Control: Temporary Elevated Cloud Access
        ("T1098.003", 0.85),
    ],
    "PrivilegeEscalation:Runtime/DockerSocketAccessed": [
        ("T1611", 0.9),  # Escape to Host
    ],
    "PrivilegeEscalation:Runtime/RuncContainerEscape": [
        ("T1611", 0.95),
    ],
    "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified": [
        ("T1611", 0.95),
    ],
    "PrivilegeEscalation:Kubernetes/PrivilegedContainer": [
        ("T1611", 0.85),
    ],
    # Defense Evasion findings
    "DefenseEvasion:EC2/UnusualDNSResolver": [
        ("T1568.002", 0.85),  # Dynamic Resolution: Domain Generation Algorithms
    ],
    "DefenseEvasion:EC2/UnusualDoHActivity": [
        ("T1572", 0.8),  # Protocol Tunneling
    ],
    "DefenseEvasion:EC2/UnusualDoTActivity": [
        ("T1572", 0.8),
    ],
    "DefenseEvasion:Runtime/FilelessExecution": [
        ("T1620", 0.9),  # Reflective Code Loading
    ],
    "DefenseEvasion:Runtime/ProcessInjection.Ptrace": [
        ("T1055", 0.95),  # Process Injection
    ],
    "DefenseEvasion:Runtime/ProcessInjection.VirtualMemoryWrite": [
        ("T1055", 0.95),
    ],
    "Stealth:IAMUser/CloudTrailLoggingDisabled": [
        ("T1562.008", 0.95),  # Impair Defenses: Disable Cloud Logs
    ],
    "Stealth:IAMUser/PasswordPolicyChange": [
        ("T1562.001", 0.85),  # Impair Defenses: Disable or Modify Tools
    ],
    "Stealth:IAMUser/LoggingConfigurationModified": [
        ("T1562.008", 0.95),
    ],
    # Credential Access findings
    "CredentialAccess:IAMUser/AnomalousBehavior": [
        ("T1528", 0.8),  # Steal Application Access Token
        ("T1552.005", 0.75),
    ],
    "CredentialAccess:Kubernetes/MaliciousIPCaller": [
        ("T1552.005", 0.85),
    ],
    "CredentialAccess:Kubernetes/SuccessfulAnonymousAccess": [
        ("T1078.004", 0.85),
    ],
    # Crypto Mining findings
    "CryptoCurrency:EC2/BitcoinTool.B": [
        ("T1496", 0.95),  # Resource Hijacking
    ],
    "CryptoCurrency:EC2/BitcoinTool.B!DNS": [
        ("T1496", 0.95),
    ],
    "CryptoCurrency:Runtime/BitcoinTool.B": [
        ("T1496", 0.95),
    ],
    "CryptoCurrency:Runtime/BitcoinTool.B!DNS": [
        ("T1496", 0.95),
    ],
    # Backdoor findings
    "Backdoor:EC2/C&CActivity.B": [
        ("T1071.001", 0.9),  # Application Layer Protocol: Web Protocols
        ("T1571", 0.85),  # Non-Standard Port
    ],
    "Backdoor:EC2/C&CActivity.B!DNS": [
        ("T1071.004", 0.9),  # Application Layer Protocol: DNS
    ],
    "Backdoor:EC2/DenialOfService.Dns": [
        ("T1498", 0.9),  # Network Denial of Service
    ],
    "Backdoor:EC2/DenialOfService.Tcp": [
        ("T1498", 0.9),
    ],
    "Backdoor:EC2/DenialOfService.Udp": [
        ("T1498", 0.9),
    ],
    "Backdoor:EC2/Spambot": [
        ("T1071.003", 0.85),  # Application Layer Protocol: Mail Protocols
    ],
    # Trojan findings
    "Trojan:EC2/BlackholeTraffic": [
        ("T1071.001", 0.85),
    ],
    "Trojan:EC2/DGADomainRequest.B": [
        ("T1568.002", 0.95),  # Dynamic Resolution: Domain Generation Algorithms
    ],
    "Trojan:EC2/DGADomainRequest.C!DNS": [
        ("T1568.002", 0.95),
    ],
    "Trojan:EC2/DNSDataExfiltration": [
        (
            "T1048.003",
            0.95,
        ),  # Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
        ("T1071.004", 0.9),
    ],
    "Trojan:EC2/DropPoint": [
        ("T1071.001", 0.85),
    ],
    "Trojan:EC2/PhishingDomainRequest!DNS": [
        ("T1566", 0.85),  # Phishing
    ],
    # Impact findings
    "Impact:EC2/AbusedDomainRequest.Reputation": [
        ("T1071.001", 0.75),
    ],
    "Impact:EC2/BitcoinDomainRequest.Reputation": [
        ("T1496", 0.9),
    ],
    "Impact:EC2/MaliciousDomainRequest.Reputation": [
        ("T1071.001", 0.8),
    ],
    "Impact:EC2/PortSweep": [
        ("T1595.001", 0.85),
    ],
    "Impact:EC2/WinRMBruteForce": [
        ("T1110.001", 0.9),
    ],
    # S3 Data Protection findings
    "Exfiltration:S3/MaliciousIPCaller": [
        ("T1530", 0.9),  # Data from Cloud Storage
        ("T1537", 0.85),
    ],
    "Exfiltration:S3/ObjectRead.Unusual": [
        ("T1530", 0.85),
    ],
    "Impact:S3/MaliciousIPCaller": [
        ("T1485", 0.8),  # Data Destruction
    ],
    "Policy:S3/AccountBlockPublicAccessDisabled": [
        ("T1562.007", 0.85),  # Impair Defenses: Disable or Modify Cloud Firewall
    ],
    "Policy:S3/BucketBlockPublicAccessDisabled": [
        ("T1562.007", 0.85),
    ],
    "Policy:S3/BucketAnonymousAccessGranted": [
        ("T1537", 0.9),
    ],
    "Policy:S3/BucketPublicAccessGranted": [
        ("T1537", 0.9),
    ],
    "Stealth:S3/ServerAccessLoggingDisabled": [
        ("T1562.008", 0.9),
    ],
    "UnauthorizedAccess:S3/MaliciousIPCaller.Custom": [
        ("T1530", 0.85),
    ],
    "UnauthorizedAccess:S3/TorIPCaller": [
        ("T1530", 0.85),
        ("T1090.003", 0.8),
    ],
    # EKS/Kubernetes findings
    "Discovery:Kubernetes/MaliciousIPCaller": [
        ("T1526", 0.85),
    ],
    "Execution:Kubernetes/ExecInKubeSystemPod": [
        ("T1609", 0.9),  # Container Administration Command
    ],
    "Impact:Kubernetes/MaliciousIPCaller": [
        ("T1485", 0.8),
    ],
    "Persistence:Kubernetes/ContainerWithSensitiveMount": [
        ("T1611", 0.85),
    ],
    "Persistence:Kubernetes/MaliciousIPCaller": [
        ("T1098", 0.8),
    ],
    "Policy:Kubernetes/AdminAccessToDefaultServiceAccount": [
        ("T1078.004", 0.85),
    ],
    "Policy:Kubernetes/AnonymousAccessGranted": [
        ("T1078.004", 0.85),
    ],
    "Policy:Kubernetes/ExposedDashboard": [
        ("T1133", 0.85),  # External Remote Services
    ],
    # Runtime findings
    "Execution:Runtime/NewBinaryExecuted": [
        ("T1059", 0.8),  # Command and Scripting Interpreter
    ],
    "Execution:Runtime/NewLibraryLoaded": [
        ("T1055.001", 0.8),  # Process Injection: Dynamic-link Library Injection
    ],
    "Execution:Runtime/ReverseShell": [
        ("T1059.004", 0.95),  # Command and Scripting Interpreter: Unix Shell
        ("T1071.001", 0.85),
    ],
    "Execution:Runtime/SuspiciousCommand": [
        ("T1059", 0.85),
    ],
    "Execution:Runtime/SuspiciousTool": [
        ("T1588.002", 0.8),  # Obtain Capabilities: Tool
    ],
    "Execution:EC2/MaliciousFile": [
        ("T1204.002", 0.9),  # User Execution: Malicious File
    ],
    "Execution:ECS/MaliciousFile": [
        ("T1204.002", 0.9),
    ],
    "Execution:Kubernetes/MaliciousFile": [
        ("T1204.002", 0.9),
    ],
}


def get_mitre_mappings_for_finding(finding_type: str) -> list[tuple[str, float]]:
    """Get MITRE technique mappings for a GuardDuty finding type.

    Args:
        finding_type: The GuardDuty finding type (e.g., "Recon:EC2/PortProbeUnprotectedPort")

    Returns:
        List of (technique_id, confidence) tuples
    """
    # Check for exact match first
    if finding_type in GUARDDUTY_MITRE_MAPPINGS:
        return GUARDDUTY_MITRE_MAPPINGS[finding_type]

    # Check for prefix match (handles variations)
    for prefix, mappings in GUARDDUTY_MITRE_MAPPINGS.items():
        if finding_type.startswith(prefix.split("/")[0]):
            return mappings

    return []


def get_all_mapped_finding_types() -> list[str]:
    """Get all GuardDuty finding types that have MITRE mappings."""
    return list(GUARDDUTY_MITRE_MAPPINGS.keys())
