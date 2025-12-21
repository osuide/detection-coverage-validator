"""GuardDuty finding type to MITRE ATT&CK technique mappings.

Based on official mappings from the MITRE Center for Threat-Informed Defense
Security Stack Mappings project.

Source: https://center-for-threat-informed-defense.github.io/security-stack-mappings/AWS/
GitHub: https://github.com/center-for-threat-informed-defense/security-stack-mappings
"""

# GuardDuty finding type to MITRE technique mappings
# Format: finding_type -> [(technique_id, confidence)]
# Confidence based on MITRE coverage: Significant=0.9, Partial=0.75, Minimal=0.6

GUARDDUTY_MITRE_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # === Reconnaissance & Discovery ===
    "Recon:EC2/PortProbeEMRUnprotectedPort": [
        ("T1595.001", 0.9),  # Active Scanning: Scanning IP Blocks
        ("T1595.002", 0.9),  # Active Scanning: Vulnerability Scanning
        ("T1046", 0.9),  # Network Service Discovery
    ],
    "Recon:EC2/PortProbeUnprotectedPort": [
        ("T1595.001", 0.9),
        ("T1595.002", 0.9),
        ("T1046", 0.9),
    ],
    "Recon:EC2/Portscan": [
        ("T1595.001", 0.9),
        ("T1595.002", 0.9),
        ("T1046", 0.9),
    ],
    "Recon:IAMUser/MaliciousIPCaller": [("T1526", 0.9)],  # Cloud Service Discovery
    "Recon:IAMUser/MaliciousIPCaller.Custom": [("T1526", 0.9)],
    "Recon:IAMUser/TorIPCaller": [("T1526", 0.9)],
    "Recon:IAMUser/NetworkPermissions": [("T1526", 0.85)],
    "Recon:IAMUser/ResourcePermissions": [("T1526", 0.85)],
    "Recon:IAMUser/UserPermissions": [("T1526", 0.85)],
    # Discovery findings
    "Discovery:IAMUser/AnomalousBehavior": [
        ("T1078", 0.75),  # Valid Accounts
        ("T1580", 0.75),  # Cloud Infrastructure Discovery
    ],
    "Discovery:S3/MaliciousIPCaller": [("T1580", 0.9)],
    "Discovery:S3/MaliciousIPCaller.Custom": [("T1580", 0.9)],
    "Discovery:S3/TorIPCaller": [("T1580", 0.9)],
    "Discovery:Kubernetes/MaliciousIPCaller": [("T1526", 0.85)],
    # === Credential Access & Account Compromise ===
    "UnauthorizedAccess:IAMUser/ConsoleLogin": [("T1078", 0.9)],
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B": [("T1078", 0.9)],
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller": [("T1078", 0.9)],
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom": [("T1078", 0.9)],
    "UnauthorizedAccess:IAMUser/TorIPCaller": [("T1078", 0.9)],
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration": [
        ("T1078", 0.9),
        ("T1552.005", 0.9),  # Cloud Instance Metadata API
    ],
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS": [
        ("T1078", 0.9),
        ("T1552.005", 0.9),
    ],
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS": [
        ("T1078", 0.9),
        ("T1552.005", 0.9),
        ("T1537", 0.85),  # Transfer Data to Cloud Account
    ],
    "CredentialAccess:IAMUser/AnomalousBehavior": [("T1078", 0.75)],
    "CredentialAccess:Kubernetes/MaliciousIPCaller": [("T1552.005", 0.85)],
    "CredentialAccess:Kubernetes/SuccessfulAnonymousAccess": [("T1078.004", 0.85)],
    # === Persistence ===
    "Persistence:IAMUser/AnomalousBehavior": [
        ("T1078", 0.75),
        ("T1098", 0.75),  # Account Manipulation
        ("T1098.001", 0.75),  # Additional Cloud Credentials
        ("T1098.004", 0.75),  # SSH Authorized Keys
    ],
    "Persistence:IAMUser/NetworkPermissions": [
        ("T1098", 0.9),
        ("T1098.003", 0.85),  # Additional Cloud Roles
    ],
    "Persistence:IAMUser/ResourcePermissions": [
        ("T1098", 0.9),
        ("T1098.003", 0.85),
    ],
    "Persistence:IAMUser/UserPermissions": [
        ("T1098", 0.9),
        ("T1098.001", 0.85),
    ],
    "Persistence:Kubernetes/ContainerWithSensitiveMount": [("T1611", 0.85)],
    "Persistence:Kubernetes/MaliciousIPCaller": [("T1098", 0.8)],
    # === Privilege Escalation ===
    "PrivilegeEscalation:IAMUser/AdministrativePermissions": [("T1078", 0.9)],
    "PrivilegeEscalation:IAMUser/AnomalousBehavior": [
        ("T1548.005", 0.75),  # Temporary Elevated Cloud Access
        ("T1098.003", 0.75),
    ],
    "PrivilegeEscalation:Runtime/DockerSocketAccessed": [("T1611", 0.9)],
    "PrivilegeEscalation:Runtime/RuncContainerEscape": [("T1611", 0.95)],
    "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified": [("T1611", 0.95)],
    "PrivilegeEscalation:Kubernetes/PrivilegedContainer": [("T1611", 0.85)],
    # === Defense Evasion ===
    "DefenseEvasion:IAMUser/AnomalousBehavior": [("T1562", 0.75)],
    "DefenseEvasion:EC2/UnusualDNSResolver": [("T1568.002", 0.85)],
    "DefenseEvasion:EC2/UnusualDoHActivity": [("T1572", 0.8)],
    "DefenseEvasion:EC2/UnusualDoTActivity": [("T1572", 0.8)],
    "DefenseEvasion:Runtime/FilelessExecution": [("T1620", 0.9)],
    "DefenseEvasion:Runtime/ProcessInjection.Ptrace": [("T1055", 0.95)],
    "DefenseEvasion:Runtime/ProcessInjection.VirtualMemoryWrite": [("T1055", 0.95)],
    "DefenseEvasion:Runtime/SuspiciousCommand": [("T1562", 0.75)],
    # === Stealth / Impair Defenses ===
    "Stealth:IAMUser/CloudTrailLoggingDisabled": [
        ("T1562", 0.95),
        ("T1562.008", 0.95),  # Disable Cloud Logs
    ],
    "Stealth:IAMUser/PasswordPolicyChange": [
        ("T1562", 0.85),
        ("T1110", 0.75),  # Brute Force
    ],
    "Stealth:IAMUser/LoggingConfigurationModified": [
        ("T1562", 0.95),
        ("T1562.008", 0.95),
    ],
    "Stealth:S3/ServerAccessLoggingDisabled": [
        ("T1562", 0.9),
        ("T1562.008", 0.9),
        ("T1485", 0.75),  # Data Destruction
        ("T1486", 0.75),  # Data Encrypted for Impact
    ],
    # === Malware & Command and Control ===
    "Trojan:EC2/DriveBySourceTraffic!DNS": [("T1189", 0.9)],  # Drive-by Compromise
    "Trojan:EC2/PhishingDomainRequest!DNS": [
        ("T1566", 0.9),  # Phishing
        ("T1566.001", 0.85),
        ("T1566.002", 0.85),
        ("T1566.003", 0.85),
    ],
    "Trojan:EC2/DropPoint!DNS": [("T1071", 0.9)],
    "Trojan:EC2/DropPoint": [("T1071", 0.9)],
    "Trojan:EC2/BlackholeTraffic": [("T1071", 0.85)],
    "Trojan:EC2/BlackholeTraffic!DNS": [("T1071", 0.85)],
    "Trojan:EC2/DGADomainRequest.B": [
        ("T1568", 0.95),  # Dynamic Resolution
        ("T1568.002", 0.95),  # Domain Generation Algorithms
    ],
    "Trojan:EC2/DGADomainRequest.C!DNS": [
        ("T1568", 0.95),
        ("T1568.002", 0.95),
    ],
    "Trojan:EC2/DNSDataExfiltration": [
        ("T1048", 0.95),  # Exfiltration Over Alternative Protocol
        ("T1048.003", 0.95),
    ],
    # Backdoor / C2 findings
    "Backdoor:EC2/C&CActivity.B!DNS": [("T1071", 0.9)],
    "Backdoor:EC2/C&CActivity.B": [
        ("T1071", 0.9),
        ("T1071.001", 0.9),  # Web Protocols
        ("T1071.002", 0.85),  # File Transfer Protocols
        ("T1071.003", 0.85),  # Mail Protocols
        ("T1071.004", 0.85),  # DNS
    ],
    "Backdoor:EC2/Spambot": [("T1071.003", 0.85)],
    # === Network Behaviour ===
    "Behavior:EC2/NetworkPortUnusual": [("T1571", 0.9)],  # Non-Standard Port
    "Behavior:EC2/TrafficVolumeUnusual": [
        ("T1020", 0.75),  # Automated Exfiltration
        ("T1029", 0.75),  # Scheduled Transfer
        ("T1041", 0.75),  # Exfiltration Over C2 Channel
        ("T1048", 0.75),  # Exfiltration Over Alternative Protocol
        ("T1567", 0.75),  # Exfiltration Over Web Service
    ],
    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom": [("T1071", 0.75)],
    # === Proxy & Anonymisation ===
    "UnauthorizedAccess:EC2/TorClient": [
        ("T1090", 0.9),  # Proxy
        ("T1090.001", 0.85),
        ("T1090.002", 0.85),
        ("T1090.003", 0.9),  # Multi-hop Proxy
    ],
    "UnauthorizedAccess:EC2/TorRelay": [
        ("T1090", 0.9),
        ("T1090.001", 0.85),
        ("T1090.002", 0.85),
        ("T1090.003", 0.9),
        ("T1496", 0.75),  # Resource Hijacking
    ],
    # === Brute Force Attacks ===
    "UnauthorizedAccess:EC2/RDPBruteForce": [
        ("T1110", 0.95),
        ("T1110.001", 0.95),  # Password Guessing
        ("T1110.003", 0.9),  # Password Spraying
        ("T1110.004", 0.9),  # Credential Stuffing
    ],
    "UnauthorizedAccess:EC2/SSHBruteForce": [
        ("T1110", 0.95),
        ("T1110.001", 0.95),
        ("T1110.003", 0.9),
        ("T1110.004", 0.9),
    ],
    "Impact:EC2/WinRMBruteForce": [("T1110", 0.9)],
    # === Exploitation ===
    "UnauthorizedAccess:EC2/MetadataDNSRebind": [("T1190", 0.9)],
    # === S3 & Cloud Storage ===
    "Policy:S3/AccountBlockPublicAccessDisabled": [("T1078", 0.85)],
    "Policy:S3/BucketAnonymousAccessGranted": [("T1078", 0.85)],
    "Policy:S3/BucketBlockPublicAccessDisabled": [("T1078", 0.85)],
    "Policy:S3/BucketPublicAccessGranted": [("T1078", 0.85)],
    "Impact:S3/MaliciousIPCaller": [
        ("T1530", 0.9),  # Data from Cloud Storage
        ("T1552.001", 0.85),  # Credentials In Files
        ("T1020", 0.75),
        ("T1485", 0.9),  # Data Destruction
        ("T1486", 0.9),  # Data Encrypted for Impact
        ("T1565", 0.85),  # Data Manipulation
        ("T1565.001", 0.85),
        ("T1491", 0.85),  # Defacement
        ("T1491.001", 0.85),
        ("T1491.002", 0.85),
    ],
    "Exfiltration:S3/MaliciousIPCaller": [
        ("T1530", 0.9),
        ("T1552.001", 0.85),
        ("T1020", 0.75),
        ("T1485", 0.9),
        ("T1486", 0.9),
        ("T1491", 0.85),
        ("T1491.001", 0.85),
        ("T1491.002", 0.85),
    ],
    "Exfiltration:S3/ObjectRead.Unusual": [
        ("T1530", 0.9),
        ("T1552.001", 0.85),
        ("T1020", 0.75),
        ("T1491", 0.85),
        ("T1491.001", 0.85),
        ("T1491.002", 0.85),
        ("T1567", 0.85),
        ("T1567.001", 0.85),
        ("T1567.002", 0.85),
    ],
    "Exfiltration:IAMUser/AnomalousBehavior": [
        ("T1567", 0.75),
        ("T1567.001", 0.75),
        ("T1567.002", 0.75),
    ],
    "UnauthorizedAccess:S3/MaliciousIPCaller.Custom": [
        ("T1530", 0.9),
        ("T1552.001", 0.85),
        ("T1020", 0.75),
        ("T1485", 0.9),
        ("T1486", 0.9),
        ("T1491", 0.85),
        ("T1491.001", 0.85),
        ("T1491.002", 0.85),
    ],
    "UnauthorizedAccess:S3/TorIPCaller": [
        ("T1530", 0.9),
        ("T1552.001", 0.85),
        ("T1020", 0.75),
        ("T1485", 0.9),
        ("T1486", 0.9),
        ("T1491", 0.85),
        ("T1491.001", 0.85),
        ("T1491.002", 0.85),
    ],
    # === Penetration Testing Tools ===
    "PenTest:IAMUser/KaliLinux": [
        ("T1078", 0.9),
        ("T1580", 0.85),
    ],
    "PenTest:IAMUser/ParrotLinux": [
        ("T1078", 0.9),
        ("T1580", 0.85),
    ],
    "PenTest:IAMUser/PentooLinux": [
        ("T1078", 0.9),
        ("T1580", 0.85),
    ],
    "PenTest:S3/KaliLinux": [
        ("T1530", 0.9),
        ("T1552.001", 0.85),
        ("T1020", 0.75),
        ("T1485", 0.9),
        ("T1486", 0.9),
        ("T1491", 0.85),
        ("T1491.001", 0.85),
        ("T1491.002", 0.85),
    ],
    "PenTest:S3/ParrotLinux": [
        ("T1530", 0.9),
        ("T1552.001", 0.85),
        ("T1020", 0.75),
        ("T1485", 0.9),
        ("T1486", 0.9),
        ("T1491", 0.85),
        ("T1491.001", 0.85),
        ("T1491.002", 0.85),
    ],
    "PenTest:S3/PentooLinux": [
        ("T1530", 0.9),
        ("T1552.001", 0.85),
        ("T1020", 0.75),
        ("T1485", 0.9),
        ("T1486", 0.9),
        ("T1491", 0.85),
        ("T1491.001", 0.85),
        ("T1491.002", 0.85),
    ],
    # === Impact ===
    "Impact:IAMUser/AnomalousBehavior": [
        ("T1078", 0.75),
        ("T1531", 0.75),  # Account Access Removal
        ("T1485", 0.75),
    ],
    "Impact:EC2/PortSweep": [
        ("T1595", 0.9),
        ("T1595.001", 0.9),
        ("T1595.002", 0.9),
    ],
    "Impact:EC2/MaliciousDomainRequest.Reputation": [
        ("T1071.001", 0.85),
        ("T1071.002", 0.85),
        ("T1071.003", 0.85),
        ("T1071.004", 0.85),
    ],
    "Impact:EC2/SuspiciousDomainRequest.Reputation": [
        ("T1071.001", 0.75),
        ("T1071.002", 0.75),
        ("T1071.003", 0.75),
        ("T1071.004", 0.75),
    ],
    "Impact:EC2/AbusedDomainRequest.Reputation": [("T1071.001", 0.75)],
    "Impact:Kubernetes/MaliciousIPCaller": [("T1485", 0.8)],
    # === Cryptocurrency & Resource Hijacking ===
    "CryptoCurrency:EC2/BitcoinTool.B": [("T1496", 0.95)],
    "CryptoCurrency:EC2/BitcoinTool.B!DNS": [("T1496", 0.95)],
    "CryptoCurrency:Runtime/BitcoinTool.B": [("T1496", 0.95)],
    "CryptoCurrency:Runtime/BitcoinTool.B!DNS": [("T1496", 0.95)],
    "Impact:EC2/BitcoinDomainRequest.Reputation": [("T1496", 0.9)],
    # === Denial of Service ===
    "Backdoor:EC2/DenialOfService.UdpOnTcpPorts": [
        ("T1498", 0.95),
        ("T1498.001", 0.9),
        ("T1498.002", 0.9),
    ],
    "Backdoor:EC2/DenialOfService.UnusualProtocol": [
        ("T1498", 0.95),
        ("T1498.001", 0.9),
        ("T1498.002", 0.9),
    ],
    "Backdoor:EC2/DenialOfService.Udp": [
        ("T1498", 0.95),
        ("T1498.001", 0.9),
        ("T1498.002", 0.9),
    ],
    "Backdoor:EC2/DenialOfService.Tcp": [
        ("T1498", 0.95),
        ("T1498.001", 0.9),
        ("T1498.002", 0.9),
    ],
    "Backdoor:EC2/DenialOfService.Dns": [
        ("T1498", 0.95),
        ("T1498.001", 0.9),
        ("T1498.002", 0.9),
    ],
    # === EKS/Kubernetes ===
    "Execution:Kubernetes/ExecInKubeSystemPod": [("T1609", 0.9)],
    "Policy:Kubernetes/AdminAccessToDefaultServiceAccount": [("T1078.004", 0.85)],
    "Policy:Kubernetes/AnonymousAccessGranted": [("T1078.004", 0.85)],
    "Policy:Kubernetes/ExposedDashboard": [("T1133", 0.85)],
    # === Runtime Execution ===
    "Execution:Runtime/NewBinaryExecuted": [("T1059", 0.8)],
    "Execution:Runtime/NewLibraryLoaded": [("T1055.001", 0.8)],
    "Execution:Runtime/ReverseShell": [
        ("T1059.004", 0.95),  # Unix Shell
        ("T1071.001", 0.85),
    ],
    "Execution:Runtime/SuspiciousCommand": [("T1059", 0.85)],
    "Execution:Runtime/SuspiciousTool": [("T1588.002", 0.8)],
    "Execution:EC2/MaliciousFile": [("T1204.002", 0.9)],
    "Execution:ECS/MaliciousFile": [("T1204.002", 0.9)],
    "Execution:Kubernetes/MaliciousFile": [("T1204.002", 0.9)],
    "Execution:Container/MaliciousFile": [("T1204.002", 0.9)],
    # Suspicious file findings - lower confidence than malicious
    "Execution:EC2/SuspiciousFile": [("T1204.002", 0.75)],
    "Execution:ECS/SuspiciousFile": [("T1204.002", 0.75)],
    "Execution:Kubernetes/SuspiciousFile": [("T1204.002", 0.75)],
    "Execution:Container/SuspiciousFile": [("T1204.002", 0.75)],
    # === Initial Access (where mappable) ===
    "InitialAccess:IAMUser/AnomalousBehavior": [
        ("T1078", 0.75),
        ("T1190", 0.6),
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

    # Check for prefix match (handles variations like .Custom suffix)
    for prefix, mappings in GUARDDUTY_MITRE_MAPPINGS.items():
        if finding_type.startswith(prefix):
            return mappings

    # Try matching on the base finding type (before any suffix)
    base_type = finding_type.split(".")[0] if "." in finding_type else finding_type
    if base_type in GUARDDUTY_MITRE_MAPPINGS:
        return GUARDDUTY_MITRE_MAPPINGS[base_type]

    return []


def get_all_mapped_finding_types() -> list[str]:
    """Get all GuardDuty finding types that have MITRE mappings."""
    return list(GUARDDUTY_MITRE_MAPPINGS.keys())
