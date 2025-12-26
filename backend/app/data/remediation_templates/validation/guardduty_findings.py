"""
AWS GuardDuty Finding Types Database.

This module provides a comprehensive mapping of valid GuardDuty finding types
and their corresponding MITRE ATT&CK techniques. Used for validating that
remediation templates reference real, valid GuardDuty findings.

Source: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html
Last updated: December 2025
"""

from typing import Dict, List, Set

# Valid GuardDuty finding types organised by resource type
GUARDDUTY_IAM_FINDINGS: Dict[str, dict] = {
    # Console Login / Impossible Travel
    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B": {
        "description": "Multiple worldwide successful console logins from different geographic locations",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1078", "T1078.004"],  # Valid Accounts
        "data_source": "CloudTrail management events",
        "detects": "impossible_travel",
    },
    # Anomalous Behavior - maps to multiple MITRE tactics
    "CredentialAccess:IAMUser/AnomalousBehavior": {
        "description": "API used to gain credential access invoked anomalously",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1552", "T1555", "T1528"],
        "data_source": "CloudTrail management events",
        "example_apis": ["GetPasswordData", "GetSecretValue"],
    },
    "DefenseEvasion:IAMUser/AnomalousBehavior": {
        "description": "API used to evade defensive measures invoked anomalously",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1562", "T1070"],
        "data_source": "CloudTrail management events",
        "example_apis": ["DeleteFlowLogs", "DisableAlarmActions", "DeleteTrail"],
    },
    "Discovery:IAMUser/AnomalousBehavior": {
        "description": "API to discover resources invoked anomalously",
        "severity": "LOW",
        "mitre_techniques": ["T1087", "T1526", "T1580"],
        "data_source": "CloudTrail management events",
        "example_apis": ["DescribeInstances", "ListAccessKeys", "ListBuckets"],
    },
    "Exfiltration:IAMUser/AnomalousBehavior": {
        "description": "API to collect or exfiltrate data invoked anomalously",
        "severity": "HIGH",
        "mitre_techniques": ["T1537", "T1530"],
        "data_source": "CloudTrail management events",
        "example_apis": ["PutBucketReplication", "CreateSnapshot"],
    },
    "Impact:IAMUser/AnomalousBehavior": {
        "description": "API to tamper with data or processes invoked anomalously",
        "severity": "HIGH",
        "mitre_techniques": ["T1485", "T1486", "T1531"],
        "data_source": "CloudTrail management events",
        "example_apis": ["DeleteSecurityGroup", "UpdateUser", "DeleteBucket"],
    },
    "InitialAccess:IAMUser/AnomalousBehavior": {
        "description": "API to gain unauthorized access invoked anomalously",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1078", "T1078.004"],
        "data_source": "CloudTrail management events",
        "example_apis": ["StartSession", "GetAuthorizationToken"],
    },
    "Persistence:IAMUser/AnomalousBehavior": {
        "description": "API to maintain unauthorized access invoked anomalously",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1098", "T1136"],
        "data_source": "CloudTrail management events",
        "example_apis": ["CreateAccessKey", "ImportKeyPair", "CreateUser"],
    },
    "PrivilegeEscalation:IAMUser/AnomalousBehavior": {
        "description": "API to obtain high-level permissions invoked anomalously",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1548", "T1078"],
        "data_source": "CloudTrail management events",
        "example_apis": ["AssociateIamInstanceProfile", "AddUserToGroup"],
    },
    # Credential Exfiltration
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS": {
        "description": "EC2 instance credentials used from a different AWS account",
        "severity": "HIGH",
        "mitre_techniques": ["T1552.005", "T1078.004"],
        "data_source": "CloudTrail management events",
    },
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS": {
        "description": "EC2 instance credentials used from external IP address",
        "severity": "HIGH",
        "mitre_techniques": ["T1552.005", "T1078.004"],
        "data_source": "CloudTrail management events",
    },
    # Malicious IP / Tor
    "Recon:IAMUser/MaliciousIPCaller": {
        "description": "API invoked from known malicious IP",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1595", "T1590"],
        "data_source": "CloudTrail management events",
    },
    "Recon:IAMUser/TorIPCaller": {
        "description": "API invoked from Tor exit node",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1090.003"],
        "data_source": "CloudTrail management events",
    },
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller": {
        "description": "API operation invoked from known malicious IP",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1078"],
        "data_source": "CloudTrail management events",
    },
    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom": {
        "description": "API operation invoked from custom threat list IP",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1078", "T1110"],
        "data_source": "CloudTrail management events",
    },
    "UnauthorizedAccess:IAMUser/TorIPCaller": {
        "description": "API invoked from Tor exit node",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1078", "T1090.003"],
        "data_source": "CloudTrail management events",
    },
    # Stealth / Defense Evasion
    "Stealth:IAMUser/CloudTrailLoggingDisabled": {
        "description": "CloudTrail logging was disabled",
        "severity": "LOW",
        "mitre_techniques": ["T1562.008"],
        "data_source": "CloudTrail management events",
    },
    "Stealth:IAMUser/PasswordPolicyChange": {
        "description": "Account password policy was weakened",
        "severity": "LOW",
        "mitre_techniques": ["T1556"],
        "data_source": "CloudTrail management events",
    },
    # Root account
    "Policy:IAMUser/RootCredentialUsage": {
        "description": "API invoked using root user credentials",
        "severity": "LOW",
        "mitre_techniques": ["T1078.004"],
        "data_source": "CloudTrail management events",
    },
}

GUARDDUTY_S3_FINDINGS: Dict[str, dict] = {
    # Malware Protection for S3
    "Object:S3/MaliciousFile": {
        "description": "S3 object scanned and identified as malicious",
        "severity": "HIGH",
        "mitre_techniques": ["T1027", "T1204", "T1566"],
        "data_source": "S3 Malware Protection",
    },
    # Discovery
    "Discovery:S3/AnomalousBehavior": {
        "description": "Anomalous S3 API activity detected",
        "severity": "LOW",
        "mitre_techniques": ["T1619"],
    },
    "Discovery:S3/MaliciousIPCaller": {
        "description": "S3 API invoked from known malicious IP",
        "severity": "HIGH",
        "mitre_techniques": ["T1619"],
    },
    "Discovery:S3/MaliciousIPCaller.Custom": {
        "description": "S3 API invoked from custom threat list IP",
        "severity": "HIGH",
        "mitre_techniques": ["T1619"],
    },
    "Discovery:S3/TorIPCaller": {
        "description": "S3 API invoked from Tor exit node",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1619"],
    },
    # Exfiltration
    "Exfiltration:S3/AnomalousBehavior": {
        "description": "Anomalous S3 data exfiltration pattern",
        "severity": "HIGH",
        "mitre_techniques": ["T1530", "T1537"],
    },
    "Exfiltration:S3/MaliciousIPCaller": {
        "description": "S3 object retrieved from malicious IP",
        "severity": "HIGH",
        "mitre_techniques": ["T1530"],
    },
    "Exfiltration:S3/ObjectRead.Unusual": {
        "description": "Unusual S3 object access pattern",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1530"],
    },
    # Impact
    "Impact:S3/AnomalousBehavior.Delete": {
        "description": "Anomalous S3 deletion activity",
        "severity": "HIGH",
        "mitre_techniques": ["T1485"],
    },
    "Impact:S3/AnomalousBehavior.Permission": {
        "description": "Anomalous S3 permission modification",
        "severity": "HIGH",
        "mitre_techniques": ["T1098"],
    },
    "Impact:S3/AnomalousBehavior.Write": {
        "description": "Anomalous S3 write activity",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1565"],
    },
    "Impact:S3/MaliciousIPCaller": {
        "description": "S3 API to manipulate data from malicious IP",
        "severity": "HIGH",
        "mitre_techniques": ["T1485", "T1565"],
    },
    "Impact:S3/PermissionsModification.Unusual": {
        "description": "Unusual S3 permission modification",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1098"],
    },
    # PenTest
    "PenTest:S3/KaliLinux": {
        "description": "S3 API invoked from Kali Linux",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1595"],
    },
    "PenTest:S3/ParrotLinux": {
        "description": "S3 API invoked from Parrot Security Linux",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1595"],
    },
    "PenTest:S3/PentooLinux": {
        "description": "S3 API invoked from Pentoo Linux",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1595"],
    },
    # Policy
    "Policy:S3/AccountBlockPublicAccessDisabled": {
        "description": "S3 block public access disabled",
        "severity": "LOW",
        "mitre_techniques": ["T1562.007"],
    },
    "Policy:S3/BucketAnonymousAccessGranted": {
        "description": "S3 bucket anonymous access granted",
        "severity": "HIGH",
        "mitre_techniques": ["T1530"],
    },
    "Policy:S3/BucketBlockPublicAccessDisabled": {
        "description": "Bucket block public access disabled",
        "severity": "LOW",
        "mitre_techniques": ["T1562.007"],
    },
    "Policy:S3/BucketPublicAccessGranted": {
        "description": "S3 bucket public access granted",
        "severity": "HIGH",
        "mitre_techniques": ["T1530"],
    },
    # Stealth
    "Stealth:S3/ServerAccessLoggingDisabled": {
        "description": "S3 server access logging disabled",
        "severity": "LOW",
        "mitre_techniques": ["T1562.008"],
    },
    # UnauthorizedAccess
    "UnauthorizedAccess:S3/MaliciousIPCaller.Custom": {
        "description": "S3 API from custom threat list IP",
        "severity": "HIGH",
        "mitre_techniques": ["T1530"],
    },
    "UnauthorizedAccess:S3/TorIPCaller": {
        "description": "S3 API from Tor exit node",
        "severity": "HIGH",
        "mitre_techniques": ["T1530"],
    },
}

GUARDDUTY_EC2_FINDINGS: Dict[str, dict] = {
    # Malware Protection
    "Execution:EC2/MaliciousFile": {
        "description": "Malicious file detected on EC2 instance",
        "severity": "HIGH",
        "mitre_techniques": ["T1204", "T1059", "T1566"],
        "data_source": "Malware Protection for EC2",
    },
    # DNS over HTTPS/TLS (Defence Evasion)
    "DefenseEvasion:EC2/UnusualDoHActivity": {
        "description": "EC2 instance using DNS over HTTPS to evade detection",
        "severity": "HIGH",
        "mitre_techniques": ["T1071.004", "T1572"],
        "data_source": "DNS logs",
    },
    "DefenseEvasion:EC2/UnusualDoTActivity": {
        "description": "EC2 instance using DNS over TLS to evade detection",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1071.004", "T1572"],
        "data_source": "DNS logs",
    },
    "DefenseEvasion:EC2/UnusualDNSResolver": {
        "description": "EC2 instance using unusual DNS resolver",
        "severity": "LOW",
        "mitre_techniques": ["T1071.004"],
        "data_source": "DNS logs",
    },
    # C&C Activity
    "Backdoor:EC2/C&CActivity.B": {
        "description": "EC2 instance querying C&C server domain",
        "severity": "HIGH",
        "mitre_techniques": ["T1071", "T1095"],
    },
    "Backdoor:EC2/C&CActivity.B!DNS": {
        "description": "EC2 instance querying C&C server via DNS",
        "severity": "HIGH",
        "mitre_techniques": ["T1071.004"],
    },
    "Backdoor:EC2/DenialOfService.Dns": {
        "description": "EC2 instance performing DNS DDoS",
        "severity": "HIGH",
        "mitre_techniques": ["T1498", "T1499"],
    },
    "Backdoor:EC2/DenialOfService.Tcp": {
        "description": "EC2 instance performing TCP DDoS",
        "severity": "HIGH",
        "mitre_techniques": ["T1498.001"],
    },
    "Backdoor:EC2/DenialOfService.Udp": {
        "description": "EC2 instance performing UDP DDoS",
        "severity": "HIGH",
        "mitre_techniques": ["T1498.001"],
    },
    "Backdoor:EC2/DenialOfService.UdpOnTcpPorts": {
        "description": "EC2 instance performing unusual DDoS",
        "severity": "HIGH",
        "mitre_techniques": ["T1498"],
    },
    "Backdoor:EC2/DenialOfService.UnusualProtocol": {
        "description": "EC2 instance performing unusual protocol DDoS",
        "severity": "HIGH",
        "mitre_techniques": ["T1498"],
    },
    "Backdoor:EC2/Spambot": {
        "description": "EC2 instance sending spam",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1071"],
    },
    "Behavior:EC2/NetworkPortUnusual": {
        "description": "EC2 instance communicating on unusual port",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1571"],
    },
    "Behavior:EC2/TrafficVolumeUnusual": {
        "description": "Unusual traffic volume from EC2 instance",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1048"],
    },
    "CryptoCurrency:EC2/BitcoinTool.B": {
        "description": "EC2 instance querying cryptocurrency-related domain",
        "severity": "HIGH",
        "mitre_techniques": ["T1496"],
    },
    "CryptoCurrency:EC2/BitcoinTool.B!DNS": {
        "description": "EC2 instance querying cryptocurrency domain via DNS",
        "severity": "HIGH",
        "mitre_techniques": ["T1496"],
    },
    "Impact:EC2/AbusedDomainRequest.Reputation": {
        "description": "EC2 instance querying low-reputation domain",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1071"],
    },
    "Impact:EC2/BitcoinDomainRequest.Reputation": {
        "description": "EC2 instance querying cryptocurrency domain",
        "severity": "HIGH",
        "mitre_techniques": ["T1496"],
    },
    "Impact:EC2/MaliciousDomainRequest.Reputation": {
        "description": "EC2 instance querying malicious domain",
        "severity": "HIGH",
        "mitre_techniques": ["T1071"],
    },
    "Impact:EC2/PortSweep": {
        "description": "EC2 instance performing port sweep",
        "severity": "HIGH",
        "mitre_techniques": ["T1046"],
    },
    "Impact:EC2/SuspiciousDomainRequest.Reputation": {
        "description": "EC2 instance querying suspicious domain",
        "severity": "LOW",
        "mitre_techniques": ["T1071"],
    },
    "Impact:EC2/WinRMBruteForce": {
        "description": "EC2 instance performing WinRM brute force",
        "severity": "LOW",
        "mitre_techniques": ["T1110"],
    },
    "Recon:EC2/PortProbeEMRUnprotectedPort": {
        "description": "Unprotected EMR port probed",
        "severity": "HIGH",
        "mitre_techniques": ["T1046"],
    },
    "Recon:EC2/PortProbeUnprotectedPort": {
        "description": "Unprotected port on EC2 being probed",
        "severity": "LOW",
        "mitre_techniques": ["T1046"],
    },
    "Recon:EC2/Portscan": {
        "description": "EC2 instance performing port scan",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1046"],
    },
    "Trojan:EC2/BlackholeTraffic": {
        "description": "EC2 instance communicating with black hole IP",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1071"],
    },
    "Trojan:EC2/BlackholeTraffic!DNS": {
        "description": "EC2 instance querying black hole domain",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1071.004"],
    },
    "Trojan:EC2/DGADomainRequest.B": {
        "description": "EC2 instance querying DGA domain",
        "severity": "HIGH",
        "mitre_techniques": ["T1568.002"],
    },
    "Trojan:EC2/DGADomainRequest.C!DNS": {
        "description": "EC2 instance querying DGA domain via DNS",
        "severity": "HIGH",
        "mitre_techniques": ["T1568.002"],
    },
    "Trojan:EC2/DNSDataExfiltration": {
        "description": "Data exfiltration via DNS",
        "severity": "HIGH",
        "mitre_techniques": ["T1048", "T1071.004"],
    },
    "Trojan:EC2/DriveBySourceTraffic!DNS": {
        "description": "EC2 instance querying drive-by source domain",
        "severity": "HIGH",
        "mitre_techniques": ["T1189"],
    },
    "Trojan:EC2/DropPoint": {
        "description": "EC2 instance communicating with drop point",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1071"],
    },
    "Trojan:EC2/DropPoint!DNS": {
        "description": "EC2 instance querying drop point domain",
        "severity": "HIGH",
        "mitre_techniques": ["T1071.004"],
    },
    "Trojan:EC2/PhishingDomainRequest!DNS": {
        "description": "EC2 instance querying phishing domain",
        "severity": "HIGH",
        "mitre_techniques": ["T1566"],
    },
    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom": {
        "description": "EC2 instance communicating with custom threat list IP",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1071"],
    },
    "UnauthorizedAccess:EC2/MetadataDNSRebind": {
        "description": "EC2 metadata service DNS rebind attack",
        "severity": "HIGH",
        "mitre_techniques": ["T1552.005"],
    },
    "UnauthorizedAccess:EC2/RDPBruteForce": {
        "description": "RDP brute force attack on EC2",
        "severity": "LOW",
        "mitre_techniques": ["T1110"],
    },
    "UnauthorizedAccess:EC2/SSHBruteForce": {
        "description": "SSH brute force attack on EC2",
        "severity": "LOW",
        "mitre_techniques": ["T1110"],
    },
    "UnauthorizedAccess:EC2/TorClient": {
        "description": "EC2 instance connecting to Tor network",
        "severity": "HIGH",
        "mitre_techniques": ["T1090.003"],
    },
    "UnauthorizedAccess:EC2/TorRelay": {
        "description": "EC2 instance acting as Tor relay",
        "severity": "HIGH",
        "mitre_techniques": ["T1090.003"],
    },
}

GUARDDUTY_RUNTIME_FINDINGS: Dict[str, dict] = {
    # Runtime monitoring (EC2, ECS, EKS)
    # Execution findings
    "Execution:Runtime/MaliciousFileExecuted": {
        "description": "Malicious file executed in runtime",
        "severity": "HIGH",
        "mitre_techniques": ["T1204", "T1059"],
    },
    "Execution:Runtime/NewBinaryExecuted": {
        "description": "New binary executed in container/instance",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1059"],
    },
    "Execution:Runtime/NewLibraryLoaded": {
        "description": "New library loaded in runtime",
        "severity": "LOW",
        "mitre_techniques": ["T1055"],
    },
    "Execution:Runtime/ReverseShell": {
        "description": "Reverse shell detected",
        "severity": "HIGH",
        "mitre_techniques": ["T1059"],
    },
    "Execution:Runtime/SuspiciousCommand": {
        "description": "Suspicious command executed",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1059"],
    },
    "Execution:Runtime/SuspiciousTool": {
        "description": "Suspicious tool executed",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1059"],
    },
    # Defence Evasion findings
    "DefenseEvasion:Runtime/FilelessExecution": {
        "description": "Fileless execution detected",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1620"],
    },
    "DefenseEvasion:Runtime/ProcessInjection.Proc": {
        "description": "Process injection via /proc detected",
        "severity": "HIGH",
        "mitre_techniques": ["T1055"],
    },
    "DefenseEvasion:Runtime/ProcessInjection.Ptrace": {
        "description": "Process injection via ptrace detected",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1055"],
    },
    "DefenseEvasion:Runtime/ProcessInjection.VirtualMemoryWrite": {
        "description": "Process injection via virtual memory write",
        "severity": "HIGH",
        "mitre_techniques": ["T1055"],
    },
    "DefenseEvasion:Runtime/SuspiciousCommand": {
        "description": "Defence evasion command executed",
        "severity": "HIGH",
        "mitre_techniques": ["T1070", "T1562"],
    },
    # Privilege Escalation findings
    "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory": {
        "description": "Container mounts host directory for escape",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1611"],
    },
    "PrivilegeEscalation:Runtime/DockerSocketAccessed": {
        "description": "Docker socket accessed from container",
        "severity": "HIGH",
        "mitre_techniques": ["T1611"],
    },
    "PrivilegeEscalation:Runtime/RuncContainerEscape": {
        "description": "Container escape via runc vulnerability",
        "severity": "HIGH",
        "mitre_techniques": ["T1611"],
    },
    "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified": {
        "description": "Cgroups release agent modified for escape",
        "severity": "HIGH",
        "mitre_techniques": ["T1611"],
    },
    "PrivilegeEscalation:Runtime/SuspiciousCommand": {
        "description": "Privilege escalation command executed",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1548"],
    },
    # Discovery findings
    "Discovery:Runtime/SuspiciousCommand": {
        "description": "Discovery command executed",
        "severity": "LOW",
        "mitre_techniques": ["T1082", "T1083"],
    },
    # Persistence findings
    "Persistence:Runtime/SuspiciousCommand": {
        "description": "Persistence command executed",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1136", "T1098"],
    },
    # Credential Access findings
    "CredentialAccess:Runtime/SuspiciousCommand": {
        "description": "Credential access command executed",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1552"],
    },
    # Impact findings
    "Impact:Runtime/CryptoMinerExecuted": {
        "description": "Cryptocurrency miner executed",
        "severity": "HIGH",
        "mitre_techniques": ["T1496"],
    },
    "CryptoCurrency:Runtime/BitcoinTool.B": {
        "description": "Cryptocurrency tool executed in runtime",
        "severity": "HIGH",
        "mitre_techniques": ["T1496"],
    },
    # Backdoor findings
    "Backdoor:Runtime/C&CActivity.B": {
        "description": "Runtime C&C communication detected",
        "severity": "HIGH",
        "mitre_techniques": ["T1071"],
    },
    # Container findings
    "Execution:Container/SuspiciousFile": {
        "description": "Suspicious file executed in container",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1059", "T1574"],
    },
}

# Lambda findings
GUARDDUTY_LAMBDA_FINDINGS: Dict[str, dict] = {
    "Backdoor:Lambda/C&CActivity.B": {
        "description": "Lambda function communicating with C&C server",
        "severity": "HIGH",
        "mitre_techniques": ["T1071", "T1648"],
        "data_source": "VPC flow logs",
    },
    "CryptoCurrency:Lambda/BitcoinTool.B": {
        "description": "Lambda function querying cryptocurrency-related domain",
        "severity": "HIGH",
        "mitre_techniques": ["T1496", "T1648"],
        "data_source": "VPC flow logs",
    },
    "Trojan:Lambda/BlackholeTraffic": {
        "description": "Lambda function communicating with black hole IP",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1071", "T1648"],
        "data_source": "VPC flow logs",
    },
    "Trojan:Lambda/DropPoint": {
        "description": "Lambda function communicating with drop point",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1071", "T1648"],
        "data_source": "VPC flow logs",
    },
    "UnauthorizedAccess:Lambda/MaliciousIPCaller.Custom": {
        "description": "Lambda function invoked from custom threat list IP",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1648"],
        "data_source": "VPC flow logs",
    },
    "UnauthorizedAccess:Lambda/TorClient": {
        "description": "Lambda function connecting to Tor network",
        "severity": "HIGH",
        "mitre_techniques": ["T1090.003", "T1648"],
        "data_source": "VPC flow logs",
    },
    "UnauthorizedAccess:Lambda/TorRelay": {
        "description": "Lambda function acting as Tor relay",
        "severity": "HIGH",
        "mitre_techniques": ["T1090.003", "T1648"],
        "data_source": "VPC flow logs",
    },
}

# Additional Kubernetes findings
GUARDDUTY_KUBERNETES_FINDINGS: Dict[str, dict] = {
    "CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed": {
        "description": "Anomalous Kubernetes secrets access",
        "severity": "MEDIUM",
        "mitre_techniques": ["T1552"],
    },
    "CredentialAccess:Kubernetes/MaliciousIPCaller.Custom": {
        "description": "Kubernetes API from custom threat IP",
        "severity": "HIGH",
        "mitre_techniques": ["T1552"],
    },
}


def get_all_finding_types() -> Set[str]:
    """Return all valid GuardDuty finding type names."""
    all_findings = set()
    all_findings.update(GUARDDUTY_IAM_FINDINGS.keys())
    all_findings.update(GUARDDUTY_S3_FINDINGS.keys())
    all_findings.update(GUARDDUTY_EC2_FINDINGS.keys())
    all_findings.update(GUARDDUTY_RUNTIME_FINDINGS.keys())
    all_findings.update(GUARDDUTY_LAMBDA_FINDINGS.keys())
    all_findings.update(GUARDDUTY_KUBERNETES_FINDINGS.keys())
    return all_findings


def get_findings_for_technique(technique_id: str) -> List[str]:
    """Return GuardDuty finding types that detect a given MITRE technique."""
    findings = []
    all_dicts = [
        GUARDDUTY_IAM_FINDINGS,
        GUARDDUTY_S3_FINDINGS,
        GUARDDUTY_EC2_FINDINGS,
        GUARDDUTY_RUNTIME_FINDINGS,
        GUARDDUTY_LAMBDA_FINDINGS,
        GUARDDUTY_KUBERNETES_FINDINGS,
    ]

    for finding_dict in all_dicts:
        for finding_type, info in finding_dict.items():
            techniques = info.get("mitre_techniques", [])
            if technique_id in techniques:
                findings.append(finding_type)

    return findings


def validate_finding_type(finding_type: str) -> bool:
    """Check if a GuardDuty finding type is valid."""
    return finding_type in get_all_finding_types()


def get_finding_info(finding_type: str) -> dict | None:
    """Get information about a specific finding type."""
    all_dicts = [
        GUARDDUTY_IAM_FINDINGS,
        GUARDDUTY_S3_FINDINGS,
        GUARDDUTY_EC2_FINDINGS,
        GUARDDUTY_RUNTIME_FINDINGS,
        GUARDDUTY_LAMBDA_FINDINGS,
        GUARDDUTY_KUBERNETES_FINDINGS,
    ]

    for finding_dict in all_dicts:
        if finding_type in finding_dict:
            return finding_dict[finding_type]

    return None


# MITRE technique to GuardDuty capability mapping
# This indicates which techniques have native GuardDuty detection
GUARDDUTY_TECHNIQUE_COVERAGE = {
    # Initial Access
    "T1078": [
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "InitialAccess:IAMUser/AnomalousBehavior",
    ],
    "T1078.004": [
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "Policy:IAMUser/RootCredentialUsage",
    ],
    "T1190": [],  # No direct GuardDuty finding - use WAF/Shield
    # Persistence
    "T1098": ["Persistence:IAMUser/AnomalousBehavior"],
    "T1136": ["Persistence:IAMUser/AnomalousBehavior"],
    # Privilege Escalation
    "T1548": ["PrivilegeEscalation:IAMUser/AnomalousBehavior"],
    "T1611": [
        "PrivilegeEscalation:Runtime/DockerSocketAccessed",
        "PrivilegeEscalation:Runtime/RuncContainerEscape",
    ],
    # Defense Evasion
    "T1562.008": [
        "Stealth:IAMUser/CloudTrailLoggingDisabled",
        "Stealth:S3/ServerAccessLoggingDisabled",
    ],
    "T1070": ["DefenseEvasion:IAMUser/AnomalousBehavior"],
    # Credential Access
    "T1552": ["CredentialAccess:IAMUser/AnomalousBehavior"],
    "T1552.005": [
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "UnauthorizedAccess:EC2/MetadataDNSRebind",
    ],
    "T1110": [
        "UnauthorizedAccess:EC2/SSHBruteForce",
        "UnauthorizedAccess:EC2/RDPBruteForce",
    ],
    # Discovery
    "T1046": ["Recon:EC2/Portscan", "Recon:EC2/PortProbeUnprotectedPort"],
    "T1087": ["Discovery:IAMUser/AnomalousBehavior"],
    "T1526": ["Discovery:IAMUser/AnomalousBehavior"],
    "T1619": ["Discovery:S3/MaliciousIPCaller", "Discovery:S3/TorIPCaller"],
    # Lateral Movement
    "T1021": [],  # Use VPC Flow Logs + CloudWatch
    # Collection
    "T1530": [
        "Exfiltration:S3/MaliciousIPCaller",
        "Exfiltration:S3/ObjectRead.Unusual",
    ],
    # Exfiltration
    "T1048": ["Behavior:EC2/TrafficVolumeUnusual", "Trojan:EC2/DNSDataExfiltration"],
    "T1537": ["Exfiltration:IAMUser/AnomalousBehavior"],
    # Command and Control
    "T1071": ["Backdoor:EC2/C&CActivity.B", "Trojan:EC2/DropPoint"],
    "T1071.004": ["Backdoor:EC2/C&CActivity.B!DNS", "Trojan:EC2/DNSDataExfiltration"],
    "T1090.003": ["Recon:IAMUser/TorIPCaller", "UnauthorizedAccess:EC2/TorClient"],
    "T1568.002": ["Trojan:EC2/DGADomainRequest.B", "Trojan:EC2/DGADomainRequest.C!DNS"],
    # Impact
    "T1485": ["Impact:IAMUser/AnomalousBehavior", "Impact:S3/MaliciousIPCaller"],
    "T1486": ["Impact:IAMUser/AnomalousBehavior"],
    "T1496": ["CryptoCurrency:EC2/BitcoinTool.B", "Impact:Runtime/CryptoMinerExecuted"],
    "T1498": ["Backdoor:EC2/DenialOfService.Dns", "Backdoor:EC2/DenialOfService.Tcp"],
}


def technique_has_guardduty_coverage(technique_id: str) -> bool:
    """Check if a technique has native GuardDuty detection coverage."""
    findings = GUARDDUTY_TECHNIQUE_COVERAGE.get(technique_id, [])
    return len(findings) > 0


def get_recommended_guardduty_findings(technique_id: str) -> List[str]:
    """Get recommended GuardDuty findings for a technique."""
    return GUARDDUTY_TECHNIQUE_COVERAGE.get(technique_id, [])
