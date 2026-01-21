"""Azure Policy assignment to MITRE ATT&CK technique mappings.

Based on pattern matching of Azure Policy definition names and categories.
Unlike Defender, Azure Policy does not include native MITRE tags, so mappings
are pattern-based using common policy names and categories.

Source: MITRE CTID Security Stack Mappings for Azure
        Microsoft Azure Policy built-in definitions
"""

# Azure Policy definition name patterns to MITRE technique mappings
# Format: policy_pattern -> [(technique_id, confidence)]
# Patterns are matched case-insensitively against policy definition names or categories

POLICY_MITRE_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # === Identity and Access Management ===
    "Multi-factor authentication": [
        ("T1078.004", 0.9),  # Valid Accounts: Cloud Accounts
        ("T1110", 0.85),  # Brute Force
    ],
    "MFA should be enabled": [
        ("T1078.004", 0.9),
        ("T1110", 0.85),
    ],
    "Accounts with owner permissions": [
        ("T1078.004", 0.9),
        ("T1098", 0.85),  # Account Manipulation
    ],
    "External accounts": [
        ("T1078.004", 0.9),
        ("T1199", 0.85),  # Trusted Relationship
    ],
    "Privileged access": [
        ("T1078.004", 0.9),
        ("T1098", 0.85),
    ],
    "Role-based access control": [
        ("T1078.004", 0.85),
    ],
    "RBAC": [
        ("T1078.004", 0.85),
    ],
    "Service principal": [
        ("T1078.004", 0.85),
        ("T1552.004", 0.8),  # Unsecured Credentials: Private Keys
    ],
    "Managed identity": [
        ("T1078.004", 0.85),
        ("T1552.001", 0.8),  # Unsecured Credentials: Credentials In Files
    ],
    "Azure Active Directory": [
        ("T1078.004", 0.85),
    ],
    "Guest users": [
        ("T1078.004", 0.85),
    ],
    # === Network Security ===
    "Network security group": [
        ("T1562.007", 0.9),  # Impair Defenses: Disable or Modify Cloud Firewall
    ],
    "NSG": [
        ("T1562.007", 0.9),
    ],
    "Firewall": [
        ("T1562.007", 0.9),
    ],
    "Internet-facing": [
        ("T1190", 0.9),  # Exploit Public-Facing Application
        ("T1562.007", 0.85),
    ],
    "Public IP": [
        ("T1190", 0.85),
        ("T1133", 0.8),  # External Remote Services
    ],
    "Private endpoint": [
        ("T1190", 0.85),
        ("T1133", 0.8),
    ],
    "Network access": [
        ("T1562.007", 0.85),
    ],
    "DDoS": [
        ("T1499", 0.95),  # Endpoint Denial of Service
        ("T1498", 0.9),  # Network Denial of Service
    ],
    "Web Application Firewall": [
        ("T1190", 0.95),
        ("T1505.003", 0.85),  # Server Software Component: Web Shell
    ],
    "WAF": [
        ("T1190", 0.95),
        ("T1505.003", 0.85),
    ],
    "IP forwarding": [
        ("T1090", 0.9),  # Proxy
        ("T1557", 0.85),  # Adversary-in-the-Middle
    ],
    "Management ports": [
        ("T1021.001", 0.9),  # Remote Services: RDP
        ("T1021.004", 0.9),  # Remote Services: SSH
    ],
    "RDP": [
        ("T1021.001", 0.95),
    ],
    "SSH": [
        ("T1021.004", 0.95),
    ],
    "Just-in-time": [
        ("T1021", 0.9),  # Remote Services
        ("T1133", 0.85),
    ],
    "JIT": [
        ("T1021", 0.9),
        ("T1133", 0.85),
    ],
    # === Data Protection & Encryption ===
    "Encryption": [
        ("T1005", 0.9),  # Data from Local System
        ("T1530", 0.85),  # Data from Cloud Storage
    ],
    "Transparent Data Encryption": [
        ("T1530", 0.95),
        ("T1005", 0.9),
    ],
    "TDE": [
        ("T1530", 0.95),
        ("T1005", 0.9),
    ],
    "Customer-managed key": [
        ("T1552.001", 0.9),
        ("T1530", 0.85),
    ],
    "CMK": [
        ("T1552.001", 0.9),
    ],
    "Disk encryption": [
        ("T1005", 0.95),
    ],
    "Encryption at host": [
        ("T1005", 0.9),
    ],
    "Encryption at rest": [
        ("T1530", 0.9),
        ("T1005", 0.85),
    ],
    "Encryption in transit": [
        ("T1040", 0.95),  # Network Sniffing
        ("T1557", 0.9),  # Adversary-in-the-Middle
    ],
    "Secure transfer": [
        ("T1040", 0.95),
        ("T1557", 0.9),
    ],
    "TLS": [
        ("T1040", 0.95),
        ("T1557", 0.9),
    ],
    "SSL": [
        ("T1040", 0.95),
        ("T1557", 0.9),
    ],
    "HTTPS": [
        ("T1040", 0.95),
        ("T1557", 0.9),
    ],
    # === Storage Security ===
    "Storage account": [
        ("T1530", 0.85),  # Data from Cloud Storage
    ],
    "Blob storage": [
        ("T1530", 0.85),
    ],
    "Public blob": [
        ("T1530", 0.9),
        ("T1567.002", 0.85),  # Exfiltration to Cloud Storage
    ],
    "Shared key": [
        ("T1552.001", 0.9),
        ("T1078.004", 0.85),
    ],
    "SAS token": [
        ("T1552.001", 0.9),
        ("T1528", 0.85),  # Steal Application Access Token
    ],
    # === Container Security ===
    "Container": [
        ("T1525", 0.85),  # Implant Internal Image
        ("T1610", 0.8),  # Deploy Container
    ],
    "Kubernetes": [
        ("T1525", 0.85),
        ("T1611", 0.8),  # Escape to Host
    ],
    "AKS": [
        ("T1525", 0.85),
        ("T1611", 0.8),
    ],
    "Container registry": [
        ("T1525", 0.9),
        ("T1204.003", 0.85),  # User Execution: Malicious Image
    ],
    "ACR": [
        ("T1525", 0.9),
        ("T1204.003", 0.85),
    ],
    "Container image": [
        ("T1525", 0.9),
        ("T1204.003", 0.85),
    ],
    "Privilege escalation": [
        ("T1611", 0.95),
        ("T1068", 0.9),  # Exploitation for Privilege Escalation
    ],
    "Privileged container": [
        ("T1611", 0.95),
    ],
    "Host network": [
        ("T1611", 0.9),
    ],
    "Host PID": [
        ("T1611", 0.9),
    ],
    "Host IPC": [
        ("T1611", 0.9),
    ],
    # === Monitoring and Logging ===
    "Diagnostic logs": [
        ("T1562.008", 0.95),  # Impair Defenses: Disable Cloud Logs
        ("T1070", 0.9),  # Indicator Removal
    ],
    "Activity log": [
        ("T1562.008", 0.95),
        ("T1070", 0.9),
    ],
    "Audit logs": [
        ("T1562.008", 0.95),
        ("T1070", 0.9),
    ],
    "Log Analytics": [
        ("T1562.008", 0.9),
    ],
    "Log retention": [
        ("T1562.008", 0.9),
        ("T1070", 0.85),
    ],
    "Azure Monitor": [
        ("T1562.008", 0.85),
    ],
    # === Defender Plans ===
    "Azure Defender": [
        ("T1190", 0.85),
        ("T1068", 0.8),
    ],
    "Microsoft Defender": [
        ("T1190", 0.85),
        ("T1068", 0.8),
    ],
    "Defender for Servers": [
        ("T1190", 0.9),
        ("T1068", 0.85),
        ("T1203", 0.85),  # Exploitation for Client Execution
    ],
    "Defender for App Service": [
        ("T1190", 0.95),
        ("T1505.003", 0.9),
    ],
    "Defender for SQL": [
        ("T1190", 0.95),
        ("T1059.007", 0.9),  # Command and Scripting Interpreter: JavaScript
    ],
    "Defender for Storage": [
        ("T1530", 0.95),
        ("T1567.002", 0.9),
    ],
    "Defender for Key Vault": [
        ("T1552.001", 0.95),
        ("T1552.004", 0.9),
    ],
    "Defender for Kubernetes": [
        ("T1525", 0.95),
        ("T1611", 0.9),
    ],
    "Defender for container registries": [
        ("T1525", 0.95),
        ("T1204.003", 0.9),
    ],
    # === Database Security ===
    "SQL": [
        ("T1190", 0.85),
        ("T1059.007", 0.8),
    ],
    "SQL Server": [
        ("T1190", 0.85),
        ("T1059.007", 0.8),
    ],
    "SQL Database": [
        ("T1190", 0.85),
        ("T1059.007", 0.8),
    ],
    "Advanced Data Security": [
        ("T1190", 0.9),
        ("T1059.007", 0.85),
    ],
    "Vulnerability assessment": [
        ("T1190", 0.9),
        ("T1203", 0.85),
    ],
    "PostgreSQL": [
        ("T1040", 0.85),
        ("T1110", 0.8),
    ],
    "MySQL": [
        ("T1040", 0.85),
        ("T1110", 0.8),
    ],
    "Cosmos DB": [
        ("T1530", 0.85),
        ("T1552.001", 0.8),
    ],
    # === Key Vault ===
    "Key Vault": [
        ("T1552.001", 0.9),
        ("T1552.004", 0.85),
    ],
    "Keys should have an expiration": [
        ("T1552.004", 0.9),
        ("T1528", 0.85),
    ],
    "Secrets should have an expiration": [
        ("T1552.001", 0.9),
        ("T1528", 0.85),
    ],
    "Certificates should have an expiration": [
        ("T1552.004", 0.9),
    ],
    "Purge protection": [
        ("T1485", 0.95),  # Data Destruction
        ("T1490", 0.9),  # Inhibit System Recovery
    ],
    "Soft delete": [
        ("T1485", 0.9),
        ("T1490", 0.85),
    ],
    # === Compute Security ===
    "Virtual machine": [
        ("T1078.004", 0.8),
    ],
    "VM": [
        ("T1078.004", 0.8),
    ],
    "System updates": [
        ("T1203", 0.9),
        ("T1068", 0.85),
    ],
    "Security updates": [
        ("T1203", 0.9),
        ("T1068", 0.85),
    ],
    "Endpoint protection": [
        ("T1562.001", 0.95),
        ("T1204", 0.85),
    ],
    "Antimalware": [
        ("T1562.001", 0.95),
    ],
    "Adaptive application controls": [
        ("T1204.002", 0.9),
        ("T1059", 0.85),
    ],
    "Application whitelisting": [
        ("T1204.002", 0.9),
    ],
    # === App Service ===
    "App Service": [
        ("T1190", 0.85),
    ],
    "Function App": [
        ("T1190", 0.85),
    ],
    "Authentication": [
        ("T1078.004", 0.9),
        ("T1190", 0.85),
    ],
    "CORS": [
        ("T1190", 0.9),
        ("T1059.007", 0.85),
    ],
    "Remote debugging": [
        ("T1078.004", 0.9),
        ("T1059", 0.85),
    ],
    "Client certificates": [
        ("T1552.004", 0.85),
    ],
    # === Resource Management ===
    "Resource lock": [
        ("T1485", 0.85),
        ("T1496", 0.8),  # Resource Hijacking
    ],
    "Automation account": [
        ("T1552.001", 0.9),
    ],
    "Automation variable": [
        ("T1552.001", 0.9),
    ],
}


def get_mitre_techniques_for_policy(policy_name: str) -> list[tuple[str, float]]:
    """Get MITRE ATT&CK techniques for an Azure Policy assignment.

    Args:
        policy_name: The policy assignment name or definition name

    Returns:
        List of (technique_id, confidence) tuples, empty if no match
    """
    if not policy_name:
        return []

    # Case-insensitive pattern matching
    policy_name_lower = policy_name.lower()

    # Collect all matching techniques (a policy can match multiple patterns)
    all_techniques: dict[str, float] = {}

    for pattern, techniques in POLICY_MITRE_MAPPINGS.items():
        if pattern.lower() in policy_name_lower:
            for technique_id, confidence in techniques:
                # Keep highest confidence if technique matches multiple patterns
                if (
                    technique_id not in all_techniques
                    or confidence > all_techniques[technique_id]
                ):
                    all_techniques[technique_id] = confidence

    return list(all_techniques.items())


def get_all_policy_techniques() -> set[str]:
    """Get set of all unique MITRE techniques referenced in Policy mappings.

    Returns:
        Set of technique IDs (e.g., {"T1078.004", "T1190", ...})
    """
    techniques = set()
    for technique_list in POLICY_MITRE_MAPPINGS.values():
        for technique_id, _ in technique_list:
            techniques.add(technique_id)
    return techniques
