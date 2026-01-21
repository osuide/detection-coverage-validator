"""Microsoft Defender for Cloud assessment to MITRE ATT&CK technique mappings.

Based on official mappings from the MITRE Center for Threat-Informed Defense
Security Stack Mappings project and Microsoft Defender for Cloud assessment categories.

Source: https://center-for-threat-informed-defense.github.io/security-stack-mappings/Azure/
GitHub: https://github.com/center-for-threat-informed-defense/security-stack-mappings
Microsoft Defender Docs: https://learn.microsoft.com/en-us/azure/defender-for-cloud/
"""

# Defender assessment display name patterns to MITRE technique mappings
# Format: assessment_pattern -> [(technique_id, confidence)]
# Patterns are matched case-insensitively against assessment displayName

DEFENDER_MITRE_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # === Compute & Virtual Machine Security ===
    "Endpoint protection should be installed": [
        ("T1562.001", 0.95),  # Impair Defenses: Disable or Modify Tools
        ("T1204", 0.85),  # User Execution
    ],
    "Endpoint protection health issues should be resolved": [
        ("T1562.001", 0.9),
        ("T1562", 0.85),  # Impair Defenses
    ],
    "System updates should be installed": [
        ("T1203", 0.9),  # Exploitation for Client Execution
        ("T1068", 0.85),  # Exploitation for Privilege Escalation
    ],
    "Vulnerabilities should be remediated": [
        ("T1203", 0.9),
        ("T1068", 0.85),
        ("T1190", 0.8),  # Exploit Public-Facing Application
    ],
    "Just-In-Time network access control should be applied": [
        ("T1078.004", 0.9),  # Valid Accounts: Cloud Accounts
        ("T1021", 0.85),  # Remote Services
    ],
    "Management ports should be closed": [
        ("T1021.001", 0.95),  # Remote Services: Remote Desktop Protocol
        ("T1021.004", 0.95),  # Remote Services: SSH
        ("T1133", 0.85),  # External Remote Services
    ],
    "Management ports of virtual machines should be protected with just-in-time": [
        ("T1021.001", 0.9),
        ("T1021.004", 0.9),
        ("T1133", 0.85),
    ],
    "Adaptive application controls should be enabled": [
        ("T1204.002", 0.9),  # User Execution: Malicious File
        ("T1059", 0.85),  # Command and Scripting Interpreter
    ],
    "Disk encryption should be applied": [
        ("T1005", 0.95),  # Data from Local System
        ("T1530", 0.9),  # Data from Cloud Storage
    ],
    "Virtual machines should encrypt temp disks": [
        ("T1005", 0.9),
        ("T1025", 0.85),  # Data from Removable Media
    ],
    # === Network Security ===
    "Network Security Groups should be enabled": [
        ("T1562.007", 0.95),  # Impair Defenses: Disable or Modify Cloud Firewall
        ("T1090", 0.8),  # Proxy
    ],
    "All network ports should be restricted": [
        ("T1562.007", 0.9),
        ("T1021", 0.85),  # Remote Services
    ],
    "Internet-facing virtual machines should be protected with Network Security Groups": [
        ("T1562.007", 0.95),
        ("T1190", 0.9),  # Exploit Public-Facing Application
    ],
    "Subnets should be associated with a Network Security Group": [
        ("T1562.007", 0.9),
    ],
    "IP Forwarding should be disabled": [
        ("T1090", 0.95),  # Proxy
        ("T1557", 0.85),  # Adversary-in-the-Middle
    ],
    "DDoS Protection Standard should be enabled": [
        ("T1499", 0.95),  # Endpoint Denial of Service
        ("T1498", 0.9),  # Network Denial of Service
    ],
    "Web Application Firewall should be enabled": [
        ("T1190", 0.95),  # Exploit Public-Facing Application
        ("T1505.003", 0.85),  # Server Software Component: Web Shell
    ],
    # === Identity and Access Management ===
    "MFA should be enabled on accounts with owner permissions": [
        ("T1078.004", 0.95),  # Valid Accounts: Cloud Accounts
        ("T1110", 0.9),  # Brute Force
    ],
    "MFA should be enabled on accounts with write permissions": [
        ("T1078.004", 0.95),
        ("T1110", 0.85),
    ],
    "MFA should be enabled on accounts with read permissions": [
        ("T1078.004", 0.9),
    ],
    "Privileged accounts should not have owner permissions": [
        ("T1078.004", 0.95),
        ("T1098", 0.9),  # Account Manipulation
    ],
    "External accounts with owner permissions should be removed": [
        ("T1078.004", 0.95),
        ("T1199", 0.9),  # Trusted Relationship
    ],
    "Deprecated accounts should be removed": [
        ("T1078.004", 0.9),
        ("T1098", 0.85),
    ],
    "Guest accounts should be removed": [
        ("T1078.004", 0.9),
    ],
    "Service principals should be used instead of certificates": [
        ("T1552.004", 0.9),  # Unsecured Credentials: Private Keys
        ("T1528", 0.85),  # Steal Application Access Token
    ],
    "Azure Active Directory authentication should be enabled": [
        ("T1078.004", 0.9),
        ("T1552.001", 0.85),  # Unsecured Credentials: Credentials In Files
    ],
    "Role-Based Access Control should be used": [
        ("T1078.004", 0.9),
        ("T1098", 0.85),
    ],
    # === Data & Storage Security ===
    "Storage accounts should restrict network access": [
        ("T1530", 0.95),  # Data from Cloud Storage
        (
            "T1567.002",
            0.9,
        ),  # Exfiltration Over Web Service: Exfiltration to Cloud Storage
    ],
    "Secure transfer to storage accounts should be enabled": [
        ("T1040", 0.95),  # Network Sniffing
        ("T1557", 0.9),  # Adversary-in-the-Middle
    ],
    "Storage accounts should use customer-managed key": [
        ("T1530", 0.9),
        ("T1552.001", 0.85),
    ],
    "Public network access should be disabled for storage accounts": [
        ("T1530", 0.95),
        ("T1567.002", 0.9),
    ],
    "Storage account encryption scopes should use customer-managed keys": [
        ("T1530", 0.9),
    ],
    "Blob storage should require secure transfer": [
        ("T1040", 0.9),
        ("T1557", 0.85),
    ],
    "Storage accounts should prevent shared key access": [
        ("T1552.001", 0.9),
        ("T1078.004", 0.85),
    ],
    # === Database Security ===
    "Transparent Data Encryption should be enabled": [
        ("T1530", 0.95),  # Data from Cloud Storage
        ("T1005", 0.9),  # Data from Local System
    ],
    "SQL servers should have an Azure Active Directory administrator": [
        ("T1078.004", 0.9),
        ("T1552.001", 0.85),
    ],
    "Advanced data security should be enabled on SQL servers": [
        ("T1190", 0.9),
        ("T1059.007", 0.85),  # Command and Scripting Interpreter: JavaScript
    ],
    "SQL databases should have vulnerability findings resolved": [
        ("T1190", 0.95),
        ("T1059.007", 0.9),
    ],
    "Auditing should be enabled on SQL Server": [
        ("T1562.008", 0.9),  # Impair Defenses: Disable Cloud Logs
        ("T1070", 0.85),  # Indicator Removal
    ],
    "Connection throttling should be enabled for PostgreSQL": [
        ("T1110", 0.9),  # Brute Force
    ],
    "Enforce SSL connection should be enabled for PostgreSQL": [
        ("T1040", 0.95),
        ("T1557", 0.9),
    ],
    "Enforce SSL connection should be enabled for MySQL": [
        ("T1040", 0.95),
        ("T1557", 0.9),
    ],
    "Private endpoint should be configured for SQL servers": [
        ("T1190", 0.9),
        ("T1133", 0.85),
    ],
    "SQL managed instances should have public network access disabled": [
        ("T1190", 0.95),
        ("T1133", 0.9),
    ],
    # === Container Security (AKS, ACR) ===
    "Container images should have vulnerability findings resolved": [
        ("T1525", 0.95),  # Implant Internal Image
        ("T1204.003", 0.9),  # User Execution: Malicious Image
    ],
    "Container registries should not allow unrestricted network access": [
        ("T1525", 0.9),
        ("T1199", 0.85),
    ],
    "Container registries should use customer-managed keys": [
        ("T1552.001", 0.9),
    ],
    "Kubernetes clusters should not allow container privilege escalation": [
        ("T1611", 0.95),  # Escape to Host
        ("T1068", 0.9),
    ],
    "Kubernetes clusters should disable automounting API credentials": [
        ("T1552.007", 0.9),  # Unsecured Credentials: Container API
        ("T1078.004", 0.85),
    ],
    "Kubernetes clusters should not use the default namespace": [
        ("T1610", 0.85),  # Deploy Container
    ],
    "Kubernetes Services should use approved images only": [
        ("T1525", 0.95),
        ("T1204.003", 0.9),
    ],
    "Role-Based Access Control should be used on Kubernetes Services": [
        ("T1078.004", 0.9),
        ("T1098", 0.85),
    ],
    "Kubernetes API server should be accessible only over HTTPS": [
        ("T1040", 0.95),
        ("T1557", 0.9),
    ],
    "Azure Container Registry images should have vulnerability findings resolved": [
        ("T1525", 0.95),
        ("T1204.003", 0.9),
    ],
    # === Key Vault Security ===
    "Key Vault should have purge protection enabled": [
        ("T1485", 0.95),  # Data Destruction
        ("T1490", 0.9),  # Inhibit System Recovery
    ],
    "Key Vault should have soft delete enabled": [
        ("T1485", 0.9),
        ("T1490", 0.85),
    ],
    "Key Vault keys should have an expiration date": [
        ("T1552.004", 0.9),  # Unsecured Credentials: Private Keys
        ("T1528", 0.85),
    ],
    "Key Vault secrets should have an expiration date": [
        ("T1552.001", 0.9),
        ("T1528", 0.85),
    ],
    "Key Vault should use a firewall": [
        ("T1552.001", 0.9),
        ("T1078.004", 0.85),
    ],
    "Key Vault certificates should have an expiration date": [
        ("T1552.004", 0.9),
    ],
    "Key Vault objects should be recoverable": [
        ("T1485", 0.9),
        ("T1490", 0.85),
    ],
    # === App Service Security ===
    "App Service apps should use latest TLS version": [
        ("T1040", 0.95),  # Network Sniffing
        ("T1557", 0.9),
    ],
    "App Service apps should have authentication enabled": [
        ("T1078.004", 0.95),
        ("T1190", 0.9),
    ],
    "App Service apps should not have CORS configured to allow every resource": [
        ("T1190", 0.9),
        ("T1059.007", 0.85),
    ],
    "App Service apps should only be accessible over HTTPS": [
        ("T1040", 0.95),
        ("T1557", 0.9),
    ],
    "Remote debugging should be turned off for App Service apps": [
        ("T1078.004", 0.9),
        ("T1059", 0.85),
    ],
    "Function apps should use latest TLS version": [
        ("T1040", 0.95),
        ("T1557", 0.9),
    ],
    "Function apps should have authentication enabled": [
        ("T1078.004", 0.95),
        ("T1190", 0.9),
    ],
    "Function apps should only be accessible over HTTPS": [
        ("T1040", 0.95),
        ("T1557", 0.9),
    ],
    "App Service apps should have resource logs enabled": [
        ("T1562.008", 0.9),  # Impair Defenses: Disable Cloud Logs
        ("T1070", 0.85),
    ],
    # === Monitoring and Logging ===
    "Activity logs should be retained for at least 365 days": [
        ("T1562.008", 0.95),
        ("T1070", 0.9),
    ],
    "Azure Monitor log profile should collect logs for all regions": [
        ("T1562.008", 0.9),
        ("T1070", 0.85),
    ],
    "Diagnostic logs should be enabled": [
        ("T1562.008", 0.95),
        ("T1070", 0.9),
    ],
    "Azure Defender for servers should be enabled": [
        ("T1190", 0.9),
        ("T1068", 0.85),
        ("T1203", 0.85),
    ],
    "Azure Defender for App Service should be enabled": [
        ("T1190", 0.95),
        ("T1505.003", 0.9),
    ],
    "Azure Defender for SQL servers should be enabled": [
        ("T1190", 0.95),
        ("T1059.007", 0.9),
    ],
    "Azure Defender for Storage should be enabled": [
        ("T1530", 0.95),
        ("T1567.002", 0.9),
    ],
    "Azure Defender for Key Vault should be enabled": [
        ("T1552.001", 0.95),
        ("T1552.004", 0.9),
    ],
    "Azure Defender for Kubernetes should be enabled": [
        ("T1525", 0.95),
        ("T1611", 0.9),
    ],
    "Azure Defender for container registries should be enabled": [
        ("T1525", 0.95),
        ("T1204.003", 0.9),
    ],
    "Security Center standard pricing tier should be selected": [
        ("T1190", 0.85),
        ("T1078.004", 0.85),
    ],
    "Email notifications for high severity alerts should be enabled": [
        ("T1562.008", 0.85),
    ],
    "Security contact email addresses should be set": [
        ("T1562.008", 0.8),
    ],
    # === Resource Configuration ===
    "Automation account variables should be encrypted": [
        ("T1552.001", 0.95),
        ("T1078.004", 0.85),
    ],
    "Azure resources should have resource locks": [
        ("T1485", 0.85),  # Data Destruction
        ("T1496", 0.8),  # Resource Hijacking
    ],
    "Subscriptions should have a contact email address for security issues": [
        ("T1562.008", 0.8),
    ],
    "Guest configuration extension should be installed": [
        ("T1562.001", 0.85),
    ],
    "System-assigned managed identity should be used": [
        ("T1552.001", 0.9),
        ("T1078.004", 0.85),
    ],
    "Virtual machine scale sets should have encryption at host enabled": [
        ("T1005", 0.9),
        ("T1530", 0.85),
    ],
}


def get_mitre_techniques_for_defender_assessment(
    assessment_display_name: str,
) -> list[tuple[str, float]]:
    """Get MITRE ATT&CK techniques for a Defender assessment.

    Args:
        assessment_display_name: The displayName from Defender assessment

    Returns:
        List of (technique_id, confidence) tuples, empty if no match
    """
    if not assessment_display_name:
        return []

    # Case-insensitive pattern matching
    display_name_lower = assessment_display_name.lower()

    for pattern, techniques in DEFENDER_MITRE_MAPPINGS.items():
        if pattern.lower() in display_name_lower:
            return techniques

    return []


def get_all_defender_techniques() -> set[str]:
    """Get set of all unique MITRE techniques referenced in Defender mappings.

    Returns:
        Set of technique IDs (e.g., {"T1078.004", "T1190", ...})
    """
    techniques = set()
    for technique_list in DEFENDER_MITRE_MAPPINGS.values():
        for technique_id, _ in technique_list:
            techniques.add(technique_id)
    return techniques
