"""GCP Security Command Center finding to MITRE ATT&CK technique mappings.

Based on official mappings from the MITRE Center for Threat-Informed Defense
Security Stack Mappings project.

Source: https://center-for-threat-informed-defense.github.io/security-stack-mappings/GCP/
GitHub: https://github.com/center-for-threat-informed-defense/security-stack-mappings
"""

from typing import Optional

# SCC finding category/type to MITRE technique mappings
# Based on official MITRE CTID Security Stack Mappings for GCP SCC
# Format: finding_category -> [(technique_id, confidence)]

SCC_MITRE_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # === Container & Image Security ===
    "MALICIOUS_IMAGE": [
        ("T1204.003", 0.9),  # User Execution: Malicious Image
        ("T1525", 0.9),  # Implant Internal Image
    ],
    "ADDED_BINARY_EXECUTED": [
        ("T1204.003", 0.85),
        ("T1525", 0.85),
    ],
    "ADDED_LIBRARY_LOADED": [
        ("T1525", 0.8),
    ],
    "EXECUTION_ADDED_MALICIOUS_BINARY": [
        ("T1204.003", 0.9),
        ("T1525", 0.9),
    ],
    "EXECUTION_ADDED_MALICIOUS_LIBRARY": [
        ("T1525", 0.9),
    ],
    "EXECUTION_BUILT_IN_MALICIOUS_BINARY": [
        ("T1204.003", 0.9),
    ],
    "EXECUTION_MODIFIED_MALICIOUS_BINARY": [
        ("T1204.003", 0.9),
        ("T1525", 0.85),
    ],
    # === Network & External Access ===
    "EXTERNAL_MEMBER_ADDED_TO_PRIVILEGED_GROUP": [
        ("T1133", 0.85),  # External Remote Services
        ("T1078.004", 0.8),  # Valid Accounts: Cloud Accounts
    ],
    "OPEN_FIREWALL": [
        ("T1562.007", 0.9),  # Impair Defenses: Disable or Modify Cloud Firewall
    ],
    "OPEN_SSH_PORT": [
        ("T1562.007", 0.85),
    ],
    "OPEN_RDP_PORT": [
        ("T1562.007", 0.85),
    ],
    "OPEN_CISCOSECURE_WEBSM_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_DIRECTORY_SERVICES_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_DNS_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_ELASTICSEARCH_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_FTP_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_HTTP_PORT": [
        ("T1562.007", 0.75),
    ],
    "OPEN_LDAP_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_MEMCACHED_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_MONGODB_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_MYSQL_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_NETBIOS_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_ORACLEDB_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_POP3_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_POSTGRESQL_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_REDIS_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_SMTP_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_SQLSERVER_PORT": [
        ("T1562.007", 0.8),
    ],
    "OPEN_TELNET_PORT": [
        ("T1562.007", 0.85),
    ],
    # === Web Shell & Remote Access ===
    "WEB_SHELL_EXECUTION": [
        ("T1505.003", 0.95),  # Server Software Component: Web Shell
        ("T1059.004", 0.85),  # Command and Scripting Interpreter: Unix Shell
    ],
    "REVERSE_SHELL": [
        ("T1059.004", 0.95),
        ("T1105", 0.85),  # Ingress Tool Transfer
    ],
    "SHELL_EXECUTION": [
        ("T1059.004", 0.85),
    ],
    "MALICIOUS_SCRIPT_EXECUTED": [
        ("T1059", 0.9),  # Command and Scripting Interpreter
    ],
    # === Command and Control ===
    "DNS_EXFILTRATION": [
        ("T1071.004", 0.9),  # Application Layer Protocol: DNS
        ("T1567", 0.85),  # Exfiltration Over Web Service
    ],
    "UNEXPECTED_CHILD_SHELL": [
        ("T1059.004", 0.85),
    ],
    "BINARY_RUN_BY_MALICIOUS_LIBRARY": [
        ("T1055", 0.85),  # Process Injection
    ],
    # === Brute Force & Credential Access ===
    "BRUTE_FORCE_SSH": [
        ("T1110", 0.95),  # Brute Force
        ("T1078.004", 0.8),
    ],
    "SSH_BRUTE_FORCE": [
        ("T1110", 0.95),
        ("T1078.004", 0.8),
    ],
    "INCOMING_SSH_BLOCK": [
        ("T1110", 0.8),
    ],
    # === Defense Evasion ===
    "DEFENSE_EVASION_MODIFY_VPC_SERVICE_CONTROL": [
        ("T1562", 0.9),  # Impair Defenses
        ("T1562.007", 0.9),
    ],
    "IAM_DISABLE_AUDIT_LOGGING": [
        ("T1562.008", 0.95),  # Impair Defenses: Disable Cloud Logs
    ],
    "DISABLE_LOGGING": [
        ("T1562.008", 0.95),
    ],
    "VPC_FLOW_LOGS_SETTINGS_CHANGED": [
        ("T1562.008", 0.85),
    ],
    "AUDIT_LOGGING_DISABLED": [
        ("T1562.008", 0.95),
    ],
    "LOG_SINK_DELETED": [
        ("T1562.008", 0.9),
    ],
    # === Exfiltration ===
    "EXFILTRATION": [
        ("T1567", 0.9),
        ("T1567.002", 0.85),  # Exfiltration to Cloud Storage
    ],
    "DATA_EXFILTRATION": [
        ("T1567", 0.9),
        ("T1567.002", 0.85),
    ],
    "EXFILTRATION_TO_CLOUD_STORAGE": [
        ("T1567.002", 0.95),
    ],
    # === SQL Injection ===
    "SQL_INJECTION": [
        ("T1505.001", 0.9),  # Server Software Component: SQL Stored Procedures
        ("T1190", 0.85),  # Exploit Public-Facing Application
    ],
    # === Credential Exposure ===
    "CREDENTIALS_LEAKED": [
        ("T1589.001", 0.9),  # Gather Victim Identity Info: Credentials
        ("T1552", 0.85),  # Unsecured Credentials
    ],
    "SERVICE_ACCOUNT_KEY_EXPOSED": [
        ("T1589.001", 0.9),
        ("T1552", 0.9),
    ],
    "PUBLIC_IP_ADDRESS": [
        ("T1190", 0.75),
    ],
    # === IAM & Account Manipulation ===
    "ANOMALOUS_IAM_GRANT": [
        ("T1098.001", 0.85),  # Account Manipulation: Additional Cloud Credentials
        ("T1078.004", 0.8),
    ],
    "SERVICE_ACCOUNT_ANOMALOUS_TOKEN_CREATION": [
        ("T1098.001", 0.85),
    ],
    "SERVICE_ACCOUNT_KEY_CREATION": [
        ("T1098.001", 0.8),
    ],
    "ADMIN_SERVICE_ACCOUNT": [
        ("T1078.004", 0.8),
    ],
    "PRIMITIVE_ROLE_GRANTED": [
        ("T1098.001", 0.85),
        ("T1078.004", 0.8),
    ],
    "SERVICE_ACCOUNT_SELF_IMPERSONATION": [
        ("T1134", 0.8),  # Access Token Manipulation
    ],
    "IAM_ANOMALOUS_GRANT": [
        ("T1098.001", 0.85),
    ],
    "IAM_CUSTOM_ROLE_CREATED": [
        ("T1136.003", 0.8),  # Create Account: Cloud Account
    ],
    "OVER_PRIVILEGED_SERVICE_ACCOUNT": [
        ("T1078.004", 0.75),
    ],
    "USER_MANAGED_SERVICE_ACCOUNT_KEY": [
        ("T1098.001", 0.75),
    ],
    # === Resource Hijacking ===
    "CRYPTOMINING": [
        ("T1496", 0.95),  # Resource Hijacking
    ],
    "RESOURCE_HIJACKING": [
        ("T1496", 0.95),
    ],
    "BITCOIN_MINING": [
        ("T1496", 0.95),
    ],
    "CRYPTO_MINER_POOL_DOMAIN_CONTACTED": [
        ("T1496", 0.95),
    ],
    "CRYPTO_MINER_USER_AGENT_OBSERVED": [
        ("T1496", 0.95),
    ],
    # === Code Repository Access ===
    "UNAUTHORIZED_REPOSITORY_ACCESS": [
        ("T1213.003", 0.85),  # Data from Information Repositories: Code Repositories
    ],
    # === Network Sniffing ===
    "PACKET_CAPTURE_ENABLED": [
        ("T1040", 0.85),  # Network Sniffing
    ],
    # === Public-Facing Application ===
    "PUBLIC_BUCKET_ACL": [
        ("T1530", 0.9),  # Data from Cloud Storage Object
        ("T1190", 0.75),
    ],
    "PUBLIC_COMPUTE_IMAGE": [
        ("T1190", 0.8),
    ],
    "PUBLIC_DATASET": [
        ("T1530", 0.85),
    ],
    "PUBLIC_LOG_BUCKET": [
        ("T1530", 0.85),
        ("T1562.008", 0.75),
    ],
    "PUBLIC_SQL_INSTANCE": [
        ("T1190", 0.9),
    ],
    "PUBLICLY_ACCESSIBLE_SERVICES": [
        ("T1190", 0.85),
    ],
    "PRIVATE_GOOGLE_ACCESS_DISABLED": [
        ("T1562.007", 0.7),
    ],
    # === Compute Infrastructure ===
    "COMPUTE_PROJECT_WIDE_SSH_KEYS_ALLOWED": [
        ("T1078.004", 0.75),
    ],
    "COMPUTE_SECURE_BOOT_DISABLED": [
        ("T1542", 0.8),  # Pre-OS Boot
        ("T1542.003", 0.8),  # Bootkit
    ],
    "SHIELDED_VM_DISABLED": [
        ("T1014", 0.8),  # Rootkit
        ("T1542", 0.8),
    ],
    "OS_LOGIN_DISABLED": [
        ("T1078.001", 0.75),  # Valid Accounts: Default Accounts
    ],
    "SERIAL_PORT_ENABLED": [
        ("T1078.004", 0.7),
    ],
    # === Indicator Removal ===
    "LOGS_DELETED": [
        ("T1070", 0.9),  # Indicator Removal on Host
        ("T1562.008", 0.9),
    ],
    "DISK_DELETED": [
        ("T1070", 0.85),
    ],
    "SNAPSHOT_DELETED": [
        ("T1070", 0.8),
    ],
    "VM_DELETED": [
        ("T1070", 0.75),
    ],
    # === Policy Modification ===
    "ORG_POLICY_CHANGED": [
        ("T1484", 0.85),  # Domain Policy Modification
    ],
    "FOLDER_POLICY_CHANGED": [
        ("T1484", 0.8),
    ],
    "PROJECT_POLICY_CHANGED": [
        ("T1484", 0.8),
    ],
    # === Cloud Compute Modification ===
    "INSTANCE_TEMPLATE_CREATED_WITH_SENSITIVE_CONFIGS": [
        ("T1578", 0.8),  # Modify Cloud Compute Infrastructure
    ],
    "SUSPICIOUS_COMPUTE_CREATION": [
        ("T1578", 0.85),
    ],
    # === Encryption ===
    "DEFAULT_KMS_KEY_USED": [
        ("T1486", 0.7),  # Data Encrypted for Impact
    ],
    "KMS_KEY_DESTROYED": [
        ("T1486", 0.85),
    ],
    "WEAK_SSL_POLICY": [
        ("T1040", 0.75),
    ],
    "SSL_NOT_ENFORCED": [
        ("T1040", 0.75),
    ],
    # === MFA & Authentication ===
    "MFA_NOT_ENFORCED": [
        ("T1078.004", 0.8),
        ("T1110", 0.75),
    ],
    "TWO_STEP_VERIFICATION_DISABLED": [
        ("T1078.004", 0.8),
        ("T1110", 0.75),
    ],
}


def get_mitre_mappings_for_scc_finding(
    finding_category: str,
    finding_class: Optional[str] = None,
) -> list[tuple[str, float]]:
    """Get MITRE technique mappings for a GCP Security Command Center finding.

    Args:
        finding_category: The SCC finding category (e.g., 'CRYPTOMINING', 'OPEN_FIREWALL')
        finding_class: Optional finding class for additional context

    Returns:
        List of (technique_id, confidence) tuples
    """
    # Normalise the category
    category_upper = finding_category.upper().replace("-", "_").replace(" ", "_")

    # Check for exact match
    if category_upper in SCC_MITRE_MAPPINGS:
        return SCC_MITRE_MAPPINGS[category_upper]

    # Check for partial matches
    for pattern, mappings in SCC_MITRE_MAPPINGS.items():
        if pattern in category_upper or category_upper in pattern:
            return mappings

    return []


def get_all_mapped_scc_categories() -> list[str]:
    """Get all SCC finding categories that have MITRE mappings."""
    return list(SCC_MITRE_MAPPINGS.keys())
