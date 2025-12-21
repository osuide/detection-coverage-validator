"""GCP Chronicle detection to MITRE ATT&CK technique mappings.

Based on official mappings from the MITRE Center for Threat-Informed Defense
Security Stack Mappings project.

Source: https://center-for-threat-informed-defense.github.io/security-stack-mappings/GCP/
GitHub: https://github.com/center-for-threat-informed-defense/security-stack-mappings

Chronicle is Google's security analytics platform that ingests security telemetry
and provides threat detection. These mappings cover Chronicle's built-in detection
rules organised by MITRE ATT&CK tactic.
"""

from typing import Optional

# Chronicle rule category to MITRE technique mappings
# Based on official MITRE CTID Security Stack Mappings for GCP Chronicle
# Format: rule_category -> [(technique_id, confidence)]

CHRONICLE_MITRE_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # === Initial Access ===
    "PHISHING": [
        ("T1566", 0.9),  # Phishing
        ("T1566.001", 0.85),  # Spearphishing Attachment
        ("T1566.002", 0.85),  # Spearphishing Link
    ],
    "EXPLOIT_PUBLIC_APPLICATION": [
        ("T1190", 0.9),  # Exploit Public-Facing Application
    ],
    "VALID_ACCOUNTS": [
        ("T1078", 0.85),  # Valid Accounts
        ("T1078.004", 0.85),  # Cloud Accounts
    ],
    "EXTERNAL_REMOTE_SERVICES": [
        ("T1133", 0.85),  # External Remote Services
    ],
    "SUPPLY_CHAIN_COMPROMISE": [
        ("T1195", 0.85),  # Supply Chain Compromise
        ("T1195.002", 0.85),  # Compromise Software Supply Chain
    ],
    "DRIVE_BY_COMPROMISE": [
        ("T1189", 0.85),  # Drive-by Compromise
    ],
    # === Execution ===
    "COMMAND_SCRIPTING_INTERPRETER": [
        ("T1059", 0.9),  # Command and Scripting Interpreter
        ("T1059.003", 0.85),  # Windows Command Shell
        ("T1059.007", 0.85),  # JavaScript
    ],
    "SCHEDULED_TASK_JOB": [
        ("T1053", 0.85),  # Scheduled Task/Job
        ("T1053.005", 0.85),  # Scheduled Task
    ],
    "USER_EXECUTION": [
        ("T1204", 0.85),  # User Execution
    ],
    "EXPLOITATION_CLIENT_EXECUTION": [
        ("T1203", 0.9),  # Exploitation for Client Execution
    ],
    "NATIVE_API": [
        ("T1106", 0.8),  # Native API
    ],
    "INTER_PROCESS_COMMUNICATION": [
        ("T1559", 0.8),  # Inter-Process Communication
    ],
    "SHARED_MODULES": [
        ("T1129", 0.8),  # Shared Modules
    ],
    "SOFTWARE_DEPLOYMENT_TOOLS": [
        ("T1072", 0.85),  # Software Deployment Tools
    ],
    "SYSTEM_SERVICES": [
        ("T1569", 0.85),  # System Services
        ("T1569.002", 0.85),  # Service Execution
    ],
    # === Persistence ===
    "ACCOUNT_MANIPULATION": [
        ("T1098", 0.9),  # Account Manipulation
        ("T1098.001", 0.85),  # Additional Cloud Credentials
    ],
    "CREATE_ACCOUNT": [
        ("T1136", 0.9),  # Create Account
        ("T1136.001", 0.85),  # Local Account
    ],
    "BOOT_LOGON_AUTOSTART": [
        ("T1547", 0.85),  # Boot or Logon Autostart Execution
        ("T1547.001", 0.85),  # Registry Run Keys
    ],
    "BOOT_LOGON_INIT_SCRIPTS": [
        ("T1037", 0.85),  # Boot or Logon Initialization Scripts
        ("T1037.003", 0.85),  # Network Logon Script
    ],
    "CREATE_MODIFY_SYSTEM_PROCESS": [
        ("T1543", 0.85),  # Create or Modify System Process
        ("T1543.001", 0.85),  # Launch Agent
        ("T1543.003", 0.85),  # Windows Service
        ("T1543.004", 0.85),  # Launch Daemon
    ],
    "EVENT_TRIGGERED_EXECUTION": [
        ("T1546", 0.85),  # Event Triggered Execution
        ("T1546.001", 0.85),  # Change Default File Association
        ("T1546.003", 0.85),  # Windows Management Instrumentation Event
        ("T1546.007", 0.85),  # Netsh Helper DLL
        ("T1546.008", 0.85),  # Accessibility Features
    ],
    "HIJACK_EXECUTION_FLOW": [
        ("T1574", 0.85),  # Hijack Execution Flow
        ("T1574.007", 0.85),  # Path Interception by PATH Environment Variable
    ],
    "OFFICE_APPLICATION_STARTUP": [
        ("T1137", 0.8),  # Office Application Startup
        ("T1137.001", 0.8),  # Office Template Macros
    ],
    "MODIFY_AUTHENTICATION_PROCESS": [
        ("T1556", 0.85),  # Modify Authentication Process
    ],
    "SERVER_SOFTWARE_COMPONENT": [
        ("T1505", 0.85),  # Server Software Component
        ("T1505.003", 0.9),  # Web Shell
    ],
    # === Privilege Escalation ===
    "ABUSE_ELEVATION_CONTROL": [
        ("T1548", 0.9),  # Abuse Elevation Control Mechanism
        ("T1548.002", 0.85),  # Bypass User Account Control
    ],
    "ACCESS_TOKEN_MANIPULATION": [
        ("T1134", 0.9),  # Access Token Manipulation
        ("T1134.005", 0.85),  # SID-History Injection
    ],
    "EXPLOITATION_PRIVILEGE_ESCALATION": [
        ("T1068", 0.9),  # Exploitation for Privilege Escalation
    ],
    "PROCESS_INJECTION": [
        ("T1055", 0.9),  # Process Injection
    ],
    # === Defense Evasion ===
    "IMPAIR_DEFENSES": [
        ("T1562", 0.9),  # Impair Defenses
        ("T1562.004", 0.85),  # Disable or Modify System Firewall
    ],
    "INDICATOR_REMOVAL": [
        ("T1070", 0.9),  # Indicator Removal
        ("T1070.001", 0.85),  # Clear Windows Event Logs
        ("T1070.002", 0.85),  # Clear Linux or Mac System Logs
        ("T1070.004", 0.85),  # File Deletion
        ("T1070.006", 0.85),  # Timestomp
    ],
    "MASQUERADING": [
        ("T1036", 0.85),  # Masquerading
        ("T1036.005", 0.85),  # Match Legitimate Name or Location
    ],
    "OBFUSCATED_FILES": [
        ("T1027", 0.85),  # Obfuscated Files or Information
        ("T1027.004", 0.85),  # Compile After Delivery
    ],
    "MODIFY_REGISTRY": [
        ("T1112", 0.85),  # Modify Registry
    ],
    "ROOTKIT": [
        ("T1014", 0.9),  # Rootkit
    ],
    "SIGNED_BINARY_PROXY": [
        ("T1218", 0.85),  # System Binary Proxy Execution
        ("T1218.003", 0.85),  # CMSTP
        ("T1218.005", 0.85),  # Mshta
        ("T1218.010", 0.85),  # Regsvr32
    ],
    "TRUSTED_DEVELOPER_UTILITIES": [
        ("T1127", 0.85),  # Trusted Developer Utilities Proxy Execution
        ("T1127.001", 0.85),  # MSBuild
    ],
    "VIRTUALIZATION_SANDBOX_EVASION": [
        ("T1497", 0.85),  # Virtualization/Sandbox Evasion
    ],
    "INDIRECT_COMMAND_EXECUTION": [
        ("T1202", 0.8),  # Indirect Command Execution
    ],
    "PRE_OS_BOOT": [
        ("T1542", 0.85),  # Pre-OS Boot
    ],
    "SUBVERT_TRUST_CONTROLS": [
        ("T1553", 0.85),  # Subvert Trust Controls
    ],
    "DOMAIN_POLICY_MODIFICATION": [
        ("T1484", 0.85),  # Domain Policy Modification
    ],
    # === Credential Access ===
    "BRUTE_FORCE": [
        ("T1110", 0.95),  # Brute Force
        ("T1110.001", 0.9),  # Password Guessing
        ("T1110.003", 0.9),  # Password Spraying
        ("T1110.004", 0.9),  # Credential Stuffing
    ],
    "OS_CREDENTIAL_DUMPING": [
        ("T1003", 0.95),  # OS Credential Dumping
        ("T1003.001", 0.9),  # LSASS Memory
        ("T1003.003", 0.9),  # NTDS
    ],
    "UNSECURED_CREDENTIALS": [
        ("T1552", 0.9),  # Unsecured Credentials
    ],
    "EXPLOITATION_CREDENTIAL_ACCESS": [
        ("T1212", 0.9),  # Exploitation for Credential Access
    ],
    "INPUT_CAPTURE": [
        ("T1056", 0.85),  # Input Capture
        ("T1056.003", 0.85),  # Web Portal Capture
        ("T1056.004", 0.85),  # Credential API Hooking
    ],
    "STEAL_APPLICATION_ACCESS_TOKEN": [
        ("T1528", 0.9),  # Steal Application Access Token
    ],
    "FORGE_WEB_CREDENTIALS": [
        ("T1606", 0.85),  # Forge Web Credentials
    ],
    # === Discovery ===
    "ACCOUNT_DISCOVERY": [
        ("T1087", 0.85),  # Account Discovery
        ("T1087.004", 0.85),  # Cloud Account
    ],
    "CLOUD_INFRASTRUCTURE_DISCOVERY": [
        ("T1580", 0.85),  # Cloud Infrastructure Discovery
    ],
    "CLOUD_SERVICE_DISCOVERY": [
        ("T1526", 0.85),  # Cloud Service Discovery
    ],
    "NETWORK_SERVICE_DISCOVERY": [
        ("T1046", 0.85),  # Network Service Discovery
    ],
    "REMOTE_SYSTEM_DISCOVERY": [
        ("T1018", 0.85),  # Remote System Discovery
    ],
    "PROCESS_DISCOVERY": [
        ("T1057", 0.8),  # Process Discovery
    ],
    "SYSTEM_INFORMATION_DISCOVERY": [
        ("T1082", 0.8),  # System Information Discovery
    ],
    "SYSTEM_NETWORK_CONFIG_DISCOVERY": [
        ("T1016", 0.8),  # System Network Configuration Discovery
    ],
    "SYSTEM_NETWORK_CONNECTIONS": [
        ("T1049", 0.8),  # System Network Connections Discovery
    ],
    "SYSTEM_OWNER_DISCOVERY": [
        ("T1033", 0.8),  # System Owner/User Discovery
    ],
    # === Lateral Movement ===
    "REMOTE_SERVICES": [
        ("T1021", 0.9),  # Remote Services
        ("T1021.002", 0.85),  # SMB/Windows Admin Shares
        ("T1021.004", 0.85),  # SSH
    ],
    "EXPLOITATION_REMOTE_SERVICES": [
        ("T1210", 0.9),  # Exploitation of Remote Services
    ],
    "LATERAL_TOOL_TRANSFER": [
        ("T1570", 0.85),  # Lateral Tool Transfer
    ],
    "TAINT_SHARED_CONTENT": [
        ("T1080", 0.8),  # Taint Shared Content
    ],
    # === Collection ===
    "ARCHIVE_COLLECTED_DATA": [
        ("T1560", 0.85),  # Archive Collected Data
    ],
    "DATA_FROM_CLOUD_STORAGE": [
        ("T1530", 0.9),  # Data from Cloud Storage Object
    ],
    "DATA_FROM_INFO_REPOSITORIES": [
        ("T1213", 0.85),  # Data from Information Repositories
    ],
    "AUTOMATED_COLLECTION": [
        ("T1119", 0.8),  # Automated Collection
    ],
    # === Command and Control ===
    "APPLICATION_LAYER_PROTOCOL": [
        ("T1071", 0.9),  # Application Layer Protocol
        ("T1071.001", 0.85),  # Web Protocols
    ],
    "DATA_ENCODING": [
        ("T1132", 0.8),  # Data Encoding
        ("T1132.001", 0.8),  # Standard Encoding
    ],
    "INGRESS_TOOL_TRANSFER": [
        ("T1105", 0.9),  # Ingress Tool Transfer
    ],
    "PROXY": [
        ("T1090", 0.85),  # Proxy
    ],
    "REMOTE_ACCESS_SOFTWARE": [
        ("T1219", 0.85),  # Remote Access Software
    ],
    "DYNAMIC_RESOLUTION": [
        ("T1568", 0.85),  # Dynamic Resolution
    ],
    "NON_STANDARD_PORT": [
        ("T1571", 0.85),  # Non-Standard Port
    ],
    "PROTOCOL_TUNNELING": [
        ("T1572", 0.85),  # Protocol Tunneling
    ],
    # === Exfiltration ===
    "AUTOMATED_EXFILTRATION": [
        ("T1020", 0.9),  # Automated Exfiltration
    ],
    "DATA_TRANSFER_SIZE_LIMITS": [
        ("T1030", 0.8),  # Data Transfer Size Limits
    ],
    "EXFILTRATION_OVER_C2": [
        ("T1041", 0.9),  # Exfiltration Over C2 Channel
    ],
    "EXFILTRATION_OVER_ALTERNATIVE": [
        ("T1048", 0.9),  # Exfiltration Over Alternative Protocol
    ],
    "EXFILTRATION_OVER_WEB": [
        ("T1567", 0.9),  # Exfiltration Over Web Service
        ("T1567.002", 0.85),  # Exfiltration to Cloud Storage
    ],
    "EXFILTRATION_OVER_PHYSICAL": [
        ("T1052", 0.8),  # Exfiltration Over Physical Medium
        ("T1052.001", 0.8),  # Exfiltration over USB
    ],
    "TRANSFER_DATA_TO_CLOUD": [
        ("T1537", 0.9),  # Transfer Data to Cloud Account
    ],
    "SCHEDULED_TRANSFER": [
        ("T1029", 0.8),  # Scheduled Transfer
    ],
    # === Impact ===
    "DATA_DESTRUCTION": [
        ("T1485", 0.95),  # Data Destruction
    ],
    "DATA_ENCRYPTED_FOR_IMPACT": [
        ("T1486", 0.95),  # Data Encrypted for Impact
    ],
    "DEFACEMENT": [
        ("T1491", 0.85),  # Defacement
    ],
    "DISK_WIPE": [
        ("T1561", 0.9),  # Disk Wipe
    ],
    "ENDPOINT_DENIAL_OF_SERVICE": [
        ("T1499", 0.85),  # Endpoint Denial of Service
    ],
    "FIRMWARE_CORRUPTION": [
        ("T1495", 0.85),  # Firmware Corruption
    ],
    "INHIBIT_SYSTEM_RECOVERY": [
        ("T1490", 0.9),  # Inhibit System Recovery
    ],
    "NETWORK_DENIAL_OF_SERVICE": [
        ("T1498", 0.85),  # Network Denial of Service
    ],
    "RESOURCE_HIJACKING": [
        ("T1496", 0.95),  # Resource Hijacking
    ],
    "SERVICE_STOP": [
        ("T1489", 0.85),  # Service Stop
    ],
    "ACCOUNT_ACCESS_REMOVAL": [
        ("T1531", 0.9),  # Account Access Removal
    ],
    # === Resource Development ===
    "COMPROMISE_INFRASTRUCTURE": [
        ("T1584", 0.8),  # Compromise Infrastructure
        ("T1584.002", 0.8),  # DNS Server
    ],
    "OBTAIN_CAPABILITIES": [
        ("T1588", 0.8),  # Obtain Capabilities
        ("T1588.002", 0.8),  # Tool
    ],
    "STAGE_CAPABILITIES": [
        ("T1608", 0.8),  # Stage Capabilities
    ],
}


def get_mitre_mappings_for_chronicle_rule(
    rule_category: str,
    rule_name: Optional[str] = None,
) -> list[tuple[str, float]]:
    """Get MITRE technique mappings for a Chronicle detection rule.

    Args:
        rule_category: The Chronicle rule category (e.g., 'BRUTE_FORCE', 'EXFILTRATION')
        rule_name: Optional rule name for additional context

    Returns:
        List of (technique_id, confidence) tuples
    """
    # Normalise the category
    category_upper = rule_category.upper().replace("-", "_").replace(" ", "_")

    # Check for exact match
    if category_upper in CHRONICLE_MITRE_MAPPINGS:
        return CHRONICLE_MITRE_MAPPINGS[category_upper]

    # Check for partial matches
    for pattern, mappings in CHRONICLE_MITRE_MAPPINGS.items():
        if pattern in category_upper or category_upper in pattern:
            return mappings

    return []


def get_all_mapped_chronicle_categories() -> list[str]:
    """Get all Chronicle rule categories that have MITRE mappings."""
    return list(CHRONICLE_MITRE_MAPPINGS.keys())
