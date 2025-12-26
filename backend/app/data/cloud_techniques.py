"""Cloud-relevant MITRE ATT&CK technique IDs.

This module defines which techniques are considered cloud-relevant for
compliance coverage calculations. Based on the MITRE ATT&CK IaaS Cloud Matrix.

Techniques from Reconnaissance (TA0043) and Resource Development (TA0042)
are marked as PRE-compromise and NOT included, as they occur before
cloud infrastructure is targeted and cannot be detected via cloud-native
logging (CloudTrail, Cloud Audit Logs, etc.).

Source: backend/app/scripts/seed_mitre.py - platforms assignment logic
"""

# Cloud-relevant techniques from MITRE ATT&CK IaaS Cloud Matrix
# These have platforms: ["AWS", "Azure", "GCP", "IaaS"]
# Excludes PRE-compromise techniques (Reconnaissance TA0043, Resource Development TA0042)
CLOUD_TECHNIQUE_IDS: frozenset[str] = frozenset(
    {
        # ==================== INITIAL ACCESS (TA0001) ====================
        "T1190",  # Exploit Public-Facing Application
        "T1199",  # Trusted Relationship
        "T1078",  # Valid Accounts
        "T1078.001",  # Valid Accounts: Default Accounts
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1566",  # Phishing
        "T1566.001",  # Phishing: Spearphishing Attachment
        "T1566.002",  # Phishing: Spearphishing Link
        "T1133",  # External Remote Services
        "T1200",  # Hardware Additions
        # ==================== EXECUTION (TA0002) ====================
        "T1651",  # Cloud Administration Command
        "T1059",  # Command and Scripting Interpreter
        "T1059.009",  # Command and Scripting Interpreter: Cloud API
        "T1648",  # Serverless Execution
        "T1204",  # User Execution
        "T1204.001",  # User Execution: Malicious Link
        "T1204.002",  # User Execution: Malicious File
        "T1204.003",  # User Execution: Malicious Image
        "T1609",  # Container Administration Command
        "T1610",  # Deploy Container
        # ==================== PERSISTENCE (TA0003) ====================
        "T1098",  # Account Manipulation
        "T1098.001",  # Account Manipulation: Additional Cloud Credentials
        "T1098.003",  # Account Manipulation: Additional Cloud Roles
        "T1098.004",  # Account Manipulation: SSH Authorized Keys
        "T1098.006",  # Account Manipulation: Additional Container Cluster Roles
        "T1136",  # Create Account
        "T1136.003",  # Create Account: Cloud Account
        "T1546",  # Event Triggered Execution
        "T1546.008",  # Event Triggered Execution: Serverless
        "T1525",  # Implant Internal Image
        "T1556",  # Modify Authentication Process
        "T1556.006",  # Modify Authentication Process: Multi-Factor Authentication
        "T1556.007",  # Modify Authentication Process: Hybrid Identity
        "T1556.009",  # Modify Authentication Process: Conditional Access Policies
        # ==================== PRIVILEGE ESCALATION (TA0004) ====================
        "T1548",  # Abuse Elevation Control Mechanism
        "T1548.005",  # Abuse Elevation Control: Temporary Elevated Cloud Access
        "T1611",  # Escape to Host
        "T1068",  # Exploitation for Privilege Escalation
        # ==================== DEFENSE EVASION (TA0005) ====================
        "T1211",  # Exploitation for Defense Evasion
        "T1562",  # Impair Defenses
        "T1562.001",  # Impair Defenses: Disable or Modify Tools
        "T1562.007",  # Impair Defenses: Disable or Modify Cloud Firewall
        "T1562.008",  # Impair Defenses: Disable or Modify Cloud Logs
        "T1578",  # Modify Cloud Compute Infrastructure
        "T1578.001",  # Modify Cloud Compute: Create Snapshot
        "T1578.002",  # Modify Cloud Compute: Create Cloud Instance
        "T1578.003",  # Modify Cloud Compute: Delete Cloud Instance
        "T1578.004",  # Modify Cloud Compute: Revert Cloud Instance
        "T1578.005",  # Modify Cloud Compute: Modify Cloud Compute Configurations
        "T1666",  # Modify Cloud Resource Hierarchy
        "T1535",  # Unused/Unsupported Cloud Regions
        "T1550",  # Use Alternate Authentication Material
        "T1550.001",  # Use Alternate Authentication: Application Access Token
        "T1550.004",  # Use Alternate Authentication: Web Session Cookie
        "T1620",  # Reflective Code Loading
        "T1055",  # Process Injection
        "T1027",  # Obfuscated Files or Information
        "T1027.006",  # Obfuscated Files: HTML Smuggling
        "T1612",  # Build Image on Host
        # ==================== CREDENTIAL ACCESS (TA0006) ====================
        "T1110",  # Brute Force
        "T1110.001",  # Brute Force: Password Guessing
        "T1110.003",  # Brute Force: Password Spraying
        "T1110.004",  # Brute Force: Credential Stuffing
        "T1555",  # Credentials from Password Stores
        "T1555.006",  # Credentials from Password Stores: Cloud Secrets Management Stores
        "T1606",  # Forge Web Credentials
        "T1606.001",  # Forge Web Credentials: Web Cookies
        "T1606.002",  # Forge Web Credentials: SAML Tokens
        "T1621",  # Multi-Factor Authentication Request Generation
        "T1040",  # Network Sniffing
        "T1528",  # Steal Application Access Token
        "T1552",  # Unsecured Credentials
        "T1552.001",  # Unsecured Credentials: Credentials In Files
        "T1552.005",  # Unsecured Credentials: Cloud Instance Metadata API
        "T1552.007",  # Unsecured Credentials: Container API
        # ==================== DISCOVERY (TA0007) ====================
        "T1087",  # Account Discovery
        "T1087.004",  # Account Discovery: Cloud Account
        "T1580",  # Cloud Infrastructure Discovery
        "T1538",  # Cloud Service Dashboard
        "T1526",  # Cloud Service Discovery
        "T1619",  # Cloud Storage Object Discovery
        "T1613",  # Container and Resource Discovery
        "T1680",  # Local Storage Discovery
        "T1654",  # Log Enumeration
        "T1046",  # Network Service Discovery
        "T1135",  # Network Share Discovery
        "T1201",  # Password Policy Discovery
        "T1069",  # Permission Groups Discovery
        "T1069.003",  # Permission Groups Discovery: Cloud Groups
        "T1518",  # Software Discovery
        "T1518.001",  # Software Discovery: Security Software Discovery
        "T1082",  # System Information Discovery
        "T1614",  # System Location Discovery
        "T1016",  # System Network Configuration Discovery
        "T1049",  # System Network Connections Discovery
        "T1033",  # System Owner/User Discovery
        "T1007",  # System Service Discovery
        # ==================== LATERAL MOVEMENT (TA0008) ====================
        "T1021",  # Remote Services
        "T1021.007",  # Remote Services: Cloud Services
        "T1021.008",  # Remote Services: Direct Cloud VM Connections
        "T1072",  # Software Deployment Tools
        # ==================== COLLECTION (TA0009) ====================
        "T1119",  # Automated Collection
        "T1530",  # Data from Cloud Storage
        "T1213",  # Data from Information Repositories
        "T1213.003",  # Data from Information Repositories: Code Repositories
        "T1213.006",  # Data from Information Repositories: Databases
        "T1005",  # Data from Local System
        "T1074",  # Data Staged
        "T1074.002",  # Data Staged: Remote Data Staging
        # ==================== EXFILTRATION (TA0010) ====================
        "T1048",  # Exfiltration Over Alternative Protocol
        "T1048.003",  # Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol
        "T1041",  # Exfiltration Over C2 Channel
        "T1567",  # Exfiltration Over Web Service
        "T1567.002",  # Exfiltration Over Web Service: Exfiltration to Cloud Storage
        "T1537",  # Transfer Data to Cloud Account
        # ==================== COMMAND AND CONTROL (TA0011) ====================
        "T1071",  # Application Layer Protocol
        "T1071.001",  # Application Layer Protocol: Web Protocols
        "T1071.003",  # Application Layer Protocol: Mail Protocols
        "T1071.004",  # Application Layer Protocol: DNS
        "T1090",  # Proxy
        "T1090.003",  # Proxy: Multi-hop Proxy
        "T1572",  # Protocol Tunneling
        "T1571",  # Non-Standard Port
        "T1568",  # Dynamic Resolution
        "T1568.002",  # Dynamic Resolution: Domain Generation Algorithms
        "T1102",  # Web Service
        "T1102.002",  # Web Service: Bidirectional Communication
        # ==================== IMPACT (TA0040) ====================
        "T1531",  # Account Access Removal
        "T1485",  # Data Destruction
        "T1485.001",  # Data Destruction: Lifecycle-Triggered Deletion
        "T1486",  # Data Encrypted for Impact
        "T1491",  # Defacement
        "T1491.002",  # Defacement: External Defacement
        "T1499",  # Endpoint Denial of Service
        "T1499.002",  # Endpoint DoS: Service Exhaustion Flood
        "T1499.003",  # Endpoint DoS: Application Exhaustion Flood
        "T1499.004",  # Endpoint DoS: Application or System Exploitation
        "T1490",  # Inhibit System Recovery
        "T1498",  # Network Denial of Service
        "T1498.001",  # Network DoS: Direct Network Flood
        "T1498.002",  # Network DoS: Reflection Amplification
        "T1496",  # Resource Hijacking
        "T1496.001",  # Resource Hijacking: Compute Hijacking
        "T1496.002",  # Resource Hijacking: Bandwidth Hijacking
        "T1489",  # Service Stop
    }
)

# PRE-compromise techniques (Reconnaissance + Resource Development)
# These are NOT cloud-relevant as they occur before cloud infrastructure is targeted
PRE_TECHNIQUE_IDS: frozenset[str] = frozenset(
    {
        # ==================== RECONNAISSANCE (TA0043) ====================
        "T1595",  # Active Scanning
        "T1595.001",  # Active Scanning: Scanning IP Blocks
        "T1595.002",  # Active Scanning: Vulnerability Scanning
        "T1595.003",  # Active Scanning: Wordlist Scanning
        "T1592",  # Gather Victim Host Information
        "T1589",  # Gather Victim Identity Information
        "T1590",  # Gather Victim Network Information
        "T1591",  # Gather Victim Org Information
        "T1598",  # Phishing for Information
        "T1597",  # Search Closed Sources
        "T1596",  # Search Open Technical Databases
        "T1593",  # Search Open Websites/Domains
        "T1594",  # Search Victim-Owned Websites
        # ==================== RESOURCE DEVELOPMENT (TA0042) ====================
        "T1583",  # Acquire Infrastructure
        "T1583.006",  # Acquire Infrastructure: Web Services
        "T1586",  # Compromise Accounts
        "T1586.003",  # Compromise Accounts: Cloud Accounts
        "T1584",  # Compromise Infrastructure
        "T1587",  # Develop Capabilities
        "T1585",  # Establish Accounts
        "T1588",  # Obtain Capabilities
        "T1588.002",  # Obtain Capabilities: Tool
        "T1608",  # Stage Capabilities
    }
)


def is_cloud_relevant(technique_id: str) -> bool:
    """Check if a technique ID is cloud-relevant.

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1078", "T1078.004")

    Returns:
        True if the technique is in the IaaS Cloud Matrix and detectable
        via cloud-native logging sources.
    """
    return technique_id in CLOUD_TECHNIQUE_IDS


def is_pre_compromise(technique_id: str) -> bool:
    """Check if a technique is a PRE-compromise technique.

    Args:
        technique_id: MITRE ATT&CK technique ID

    Returns:
        True if the technique is Reconnaissance or Resource Development.
    """
    return technique_id in PRE_TECHNIQUE_IDS
