"""Comprehensive MITRE ATT&CK technique metadata for CTID mappings.

This module provides technique names and tactic associations for all techniques
used in our CTID mappings. This is separate from the indicator library which
is designed for pattern-based detection.

Source: https://attack.mitre.org/techniques/enterprise/
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class TechniqueMetadata:
    """Metadata for a MITRE ATT&CK technique."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str


# Comprehensive technique metadata for all CTID-mapped techniques
# Format: technique_id -> TechniqueMetadata
TECHNIQUE_METADATA: dict[str, TechniqueMetadata] = {
    # === Reconnaissance (TA0043) ===
    "T1595": TechniqueMetadata("T1595", "Active Scanning", "TA0043", "Reconnaissance"),
    "T1595.001": TechniqueMetadata(
        "T1595.001", "Active Scanning: Scanning IP Blocks", "TA0043", "Reconnaissance"
    ),
    "T1595.002": TechniqueMetadata(
        "T1595.002",
        "Active Scanning: Vulnerability Scanning",
        "TA0043",
        "Reconnaissance",
    ),
    "T1589": TechniqueMetadata(
        "T1589", "Gather Victim Identity Information", "TA0043", "Reconnaissance"
    ),
    "T1589.001": TechniqueMetadata(
        "T1589.001",
        "Gather Victim Identity Information: Credentials",
        "TA0043",
        "Reconnaissance",
    ),
    "T1590": TechniqueMetadata(
        "T1590", "Gather Victim Network Information", "TA0043", "Reconnaissance"
    ),
    "T1591": TechniqueMetadata(
        "T1591", "Gather Victim Org Information", "TA0043", "Reconnaissance"
    ),
    "T1592": TechniqueMetadata(
        "T1592", "Gather Victim Host Information", "TA0043", "Reconnaissance"
    ),
    # === Resource Development (TA0042) ===
    "T1584": TechniqueMetadata(
        "T1584", "Compromise Infrastructure", "TA0042", "Resource Development"
    ),
    "T1584.002": TechniqueMetadata(
        "T1584.002",
        "Compromise Infrastructure: DNS Server",
        "TA0042",
        "Resource Development",
    ),
    "T1588": TechniqueMetadata(
        "T1588", "Obtain Capabilities", "TA0042", "Resource Development"
    ),
    "T1588.002": TechniqueMetadata(
        "T1588.002", "Obtain Capabilities: Tool", "TA0042", "Resource Development"
    ),
    "T1608": TechniqueMetadata(
        "T1608", "Stage Capabilities", "TA0042", "Resource Development"
    ),
    # === Initial Access (TA0001) ===
    "T1189": TechniqueMetadata(
        "T1189", "Drive-by Compromise", "TA0001", "Initial Access"
    ),
    "T1190": TechniqueMetadata(
        "T1190", "Exploit Public-Facing Application", "TA0001", "Initial Access"
    ),
    "T1133": TechniqueMetadata(
        "T1133", "External Remote Services", "TA0001", "Initial Access"
    ),
    "T1566": TechniqueMetadata("T1566", "Phishing", "TA0001", "Initial Access"),
    "T1566.001": TechniqueMetadata(
        "T1566.001", "Phishing: Spearphishing Attachment", "TA0001", "Initial Access"
    ),
    "T1566.002": TechniqueMetadata(
        "T1566.002", "Phishing: Spearphishing Link", "TA0001", "Initial Access"
    ),
    "T1566.003": TechniqueMetadata(
        "T1566.003", "Phishing: Spearphishing via Service", "TA0001", "Initial Access"
    ),
    "T1195": TechniqueMetadata(
        "T1195", "Supply Chain Compromise", "TA0001", "Initial Access"
    ),
    "T1195.002": TechniqueMetadata(
        "T1195.002",
        "Supply Chain Compromise: Compromise Software Supply Chain",
        "TA0001",
        "Initial Access",
    ),
    "T1078": TechniqueMetadata("T1078", "Valid Accounts", "TA0001", "Initial Access"),
    "T1078.001": TechniqueMetadata(
        "T1078.001", "Valid Accounts: Default Accounts", "TA0001", "Initial Access"
    ),
    "T1078.004": TechniqueMetadata(
        "T1078.004", "Valid Accounts: Cloud Accounts", "TA0001", "Initial Access"
    ),
    # === Execution (TA0002) ===
    "T1059": TechniqueMetadata(
        "T1059", "Command and Scripting Interpreter", "TA0002", "Execution"
    ),
    "T1059.003": TechniqueMetadata(
        "T1059.003",
        "Command and Scripting Interpreter: Windows Command Shell",
        "TA0002",
        "Execution",
    ),
    "T1059.004": TechniqueMetadata(
        "T1059.004",
        "Command and Scripting Interpreter: Unix Shell",
        "TA0002",
        "Execution",
    ),
    "T1059.007": TechniqueMetadata(
        "T1059.007",
        "Command and Scripting Interpreter: JavaScript",
        "TA0002",
        "Execution",
    ),
    "T1609": TechniqueMetadata(
        "T1609", "Container Administration Command", "TA0002", "Execution"
    ),
    "T1610": TechniqueMetadata("T1610", "Deploy Container", "TA0002", "Execution"),
    "T1203": TechniqueMetadata(
        "T1203", "Exploitation for Client Execution", "TA0002", "Execution"
    ),
    "T1559": TechniqueMetadata(
        "T1559", "Inter-Process Communication", "TA0002", "Execution"
    ),
    "T1106": TechniqueMetadata("T1106", "Native API", "TA0002", "Execution"),
    "T1053": TechniqueMetadata("T1053", "Scheduled Task/Job", "TA0002", "Execution"),
    "T1053.005": TechniqueMetadata(
        "T1053.005", "Scheduled Task/Job: Scheduled Task", "TA0002", "Execution"
    ),
    "T1129": TechniqueMetadata("T1129", "Shared Modules", "TA0002", "Execution"),
    "T1072": TechniqueMetadata(
        "T1072", "Software Deployment Tools", "TA0002", "Execution"
    ),
    "T1569": TechniqueMetadata("T1569", "System Services", "TA0002", "Execution"),
    "T1569.002": TechniqueMetadata(
        "T1569.002", "System Services: Service Execution", "TA0002", "Execution"
    ),
    "T1204": TechniqueMetadata("T1204", "User Execution", "TA0002", "Execution"),
    "T1204.002": TechniqueMetadata(
        "T1204.002", "User Execution: Malicious File", "TA0002", "Execution"
    ),
    "T1204.003": TechniqueMetadata(
        "T1204.003", "User Execution: Malicious Image", "TA0002", "Execution"
    ),
    # === Persistence (TA0003) ===
    "T1098": TechniqueMetadata(
        "T1098", "Account Manipulation", "TA0003", "Persistence"
    ),
    "T1098.001": TechniqueMetadata(
        "T1098.001",
        "Account Manipulation: Additional Cloud Credentials",
        "TA0003",
        "Persistence",
    ),
    "T1098.003": TechniqueMetadata(
        "T1098.003",
        "Account Manipulation: Additional Cloud Roles",
        "TA0003",
        "Persistence",
    ),
    "T1098.004": TechniqueMetadata(
        "T1098.004",
        "Account Manipulation: SSH Authorized Keys",
        "TA0003",
        "Persistence",
    ),
    "T1547": TechniqueMetadata(
        "T1547", "Boot or Logon Autostart Execution", "TA0003", "Persistence"
    ),
    "T1547.001": TechniqueMetadata(
        "T1547.001",
        "Boot or Logon Autostart Execution: Registry Run Keys",
        "TA0003",
        "Persistence",
    ),
    "T1037": TechniqueMetadata(
        "T1037", "Boot or Logon Initialization Scripts", "TA0003", "Persistence"
    ),
    "T1037.003": TechniqueMetadata(
        "T1037.003",
        "Boot or Logon Initialization Scripts: Network Logon Script",
        "TA0003",
        "Persistence",
    ),
    "T1136": TechniqueMetadata("T1136", "Create Account", "TA0003", "Persistence"),
    "T1136.001": TechniqueMetadata(
        "T1136.001", "Create Account: Local Account", "TA0003", "Persistence"
    ),
    "T1136.003": TechniqueMetadata(
        "T1136.003", "Create Account: Cloud Account", "TA0003", "Persistence"
    ),
    "T1543": TechniqueMetadata(
        "T1543", "Create or Modify System Process", "TA0003", "Persistence"
    ),
    "T1543.001": TechniqueMetadata(
        "T1543.001",
        "Create or Modify System Process: Launch Agent",
        "TA0003",
        "Persistence",
    ),
    "T1543.003": TechniqueMetadata(
        "T1543.003",
        "Create or Modify System Process: Windows Service",
        "TA0003",
        "Persistence",
    ),
    "T1543.004": TechniqueMetadata(
        "T1543.004",
        "Create or Modify System Process: Launch Daemon",
        "TA0003",
        "Persistence",
    ),
    "T1546": TechniqueMetadata(
        "T1546", "Event Triggered Execution", "TA0003", "Persistence"
    ),
    "T1546.001": TechniqueMetadata(
        "T1546.001",
        "Event Triggered Execution: Change Default File Association",
        "TA0003",
        "Persistence",
    ),
    "T1546.003": TechniqueMetadata(
        "T1546.003",
        "Event Triggered Execution: WMI Event Subscription",
        "TA0003",
        "Persistence",
    ),
    "T1546.007": TechniqueMetadata(
        "T1546.007",
        "Event Triggered Execution: Netsh Helper DLL",
        "TA0003",
        "Persistence",
    ),
    "T1546.008": TechniqueMetadata(
        "T1546.008",
        "Event Triggered Execution: Accessibility Features",
        "TA0003",
        "Persistence",
    ),
    "T1574": TechniqueMetadata(
        "T1574", "Hijack Execution Flow", "TA0003", "Persistence"
    ),
    "T1574.007": TechniqueMetadata(
        "T1574.007",
        "Hijack Execution Flow: Path Interception by PATH Environment Variable",
        "TA0003",
        "Persistence",
    ),
    "T1556": TechniqueMetadata(
        "T1556", "Modify Authentication Process", "TA0003", "Persistence"
    ),
    "T1137": TechniqueMetadata(
        "T1137", "Office Application Startup", "TA0003", "Persistence"
    ),
    "T1137.001": TechniqueMetadata(
        "T1137.001",
        "Office Application Startup: Office Template Macros",
        "TA0003",
        "Persistence",
    ),
    "T1505": TechniqueMetadata(
        "T1505", "Server Software Component", "TA0003", "Persistence"
    ),
    "T1505.001": TechniqueMetadata(
        "T1505.001",
        "Server Software Component: SQL Stored Procedures",
        "TA0003",
        "Persistence",
    ),
    "T1505.003": TechniqueMetadata(
        "T1505.003", "Server Software Component: Web Shell", "TA0003", "Persistence"
    ),
    "T1525": TechniqueMetadata(
        "T1525", "Implant Internal Image", "TA0003", "Persistence"
    ),
    # === Privilege Escalation (TA0004) ===
    "T1548": TechniqueMetadata(
        "T1548", "Abuse Elevation Control Mechanism", "TA0004", "Privilege Escalation"
    ),
    "T1548.002": TechniqueMetadata(
        "T1548.002",
        "Abuse Elevation Control Mechanism: Bypass User Account Control",
        "TA0004",
        "Privilege Escalation",
    ),
    "T1548.005": TechniqueMetadata(
        "T1548.005",
        "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
        "TA0004",
        "Privilege Escalation",
    ),
    "T1134": TechniqueMetadata(
        "T1134", "Access Token Manipulation", "TA0004", "Privilege Escalation"
    ),
    "T1134.005": TechniqueMetadata(
        "T1134.005",
        "Access Token Manipulation: SID-History Injection",
        "TA0004",
        "Privilege Escalation",
    ),
    "T1068": TechniqueMetadata(
        "T1068",
        "Exploitation for Privilege Escalation",
        "TA0004",
        "Privilege Escalation",
    ),
    "T1055": TechniqueMetadata(
        "T1055", "Process Injection", "TA0004", "Privilege Escalation"
    ),
    "T1055.001": TechniqueMetadata(
        "T1055.001",
        "Process Injection: Dynamic-link Library Injection",
        "TA0004",
        "Privilege Escalation",
    ),
    "T1611": TechniqueMetadata(
        "T1611", "Escape to Host", "TA0004", "Privilege Escalation"
    ),
    # === Defense Evasion (TA0005) ===
    "T1484": TechniqueMetadata(
        "T1484", "Domain or Tenant Policy Modification", "TA0005", "Defense Evasion"
    ),
    "T1562": TechniqueMetadata("T1562", "Impair Defenses", "TA0005", "Defense Evasion"),
    "T1562.001": TechniqueMetadata(
        "T1562.001",
        "Impair Defenses: Disable or Modify Tools",
        "TA0005",
        "Defense Evasion",
    ),
    "T1562.004": TechniqueMetadata(
        "T1562.004",
        "Impair Defenses: Disable or Modify System Firewall",
        "TA0005",
        "Defense Evasion",
    ),
    "T1562.007": TechniqueMetadata(
        "T1562.007",
        "Impair Defenses: Disable or Modify Cloud Firewall",
        "TA0005",
        "Defense Evasion",
    ),
    "T1562.008": TechniqueMetadata(
        "T1562.008", "Impair Defenses: Disable Cloud Logs", "TA0005", "Defense Evasion"
    ),
    "T1070": TechniqueMetadata(
        "T1070", "Indicator Removal", "TA0005", "Defense Evasion"
    ),
    "T1070.001": TechniqueMetadata(
        "T1070.001",
        "Indicator Removal: Clear Windows Event Logs",
        "TA0005",
        "Defense Evasion",
    ),
    "T1070.002": TechniqueMetadata(
        "T1070.002",
        "Indicator Removal: Clear Linux or Mac System Logs",
        "TA0005",
        "Defense Evasion",
    ),
    "T1070.004": TechniqueMetadata(
        "T1070.004", "Indicator Removal: File Deletion", "TA0005", "Defense Evasion"
    ),
    "T1070.006": TechniqueMetadata(
        "T1070.006", "Indicator Removal: Timestomp", "TA0005", "Defense Evasion"
    ),
    "T1202": TechniqueMetadata(
        "T1202", "Indirect Command Execution", "TA0005", "Defense Evasion"
    ),
    "T1036": TechniqueMetadata("T1036", "Masquerading", "TA0005", "Defense Evasion"),
    "T1036.005": TechniqueMetadata(
        "T1036.005",
        "Masquerading: Match Legitimate Name or Location",
        "TA0005",
        "Defense Evasion",
    ),
    "T1112": TechniqueMetadata("T1112", "Modify Registry", "TA0005", "Defense Evasion"),
    "T1578": TechniqueMetadata(
        "T1578", "Modify Cloud Compute Infrastructure", "TA0005", "Defense Evasion"
    ),
    "T1027": TechniqueMetadata(
        "T1027", "Obfuscated Files or Information", "TA0005", "Defense Evasion"
    ),
    "T1027.004": TechniqueMetadata(
        "T1027.004",
        "Obfuscated Files or Information: Compile After Delivery",
        "TA0005",
        "Defense Evasion",
    ),
    "T1542": TechniqueMetadata("T1542", "Pre-OS Boot", "TA0005", "Defense Evasion"),
    "T1542.003": TechniqueMetadata(
        "T1542.003", "Pre-OS Boot: Bootkit", "TA0005", "Defense Evasion"
    ),
    "T1014": TechniqueMetadata("T1014", "Rootkit", "TA0005", "Defense Evasion"),
    "T1553": TechniqueMetadata(
        "T1553", "Subvert Trust Controls", "TA0005", "Defense Evasion"
    ),
    "T1218": TechniqueMetadata(
        "T1218", "System Binary Proxy Execution", "TA0005", "Defense Evasion"
    ),
    "T1218.003": TechniqueMetadata(
        "T1218.003", "System Binary Proxy Execution: CMSTP", "TA0005", "Defense Evasion"
    ),
    "T1218.005": TechniqueMetadata(
        "T1218.005", "System Binary Proxy Execution: Mshta", "TA0005", "Defense Evasion"
    ),
    "T1218.010": TechniqueMetadata(
        "T1218.010",
        "System Binary Proxy Execution: Regsvr32",
        "TA0005",
        "Defense Evasion",
    ),
    "T1127": TechniqueMetadata(
        "T1127",
        "Trusted Developer Utilities Proxy Execution",
        "TA0005",
        "Defense Evasion",
    ),
    "T1127.001": TechniqueMetadata(
        "T1127.001",
        "Trusted Developer Utilities Proxy Execution: MSBuild",
        "TA0005",
        "Defense Evasion",
    ),
    "T1497": TechniqueMetadata(
        "T1497", "Virtualization/Sandbox Evasion", "TA0005", "Defense Evasion"
    ),
    "T1211": TechniqueMetadata(
        "T1211", "Exploitation for Defense Evasion", "TA0005", "Defense Evasion"
    ),
    "T1620": TechniqueMetadata(
        "T1620", "Reflective Code Loading", "TA0005", "Defense Evasion"
    ),
    # === Credential Access (TA0006) ===
    "T1110": TechniqueMetadata("T1110", "Brute Force", "TA0006", "Credential Access"),
    "T1110.001": TechniqueMetadata(
        "T1110.001", "Brute Force: Password Guessing", "TA0006", "Credential Access"
    ),
    "T1110.003": TechniqueMetadata(
        "T1110.003", "Brute Force: Password Spraying", "TA0006", "Credential Access"
    ),
    "T1110.004": TechniqueMetadata(
        "T1110.004", "Brute Force: Credential Stuffing", "TA0006", "Credential Access"
    ),
    "T1212": TechniqueMetadata(
        "T1212", "Exploitation for Credential Access", "TA0006", "Credential Access"
    ),
    "T1606": TechniqueMetadata(
        "T1606", "Forge Web Credentials", "TA0006", "Credential Access"
    ),
    "T1056": TechniqueMetadata("T1056", "Input Capture", "TA0006", "Credential Access"),
    "T1056.003": TechniqueMetadata(
        "T1056.003", "Input Capture: Web Portal Capture", "TA0006", "Credential Access"
    ),
    "T1056.004": TechniqueMetadata(
        "T1056.004",
        "Input Capture: Credential API Hooking",
        "TA0006",
        "Credential Access",
    ),
    "T1003": TechniqueMetadata(
        "T1003", "OS Credential Dumping", "TA0006", "Credential Access"
    ),
    "T1003.001": TechniqueMetadata(
        "T1003.001",
        "OS Credential Dumping: LSASS Memory",
        "TA0006",
        "Credential Access",
    ),
    "T1003.003": TechniqueMetadata(
        "T1003.003", "OS Credential Dumping: NTDS", "TA0006", "Credential Access"
    ),
    "T1528": TechniqueMetadata(
        "T1528", "Steal Application Access Token", "TA0006", "Credential Access"
    ),
    "T1552": TechniqueMetadata(
        "T1552", "Unsecured Credentials", "TA0006", "Credential Access"
    ),
    "T1552.001": TechniqueMetadata(
        "T1552.001",
        "Unsecured Credentials: Credentials In Files",
        "TA0006",
        "Credential Access",
    ),
    "T1552.005": TechniqueMetadata(
        "T1552.005",
        "Unsecured Credentials: Cloud Instance Metadata API",
        "TA0006",
        "Credential Access",
    ),
    # === Discovery (TA0007) ===
    "T1087": TechniqueMetadata("T1087", "Account Discovery", "TA0007", "Discovery"),
    "T1087.004": TechniqueMetadata(
        "T1087.004", "Account Discovery: Cloud Account", "TA0007", "Discovery"
    ),
    "T1580": TechniqueMetadata(
        "T1580", "Cloud Infrastructure Discovery", "TA0007", "Discovery"
    ),
    "T1526": TechniqueMetadata(
        "T1526", "Cloud Service Discovery", "TA0007", "Discovery"
    ),
    "T1046": TechniqueMetadata(
        "T1046", "Network Service Discovery", "TA0007", "Discovery"
    ),
    "T1040": TechniqueMetadata("T1040", "Network Sniffing", "TA0007", "Discovery"),
    "T1057": TechniqueMetadata("T1057", "Process Discovery", "TA0007", "Discovery"),
    "T1018": TechniqueMetadata(
        "T1018", "Remote System Discovery", "TA0007", "Discovery"
    ),
    "T1082": TechniqueMetadata(
        "T1082", "System Information Discovery", "TA0007", "Discovery"
    ),
    "T1016": TechniqueMetadata(
        "T1016", "System Network Configuration Discovery", "TA0007", "Discovery"
    ),
    "T1049": TechniqueMetadata(
        "T1049", "System Network Connections Discovery", "TA0007", "Discovery"
    ),
    "T1033": TechniqueMetadata(
        "T1033", "System Owner/User Discovery", "TA0007", "Discovery"
    ),
    # === Lateral Movement (TA0008) ===
    "T1210": TechniqueMetadata(
        "T1210", "Exploitation of Remote Services", "TA0008", "Lateral Movement"
    ),
    "T1570": TechniqueMetadata(
        "T1570", "Lateral Tool Transfer", "TA0008", "Lateral Movement"
    ),
    "T1021": TechniqueMetadata(
        "T1021", "Remote Services", "TA0008", "Lateral Movement"
    ),
    "T1021.002": TechniqueMetadata(
        "T1021.002",
        "Remote Services: SMB/Windows Admin Shares",
        "TA0008",
        "Lateral Movement",
    ),
    "T1021.004": TechniqueMetadata(
        "T1021.004", "Remote Services: SSH", "TA0008", "Lateral Movement"
    ),
    "T1080": TechniqueMetadata(
        "T1080", "Taint Shared Content", "TA0008", "Lateral Movement"
    ),
    # === Collection (TA0009) ===
    "T1560": TechniqueMetadata(
        "T1560", "Archive Collected Data", "TA0009", "Collection"
    ),
    "T1119": TechniqueMetadata("T1119", "Automated Collection", "TA0009", "Collection"),
    "T1530": TechniqueMetadata(
        "T1530", "Data from Cloud Storage Object", "TA0009", "Collection"
    ),
    "T1213": TechniqueMetadata(
        "T1213", "Data from Information Repositories", "TA0009", "Collection"
    ),
    "T1213.003": TechniqueMetadata(
        "T1213.003",
        "Data from Information Repositories: Code Repositories",
        "TA0009",
        "Collection",
    ),
    # === Command and Control (TA0011) ===
    "T1071": TechniqueMetadata(
        "T1071", "Application Layer Protocol", "TA0011", "Command and Control"
    ),
    "T1071.001": TechniqueMetadata(
        "T1071.001",
        "Application Layer Protocol: Web Protocols",
        "TA0011",
        "Command and Control",
    ),
    "T1071.002": TechniqueMetadata(
        "T1071.002",
        "Application Layer Protocol: File Transfer Protocols",
        "TA0011",
        "Command and Control",
    ),
    "T1071.003": TechniqueMetadata(
        "T1071.003",
        "Application Layer Protocol: Mail Protocols",
        "TA0011",
        "Command and Control",
    ),
    "T1071.004": TechniqueMetadata(
        "T1071.004", "Application Layer Protocol: DNS", "TA0011", "Command and Control"
    ),
    "T1132": TechniqueMetadata(
        "T1132", "Data Encoding", "TA0011", "Command and Control"
    ),
    "T1132.001": TechniqueMetadata(
        "T1132.001", "Data Encoding: Standard Encoding", "TA0011", "Command and Control"
    ),
    "T1568": TechniqueMetadata(
        "T1568", "Dynamic Resolution", "TA0011", "Command and Control"
    ),
    "T1568.002": TechniqueMetadata(
        "T1568.002",
        "Dynamic Resolution: Domain Generation Algorithms",
        "TA0011",
        "Command and Control",
    ),
    "T1105": TechniqueMetadata(
        "T1105", "Ingress Tool Transfer", "TA0011", "Command and Control"
    ),
    "T1571": TechniqueMetadata(
        "T1571", "Non-Standard Port", "TA0011", "Command and Control"
    ),
    "T1572": TechniqueMetadata(
        "T1572", "Protocol Tunneling", "TA0011", "Command and Control"
    ),
    "T1090": TechniqueMetadata("T1090", "Proxy", "TA0011", "Command and Control"),
    "T1090.001": TechniqueMetadata(
        "T1090.001", "Proxy: Internal Proxy", "TA0011", "Command and Control"
    ),
    "T1090.002": TechniqueMetadata(
        "T1090.002", "Proxy: External Proxy", "TA0011", "Command and Control"
    ),
    "T1090.003": TechniqueMetadata(
        "T1090.003", "Proxy: Multi-hop Proxy", "TA0011", "Command and Control"
    ),
    "T1219": TechniqueMetadata(
        "T1219", "Remote Access Software", "TA0011", "Command and Control"
    ),
    # === Exfiltration (TA0010) ===
    "T1020": TechniqueMetadata(
        "T1020", "Automated Exfiltration", "TA0010", "Exfiltration"
    ),
    "T1030": TechniqueMetadata(
        "T1030", "Data Transfer Size Limits", "TA0010", "Exfiltration"
    ),
    "T1048": TechniqueMetadata(
        "T1048", "Exfiltration Over Alternative Protocol", "TA0010", "Exfiltration"
    ),
    "T1048.003": TechniqueMetadata(
        "T1048.003",
        "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
        "TA0010",
        "Exfiltration",
    ),
    "T1041": TechniqueMetadata(
        "T1041", "Exfiltration Over C2 Channel", "TA0010", "Exfiltration"
    ),
    "T1052": TechniqueMetadata(
        "T1052", "Exfiltration Over Physical Medium", "TA0010", "Exfiltration"
    ),
    "T1052.001": TechniqueMetadata(
        "T1052.001",
        "Exfiltration Over Physical Medium: Exfiltration over USB",
        "TA0010",
        "Exfiltration",
    ),
    "T1567": TechniqueMetadata(
        "T1567", "Exfiltration Over Web Service", "TA0010", "Exfiltration"
    ),
    "T1567.001": TechniqueMetadata(
        "T1567.001",
        "Exfiltration Over Web Service: Exfiltration to Code Repository",
        "TA0010",
        "Exfiltration",
    ),
    "T1567.002": TechniqueMetadata(
        "T1567.002",
        "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "TA0010",
        "Exfiltration",
    ),
    "T1029": TechniqueMetadata("T1029", "Scheduled Transfer", "TA0010", "Exfiltration"),
    "T1537": TechniqueMetadata(
        "T1537", "Transfer Data to Cloud Account", "TA0010", "Exfiltration"
    ),
    # === Impact (TA0040) ===
    "T1531": TechniqueMetadata("T1531", "Account Access Removal", "TA0040", "Impact"),
    "T1485": TechniqueMetadata("T1485", "Data Destruction", "TA0040", "Impact"),
    "T1486": TechniqueMetadata(
        "T1486", "Data Encrypted for Impact", "TA0040", "Impact"
    ),
    "T1565": TechniqueMetadata("T1565", "Data Manipulation", "TA0040", "Impact"),
    "T1565.001": TechniqueMetadata(
        "T1565.001", "Data Manipulation: Stored Data Manipulation", "TA0040", "Impact"
    ),
    "T1491": TechniqueMetadata("T1491", "Defacement", "TA0040", "Impact"),
    "T1491.001": TechniqueMetadata(
        "T1491.001", "Defacement: Internal Defacement", "TA0040", "Impact"
    ),
    "T1491.002": TechniqueMetadata(
        "T1491.002", "Defacement: External Defacement", "TA0040", "Impact"
    ),
    "T1561": TechniqueMetadata("T1561", "Disk Wipe", "TA0040", "Impact"),
    "T1499": TechniqueMetadata(
        "T1499", "Endpoint Denial of Service", "TA0040", "Impact"
    ),
    "T1495": TechniqueMetadata("T1495", "Firmware Corruption", "TA0040", "Impact"),
    "T1490": TechniqueMetadata("T1490", "Inhibit System Recovery", "TA0040", "Impact"),
    "T1498": TechniqueMetadata(
        "T1498", "Network Denial of Service", "TA0040", "Impact"
    ),
    "T1498.001": TechniqueMetadata(
        "T1498.001",
        "Network Denial of Service: Direct Network Flood",
        "TA0040",
        "Impact",
    ),
    "T1498.002": TechniqueMetadata(
        "T1498.002",
        "Network Denial of Service: Reflection Amplification",
        "TA0040",
        "Impact",
    ),
    "T1496": TechniqueMetadata("T1496", "Resource Hijacking", "TA0040", "Impact"),
    "T1489": TechniqueMetadata("T1489", "Service Stop", "TA0040", "Impact"),
}


def get_technique_metadata(technique_id: str) -> Optional[TechniqueMetadata]:
    """Get metadata for a MITRE ATT&CK technique.

    Args:
        technique_id: The technique ID (e.g., "T1204.002")

    Returns:
        TechniqueMetadata if found, None otherwise
    """
    return TECHNIQUE_METADATA.get(technique_id)
