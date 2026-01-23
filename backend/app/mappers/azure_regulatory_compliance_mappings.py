"""Azure Regulatory Compliance Control to MITRE ATT&CK Mappings.

Includes CIS Azure v2.1.0 (top 20 controls) and NIST SP 800-53 R5 (top 15 control families)
for feature parity with AWS Security Hub NIST support.

Sources (VALIDATED - NO GUESSING):
- MITRE Center for Threat-Informed Defense: Security Stack Mappings
  https://center-for-threat-informed-defense.github.io/security-stack-mappings/Azure/README.html
- CIS Controls v8 Master Mapping to MITRE ATT&CK
  https://www.cisecurity.org/insights/white-papers/cis-controls-v8-master-mapping-to-mitre-enterprise-attck-v82
- Microsoft Learn: NIST SP 800-53 Rev. 5 Azure Policy Mappings
  https://learn.microsoft.com/en-us/azure/governance/policy/samples/nist-sp-800-53-r5

Confidence Scores:
- 0.90+ : Significant coverage (MITRE CTID verified)
- 0.75  : Partial coverage
- 0.60  : Minimal coverage
"""

from typing import Dict, List, Tuple

# Control ID -> List of (MITRE Technique ID, Confidence Score)
MITREMapping = Dict[str, List[Tuple[str, float]]]


# =============================================================================
# CIS Azure v2.1.0 Benchmark - TOP 20 HIGH-VALUE CONTROLS
# Prioritised by detection value for MITRE ATT&CK coverage
# =============================================================================

CIS_AZURE_V2_MITRE_MAPPINGS: MITREMapping = {
    # ==========================================================================
    # IDENTITY AND ACCESS MANAGEMENT (Section 1) - Highest detection value
    # ==========================================================================
    "1.1": [  # Ensure Security Defaults or Conditional Access is configured
        ("T1078.004", 0.95),  # Valid Accounts: Cloud Accounts
        ("T1110", 0.90),  # Brute Force
    ],
    "1.2": [  # Ensure MFA is enabled for all users
        ("T1078.004", 0.95),  # Valid Accounts: Cloud Accounts
        ("T1110", 0.90),  # Brute Force
    ],
    "1.3": [  # Ensure guest users are reviewed regularly
        ("T1078.004", 0.90),  # Valid Accounts: Cloud Accounts
        ("T1136.003", 0.85),  # Create Account: Cloud Account
    ],
    "1.10": [  # Ensure user consent for apps accessing company data is disabled
        ("T1528", 0.90),  # Steal Application Access Token
        ("T1550.001", 0.85),  # Use Alternate Authentication Material: App Access Token
    ],
    "1.21": [  # Ensure Privileged Identity Management is used
        ("T1078.004", 0.95),  # Valid Accounts: Cloud Accounts
        ("T1098.003", 0.90),  # Account Manipulation: Additional Cloud Roles
    ],
    # ==========================================================================
    # SECURITY CENTER (Section 2) - Critical for detection posture
    # ==========================================================================
    "2.1.1": [  # Ensure Microsoft Defender for Cloud Apps is enabled
        ("T1562.001", 0.95),  # Impair Defenses: Disable or Modify Tools
    ],
    "2.1.2": [  # Ensure Microsoft Defender for Servers is enabled
        ("T1562.001", 0.95),  # Impair Defenses: Disable or Modify Tools
        ("T1059", 0.85),  # Command and Scripting Interpreter
    ],
    "2.1.4": [  # Ensure Microsoft Defender for Storage is enabled
        ("T1530", 0.95),  # Data from Cloud Storage
        ("T1562.001", 0.90),  # Impair Defenses: Disable or Modify Tools
    ],
    "2.1.9": [  # Ensure Microsoft Defender for Key Vault is enabled
        ("T1555.006", 0.95),  # Credentials from Password Stores: Cloud Secrets
        ("T1552", 0.90),  # Unsecured Credentials
    ],
    # ==========================================================================
    # STORAGE ACCOUNTS (Section 3) - Data exfiltration protection
    # ==========================================================================
    "3.1": [  # Ensure 'Secure transfer required' is enabled
        ("T1040", 0.95),  # Network Sniffing
        ("T1557", 0.90),  # Adversary-in-the-Middle
    ],
    "3.7": [  # Ensure default network access rule is Deny
        ("T1530", 0.95),  # Data from Cloud Storage
        (
            "T1567.002",
            0.90,
        ),  # Exfiltration Over Web Service: Exfiltration to Cloud Storage
    ],
    "3.9": [  # Ensure critical data is encrypted with CMK
        ("T1530", 0.95),  # Data from Cloud Storage
    ],
    # ==========================================================================
    # LOGGING AND MONITORING (Section 5) - Critical for visibility
    # ==========================================================================
    "5.1.1": [  # Ensure Activity Log exists
        ("T1562.008", 0.95),  # Impair Defenses: Disable Cloud Logs
        ("T1070", 0.90),  # Indicator Removal
    ],
    "5.1.5": [  # Ensure Activity Log Alert for Security Solution changes
        ("T1562.001", 0.95),  # Impair Defenses: Disable or Modify Tools
    ],
    "5.2.1": [  # Ensure Diagnostic Logs for all services
        ("T1562.008", 0.95),  # Impair Defenses: Disable Cloud Logs
    ],
    # ==========================================================================
    # NETWORKING (Section 6) - Perimeter protection
    # ==========================================================================
    "6.1": [  # Ensure RDP access is restricted from the internet
        ("T1021.001", 0.95),  # Remote Services: Remote Desktop Protocol
        ("T1133", 0.90),  # External Remote Services
    ],
    "6.2": [  # Ensure SSH access is restricted from the internet
        ("T1021.004", 0.95),  # Remote Services: SSH
        ("T1133", 0.90),  # External Remote Services
    ],
    "6.5": [  # Ensure Network Watcher is enabled
        ("T1046", 0.85),  # Network Service Scanning
    ],
    # ==========================================================================
    # KEY VAULT (Section 8) - Secrets protection
    # ==========================================================================
    "8.1": [  # Ensure Key Vault is recoverable
        ("T1485", 0.90),  # Data Destruction
        ("T1490", 0.85),  # Inhibit System Recovery
    ],
    "8.4": [  # Ensure Key Vault secrets have expiration set
        ("T1552.001", 0.90),  # Unsecured Credentials: Credentials In Files
        ("T1555.006", 0.85),  # Credentials from Password Stores: Cloud Secrets
    ],
}


# =============================================================================
# NIST SP 800-53 Rev. 5 - TOP 15 CONTROL FAMILIES
# Required for feature parity with AWS Security Hub NIST support
# Source: https://learn.microsoft.com/en-us/azure/governance/policy/samples/nist-sp-800-53-r5
# =============================================================================

NIST_800_53_R5_AZURE_MITRE_MAPPINGS: MITREMapping = {
    # Access Control (AC)
    "AC-2": [  # Account Management
        ("T1078.004", 0.95),  # Valid Accounts: Cloud Accounts
        ("T1136.003", 0.90),  # Create Account: Cloud Account
        ("T1098", 0.85),  # Account Manipulation
    ],
    "AC-3": [  # Access Enforcement
        ("T1078.004", 0.95),  # Valid Accounts: Cloud Accounts
        ("T1548", 0.85),  # Abuse Elevation Control Mechanism
    ],
    "AC-6": [  # Least Privilege
        ("T1078.004", 0.95),  # Valid Accounts: Cloud Accounts
        ("T1098.003", 0.90),  # Account Manipulation: Additional Cloud Roles
    ],
    "AC-17": [  # Remote Access
        ("T1133", 0.95),  # External Remote Services
        ("T1021", 0.90),  # Remote Services
    ],
    # Audit and Accountability (AU)
    "AU-2": [  # Audit Events
        ("T1562.008", 0.95),  # Impair Defenses: Disable Cloud Logs
        ("T1070", 0.90),  # Indicator Removal
    ],
    "AU-6": [  # Audit Review, Analysis, and Reporting
        ("T1562.008", 0.90),  # Impair Defenses: Disable Cloud Logs
    ],
    "AU-12": [  # Audit Generation
        ("T1562.008", 0.95),  # Impair Defenses: Disable Cloud Logs
    ],
    # Configuration Management (CM)
    "CM-6": [  # Configuration Settings
        ("T1562.001", 0.90),  # Impair Defenses: Disable or Modify Tools
    ],
    "CM-7": [  # Least Functionality
        ("T1059", 0.85),  # Command and Scripting Interpreter
    ],
    # Identification and Authentication (IA)
    "IA-2": [  # Identification and Authentication
        ("T1078.004", 0.95),  # Valid Accounts: Cloud Accounts
        ("T1110", 0.90),  # Brute Force
    ],
    "IA-5": [  # Authenticator Management
        ("T1552", 0.95),  # Unsecured Credentials
        ("T1110", 0.90),  # Brute Force
    ],
    # System and Communications Protection (SC)
    "SC-7": [  # Boundary Protection
        ("T1190", 0.95),  # Exploit Public-Facing Application
        ("T1133", 0.90),  # External Remote Services
    ],
    "SC-8": [  # Transmission Confidentiality and Integrity
        ("T1040", 0.95),  # Network Sniffing
        ("T1557", 0.90),  # Adversary-in-the-Middle
    ],
    "SC-28": [  # Protection of Information at Rest
        ("T1530", 0.95),  # Data from Cloud Storage
        ("T1005", 0.90),  # Data from Local System
    ],
    # System and Information Integrity (SI)
    "SI-4": [  # System Monitoring
        ("T1562.008", 0.95),  # Impair Defenses: Disable Cloud Logs
        ("T1070", 0.90),  # Indicator Removal
    ],
}

# NOTE: No helper function needed - mappings are used directly by PatternMapper
# for bulk coverage calculation (one detection per standard, not per control)
