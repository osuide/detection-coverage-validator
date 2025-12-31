"""AWS Macie finding type to MITRE ATT&CK technique mappings.

Amazon Macie identifies sensitive data exposure and S3 security issues.
These map to data collection, exfiltration, and credential access techniques.

Confidence scores based on detection capability:
- 0.9+ : Direct detection of the technique
- 0.75 : Strong correlation/partial coverage
- 0.6  : Indirect correlation/minimal coverage
"""

# Macie finding type to MITRE technique mappings
# Format: finding_type_pattern -> [(technique_id, confidence)]

MACIE_MITRE_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # === Sensitive Data Findings ===
    # Credentials exposed in S3
    "SensitiveData:S3Object/Credentials": [
        ("T1552.001", 0.95),  # Unsecured Credentials: Credentials In Files
        ("T1552.005", 0.85),  # Unsecured Credentials: Cloud Instance Metadata API
        ("T1528", 0.85),  # Steal Application Access Token
        ("T1078.004", 0.80),  # Valid Accounts: Cloud Accounts
    ],
    # Financial data exposed in S3
    "SensitiveData:S3Object/Financial": [
        ("T1530", 0.95),  # Data from Cloud Storage Object
        ("T1119", 0.85),  # Automated Collection
        ("T1005", 0.80),  # Data from Local System
    ],
    # Personal information (PII) exposed in S3
    "SensitiveData:S3Object/Personal": [
        ("T1530", 0.95),  # Data from Cloud Storage Object
        ("T1119", 0.85),  # Automated Collection
        ("T1005", 0.80),  # Data from Local System
    ],
    # Custom identifier matches
    "SensitiveData:S3Object/CustomIdentifier": [
        ("T1530", 0.90),  # Data from Cloud Storage Object
        ("T1119", 0.80),  # Automated Collection
    ],
    # Multiple sensitive data types
    "SensitiveData:S3Object/Multiple": [
        ("T1530", 0.95),  # Data from Cloud Storage Object
        ("T1552.001", 0.85),  # Unsecured Credentials: Credentials In Files
        ("T1119", 0.85),  # Automated Collection
    ],
    # === Policy Findings (S3 Security) ===
    # Public access disabled at account level
    "Policy:IAMUser/S3BlockPublicAccessDisabled": [
        ("T1530", 0.85),  # Data from Cloud Storage Object (risk exposure)
        ("T1567", 0.75),  # Exfiltration Over Web Service
    ],
    # Bucket encryption disabled
    "Policy:IAMUser/S3BucketEncryptionDisabled": [
        ("T1530", 0.80),  # Data from Cloud Storage Object (risk exposure)
        ("T1565.001", 0.70),  # Data Manipulation: Stored Data Manipulation
    ],
    # Bucket is publicly accessible
    "Policy:IAMUser/S3BucketPublic": [
        ("T1530", 0.95),  # Data from Cloud Storage Object
        ("T1567", 0.85),  # Exfiltration Over Web Service
        ("T1537", 0.80),  # Transfer Data to Cloud Account
    ],
    # Bucket replicated to external account
    "Policy:IAMUser/S3BucketReplicatedExternally": [
        ("T1537", 0.95),  # Transfer Data to Cloud Account
        ("T1567", 0.85),  # Exfiltration Over Web Service
        ("T1530", 0.80),  # Data from Cloud Storage Object
    ],
    # Bucket shared with external account
    "Policy:IAMUser/S3BucketSharedExternally": [
        ("T1537", 0.90),  # Transfer Data to Cloud Account
        ("T1530", 0.85),  # Data from Cloud Storage Object
        ("T1567", 0.80),  # Exfiltration Over Web Service
    ],
}

# Category-level mappings for aggregated detection coverage
MACIE_CATEGORY_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # Automated Discovery
    "AutomatedDiscovery": [
        ("T1530", 0.95),  # Data from Cloud Storage Object
        ("T1552.001", 0.90),  # Unsecured Credentials: Credentials In Files
        ("T1119", 0.85),  # Automated Collection
        ("T1005", 0.80),  # Data from Local System
        ("T1567", 0.75),  # Exfiltration Over Web Service
    ],
    # S3 Security Posture
    "S3-SecurityPosture": [
        ("T1530", 0.90),  # Data from Cloud Storage Object
        ("T1537", 0.85),  # Transfer Data to Cloud Account
        ("T1567", 0.85),  # Exfiltration Over Web Service
        ("T1078.004", 0.75),  # Valid Accounts: Cloud Accounts
    ],
    # Credential Exposure Detection
    "CredentialExposure": [
        ("T1552.001", 0.95),  # Unsecured Credentials: Credentials In Files
        ("T1552.005", 0.90),  # Unsecured Credentials: Cloud Instance Metadata API
        ("T1528", 0.90),  # Steal Application Access Token
        ("T1078.004", 0.85),  # Valid Accounts: Cloud Accounts
        ("T1530", 0.80),  # Data from Cloud Storage Object
    ],
    # PII Exposure Detection
    "PIIExposure": [
        ("T1530", 0.95),  # Data from Cloud Storage Object
        ("T1119", 0.90),  # Automated Collection
        ("T1005", 0.85),  # Data from Local System
    ],
    # Financial Data Exposure Detection
    "FinancialDataExposure": [
        ("T1530", 0.95),  # Data from Cloud Storage Object
        ("T1119", 0.90),  # Automated Collection
        ("T1005", 0.85),  # Data from Local System
    ],
}


def get_mitre_techniques_for_macie_finding(
    finding_type: str,
) -> list[tuple[str, float]]:
    """Get MITRE ATT&CK techniques for a Macie finding type.

    Args:
        finding_type: The Macie finding type (e.g., 'SensitiveData:S3Object/Credentials')

    Returns:
        List of (technique_id, confidence) tuples
    """
    return MACIE_MITRE_MAPPINGS.get(finding_type, [])


def get_mitre_techniques_for_macie_category(
    category: str,
) -> list[tuple[str, float]]:
    """Get MITRE ATT&CK techniques for a Macie detection category.

    Args:
        category: The Macie category (e.g., 'CredentialExposure')

    Returns:
        List of (technique_id, confidence) tuples
    """
    return MACIE_CATEGORY_MAPPINGS.get(category, [])
