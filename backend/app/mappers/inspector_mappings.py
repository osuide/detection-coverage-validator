"""AWS Inspector finding type to MITRE ATT&CK technique mappings.

Amazon Inspector identifies software vulnerabilities and unintended network
exposure. These map to exploitation-related MITRE techniques.

Confidence scores based on detection capability:
- 0.9+ : Direct detection of the technique
- 0.75 : Strong correlation/partial coverage
- 0.6  : Indirect correlation/minimal coverage
"""

# Inspector finding type to MITRE technique mappings
# Format: finding_type_pattern -> [(technique_id, confidence)]

INSPECTOR_MITRE_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # === Package Vulnerability Findings ===
    # CVE-based vulnerabilities in installed packages
    "PACKAGE_VULNERABILITY": [
        ("T1190", 0.85),  # Exploit Public-Facing Application
        ("T1203", 0.80),  # Exploitation for Client Execution
        ("T1210", 0.85),  # Exploitation of Remote Services
        ("T1211", 0.75),  # Exploitation for Defense Evasion
        ("T1212", 0.75),  # Exploitation for Credential Access
    ],
    # === Network Reachability Findings ===
    # Unintended network exposure
    "NETWORK_REACHABILITY": [
        ("T1190", 0.90),  # Exploit Public-Facing Application
        ("T1133", 0.85),  # External Remote Services
        ("T1021", 0.80),  # Remote Services
        ("T1046", 0.75),  # Network Service Discovery (detection of exposure)
    ],
    # === Code Vulnerability Findings ===
    # Lambda code security issues
    "CODE_VULNERABILITY": [
        ("T1059", 0.80),  # Command and Scripting Interpreter
        ("T1203", 0.85),  # Exploitation for Client Execution
        ("T1055", 0.70),  # Process Injection
    ],
}

# Category-level mappings for aggregated detection coverage
INSPECTOR_CATEGORY_MAPPINGS: dict[str, list[tuple[str, float]]] = {
    # EC2 Vulnerability Scanning
    "EC2-VulnerabilityScanning": [
        ("T1190", 0.90),  # Exploit Public-Facing Application
        ("T1210", 0.90),  # Exploitation of Remote Services
        ("T1203", 0.85),  # Exploitation for Client Execution
        ("T1211", 0.80),  # Exploitation for Defense Evasion
        ("T1212", 0.80),  # Exploitation for Credential Access
        ("T1133", 0.85),  # External Remote Services
        ("T1046", 0.75),  # Network Service Discovery
    ],
    # ECR Container Scanning
    "ECR-ContainerScanning": [
        ("T1190", 0.85),  # Exploit Public-Facing Application
        ("T1610", 0.80),  # Deploy Container
        ("T1203", 0.80),  # Exploitation for Client Execution
        ("T1525", 0.75),  # Implant Internal Image
    ],
    # Lambda Vulnerability Scanning
    "Lambda-VulnerabilityScanning": [
        ("T1190", 0.85),  # Exploit Public-Facing Application
        ("T1059", 0.80),  # Command and Scripting Interpreter
        ("T1203", 0.80),  # Exploitation for Client Execution
    ],
    # Lambda Code Scanning
    "Lambda-CodeScanning": [
        ("T1059", 0.85),  # Command and Scripting Interpreter
        ("T1203", 0.85),  # Exploitation for Client Execution
        ("T1055", 0.75),  # Process Injection
        ("T1027", 0.70),  # Obfuscated Files or Information
    ],
}


def get_mitre_techniques_for_inspector_finding(
    finding_type: str,
) -> list[tuple[str, float]]:
    """Get MITRE ATT&CK techniques for an Inspector finding type.

    Args:
        finding_type: The Inspector finding type (e.g., 'PACKAGE_VULNERABILITY')

    Returns:
        List of (technique_id, confidence) tuples
    """
    return INSPECTOR_MITRE_MAPPINGS.get(finding_type.upper(), [])


def get_mitre_techniques_for_inspector_category(
    category: str,
) -> list[tuple[str, float]]:
    """Get MITRE ATT&CK techniques for an Inspector detection category.

    Args:
        category: The Inspector category (e.g., 'EC2-VulnerabilityScanning')

    Returns:
        List of (technique_id, confidence) tuples
    """
    return INSPECTOR_CATEGORY_MAPPINGS.get(category, [])
