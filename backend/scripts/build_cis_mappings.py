#!/usr/bin/env python3
"""Build comprehensive CIS Controls v8 mappings.

CIS Controls v8 has 18 top-level controls and 153 safeguards.
Mappings are based on CIS official ATT&CK v8.2 mappings.

Sources:
- CIS Controls: https://www.cisecurity.org/controls/v8
- CIS ATT&CK Mapping: https://www.cisecurity.org/controls/cis-controls-navigator
"""

import json
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "app" / "data" / "compliance_mappings"

# CIS Controls v8 complete structure with safeguards and ATT&CK mappings
# Based on CIS official documentation and ATT&CK v8.2 mapping
CIS_CONTROLS = [
    # Control 1: Inventory and Control of Enterprise Assets
    {
        "control_id": "1",
        "name": "Inventory and Control of Enterprise Assets",
        "safeguards": [
            {
                "id": "1.1",
                "name": "Establish and Maintain Detailed Enterprise Asset Inventory",
                "techniques": ["T1580", "T1526"],
                "ig": 1,
            },
            {
                "id": "1.2",
                "name": "Address Unauthorised Assets",
                "techniques": ["T1580", "T1526", "T1200"],
                "ig": 1,
            },
            {
                "id": "1.3",
                "name": "Utilise an Active Discovery Tool",
                "techniques": ["T1580", "T1046"],
                "ig": 2,
            },
            {
                "id": "1.4",
                "name": "Use Dynamic Host Configuration Protocol (DHCP) Logging",
                "techniques": ["T1200", "T1557"],
                "ig": 2,
            },
            {
                "id": "1.5",
                "name": "Use a Passive Asset Discovery Tool",
                "techniques": ["T1580", "T1046"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": ["Config", "Systems Manager", "EC2", "Resource Groups"],
            "gcp_services": [
                "Cloud Asset Inventory",
                "Compute Engine",
                "Resource Manager",
            ],
            "shared_responsibility": "customer",
        },
    },
    # Control 2: Inventory and Control of Software Assets
    {
        "control_id": "2",
        "name": "Inventory and Control of Software Assets",
        "safeguards": [
            {
                "id": "2.1",
                "name": "Establish and Maintain a Software Inventory",
                "techniques": ["T1072", "T1505"],
                "ig": 1,
            },
            {
                "id": "2.2",
                "name": "Ensure Authorised Software is Currently Supported",
                "techniques": ["T1072", "T1190"],
                "ig": 1,
            },
            {
                "id": "2.3",
                "name": "Address Unauthorised Software",
                "techniques": ["T1072", "T1505", "T1204"],
                "ig": 1,
            },
            {
                "id": "2.4",
                "name": "Utilise Automated Software Inventory Tools",
                "techniques": ["T1072"],
                "ig": 2,
            },
            {
                "id": "2.5",
                "name": "Allowlist Authorised Software",
                "techniques": ["T1204", "T1059", "T1072"],
                "ig": 2,
            },
            {
                "id": "2.6",
                "name": "Allowlist Authorised Libraries",
                "techniques": ["T1574", "T1055"],
                "ig": 2,
            },
            {
                "id": "2.7",
                "name": "Allowlist Authorised Scripts",
                "techniques": ["T1059", "T1204"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": ["Systems Manager", "Inspector", "ECR"],
            "gcp_services": ["Artifact Registry", "Cloud Build", "Container Analysis"],
            "shared_responsibility": "customer",
        },
    },
    # Control 3: Data Protection
    {
        "control_id": "3",
        "name": "Data Protection",
        "safeguards": [
            {
                "id": "3.1",
                "name": "Establish and Maintain a Data Management Process",
                "techniques": [],  # Administrative process - validated via documentation review
                "ig": 1,
                "cloud_applicability": "informational",
            },
            {
                "id": "3.2",
                "name": "Establish and Maintain a Data Inventory",
                "techniques": [],  # Administrative process - validated via documentation review
                "ig": 1,
                "cloud_applicability": "informational",
            },
            {
                "id": "3.3",
                "name": "Configure Data Access Control Lists",
                "techniques": ["T1530", "T1537", "T1039"],
                "ig": 1,
            },
            {
                "id": "3.4",
                "name": "Enforce Data Retention",
                "techniques": ["T1485", "T1490"],
                "ig": 1,
            },
            {
                "id": "3.5",
                "name": "Securely Dispose of Data",
                "techniques": ["T1485"],
                "ig": 1,
            },
            {
                "id": "3.6",
                "name": "Encrypt Data on End-User Devices",
                "techniques": ["T1005", "T1025"],
                "ig": 1,
            },
            {
                "id": "3.7",
                "name": "Establish and Maintain a Data Classification Scheme",
                "techniques": [],  # Administrative process - validated via documentation review
                "ig": 2,
                "cloud_applicability": "informational",
            },
            {
                "id": "3.8",
                "name": "Document Data Flows",
                "techniques": [],  # Administrative process - validated via documentation review
                "ig": 2,
                "cloud_applicability": "informational",
            },
            {
                "id": "3.9",
                "name": "Encrypt Data on Removable Media",
                "techniques": ["T1025", "T1052"],
                "ig": 2,
            },
            {
                "id": "3.10",
                "name": "Encrypt Sensitive Data in Transit",
                "techniques": ["T1040", "T1557", "T1565"],
                "ig": 2,
            },
            {
                "id": "3.11",
                "name": "Encrypt Sensitive Data at Rest",
                "techniques": ["T1530", "T1005"],
                "ig": 2,
            },
            {
                "id": "3.12",
                "name": "Segment Data Processing and Storage Based on Sensitivity",
                "techniques": ["T1530", "T1537"],
                "ig": 2,
            },
            {
                "id": "3.13",
                "name": "Deploy a Data Loss Prevention Solution",
                "techniques": ["T1048", "T1567", "T1041"],
                "ig": 3,
            },
            {
                "id": "3.14",
                "name": "Log Sensitive Data Access",
                "techniques": ["T1530", "T1213"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": ["S3", "KMS", "Macie", "EBS Encryption", "RDS Encryption"],
            "gcp_services": ["Cloud Storage", "Cloud KMS", "DLP API", "BigQuery"],
            "shared_responsibility": "customer",
        },
    },
    # Control 4: Secure Configuration of Enterprise Assets and Software
    {
        "control_id": "4",
        "name": "Secure Configuration of Enterprise Assets and Software",
        "safeguards": [
            {
                "id": "4.1",
                "name": "Establish and Maintain a Secure Configuration Process",
                "techniques": [],  # Administrative process - validated via documentation review
                "ig": 1,
                "cloud_applicability": "informational",
            },
            {
                "id": "4.2",
                "name": "Establish and Maintain a Secure Configuration Process for Network Infrastructure",
                "techniques": ["T1190", "T1021"],
                "ig": 1,
            },
            {
                "id": "4.3",
                "name": "Configure Automatic Session Locking on Enterprise Assets",
                "techniques": ["T1078"],
                "ig": 1,
            },
            {
                "id": "4.4",
                "name": "Implement and Manage a Firewall on Servers",
                "techniques": ["T1190", "T1021", "T1071"],
                "ig": 1,
            },
            {
                "id": "4.5",
                "name": "Implement and Manage a Firewall on End-User Devices",
                "techniques": ["T1071", "T1021"],
                "ig": 1,
            },
            {
                "id": "4.6",
                "name": "Securely Manage Enterprise Assets and Software",
                "techniques": ["T1021", "T1570"],
                "ig": 1,
            },
            {
                "id": "4.7",
                "name": "Manage Default Accounts on Enterprise Assets and Software",
                "techniques": ["T1078.001"],
                "ig": 1,
            },
            {
                "id": "4.8",
                "name": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software",
                "techniques": ["T1190", "T1543"],
                "ig": 2,
            },
            {
                "id": "4.9",
                "name": "Configure Trusted DNS Servers on Enterprise Assets",
                "techniques": ["T1071.004", "T1568"],
                "ig": 2,
            },
            {
                "id": "4.10",
                "name": "Enforce Automatic Device Lockout on Portable End-User Devices",
                "techniques": ["T1078"],
                "ig": 2,
            },
            {
                "id": "4.11",
                "name": "Enforce Remote Wipe Capability on Portable End-User Devices",
                "techniques": ["T1078"],
                "ig": 2,
            },
            {
                "id": "4.12",
                "name": "Separate Enterprise Workspaces on Mobile End-User Devices",
                "techniques": ["T1078"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": [
                "Config",
                "Security Hub",
                "Firewall Manager",
                "Security Groups",
            ],
            "gcp_services": [
                "Security Command Center",
                "Firewall Rules",
                "Organization Policy",
            ],
            "shared_responsibility": "customer",
        },
    },
    # Control 5: Account Management
    {
        "control_id": "5",
        "name": "Account Management",
        "safeguards": [
            {
                "id": "5.1",
                "name": "Establish and Maintain an Inventory of Accounts",
                "techniques": ["T1078", "T1136"],
                "ig": 1,
            },
            {
                "id": "5.2",
                "name": "Use Unique Passwords",
                "techniques": ["T1110", "T1078"],
                "ig": 1,
            },
            {
                "id": "5.3",
                "name": "Disable Dormant Accounts",
                "techniques": ["T1078"],
                "ig": 1,
            },
            {
                "id": "5.4",
                "name": "Restrict Administrator Privileges to Dedicated Administrator Accounts",
                "techniques": ["T1078.004", "T1098"],
                "ig": 1,
            },
            {
                "id": "5.5",
                "name": "Establish and Maintain an Inventory of Service Accounts",
                "techniques": ["T1078.001", "T1136.001"],
                "ig": 2,
            },
            {
                "id": "5.6",
                "name": "Centralise Account Management",
                "techniques": ["T1078", "T1136"],
                "ig": 2,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": ["IAM", "Organizations", "SSO", "Cognito"],
            "gcp_services": ["Cloud IAM", "Cloud Identity", "Identity Platform"],
            "shared_responsibility": "customer",
        },
    },
    # Control 6: Access Control Management
    {
        "control_id": "6",
        "name": "Access Control Management",
        "safeguards": [
            {
                "id": "6.1",
                "name": "Establish an Access Granting Process",
                "techniques": ["T1098", "T1078"],
                "ig": 1,
            },
            {
                "id": "6.2",
                "name": "Establish an Access Revoking Process",
                "techniques": ["T1098", "T1078"],
                "ig": 1,
            },
            {
                "id": "6.3",
                "name": "Require MFA for Externally-Exposed Applications",
                "techniques": ["T1078", "T1110"],
                "ig": 1,
            },
            {
                "id": "6.4",
                "name": "Require MFA for Remote Network Access",
                "techniques": ["T1078", "T1110", "T1133"],
                "ig": 1,
            },
            {
                "id": "6.5",
                "name": "Require MFA for Administrative Access",
                "techniques": ["T1078.004", "T1110"],
                "ig": 1,
            },
            {
                "id": "6.6",
                "name": "Establish and Maintain an Inventory of Authentication and Authorisation Systems",
                "techniques": ["T1078", "T1556"],
                "ig": 2,
            },
            {
                "id": "6.7",
                "name": "Centralise Access Control",
                "techniques": ["T1078", "T1098"],
                "ig": 2,
            },
            {
                "id": "6.8",
                "name": "Define and Maintain Role-Based Access Control",
                "techniques": ["T1078", "T1098"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": ["IAM", "SSO", "Cognito", "Organizations"],
            "gcp_services": ["Cloud IAM", "Identity Platform", "BeyondCorp"],
            "shared_responsibility": "customer",
        },
    },
    # Control 7: Continuous Vulnerability Management
    {
        "control_id": "7",
        "name": "Continuous Vulnerability Management",
        "safeguards": [
            {
                "id": "7.1",
                "name": "Establish and Maintain a Vulnerability Management Process",
                "techniques": ["T1190", "T1203"],
                "ig": 1,
            },
            {
                "id": "7.2",
                "name": "Establish and Maintain a Remediation Process",
                "techniques": ["T1190", "T1203"],
                "ig": 1,
            },
            {
                "id": "7.3",
                "name": "Perform Automated Operating System Patch Management",
                "techniques": ["T1190", "T1203", "T1068"],
                "ig": 1,
            },
            {
                "id": "7.4",
                "name": "Perform Automated Application Patch Management",
                "techniques": ["T1190", "T1203", "T1068"],
                "ig": 1,
            },
            {
                "id": "7.5",
                "name": "Perform Automated Vulnerability Scans of Internal Enterprise Assets",
                "techniques": ["T1190", "T1046"],
                "ig": 2,
            },
            {
                "id": "7.6",
                "name": "Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets",
                "techniques": ["T1190", "T1595"],
                "ig": 2,
            },
            {
                "id": "7.7",
                "name": "Remediate Detected Vulnerabilities",
                "techniques": ["T1190", "T1068"],
                "ig": 2,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": [
                "Inspector",
                "Systems Manager Patch Manager",
                "Security Hub",
            ],
            "gcp_services": [
                "Security Command Center",
                "OS Config",
                "Container Analysis",
            ],
            "shared_responsibility": "customer",
        },
    },
    # Control 8: Audit Log Management
    {
        "control_id": "8",
        "name": "Audit Log Management",
        "safeguards": [
            {
                "id": "8.1",
                "name": "Establish and Maintain an Audit Log Management Process",
                "techniques": ["T1562.008", "T1070"],
                "ig": 1,
            },
            {
                "id": "8.2",
                "name": "Collect Audit Logs",
                "techniques": ["T1562.008", "T1070.001"],
                "ig": 1,
            },
            {
                "id": "8.3",
                "name": "Ensure Adequate Audit Log Storage",
                "techniques": ["T1562.008"],
                "ig": 1,
            },
            {
                "id": "8.4",
                "name": "Standardise Time Synchronisation",
                "techniques": ["T1070.006"],
                "ig": 2,
            },
            {
                "id": "8.5",
                "name": "Collect Detailed Audit Logs",
                "techniques": ["T1562.008", "T1070"],
                "ig": 2,
            },
            {
                "id": "8.6",
                "name": "Collect DNS Query Audit Logs",
                "techniques": ["T1071.004", "T1568"],
                "ig": 2,
            },
            {
                "id": "8.7",
                "name": "Collect URL Request Audit Logs",
                "techniques": ["T1071.001", "T1102"],
                "ig": 2,
            },
            {
                "id": "8.8",
                "name": "Collect Command-Line Audit Logs",
                "techniques": ["T1059"],
                "ig": 2,
            },
            {
                "id": "8.9",
                "name": "Centralise Audit Logs",
                "techniques": ["T1562.008", "T1070"],
                "ig": 2,
            },
            {
                "id": "8.10",
                "name": "Retain Audit Logs",
                "techniques": ["T1070"],
                "ig": 2,
            },
            {
                "id": "8.11",
                "name": "Conduct Audit Log Reviews",
                "techniques": ["T1078", "T1110"],
                "ig": 2,
            },
            {
                "id": "8.12",
                "name": "Collect Service Provider Logs",
                "techniques": ["T1562.008"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": [
                "CloudTrail",
                "CloudWatch Logs",
                "S3",
                "Athena",
                "OpenSearch",
            ],
            "gcp_services": [
                "Cloud Audit Logs",
                "Cloud Logging",
                "BigQuery",
                "Chronicle",
            ],
            "shared_responsibility": "customer",
        },
    },
    # Control 9: Email and Web Browser Protections
    {
        "control_id": "9",
        "name": "Email and Web Browser Protections",
        "safeguards": [
            {
                "id": "9.1",
                "name": "Ensure Use of Only Fully Supported Browsers and Email Clients",
                "techniques": ["T1189", "T1566"],
                "ig": 1,
            },
            {
                "id": "9.2",
                "name": "Use DNS Filtering Services",
                "techniques": ["T1071.004", "T1568", "T1189"],
                "ig": 1,
            },
            {
                "id": "9.3",
                "name": "Maintain and Enforce Network-Based URL Filters",
                "techniques": ["T1189", "T1566.002"],
                "ig": 2,
            },
            {
                "id": "9.4",
                "name": "Restrict Unnecessary or Unauthorised Browser and Email Client Extensions",
                "techniques": ["T1176", "T1189"],
                "ig": 2,
            },
            {
                "id": "9.5",
                "name": "Implement DMARC",
                "techniques": ["T1566", "T1534"],
                "ig": 2,
            },
            {
                "id": "9.6",
                "name": "Block Unnecessary File Types",
                "techniques": ["T1566.001", "T1204"],
                "ig": 2,
            },
            {
                "id": "9.7",
                "name": "Deploy and Maintain Email Server Anti-Malware Protections",
                "techniques": ["T1566.001", "T1204.002"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "moderately_relevant",
        "cloud_context": {
            "aws_services": ["Route 53 Resolver DNS Firewall", "WorkMail"],
            "gcp_services": ["Cloud DNS", "Workspace"],
            "shared_responsibility": "customer",
        },
    },
    # Control 10: Malware Defences
    {
        "control_id": "10",
        "name": "Malware Defences",
        "safeguards": [
            {
                "id": "10.1",
                "name": "Deploy and Maintain Anti-Malware Software",
                "techniques": ["T1204", "T1059", "T1105"],
                "ig": 1,
            },
            {
                "id": "10.2",
                "name": "Configure Automatic Anti-Malware Signature Updates",
                "techniques": ["T1204", "T1059"],
                "ig": 1,
            },
            {
                "id": "10.3",
                "name": "Disable Autorun and Autoplay for Removable Media",
                "techniques": ["T1091", "T1052"],
                "ig": 1,
            },
            {
                "id": "10.4",
                "name": "Configure Automatic Anti-Malware Scanning of Removable Media",
                "techniques": ["T1091", "T1052"],
                "ig": 2,
            },
            {
                "id": "10.5",
                "name": "Enable Anti-Exploitation Features",
                "techniques": ["T1068", "T1203"],
                "ig": 2,
            },
            {
                "id": "10.6",
                "name": "Centralise Anti-Malware Logging",
                "techniques": ["T1204", "T1059"],
                "ig": 2,
            },
            {
                "id": "10.7",
                "name": "Use Behaviour-Based Anti-Malware Software",
                "techniques": ["T1059", "T1204", "T1055"],
                "ig": 2,
            },
        ],
        "cloud_applicability": "moderately_relevant",
        "cloud_context": {
            "aws_services": ["GuardDuty", "Inspector"],
            "gcp_services": ["Security Command Center", "Chronicle"],
            "shared_responsibility": "shared",
        },
    },
    # Control 11: Data Recovery
    {
        "control_id": "11",
        "name": "Data Recovery",
        "safeguards": [
            {
                "id": "11.1",
                "name": "Establish and Maintain a Data Recovery Process",
                "techniques": ["T1490", "T1485"],
                "ig": 1,
            },
            {
                "id": "11.2",
                "name": "Perform Automated Backups",
                "techniques": ["T1490", "T1485", "T1486"],
                "ig": 1,
            },
            {
                "id": "11.3",
                "name": "Protect Recovery Data",
                "techniques": ["T1490", "T1485"],
                "ig": 1,
            },
            {
                "id": "11.4",
                "name": "Establish and Maintain an Isolated Instance of Recovery Data",
                "techniques": ["T1490", "T1486"],
                "ig": 1,
            },
            {
                "id": "11.5",
                "name": "Test Data Recovery",
                "techniques": ["T1490"],
                "ig": 2,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": [
                "Backup",
                "S3",
                "RDS Snapshots",
                "EBS Snapshots",
                "Glacier",
            ],
            "gcp_services": [
                "Cloud Storage",
                "Persistent Disk Snapshots",
                "Cloud SQL Backups",
            ],
            "shared_responsibility": "customer",
        },
    },
    # Control 12: Network Infrastructure Management
    {
        "control_id": "12",
        "name": "Network Infrastructure Management",
        "safeguards": [
            {
                "id": "12.1",
                "name": "Ensure Network Infrastructure is Up-to-Date",
                "techniques": ["T1190", "T1040"],
                "ig": 1,
            },
            {
                "id": "12.2",
                "name": "Establish and Maintain a Secure Network Architecture",
                "techniques": ["T1046", "T1557"],
                "ig": 2,
            },
            {
                "id": "12.3",
                "name": "Securely Manage Network Infrastructure",
                "techniques": ["T1021", "T1557"],
                "ig": 2,
            },
            {
                "id": "12.4",
                "name": "Establish and Maintain Architecture Diagram(s)",
                "techniques": [],  # Administrative process - validated via documentation review
                "ig": 2,
                "cloud_applicability": "informational",
            },
            {
                "id": "12.5",
                "name": "Centralise Network Authentication, Authorisation, and Auditing (AAA)",
                "techniques": ["T1078", "T1021"],
                "ig": 2,
            },
            {
                "id": "12.6",
                "name": "Use of Secure Network Management and Communication Protocols",
                "techniques": ["T1557", "T1040"],
                "ig": 2,
            },
            {
                "id": "12.7",
                "name": "Ensure Remote Devices Utilise a VPN and are Connecting to an Enterprise's AAA Infrastructure",
                "techniques": ["T1133", "T1021"],
                "ig": 2,
            },
            {
                "id": "12.8",
                "name": "Establish and Maintain Dedicated Computing Resources for All Administrative Work",
                "techniques": ["T1078.004"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": ["VPC", "Transit Gateway", "Direct Connect", "Client VPN"],
            "gcp_services": [
                "VPC",
                "Cloud Interconnect",
                "Cloud VPN",
                "Network Connectivity Center",
            ],
            "shared_responsibility": "customer",
        },
    },
    # Control 13: Network Monitoring and Defence
    {
        "control_id": "13",
        "name": "Network Monitoring and Defence",
        "safeguards": [
            {
                "id": "13.1",
                "name": "Centralise Security Event Alerting",
                "techniques": ["T1562", "T1040"],
                "ig": 1,
            },
            {
                "id": "13.2",
                "name": "Deploy a Host-Based Intrusion Detection Solution",
                "techniques": ["T1055", "T1059"],
                "ig": 2,
            },
            {
                "id": "13.3",
                "name": "Deploy a Network Intrusion Detection Solution",
                "techniques": ["T1040", "T1046"],
                "ig": 2,
            },
            {
                "id": "13.4",
                "name": "Perform Traffic Filtering Between Network Segments",
                "techniques": ["T1046", "T1021", "T1071"],
                "ig": 2,
            },
            {
                "id": "13.5",
                "name": "Manage Access Control for Remote Assets",
                "techniques": ["T1133", "T1021"],
                "ig": 2,
            },
            {
                "id": "13.6",
                "name": "Collect Network Traffic Flow Logs",
                "techniques": ["T1046", "T1071", "T1048"],
                "ig": 2,
            },
            {
                "id": "13.7",
                "name": "Deploy a Host-Based Intrusion Prevention Solution",
                "techniques": ["T1055", "T1059"],
                "ig": 3,
            },
            {
                "id": "13.8",
                "name": "Deploy a Network Intrusion Prevention Solution",
                "techniques": ["T1046", "T1190"],
                "ig": 3,
            },
            {
                "id": "13.9",
                "name": "Deploy Port-Level Access Control",
                "techniques": ["T1046", "T1200"],
                "ig": 3,
            },
            {
                "id": "13.10",
                "name": "Perform Application Layer Filtering",
                "techniques": ["T1071", "T1102"],
                "ig": 3,
            },
            {
                "id": "13.11",
                "name": "Tune Security Event Alerting Thresholds",
                "techniques": ["T1562"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "highly_relevant",
        "cloud_context": {
            "aws_services": [
                "GuardDuty",
                "VPC Flow Logs",
                "Network Firewall",
                "WAF",
                "Security Hub",
            ],
            "gcp_services": [
                "Cloud IDS",
                "VPC Flow Logs",
                "Cloud Armor",
                "Security Command Center",
            ],
            "shared_responsibility": "customer",
        },
    },
    # Control 14: Security Awareness and Skills Training
    {
        "control_id": "14",
        "name": "Security Awareness and Skills Training",
        "safeguards": [
            {
                "id": "14.1",
                "name": "Establish and Maintain a Security Awareness Programme",
                "techniques": ["T1566", "T1204"],
                "ig": 1,
            },
            {
                "id": "14.2",
                "name": "Train Workforce Members to Recognise Social Engineering Attacks",
                "techniques": ["T1566", "T1534"],
                "ig": 1,
            },
            {
                "id": "14.3",
                "name": "Train Workforce Members on Authentication Best Practices",
                "techniques": ["T1078", "T1110"],
                "ig": 1,
            },
            {
                "id": "14.4",
                "name": "Train Workforce Members on Data Handling Best Practices",
                "techniques": ["T1530", "T1567"],
                "ig": 1,
            },
            {
                "id": "14.5",
                "name": "Train Workforce Members on Causes of Unintentional Data Exposure",
                "techniques": ["T1530", "T1537"],
                "ig": 1,
            },
            {
                "id": "14.6",
                "name": "Train Workforce Members on Recognising and Reporting Security Incidents",
                "techniques": ["T1566"],
                "ig": 1,
            },
            {
                "id": "14.7",
                "name": "Train Workforce Members on How to Identify and Report if Their Enterprise Assets are Missing Security Updates",
                "techniques": ["T1190"],
                "ig": 2,
            },
            {
                "id": "14.8",
                "name": "Train Workforce Members on the Dangers of Connecting to and Transmitting Enterprise Data Over Insecure Networks",
                "techniques": ["T1557", "T1040"],
                "ig": 2,
            },
            {
                "id": "14.9",
                "name": "Conduct Role-Specific Security Awareness and Skills Training",
                "techniques": ["T1566", "T1078"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "informational",
        "cloud_context": {
            "aws_services": [],
            "gcp_services": [],
            "shared_responsibility": "customer",
        },
    },
    # Control 15: Service Provider Management
    {
        "control_id": "15",
        "name": "Service Provider Management",
        "safeguards": [
            {
                "id": "15.1",
                "name": "Establish and Maintain an Inventory of Service Providers",
                "techniques": ["T1199", "T1195"],
                "ig": 1,
            },
            {
                "id": "15.2",
                "name": "Establish and Maintain a Service Provider Management Policy",
                "techniques": ["T1199"],
                "ig": 2,
            },
            {
                "id": "15.3",
                "name": "Classify Service Providers",
                "techniques": ["T1199"],
                "ig": 2,
            },
            {
                "id": "15.4",
                "name": "Ensure Service Provider Contracts Include Security Requirements",
                "techniques": ["T1199"],
                "ig": 2,
            },
            {
                "id": "15.5",
                "name": "Assess Service Providers",
                "techniques": ["T1199", "T1195"],
                "ig": 3,
            },
            {
                "id": "15.6",
                "name": "Monitor Service Providers",
                "techniques": ["T1199"],
                "ig": 3,
            },
            {
                "id": "15.7",
                "name": "Securely Decommission Service Providers",
                "techniques": ["T1199"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "moderately_relevant",
        "cloud_context": {
            "aws_services": ["Organizations", "Service Catalog", "Control Tower"],
            "gcp_services": ["Resource Manager", "Organization Policy"],
            "shared_responsibility": "customer",
        },
    },
    # Control 16: Application Software Security
    {
        "control_id": "16",
        "name": "Application Software Security",
        "safeguards": [
            {
                "id": "16.1",
                "name": "Establish and Maintain a Secure Application Development Process",
                "techniques": ["T1190", "T1059"],
                "ig": 1,
            },
            {
                "id": "16.2",
                "name": "Establish and Maintain a Process to Accept and Address Software Vulnerabilities",
                "techniques": ["T1190"],
                "ig": 1,
            },
            {
                "id": "16.3",
                "name": "Perform Root Cause Analysis on Security Vulnerabilities",
                "techniques": [],  # Administrative process - validated via incident records review
                "ig": 2,
                "cloud_applicability": "informational",
            },
            {
                "id": "16.4",
                "name": "Establish and Manage an Inventory of Third-Party Software Components",
                "techniques": ["T1195.002"],
                "ig": 2,
            },
            {
                "id": "16.5",
                "name": "Use Up-to-Date and Trusted Third-Party Software Components",
                "techniques": ["T1195.002"],
                "ig": 2,
            },
            {
                "id": "16.6",
                "name": "Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities",
                "techniques": [],  # Administrative process - validated via documentation review
                "ig": 2,
                "cloud_applicability": "informational",
            },
            {
                "id": "16.7",
                "name": "Use Standard Hardening Configuration Templates for Application Infrastructure",
                "techniques": ["T1190"],
                "ig": 2,
            },
            {
                "id": "16.8",
                "name": "Separate Production and Non-Production Systems",
                "techniques": [],  # Administrative control - environment separation validated via architecture review, not log detection
                "ig": 2,
                "cloud_applicability": "informational",
            },
            {
                "id": "16.9",
                "name": "Train Developers in Application Security Concepts and Secure Coding",
                "techniques": [],  # Training is administrative - validated via completion records
                "ig": 2,
                "cloud_applicability": "informational",
            },
            {
                "id": "16.10",
                "name": "Apply Secure Design Principles in Application Architectures",
                "techniques": ["T1190"],
                "ig": 2,
            },
            {
                "id": "16.11",
                "name": "Leverage Vetted Modules or Services for Application Security Components",
                "techniques": ["T1195.002"],
                "ig": 2,
            },
            {
                "id": "16.12",
                "name": "Implement Code-Level Security Checks",
                "techniques": ["T1190", "T1059"],
                "ig": 3,
            },
            {
                "id": "16.13",
                "name": "Conduct Application Penetration Testing",
                "techniques": ["T1190"],
                "ig": 3,
            },
            {
                "id": "16.14",
                "name": "Conduct Threat Modelling",
                "techniques": [],  # Administrative process - validated via documentation review
                "ig": 3,
                "cloud_applicability": "informational",
            },
        ],
        "cloud_applicability": "moderately_relevant",
        "cloud_context": {
            "aws_services": ["CodePipeline", "CodeBuild", "Inspector", "ECR"],
            "gcp_services": ["Cloud Build", "Container Analysis", "Artifact Registry"],
            "shared_responsibility": "customer",
        },
    },
    # Control 17: Incident Response Management
    {
        "control_id": "17",
        "name": "Incident Response Management",
        "safeguards": [
            {
                "id": "17.1",
                "name": "Designate Personnel to Manage Incident Handling",
                "techniques": [],
                "ig": 1,
            },
            {
                "id": "17.2",
                "name": "Establish and Maintain Contact Information for Reporting Security Incidents",
                "techniques": [],
                "ig": 1,
            },
            {
                "id": "17.3",
                "name": "Establish and Maintain an Enterprise Process for Reporting Incidents",
                "techniques": [],
                "ig": 1,
            },
            {
                "id": "17.4",
                "name": "Establish and Maintain an Incident Response Process",
                "techniques": [],
                "ig": 2,
            },
            {
                "id": "17.5",
                "name": "Assign Key Roles and Responsibilities",
                "techniques": [],
                "ig": 2,
            },
            {
                "id": "17.6",
                "name": "Define Mechanisms for Communicating During Incident Response",
                "techniques": [],
                "ig": 2,
            },
            {
                "id": "17.7",
                "name": "Conduct Routine Incident Response Exercises",
                "techniques": [],
                "ig": 2,
            },
            {
                "id": "17.8",
                "name": "Conduct Post-Incident Reviews",
                "techniques": [],
                "ig": 2,
            },
            {
                "id": "17.9",
                "name": "Establish and Maintain Security Incident Thresholds",
                "techniques": [],
                "ig": 3,
            },
        ],
        "cloud_applicability": "moderately_relevant",
        "cloud_context": {
            "aws_services": ["Security Hub", "Detective", "EventBridge", "Lambda"],
            "gcp_services": ["Security Command Center", "Cloud Functions", "Pub/Sub"],
            "shared_responsibility": "customer",
        },
    },
    # Control 18: Penetration Testing
    {
        "control_id": "18",
        "name": "Penetration Testing",
        "safeguards": [
            {
                "id": "18.1",
                "name": "Establish and Maintain a Penetration Testing Programme",
                "techniques": ["T1595"],
                "ig": 2,
            },
            {
                "id": "18.2",
                "name": "Perform Periodic External Penetration Tests",
                "techniques": ["T1595", "T1190"],
                "ig": 2,
            },
            {
                "id": "18.3",
                "name": "Remediate Penetration Test Findings",
                "techniques": ["T1190"],
                "ig": 2,
            },
            {
                "id": "18.4",
                "name": "Validate Security Measures",
                "techniques": ["T1190"],
                "ig": 3,
            },
            {
                "id": "18.5",
                "name": "Perform Periodic Internal Penetration Tests",
                "techniques": ["T1046"],
                "ig": 3,
            },
        ],
        "cloud_applicability": "moderately_relevant",
        "cloud_context": {
            "aws_services": ["Inspector"],
            "gcp_services": ["Security Command Center"],
            "shared_responsibility": "customer",
        },
    },
]


def build_cis_mappings() -> dict:
    """Build CIS Controls v8 mappings."""
    print("\n=== Building CIS Controls v8 Mappings ===\n")

    framework = {
        "framework_id": "cis-controls-v8",
        "name": "CIS Controls v8",
        "version": "8.0",
        "description": "CIS Critical Security Controls Version 8. The CIS Controls are a prioritised set of safeguards to mitigate the most prevalent cyber-attacks. Mappings based on CIS official ATT&CK v8.2 mapping.",
        "source_url": "https://www.cisecurity.org/controls/v8",
    }

    controls = []
    display_order = 0

    for control in CIS_CONTROLS:
        # Add top-level control
        top_level = {
            "control_id": control["control_id"],
            "control_family": control["name"],
            "name": control["name"],
            "description": f"CIS Control {control['control_id']}: {control['name']}",
            "priority": "P1" if int(control["control_id"]) <= 6 else "P2",
            "is_enhancement": False,
            "cloud_applicability": control["cloud_applicability"],
            "cloud_context": control["cloud_context"],
            "technique_mappings": [],
        }

        # Collect all techniques from safeguards
        all_techniques = set()
        for sg in control["safeguards"]:
            for t in sg.get("techniques", []):
                all_techniques.add(t)

        top_level["technique_mappings"] = [
            {"technique_id": t, "mapping_type": "mitigates"}
            for t in sorted(all_techniques)
        ]

        controls.append(top_level)
        display_order += 1

        # Add safeguards as sub-controls
        for sg in control["safeguards"]:
            # Use safeguard-level cloud_applicability if specified, otherwise inherit from parent
            sg_cloud_applicability = sg.get(
                "cloud_applicability", control["cloud_applicability"]
            )
            safeguard = {
                "control_id": sg["id"],
                "control_family": control["name"],
                "name": sg["name"],
                "description": f"CIS Safeguard {sg['id']}: {sg['name']} (IG{sg.get('ig', 1)})",
                "priority": (
                    "P1"
                    if sg.get("ig", 1) == 1
                    else ("P2" if sg.get("ig", 1) == 2 else "P3")
                ),
                "is_enhancement": True,
                "cloud_applicability": sg_cloud_applicability,
                "cloud_context": control["cloud_context"],
                "technique_mappings": [
                    {"technique_id": t, "mapping_type": "mitigates"}
                    for t in sg.get("techniques", [])
                ],
            }
            controls.append(safeguard)
            display_order += 1

    print(f"Total controls (including safeguards): {len(controls)}")

    # Count by type
    top_level_count = len([c for c in controls if not c["is_enhancement"]])
    safeguard_count = len([c for c in controls if c["is_enhancement"]])
    print(f"Top-level controls: {top_level_count}")
    print(f"Safeguards: {safeguard_count}")

    # Count techniques
    all_techniques = set()
    for c in controls:
        for t in c["technique_mappings"]:
            all_techniques.add(t["technique_id"])
    print(f"Unique techniques: {len(all_techniques)}")

    return {"framework": framework, "controls": controls}


def main():
    """Main entry point."""
    cis_data = build_cis_mappings()

    output_file = OUTPUT_DIR / "cis_controls_v8.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(cis_data, f, indent=2, ensure_ascii=False)

    print(f"\nWritten to: {output_file}")


if __name__ == "__main__":
    main()
