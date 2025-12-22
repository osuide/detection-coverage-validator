# Compliance Framework Mappings

This document describes the compliance framework mappings used in the Detection Coverage Validator, including data sources, coverage metrics, and cloud applicability metadata.

## Overview

The Detection Coverage Validator maps security detections to compliance framework controls through MITRE ATT&CK techniques. This enables organisations to:

- Measure compliance coverage based on actual detection capabilities
- Identify gaps in compliance posture
- Prioritise remediation based on cloud applicability
- Understand shared responsibility boundaries

## Supported Frameworks

### NIST 800-53 Rev 5

**Source:** [MITRE Center for Threat-Informed Defense (CTID)](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist/)

| Metric | Value |
|--------|-------|
| Controls with ATT&CK Mappings | 113 |
| Total Technique Mappings | 4,929 |
| Unique ATT&CK Techniques | 427 |
| ATT&CK Version | v12.1 |

#### Control Family Coverage

| Family | Code | Controls | Cloud Applicability |
|--------|------|----------|---------------------|
| Access Control | AC | 19 | Highly Relevant |
| Audit and Accountability | AU | 4 | Highly Relevant |
| Security Assessment and Authorisation | CA | 4 | Highly Relevant |
| Configuration Management | CM | 9 | Highly Relevant |
| Contingency Planning | CP | 5 | Moderately Relevant |
| Identification and Authentication | IA | 10 | Highly Relevant |
| Incident Response | IR | 1 | Highly Relevant |
| Media Protection | MP | 1 | Provider Responsibility |
| Risk Assessment | RA | 3 | Highly Relevant |
| System and Services Acquisition | SA | 10 | Moderately Relevant |
| System and Communications Protection | SC | 31 | Highly Relevant |
| System and Information Integrity | SI | 12 | Highly Relevant |
| Supply Chain Risk Management | SR | 4 | Moderately Relevant |

### CIS Controls v8

**Source:** [Center for Internet Security (CIS)](https://www.cisecurity.org/controls/v8)

| Metric | Value |
|--------|-------|
| Top-level Controls | 18 |
| Safeguards (Sub-controls) | 153 |
| Total Controls | 171 |
| Unique ATT&CK Techniques | 64 |
| ATT&CK Version | v8.2 |

#### Control Coverage

| Control | Name | Safeguards | Cloud Applicability |
|---------|------|------------|---------------------|
| 1 | Inventory and Control of Enterprise Assets | 5 | Highly Relevant |
| 2 | Inventory and Control of Software Assets | 7 | Highly Relevant |
| 3 | Data Protection | 14 | Highly Relevant |
| 4 | Secure Configuration of Enterprise Assets and Software | 12 | Highly Relevant |
| 5 | Account Management | 6 | Highly Relevant |
| 6 | Access Control Management | 8 | Highly Relevant |
| 7 | Continuous Vulnerability Management | 7 | Highly Relevant |
| 8 | Audit Log Management | 12 | Highly Relevant |
| 9 | Email and Web Browser Protections | 7 | Moderately Relevant |
| 10 | Malware Defences | 7 | Moderately Relevant |
| 11 | Data Recovery | 5 | Highly Relevant |
| 12 | Network Infrastructure Management | 8 | Highly Relevant |
| 13 | Network Monitoring and Defence | 11 | Highly Relevant |
| 14 | Security Awareness and Skills Training | 9 | Informational |
| 15 | Service Provider Management | 7 | Moderately Relevant |
| 16 | Application Software Security | 14 | Moderately Relevant |
| 17 | Incident Response Management | 9 | Moderately Relevant |
| 18 | Penetration Testing | 5 | Moderately Relevant |

## Cloud Applicability

Each control is classified by its relevance to cloud environments (AWS/GCP):

### Applicability Levels

| Level | Description | Example Controls |
|-------|-------------|------------------|
| **Highly Relevant** | Directly detectable via cloud APIs and services | AC-2 (Account Management), AU-2 (Audit Events), SC-7 (Boundary Protection) |
| **Moderately Relevant** | Partially applicable, may require adaptation | CP-9 (System Backup), SA-10 (Developer Configuration Management) |
| **Informational** | Not directly cloud-detectable, organisational process | AT-2 (Awareness Training), PS-3 (Personnel Screening) |
| **Provider Responsibility** | Managed by cloud provider (AWS/GCP) | PE-2 (Physical Access), MA-2 (Controlled Maintenance) |

### Cloud Context Metadata

Each control includes cloud context with:

```json
{
  "aws_services": ["IAM", "CloudTrail", "Config"],
  "gcp_services": ["Cloud IAM", "Cloud Audit Logs", "Asset Inventory"],
  "shared_responsibility": "customer"
}
```

#### Shared Responsibility Model

| Value | Description |
|-------|-------------|
| `customer` | Customer is responsible for implementation and monitoring |
| `shared` | Responsibility is shared between customer and provider |
| `provider` | Cloud provider is responsible (covered by provider certifications) |

## AWS Service Mappings

Controls are mapped to relevant AWS services for detection and monitoring:

| Control Area | AWS Services |
|--------------|--------------|
| Access Control | IAM, Organizations, SSO, STS, Cognito |
| Audit Logging | CloudTrail, CloudWatch Logs, S3, Athena |
| Configuration | Config, Systems Manager, CloudFormation |
| Network Security | VPC, Security Groups, NACLs, WAF, Network Firewall |
| Encryption | KMS, ACM, S3 Encryption, EBS Encryption |
| Threat Detection | GuardDuty, Security Hub, Inspector, Macie |
| Backup/Recovery | AWS Backup, S3, RDS Snapshots, EBS Snapshots |

## GCP Service Mappings

Controls are mapped to relevant GCP services:

| Control Area | GCP Services |
|--------------|--------------|
| Access Control | Cloud IAM, Identity Platform, Resource Manager |
| Audit Logging | Cloud Audit Logs, Cloud Logging, BigQuery, Chronicle |
| Configuration | Asset Inventory, Cloud Build, Deployment Manager |
| Network Security | VPC, Firewall Rules, Cloud Armor, Cloud IDS |
| Encryption | Cloud KMS, Customer-Managed Encryption Keys |
| Threat Detection | Security Command Center, Chronicle |
| Backup/Recovery | Cloud Storage, Persistent Disk Snapshots, Cloud SQL Backups |

## Data Sources

### MITRE CTID (NIST 800-53)

The NIST 800-53 mappings are sourced from the MITRE Center for Threat-Informed Defense:

- **Repository:** [attack-control-framework-mappings](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings)
- **Format:** STIX 2.0 JSON
- **Mapping Type:** Control → ATT&CK Technique (mitigates relationship)

### CIS Controls v8

The CIS Controls mappings are based on:

- **Source:** [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- **ATT&CK Mapping:** [CIS Controls Navigator](https://www.cisecurity.org/controls/cis-controls-navigator)
- **Implementation Groups:** IG1 (Essential), IG2 (Foundational), IG3 (Organisational)

## Regenerating Mappings

Build scripts are provided to regenerate mappings from source:

### NIST 800-53

```bash
cd backend
python3 scripts/build_compliance_mappings.py
```

This script:
1. Downloads control definitions from MITRE CTID
2. Downloads control-to-technique mappings
3. Resolves ATT&CK technique IDs
4. Adds cloud applicability metadata
5. Outputs to `app/data/compliance_mappings/nist_800_53_r5.json`

### CIS Controls v8

```bash
cd backend
python3 scripts/build_cis_mappings.py
```

This script:
1. Uses embedded CIS Controls v8 structure
2. Includes all 153 safeguards with ATT&CK mappings
3. Adds Implementation Group (IG) metadata
4. Adds cloud applicability metadata
5. Outputs to `app/data/compliance_mappings/cis_controls_v8.json`

## File Structure

```
backend/app/data/compliance_mappings/
├── nist_800_53_r5.json      # NIST 800-53 Rev 5 mappings
├── cis_controls_v8.json     # CIS Controls v8 mappings
└── loader.py                # Database loader

backend/scripts/
├── build_compliance_mappings.py  # NIST mapping generator
└── build_cis_mappings.py         # CIS mapping generator
```

## JSON Schema

### Control Structure

```json
{
  "control_id": "AC-2",
  "control_family": "Access Control",
  "name": "Account Management",
  "description": "...",
  "priority": "P1",
  "is_enhancement": false,
  "cloud_applicability": "highly_relevant",
  "cloud_context": {
    "aws_services": ["IAM", "Organizations", "SSO"],
    "gcp_services": ["Cloud IAM", "Identity Platform"],
    "shared_responsibility": "customer"
  },
  "technique_mappings": [
    {"technique_id": "T1078", "mapping_type": "mitigates"},
    {"technique_id": "T1136", "mapping_type": "mitigates"}
  ]
}
```

### Priority Levels

| Priority | Description |
|----------|-------------|
| P1 | Critical security controls (e.g., AC-2, AU-2, IA-2) |
| P2 | Important security controls |
| P3 | Other security controls in key families |
| null | Controls in non-security-critical families |

## Coverage Calculation

Compliance coverage is calculated as follows:

1. **Per Control:** Coverage = (Covered Techniques / Total Mapped Techniques)
2. **Control Status:**
   - **Covered:** ≥80% of mapped techniques detected
   - **Partial:** 40-80% of mapped techniques detected
   - **Uncovered:** <40% of mapped techniques detected
3. **Framework Coverage:** (Covered Controls / Total Controls) × 100

### Cloud-Specific Metrics

Additional cloud-focused metrics are calculated:

- **Cloud Detection Coverage:** Coverage of `highly_relevant` and `moderately_relevant` controls only
- **Customer Responsibility Coverage:** Excludes `provider_responsibility` controls
- **Provider Managed Count:** Controls managed by cloud provider (informational)

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/)
- [NIST 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)
- [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/)
- [GCP Shared Responsibility](https://cloud.google.com/architecture/framework/security/shared-responsibility-shared-fate)
