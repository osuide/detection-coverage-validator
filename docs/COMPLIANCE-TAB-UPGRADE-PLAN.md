# Compliance Tab Upgrade Plan

## Executive Summary

This plan outlines improvements to make the Compliance tab more useful and applicable to AWS and GCP cloud accounts. It identifies cloud-centric vs non-cloud control families, expands coverage using official MITRE CTID mappings, and adds cloud-specific context.

---

## Current State Analysis

### Existing Coverage

| Framework | Controls | Official CTID Mappings | Gap |
|-----------|----------|------------------------|-----|
| NIST 800-53 Rev 5 | 35 controls | 5,314 mappings (320+ controls) | ~90% missing |
| CIS Controls v8 | 18 controls | 153 safeguards | Missing CIS 19, 20 |

### Key Issues Identified

1. **Limited control coverage** - Only ~10% of official NIST 800-53 mappings
2. **No cloud applicability indicator** - Cannot distinguish cloud-relevant controls
3. **No shared responsibility context** - Missing AWS/GCP responsibility model
4. **No cloud-specific guidance** - Generic control descriptions
5. **Missing CIS sub-controls (Safeguards)** - Only top-level controls mapped

---

## Chain of Thought: Cloud-Centric Analysis

### Reasoning Process

**Question**: Which compliance control families are directly applicable to cloud IaaS environments (AWS/GCP)?

**Analysis Framework**:
1. Does the control relate to resources customers manage in cloud?
2. Can detection coverage be measured via cloud APIs?
3. Is the control part of "customer responsibility" in shared responsibility model?

### Control Family Classification

#### Highly Cloud-Centric (Primary Focus)

| Family | Code | Cloud Relevance | Detectable via Cloud APIs |
|--------|------|-----------------|---------------------------|
| **Access Control** | AC | IAM policies, roles, permissions | Yes - IAM, STS, KMS |
| **Audit and Accountability** | AU | CloudTrail, Cloud Logging | Yes - log services |
| **Configuration Management** | CM | Resource configurations | Yes - Config, Asset Inventory |
| **Identification and Authentication** | IA | Identity providers, MFA | Yes - IAM, Cognito, Identity Platform |
| **System and Communications Protection** | SC | VPCs, security groups, encryption | Yes - VPC, KMS |
| **System and Information Integrity** | SI | GuardDuty, SCC, vulnerability scanning | Yes - security services |

#### Moderately Cloud-Relevant

| Family | Code | Cloud Relevance | Notes |
|--------|------|-----------------|-------|
| **Risk Assessment** | RA | Vulnerability scanning | Partially via Inspector, SCC |
| **Security Assessment** | CA | Continuous monitoring | CloudWatch, Cloud Monitoring |
| **Incident Response** | IR | Alert handling | EventBridge, Pub/Sub |
| **Contingency Planning** | CP | Backup, DR | S3, Cloud Storage, snapshots |

#### Limited Cloud Relevance (Informational Only)

| Family | Code | Reason |
|--------|------|--------|
| **Physical and Environmental Protection** | PE | Cloud provider responsibility |
| **Personnel Security** | PS | Organisational HR process |
| **Planning** | PL | Organisational security planning |
| **Program Management** | PM | Security programme management |
| **Media Protection** | MP | Physical media - cloud provider |
| **Maintenance** | MA | Physical maintenance - cloud provider |

---

## Upgrade Plan: Phase 1 - Data Enhancement [COMPLETED]

**Commit**: `90350d8` - Phase 1: Add cloud applicability metadata to compliance framework

**Implemented**:
- Added `cloud_applicability` and `cloud_context` fields to ComplianceControl model
- Created migration `026_add_compliance_cloud_metadata.py`
- Expanded NIST 800-53 from 35 to 50 controls with full cloud metadata
- Expanded CIS Controls v8 from 18 to 32 controls (added safeguards)
- Each control now has AWS/GCP service mappings and shared responsibility

### 1.1 Add Cloud Applicability Metadata

**Schema Change**: Add to `ComplianceControl` model:

```python
cloud_applicability: Enum {
    "highly_relevant",      # Directly detectable in cloud
    "moderately_relevant",  # Partially applicable
    "informational",        # Not cloud-detectable
    "provider_responsibility"  # Cloud provider manages
}

cloud_context: JSON {
    "aws_services": ["IAM", "CloudTrail", ...],
    "gcp_services": ["Cloud IAM", "Cloud Logging", ...],
    "shared_responsibility": "customer" | "shared" | "provider",
    "detection_guidance": "string"
}
```

### 1.2 Expand NIST 800-53 Coverage

**Source**: [MITRE CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist/)

**Priority Controls to Add** (Cloud-Centric):

| Control | Name | MITRE Techniques | Priority |
|---------|------|------------------|----------|
| AC-2(1) | Automated Account Management | T1078, T1136 | P1 |
| AC-2(4) | Automated Audit Actions | T1078, T1562 | P1 |
| AC-3(7) | Role-Based Access Control | T1078, T1098 | P1 |
| AC-6(1) | Authorize Access to Security Functions | T1548 | P1 |
| AC-6(5) | Privileged Accounts | T1078.004 | P1 |
| AC-6(9) | Log Use of Privileged Functions | T1078 | P1 |
| AC-6(10) | Prohibit Non-Privileged Users | T1548 | P1 |
| AU-6(1) | Automated Process Integration | T1562.008 | P1 |
| AU-6(3) | Correlate Audit Record Repositories | T1562 | P1 |
| CM-2(2) | Automation Support | T1578 | P1 |
| CM-3(1) | Automated Documentation | T1578 | P1 |
| CM-7(1) | Periodic Review | T1190, T1133 | P1 |
| CM-8 | System Component Inventory | T1580 | P1 |
| IA-2(1) | Multi-Factor Authentication | T1078, T1110 | P1 |
| IA-2(2) | MFA for Network Access | T1078, T1133 | P1 |
| IA-5(1) | Password-Based Authentication | T1110 | P1 |
| SC-7(4) | External Telecommunications | T1048, T1071 | P1 |
| SC-7(5) | Deny by Default | T1190 | P1 |
| SI-4(2) | Automated Tools and Mechanisms | T1562 | P1 |
| SI-4(4) | Inbound and Outbound Traffic | T1048, T1041 | P1 |
| SI-4(5) | System-Generated Alerts | T1562, T1078 | P1 |

### 1.3 Expand CIS Controls v8 Coverage

**Source**: [CIS Controls v8 Master Mapping](https://www.cisecurity.org/insights/white-papers/cis-controls-v8-master-mapping-to-mitre-enterprise-attck-v82)

**Missing Controls**:

| Control | Name | Cloud Relevance |
|---------|------|-----------------|
| 19 | Incident Response and Management | Moderately relevant |
| 20 | Penetration Testing and Red Team Exercises | Moderately relevant |

**Add Sub-Controls (Safeguards)** for cloud-centric controls:

| Control | Safeguard | Name | MITRE Mapping |
|---------|-----------|------|---------------|
| 1 | 1.1 | Establish and Maintain Asset Inventory | T1580 |
| 1 | 1.2 | Address Unauthorised Assets | T1580, T1526 |
| 3 | 3.1 | Establish and Maintain Data Management Process | T1530 |
| 3 | 3.3 | Configure Data Access Control Lists | T1530, T1537 |
| 3 | 3.10 | Encrypt Sensitive Data in Transit | T1040, T1557 |
| 3 | 3.11 | Encrypt Sensitive Data at Rest | T1530 |
| 5 | 5.1 | Establish and Maintain Account Inventory | T1078, T1136 |
| 5 | 5.3 | Disable Dormant Accounts | T1078 |
| 5 | 5.4 | Restrict Administrator Privileges | T1078.004 |
| 6 | 6.1 | Establish Access Granting Process | T1098 |
| 6 | 6.3 | Require MFA for Externally-Exposed Apps | T1078, T1110 |
| 6 | 6.4 | Require MFA for Remote Network Access | T1078, T1133 |
| 6 | 6.5 | Require MFA for Administrative Access | T1078.004 |
| 8 | 8.2 | Collect Audit Logs | T1562.008 |
| 8 | 8.5 | Collect Detailed Audit Logs | T1070 |
| 8 | 8.9 | Centralize Audit Logs | T1562 |
| 8 | 8.11 | Conduct Audit Log Reviews | T1078, T1110 |

---

## Upgrade Plan: Phase 2 - UI Enhancements [COMPLETED]

**Commit**: `75018f4` - Phase 2: Add cloud applicability UI enhancements

**Implemented**:
- Added `CloudContext` and `CloudApplicability` types to frontend API
- ControlsTable now shows cloud applicability badges (green/yellow/blue/purple)
- ControlsTable shows AWS (orange) and GCP (blue) service badges
- FamilyCoverageChart shows shared responsibility indicators
- ComplianceCoverageContent has cloud applicability filter dropdown
- Updated backend calculator and service to include cloud fields

### 2.1 Cloud Applicability Filter

Add toggle to filter controls by cloud applicability:
- **All Controls** - Full compliance view
- **Cloud-Detectable** - Only controls with cloud detection coverage
- **Customer Responsibility** - Exclude provider-managed controls

### 2.2 Shared Responsibility Indicator

For each control family, display:
```
┌─────────────────────────────────────────────┐
│ Access Control (AC)                         │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ 🔵 Customer Responsibility                  │
│ AWS: IAM, Organizations, STS                │
│ GCP: Cloud IAM, Identity Platform           │
│ ─────────────────────────────────────────── │
│ Coverage: 78% (7/9 controls)                │
└─────────────────────────────────────────────┘
```

### 2.3 Cloud Service Mapping

For each control, show applicable cloud services:

```
┌─────────────────────────────────────────────┐
│ AC-2: Account Management                    │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ AWS Services:                               │
│   • IAM (Users, Roles, Policies)            │
│   • Organizations (SCPs)                    │
│   • CloudTrail (account activity)           │
│                                             │
│ GCP Services:                               │
│   • Cloud IAM (Members, Roles)              │
│   • Organization Policy                     │
│   • Cloud Audit Logs                        │
│ ─────────────────────────────────────────── │
│ Detection Coverage: ████████░░ 80%          │
│ Techniques: T1078, T1136, T1098             │
└─────────────────────────────────────────────┘
```

### 2.4 Non-Cloud Control Handling

For controls marked as `informational` or `provider_responsibility`:

```
┌─────────────────────────────────────────────┐
│ PE-2: Physical Access Authorisations        │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
│ ⚠️ Cloud Provider Responsibility            │
│                                             │
│ This control covers physical access to      │
│ data centres. In AWS/GCP environments,      │
│ this is managed by the cloud provider.      │
│                                             │
│ Provider Certifications:                    │
│   • AWS: SOC 2 Type II, ISO 27001           │
│   • GCP: SOC 2 Type II, ISO 27001           │
│ ─────────────────────────────────────────── │
│ Status: Provider Managed (Not Assessed)     │
└─────────────────────────────────────────────┘
```

---

## Upgrade Plan: Phase 3 - Enhanced Analytics [COMPLETED]

**Commit**: `219db9b` - Phase 3: Add enhanced cloud analytics to compliance

**Implemented**:
- Added `CloudCoverageMetrics` dataclass for cloud-specific analytics
- Calculates cloud-detectable coverage separately from overall coverage
- Tracks customer responsibility vs provider managed control breakdown
- Prioritises cloud-centric gaps (highly_relevant first, then moderately_relevant)
- Added `cloud_metrics` JSONB column to compliance snapshots
- Created migration `027_add_cloud_coverage_metrics.py`
- FrameworkCard shows both overall and cloud detection coverage
- Coverage summary shows Cloud Detection Analytics section
- API returns cloud metrics in summary and detailed coverage responses

### 3.1 Cloud-Specific Coverage Score

Calculate separate scores:

```python
# Cloud-detectable coverage (what we can measure)
cloud_coverage = covered_cloud_controls / total_cloud_controls

# Overall compliance (including informational)
overall_coverage = all_covered / all_controls

# Display both:
# "Cloud Detection Coverage: 82%"
# "Overall Framework Coverage: 65%"
```

### 3.2 Cross-Cloud Comparison

For multi-cloud accounts, show:

| Control | AWS Coverage | GCP Coverage | Gap |
|---------|-------------|--------------|-----|
| AC-2 | 85% | 78% | GCP: T1136.003 |
| AU-2 | 90% | 92% | - |
| CM-2 | 72% | 68% | Both: T1578.003 |

### 3.3 Priority Gap Analysis

Combine:
- Control priority (P1/P2/P3)
- Cloud applicability
- MITRE technique severity
- Existing detection coverage

To produce: "Top 5 Cloud Compliance Gaps to Address"

---

## Data Sources (Validated)

### Official MITRE CTID Sources

1. **NIST 800-53 Mappings**
   - URL: https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist/
   - Version: NIST 800-53 Rev 5 → ATT&CK v16.1
   - Mappings: 5,314 total
   - Last Updated: 2024

2. **CIS Controls Mappings**
   - URL: https://www.cisecurity.org/insights/white-papers/cis-controls-v8-master-mapping-to-mitre-enterprise-attck-v82
   - Version: CIS Controls v8 → ATT&CK v8.2
   - Source: CIS Official

### AWS Shared Responsibility Model

- Source: https://aws.amazon.com/compliance/shared-responsibility-model/
- Customer: IAM, data encryption, network config, OS patching
- AWS: Physical security, hardware, hypervisor, managed services

### GCP Shared Responsibility Model

- Source: https://cloud.google.com/architecture/framework/security/shared-responsibility-shared-fate
- Customer: Identity, access control, data, application security
- Google: Infrastructure, hardware, data centre security

---

## Implementation Estimate

| Phase | Tasks | Effort |
|-------|-------|--------|
| Phase 1.1 | Schema + data model changes | 2-3 hours |
| Phase 1.2 | Expand NIST controls (~40 more) | 4-6 hours |
| Phase 1.3 | Add CIS safeguards (~50) | 3-4 hours |
| Phase 2.1-2.4 | UI enhancements | 6-8 hours |
| Phase 3 | Analytics improvements | 4-6 hours |
| **Total** | | **19-27 hours** |

---

## Validation Checklist

Before implementation, verify:

- [ ] All NIST mappings sourced from MITRE CTID Mappings Explorer
- [ ] All CIS mappings sourced from CIS official documentation
- [ ] Shared responsibility classifications align with AWS/GCP official models
- [ ] Cloud service mappings verified against current service capabilities
- [ ] Technique IDs validated against ATT&CK v16.x

---

## Success Criteria

1. **Cloud-Detectable Coverage** visible for each framework
2. **Shared Responsibility** clearly indicated per control
3. **Non-Cloud Controls** marked as informational with provider context
4. **AWS/GCP Services** mapped to relevant controls
5. **Priority Gaps** focused on cloud-detectable issues

---

## References

- [MITRE CTID NIST 800-53 Mappings](https://ctid.mitre.org/projects/nist-800-53-control-mappings/)
- [MITRE Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist/)
- [CIS Controls v8 ATT&CK Mapping](https://www.cisecurity.org/insights/white-papers/cis-controls-v8-master-mapping-to-mitre-enterprise-attck-v82)
- [AWS Shared Responsibility Model](https://aws.amazon.com/compliance/shared-responsibility-model/)
- [GCP Shared Responsibility](https://cloud.google.com/architecture/framework/security/shared-responsibility-shared-fate)
