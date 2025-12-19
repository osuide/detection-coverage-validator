# Understanding MITRE ATT&CK Coverage

This guide explains how A13E analyses your security detection coverage using the MITRE ATT&CK framework.

## TL;DR

- **Coverage is calculated** by mapping your detections to MITRE ATT&CK techniques and assigning confidence scores (0-100%). Techniques with ≥60% confidence are considered "Covered"
- **The heatmap visualises** your coverage across 14 attack tactics (columns) and hundreds of techniques (rows), with colour-coded cells showing detection strength from dark green (excellent) to dark grey (none)
- **Confidence scores** are weighted by detection specificity (40%), quality (30%), and completeness (30%). Multiple detections for one technique use the highest confidence score
- **Industry benchmark**: Most organisations achieve 45-75% coverage depending on maturity. Focus first on Critical priority gaps in Initial Access and Persistence tactics for quick security wins

## Table of Contents

- [What is MITRE ATT&CK?](#what-is-mitre-attck)
- [Coverage Calculation](#coverage-calculation)
- [Coverage Heatmap](#coverage-heatmap)
- [Technique Details](#technique-details)
- [Tactics Overview](#tactics-overview)
- [Gap Analysis](#gap-analysis)
- [Confidence Scores](#confidence-scores)
- [Interpreting Results](#interpreting-results)

## What is MITRE ATT&CK?

**MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.

### Framework Structure

The ATT&CK framework is organised into:

1. **Tactics**: The "why" - adversary's tactical goals (e.g., gaining access, stealing data)
2. **Techniques**: The "how" - methods to achieve those goals (e.g., phishing, credential dumping)
3. **Sub-techniques**: Specific implementations of techniques
4. **Procedures**: Real-world examples from threat actors

### Why It Matters

Using ATT&CK for detection coverage helps you:

- **Standardise**: Common language across security teams
- **Prioritise**: Focus on high-risk techniques based on threat intelligence
- **Measure**: Quantify and track detection coverage improvements
- **Communicate**: Report security posture to executives and stakeholders

### ATT&CK for Cloud

A13E focuses on **ATT&CK for Cloud** (formerly Enterprise Cloud), covering:

- AWS-specific techniques
- GCP-specific techniques
- Azure techniques (future support)
- Cross-cloud techniques

Current version: **ATT&CK v13.1** (check your Dashboard for current version)

## Coverage Calculation

### How A13E Calculates Coverage

For each MITRE ATT&CK technique:

1. **Detection Mapping**: A13E maps your discovered detections to ATT&CK techniques
2. **Confidence Scoring**: Assigns confidence scores (0-100%) based on detection quality
3. **Aggregation**: Combines multiple detections for the same technique
4. **Classification**: Categorises as Covered, Partial, or Uncovered

### Coverage Categories

| Category | Confidence Range | Colour | Meaning |
|----------|------------------|--------|---------|
| **Covered** | ≥60% | Green | Strong detection capability |
| **Partial** | 40-59% | Yellow | Moderate detection, improvements possible |
| **Uncovered** | <40% | Grey | Little to no detection coverage |

### Overall Coverage Percentage

Your overall coverage percentage is calculated as:

```
Coverage % = (Covered Techniques / Total Applicable Techniques) × 100
```

**Example**:
- Total applicable techniques: 200
- Covered techniques (≥60% confidence): 120
- Partial techniques (40-59%): 40
- Uncovered techniques (<40%): 40
- **Overall Coverage: 60%** (120/200)

### Average Confidence

The average confidence score across all techniques:

```
Average Confidence = Sum of all technique confidence scores / Total techniques
```

This metric helps understand the overall strength of your detection capabilities.

## Coverage Heatmap

The MITRE ATT&CK heatmap provides a visual representation of your coverage.

### Reading the Heatmap

**Layout**:
- **Columns**: 14 MITRE ATT&CK tactics (left to right)
- **Rows**: Individual techniques within each tactic
- **Cells**: Each cell represents one technique

**Colours**:
- **Dark Green**: High coverage (80-100% confidence)
- **Light Green**: Good coverage (60-79% confidence)
- **Yellow**: Partial coverage (40-59% confidence)
- **Light Grey**: Minimal coverage (20-39% confidence)
- **Dark Grey**: No coverage (<20% confidence)

**Cell Information**:
Hover over any cell to see:
- Technique ID (e.g., T1078)
- Technique name (e.g., "Valid Accounts")
- Confidence score (e.g., 75%)
- Number of detections mapped
- Coverage status (Covered, Partial, or Uncovered)

Click a cell to view the technique in detail, including a link to the official MITRE ATT&CK documentation.

### Navigating the Heatmap

**Zoom Controls**:
- Use **+ / -** buttons to zoom in/out
- **Fit to Screen** button to see entire matrix

**Filters**:
- **By Tactic**: Show only specific tactics (e.g., "Persistence")
- **By Confidence**: Show only techniques in a confidence range
- **By Detection Source**: Filter by GuardDuty, Security Hub, etc.

**Click Actions**:
- **Click a cell**: See detailed technique information
- **Click tactic header**: Filter to show only that tactic
- **Click detection count**: Jump to Detections page filtered to that technique

### View Modes

#### Heatmap View
Full MITRE ATT&CK matrix with colour-coded coverage.

**Best for**:
- Executive presentations
- Identifying patterns across tactics
- Visual assessment of overall posture

#### Tactics View
Horizontal bar chart showing coverage by tactic.

**Best for**:
- Comparing coverage across attack stages
- Identifying which tactics need attention
- Quick summary analysis

## Technique Details

Click any technique in the heatmap or coverage table to see detailed information.

### Technique Overview

**Header Information**:
- **Technique ID**: MITRE ATT&CK ID (e.g., T1078.004)
- **Technique Name**: Full name (e.g., "Cloud Accounts")
- **Parent Technique**: If sub-technique (e.g., T1078: Valid Accounts)
- **Tactics**: Associated tactics (some techniques span multiple tactics)

### Detection Coverage

**Mapped Detections**:
List of all detections providing coverage:

```
✓ GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
  Confidence: 80%
  Source: GuardDuty

✓ Security Hub: IAM.1 - Avoid root account usage
  Confidence: 60%
  Source: Security Hub

✓ EventBridge: Monitor CreateUser API calls
  Confidence: 50%
  Source: EventBridge
```

**Overall Confidence**: Weighted average of all detection confidences

### MITRE Information

Direct from ATT&CK knowledge base:

- **Description**: What the technique involves
- **Platforms**: Applicable cloud platforms (AWS, GCP, Azure)
- **Permissions Required**: Privileges needed by adversary
- **Data Sources**: Recommended telemetry sources
- **Mitigation Strategies**: How to prevent or limit the technique
- **Detection Guidance**: How to detect this technique

### Threat Context

Real-world threat intelligence:

- **Known Groups**: APT groups observed using this technique
- **Attack Campaigns**: Recent campaigns employing this technique
- **Prevalence**: How commonly this technique is observed

## Tactics Overview

The 14 MITRE ATT&CK tactics represent stages of an attack. Here's what to expect for cloud coverage:

| Tactic | Description | Cloud Examples | Typical Coverage |
|--------|-------------|----------------|------------------|
| **1. Reconnaissance** (TA0043) | Gathering information for future operations | Enumerating S3 buckets, scanning for misconfigurations | 20-40% |
| **2. Resource Development** (TA0042) | Establishing resources for operations | Creating fake accounts, setting up C2 infrastructure | 10-30% |
| **3. Initial Access** (TA0001) | Getting into your cloud environment | Valid credentials, exploiting public apps, phishing | 60-80% |
| **4. Execution** (TA0002) | Running malicious code | Lambda functions, malicious containers, SSM commands | 50-70% |
| **5. Persistence** (TA0003) | Maintaining access over time | Backdoor IAM users, modified metadata, malicious Lambda layers | 70-85% |
| **6. Privilege Escalation** (TA0004) | Gaining higher-level permissions | IAM privilege escalation, overly permissive policies | 65-80% |
| **7. Defence Evasion** (TA0005) | Avoiding detection and security controls | Disabling CloudTrail, deleting security resources | 55-75% |
| **8. Credential Access** (TA0006) | Stealing credentials and secrets | Accessing Secrets Manager, credential dumping | 60-75% |
| **9. Discovery** (TA0007) | Learning about the environment | Listing S3 buckets, enumerating IAM, describing instances | 40-60% |
| **10. Lateral Movement** (TA0008) | Moving through the environment | Cross-account role assumption, VPC peering pivots | 50-65% |
| **11. Collection** (TA0009) | Gathering data of interest | Downloading S3 objects, exporting database snapshots | 45-65% |
| **12. Command and Control** (TA0011) | Communicating with compromised systems | Known C2 IPs, DNS tunneling, unauthorised VPN | 60-80% |
| **13. Exfiltration** (TA0010) | Stealing data from the environment | Unusual S3 transfers, snapshot sharing, large exports | 50-70% |
| **14. Impact** (TA0040) | Disrupting availability or integrity | Deleting S3 buckets, ransomware encryption, terminating instances | 60-80% |

**Why Coverage Varies**:
- **Low coverage** (Reconnaissance, Resource Development): Often happens outside your environment or involves passive activities
- **High coverage** (Initial Access, Persistence): Most organisations monitor authentication and IAM changes
- **Medium coverage** (Discovery, Collection): Depends on how comprehensively you log read-only operations

## Gap Analysis

Understanding and prioritising coverage gaps.

### What is a Gap?

A coverage gap is a MITRE ATT&CK technique with insufficient detection coverage (typically <60% confidence).

### Gap Priority Levels

A13E assigns priority based on multiple factors:

#### Critical Priority
- **Prevalence**: Observed in recent threat campaigns
- **Impact**: High potential damage if exploited
- **Exploitability**: Easy for attackers to execute
- **Environment**: Technique is applicable to your cloud setup

**Examples**:
- T1078.004 - Cloud Account credential use (if uncovered)
- T1098 - Account Manipulation in cloud
- T1537 - Transfer data to cloud account

#### High Priority
- **Prevalence**: Commonly used by threat actors
- **Impact**: Moderate to high damage potential
- **Exploitability**: Moderate difficulty

**Examples**:
- T1190 - Exploit public-facing application
- T1552.005 - Cloud Instance Metadata API credentials
- T1578 - Modify cloud compute infrastructure

#### Medium Priority
- **Prevalence**: Occasionally observed
- **Impact**: Moderate damage potential
- **Exploitability**: Requires some sophistication

**Examples**:
- T1021 - Remote Services access
- T1530 - Data from Cloud Storage Object
- T1213 - Data from Information Repositories

#### Low Priority
- **Prevalence**: Rare or theoretical
- **Impact**: Limited damage potential
- **Exploitability**: Difficult to execute

**Examples**:
- T1071 - Application Layer Protocol (generic)
- T1102 - Web Service for C2
- T1583 - Acquire Infrastructure

### Gap Details

For each gap, A13E provides:

**Why It's a Gap**:
Clear explanation of missing coverage

**Recommended Data Sources**:
AWS services and logs needed for detection

**Remediation Suggestions**:
Actionable steps to close the gap:
1. Enable specific AWS service
2. Create EventBridge rule pattern
3. Configure CloudWatch Logs query
4. Set up Security Hub control

**MITRE Reference**:
Direct link to technique on attack.mitre.org

## Confidence Scores

Understanding how confidence scores are calculated.

### Scoring Factors

Detection confidence is based on:

#### 1. Detection Specificity (40%)
How precisely the detection targets the technique.

- **100%**: Detection explicitly targets this exact technique
- **75%**: Detection covers this technique among a few others
- **50%**: Detection is somewhat related
- **25%**: Detection has tangential coverage

#### 2. Detection Quality (30%)
The reliability and accuracy of the detection.

- **High Quality**: Managed service with high fidelity (e.g., GuardDuty finding)
- **Medium Quality**: Custom rule with good signal-to-noise
- **Low Quality**: Generic control with potential false positives

#### 3. Coverage Completeness (30%)
Whether the detection covers all variations of the technique.

- **Complete**: Covers all sub-techniques and variations
- **Partial**: Covers main technique but missing sub-techniques
- **Incomplete**: Only covers specific scenarios

### Example Calculation

**Technique**: T1078.004 - Valid Accounts: Cloud Accounts

**Detection 1**: GuardDuty - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
- Specificity: 90% (explicitly targets credential theft)
- Quality: 95% (managed service, high fidelity)
- Completeness: 70% (covers credential misuse but not all cloud account scenarios)
- **Detection Confidence: 85%**

**Detection 2**: Security Hub - IAM.1 Avoid root account usage
- Specificity: 60% (related but not specific to cloud credential abuse)
- Quality: 80% (Security Hub control, good signal)
- Completeness: 50% (only addresses root account, not all cloud accounts)
- **Detection Confidence: 63%**

**Detection 3**: EventBridge - Monitor ConsoleLogin events
- Specificity: 75% (detects account usage)
- Quality: 60% (custom rule, depends on configuration)
- Completeness: 60% (covers authentication but not all account abuse)
- **Detection Confidence: 65%**

**Overall Technique Confidence**: Maximum of all detections = **85%** (from GuardDuty)

## Interpreting Results

### Benchmarking Your Coverage

**Industry Averages** (based on A13E customer data):

| Organisation Size | Average Coverage | Detections Count |
|-------------------|------------------|------------------|
| **Small** (<500 employees) | 45-55% | 50-150 |
| **Medium** (500-2000) | 55-65% | 150-300 |
| **Large** (2000-10000) | 60-70% | 300-500 |
| **Enterprise** (10000+) | 65-75% | 500+ |

**Maturity Levels**:

- **<40% Coverage**: Foundational - Focus on critical tactics
- **40-60% Coverage**: Developing - Expand across tactics
- **60-75% Coverage**: Mature - Fine-tune and optimise
- **>75% Coverage**: Advanced - Focus on exotic/advanced techniques

### Setting Goals

**Realistic Targets**:

**Year 1**:
- Achieve 50-60% overall coverage
- 100% coverage for Initial Access, Persistence
- Close all Critical priority gaps

**Year 2**:
- Achieve 65-75% overall coverage
- Expand to all 14 tactics
- Close all High priority gaps

**Year 3**:
- Achieve 75-85% overall coverage
- Optimise false positives and alert fatigue
- Focus on advanced and cloud-specific techniques

### Coverage Improvement Strategy

**1. Quick Wins (Weeks 1-4)**:
- Enable GuardDuty (if not already enabled)
- Activate Security Hub standards
- Ensure CloudTrail is logging to CloudWatch

**2. Build Foundation (Months 2-3)**:
- Create EventBridge rules for critical CloudTrail events
- Implement key CloudWatch Logs Insights queries
- Configure AWS Config rules

**3. Expand Coverage (Months 4-6)**:
- Address high and critical priority gaps
- Add detections for under-covered tactics
- Tune existing detections for better confidence

**4. Optimise (Months 7-12)**:
- Reduce false positives
- Improve detection confidence scores
- Automate response workflows

## Next Steps

- [Running Scans](./running-scans.md) - Scan regularly to track improvements
- [Team Management](./team-management.md) - Share coverage reports with stakeholders
- [Connecting AWS Accounts](./connecting-aws-accounts.md) - Expand to more environments

## Additional Resources

- [MITRE ATT&CK for Enterprise](https://attack.mitre.org/) - Official ATT&CK framework
- [AWS Security Blog](https://aws.amazon.com/blogs/security/) - AWS security best practices
- [Cloud Security Alliance](https://cloudsecurityalliance.org/) - Cloud security guidance

## Getting Help

Questions about coverage analysis?

- **In-App Help**: Click the ? icon in the Coverage page
- **Knowledge Base**: Browse articles at docs.a13e.io
- **Support**: Email support@a13e.io for coverage interpretation help
