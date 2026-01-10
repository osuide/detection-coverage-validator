# Understanding MITRE ATT&CK Coverage

Learn how A13E analyses your security detection coverage using the MITRE ATT&CK framework.

## TL;DR

- **Coverage** measures how many MITRE ATT&CK techniques your detections can identify
- **Confidence scores** (0-100%) indicate detection strength based on specificity, quality, and completeness
- **≥60% confidence** = Covered, **40-59%** = Partial, **<40%** = Uncovered
- **Gap priority** (Critical → High → Medium → Low) helps you focus remediation efforts

---

## What is MITRE ATT&CK?

**MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-recognised knowledge base of adversary behaviours based on real-world observations.

### Framework Structure

| Level | Description | Example |
|-------|-------------|---------|
| **Tactics** | The "why"—adversary's goals | Initial Access, Persistence |
| **Techniques** | The "how"—methods to achieve goals | Valid Accounts, Cloud Account |
| **Sub-techniques** | Specific implementations | T1078.004 Cloud Accounts |
| **Procedures** | Real-world examples | APT29 using compromised AWS credentials |

### Why Use ATT&CK?

Using ATT&CK for detection coverage helps you:

- **Standardise**: Common language across security teams and vendors
- **Prioritise**: Focus on techniques actually used by threat actors
- **Measure**: Quantify coverage improvements over time
- **Communicate**: Report security posture to stakeholders

### ATT&CK for Cloud

A13E focuses on **cloud-applicable techniques** covering:

- AWS-specific techniques
- GCP-specific techniques
- Cross-cloud techniques (IaaS platform)

Currently tracking approximately **350 cloud-relevant techniques** based on MITRE ATT&CK.

---

## How Coverage is Calculated

### The Process

For each MITRE ATT&CK technique:

1. **Detection Mapping**: A13E maps your discovered detections to techniques
2. **Confidence Scoring**: Assigns scores (0-100%) based on detection quality
3. **Aggregation**: Combines multiple detections for the same technique
4. **Classification**: Categorises as Covered, Partial, or Uncovered

### Coverage Categories

| Category | Confidence | Colour | Meaning |
|----------|------------|--------|---------|
| **Covered** | ≥60% | Green | Strong detection capability |
| **Partial** | 40-59% | Yellow | Some detection, but gaps exist |
| **Uncovered** | <40% | Grey | Little or no detection |

### Coverage Percentage

Your overall coverage percentage:

```
Coverage % = Covered Techniques ÷ Total Cloud Techniques × 100
```

**Example**:
- Total cloud techniques: 168
- Covered (≥60%): 84
- **Coverage: 50%** *(84 ÷ 168 = 0.50)*

### Average Confidence

The mean confidence score across all techniques:

```
Average Confidence = Sum of all technique confidence scores ÷ Total techniques
```

This indicates the overall strength of your detection capabilities.

---

## Confidence Scores Explained

Detection confidence is based on three factors:

### 1. Detection Specificity (40% weight)

How precisely the detection targets the technique.

| Score | Description |
|-------|-------------|
| **100%** | Detection explicitly targets this exact technique |
| **75%** | Detection covers this technique among a few others |
| **50%** | Detection is somewhat related |
| **25%** | Detection has tangential coverage |

### 2. Detection Quality (30% weight)

The reliability and accuracy of the detection.

| Level | Description | Example |
|-------|-------------|---------|
| **High** | Managed service with high fidelity | GuardDuty finding |
| **Medium** | Custom rule with good signal | Well-tuned EventBridge rule |
| **Low** | Generic control with potential false positives | Broad CloudWatch filter |

### 3. Coverage Completeness (30% weight)

Whether the detection covers all variations of the technique.

| Level | Description |
|-------|-------------|
| **Complete** | Covers all sub-techniques and variations |
| **Partial** | Covers main technique but misses some sub-techniques |
| **Incomplete** | Only covers specific scenarios |

### Example Calculation

**Technique**: T1078.004 - Valid Accounts: Cloud Accounts

**Detection 1**: GuardDuty - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
- Specificity: 90% (explicitly targets credential theft)
- Quality: 95% (managed service, high fidelity)
- Completeness: 70% (covers credential misuse but not all scenarios)
- **Detection Confidence: 86%** *(90×0.4 + 95×0.3 + 70×0.3 = 36 + 28.5 + 21)*

**Detection 2**: EventBridge - Monitor ConsoleLogin events
- Specificity: 75% (detects account usage)
- Quality: 60% (custom rule, depends on configuration)
- Completeness: 60% (covers authentication but not all abuse)
- **Detection Confidence: 66%** *(75×0.4 + 60×0.3 + 60×0.3 = 30 + 18 + 18)*

**Overall Technique Confidence**: Maximum of all detections = **86%** (from GuardDuty)

---

## The 12 MITRE ATT&CK Tactics

A13E covers 12 tactics that can be detected through cloud logs. Reconnaissance (TA0043) and Resource Development (TA0042) are excluded as these pre-attack activities occur outside your cloud environment and cannot be detected through cloud logs.

### Initial Access (TA0001)
**What attackers do**: Gain entry to your environment

**Examples**: Stolen credentials, exploiting public applications

**Typical coverage**: 60-80% — Most orgs monitor authentication

### Execution (TA0002)
**What attackers do**: Run malicious code

**Examples**: Malicious Lambda functions, SSM command execution

**Typical coverage**: 50-70% — Depends on workload monitoring

### Persistence (TA0003)
**What attackers do**: Maintain access over time

**Examples**: Backdoor IAM users, malicious Lambda layers

**Typical coverage**: 70-85% — IAM changes typically well monitored

### Privilege Escalation (TA0004)
**What attackers do**: Gain higher permissions

**Examples**: IAM privilege escalation, overly permissive policies

**Typical coverage**: 65-80% — Security Hub helps here

### Defence Evasion (TA0005)
**What attackers do**: Avoid detection

**Examples**: Disabling CloudTrail, deleting GuardDuty detectors

**Typical coverage**: 55-75% — Critical to monitor

### Credential Access (TA0006)
**What attackers do**: Steal credentials

**Examples**: Accessing Secrets Manager, metadata credential theft

**Typical coverage**: 60-75% — GuardDuty provides good coverage

### Discovery (TA0007)
**What attackers do**: Learn about your environment

**Examples**: Listing S3 buckets, enumerating IAM roles

**Typical coverage**: 40-60% — Read-only operations often unmonitored

### Lateral Movement (TA0008)
**What attackers do**: Move through the environment

**Examples**: Cross-account role assumption, VPC pivoting

**Typical coverage**: 50-65% — Requires custom detection

### Collection (TA0009)
**What attackers do**: Gather target data

**Examples**: Downloading S3 objects, database snapshots

**Typical coverage**: 45-65% — Data access monitoring varies

### Command and Control (TA0011)
**What attackers do**: Communicate with compromised systems

**Examples**: Known C2 IPs, DNS tunnelling

**Typical coverage**: 60-80% — GuardDuty provides good coverage

### Exfiltration (TA0010)
**What attackers do**: Steal data

**Examples**: Unusual S3 transfers, snapshot sharing

**Typical coverage**: 50-70% — Requires data flow monitoring

### Impact (TA0040)
**What attackers do**: Disrupt or destroy

**Examples**: Ransomware, resource termination

**Typical coverage**: 60-80% — Critical changes usually monitored

---

## Gap Analysis

### What is a Gap?

A coverage gap is a MITRE ATT&CK technique with insufficient detection coverage (typically <60% confidence).

### Gap Priority Levels

A13E assigns priority based on:

| Factor | Description |
|--------|-------------|
| **Prevalence** | How often this technique is observed in the wild |
| **Impact** | Potential damage if the technique is exploited |
| **Exploitability** | How easy it is for attackers to execute |
| **Environment** | Whether the technique applies to your cloud setup |

### Priority Levels

| Priority | Meaning | Example Techniques |
|----------|---------|-------------------|
| **Critical** | Address immediately | T1078.004 Cloud Accounts, T1098 Account Manipulation |
| **High** | Plan remediation soon | T1190 Exploit Public-Facing Application |
| **Medium** | Schedule for review | T1530 Data from Cloud Storage |
| **Low** | Monitor trends | T1102 Web Service |

### Gap Information

For each gap, A13E provides:

- **Why it's a gap**: Clear explanation of missing coverage
- **Business impact**: Potential consequences if exploited
- **Recommended data sources**: AWS services needed for detection
- **Detection strategies**: Specific approaches with effort levels
- **Quick wins**: Low-effort improvements marked with lightning bolt
- **IaC templates**: Ready-to-deploy CloudFormation/Terraform

---

## Reading the Heatmap

### Layout

- **Columns**: 12 tactics (attack stages, left to right)
- **Rows**: Individual techniques within each tactic
- **Cells**: One technique per cell

### Colour Coding

| Colour | Confidence | Description |
|--------|------------|-------------|
| **Dark green** | 80-100% | Excellent coverage |
| **Light green** | 60-79% | Good coverage |
| **Yellow** | 40-59% | Partial—needs improvement |
| **Light grey** | 20-39% | Minimal coverage |
| **Dark grey** | <20% | No effective coverage |

### Interacting with the Heatmap

- **Hover** over a cell: See technique ID, name, confidence, and mapped detections
- **Click** a cell: Open detailed technique information
- **Click** a tactic header: Filter to show only that tactic

### View Modes

| Mode | Best For |
|------|----------|
| **Heatmap** | Visual overview, presentations, pattern identification |
| **Tactics** | Comparing coverage across attack stages |

---

## Benchmarking Your Coverage

### Industry Averages

Based on A13E customer data:

| Organisation Size | Average Coverage | Typical Detections |
|-------------------|------------------|-------------------|
| Small (<500 employees) | 45-55% | 50-150 |
| Medium (500-2000) | 55-65% | 150-300 |
| Large (2000-10000) | 60-70% | 300-500 |
| Enterprise (10000+) | 65-75% | 500+ |

### Maturity Levels

| Coverage | Level | Focus |
|----------|-------|-------|
| <40% | Foundational | Enable core services (GuardDuty, Security Hub) |
| 40-59% | Developing | Expand detection sources |
| 60-75% | Mature | Fine-tune and optimise |
| >75% | Advanced | Focus on exotic/advanced techniques |

---

## Setting Coverage Goals

### Realistic Targets

**Year 1**:
- Achieve 50-60% overall coverage
- 80%+ coverage for Initial Access, Persistence, Privilege Escalation
- Close all Critical priority gaps

**Year 2**:
- Achieve 65-75% overall coverage
- Coverage across all 12 tactics
- Close all High priority gaps

**Year 3**:
- Achieve 75-85% overall coverage
- Optimise false positives and alert fatigue
- Focus on advanced cloud-specific techniques

### Quick Wins

**Week 1-2**:
- Enable GuardDuty (if not already)
- Activate Security Hub with AWS Foundational Best Practices
- Ensure CloudTrail is logging management events

**Month 1**:
- Create EventBridge rules for critical CloudTrail events
- Configure CloudWatch alarms for security metrics
- Enable AWS Config with managed rules

---

## Common Questions

**Q: Why is 60% the threshold for "Covered"?**

A: 60% represents meaningful detection capability that would likely trigger an alert during an attack. Below this, detection is inconsistent.

**Q: Can I have 100% coverage?**

A: In practice, no. Some techniques are theoretical or rarely observed. 75-85% is excellent for cloud environments.

**Q: Why do multiple detections for one technique use the maximum confidence?**

A: One strong detection is sufficient to detect an attack. Additional detections provide defence-in-depth but don't stack confidence scores.

**Q: How often should I check my coverage?**

A: After each scan, review the Dashboard. Do a deep-dive into Coverage and Gaps weekly or after major detection changes.

**Q: What if I disagree with a technique's priority?**

A: You can acknowledge gaps you've decided to accept (compensating controls, not applicable). These move to an "acknowledged" section.

---

## Next Steps

- [Using the Dashboards](./using-dashboards.md) - Navigate coverage visualisations
- [Running Scans](./running-scans.md) - Keep coverage data up to date
- [Getting Started](./getting-started.md) - Complete setup guide
