# Remediation Template Improvement Patterns

This document captures reusable patterns for creating high-quality detection templates. These patterns were derived from improving T1538 (Cloud Service Dashboard) and should be applied to other MITRE ATT&CK technique templates.

## Pattern 1: Anomaly Scoring Over Raw Alerting

**Problem**: Sending every matching event to SNS creates noise and alert fatigue.

**Solution**: Use a Lambda evaluator that applies scoring logic before alerting.

```python
# Score events based on multiple risk indicators
score = 0
if is_out_of_hours(event_time):
    score += 20
if not has_mfa(event):
    score += 25
if is_new_source_ip(principal, source_ip):
    score += 30
if is_new_user_agent(principal, user_agent):
    score += 15
if is_failed_login(event):
    score += 10

# Only alert if score exceeds threshold
if score >= ALERT_THRESHOLD:
    publish_alert(event, score, reasons)
```

**When to apply**: Any detection where the raw event volume would be high (console logins, API calls, network connections).

---

## Pattern 2: Baseline Storage with TTL

**Problem**: Can't distinguish normal from anomalous without knowing historical patterns.

**Solution**: Use DynamoDB with TTL to track per-principal baselines.

```hcl
resource "aws_dynamodb_table" "baseline" {
  name         = "${var.name_prefix}-baseline"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_arn"

  attribute {
    name = "principal_arn"
    type = "S"
  }

  ttl {
    attribute_name = "ttl_epoch"
    enabled        = true
  }

  point_in_time_recovery { enabled = true }
  server_side_encryption { enabled = true }
}
```

**Baseline data to track**:
- Known source IPs (set)
- Known user agents (set)
- First seen timestamp
- Last seen timestamp
- Login count

**When to apply**: Account access, service access, data access patterns.

---

## Pattern 3: Business Context Filtering

**Problem**: Alerting on legitimate business-hours activity from known locations.

**Solution**: Make business hours configurable and apply time-based suppression.

```hcl
variable "timezone" {
  type        = string
  default     = "Europe/London"
  description = "IANA timezone for out-of-hours logic"
}

variable "business_start_hour" {
  type    = number
  default = 8
}

variable "business_end_hour" {
  type    = number
  default = 18
}

variable "business_days" {
  type        = list(number)
  default     = [0, 1, 2, 3, 4]  # Mon-Fri (Python weekday)
  description = "Days considered business days"
}
```

```python
# In Lambda handler
from zoneinfo import ZoneInfo

def is_out_of_hours(event_time: datetime) -> bool:
    tz = ZoneInfo(os.environ["TZ"])
    local = event_time.astimezone(tz)

    if local.weekday() not in BUSINESS_DAYS:
        return True
    if not (BUSINESS_START <= local.hour < BUSINESS_END):
        return True
    return False
```

**When to apply**: Any user-interactive detection (console access, VPN, SSO).

---

## Pattern 4: Principal and Network Allowlisting

**Problem**: Automation accounts, break-glass principals, and corporate VPN egress trigger false positives.

**Solution**: Configurable allowlists with CIDR matching.

```hcl
variable "allowlisted_principal_arns" {
  type        = list(string)
  default     = []
  description = "Suppress alerts for these principal ARNs (break-glass, automation)"
}

variable "allowlisted_source_cidrs" {
  type        = list(string)
  default     = []
  description = "Suppress alerts for these CIDR ranges (corporate VPN egress)"
}
```

```python
import ipaddress

def is_allowlisted(principal_arn: str, source_ip: str) -> bool:
    if principal_arn in ALLOWLIST_ARNS:
        return True

    ip = ipaddress.ip_address(source_ip)
    for cidr in ALLOWLIST_CIDRS:
        if ip in ipaddress.ip_network(cidr):
            return True

    return False
```

**When to apply**: Any detection involving identity or network source.

---

## Pattern 5: Leverage Managed Detection Services

**Problem**: Building ML-based anomaly detection from scratch is expensive and complex.

**Solution**: Consume existing managed signals (GuardDuty, Security Hub, SCC).

```hcl
# GuardDuty provides purpose-built anomaly signals
resource "aws_cloudwatch_event_rule" "guardduty_console_anomalies" {
  count       = var.guardduty_enable ? 1 : 0
  name        = "${var.name_prefix}-guardduty-console-anomalies"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.guardduty_min_severity] }]
      type = [
        { wildcard = "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess*" },
        { wildcard = "UnauthorizedAccess:IAMUser/TorIPCaller*" },
        { wildcard = "*:IAMUser/AnomalousBehavior" }
      ]
    }
  })
}
```

**GuardDuty findings to consider by technique**:
| Technique | Relevant GuardDuty Findings |
|-----------|----------------------------|
| T1538 Console | `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` |
| T1078 Valid Accounts | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` |
| T1110 Brute Force | `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` |
| T1040 Network Sniffing | `Trojan:EC2/DNSDataExfiltration` |

**When to apply**: Any technique where GuardDuty, Security Hub, or SCC has relevant finding types.

---

## Pattern 6: Multi-Region Awareness

**Problem**: Some AWS events (ConsoleLogin, global services) have unpredictable region attribution.

**Solution**: Document region behaviour and provide deployment guidance.

```hcl
# In module documentation:
# IMPORTANT: ConsoleLogin Region varies by:
# - IAM user: recorded in us-east-1
# - Federated user: recorded in the console endpoint region
# - Root user: recorded in us-east-1
#
# Options:
# 1. Deploy this module in all regions where users might sign in
# 2. Use CloudWatch cross-region event forwarding to centralise
# 3. Use AWS Organizations with delegated admin for org-wide coverage
```

**When to apply**: Console access, IAM operations, global service APIs (S3, Route53, CloudFront).

---

## Pattern 7: Modular Terraform Structure

**Problem**: Inline Terraform blocks are hard to maintain and test.

**Solution**: Use proper module file layout.

```
t1538-console-anomaly/
├── versions.tf      # terraform and provider requirements
├── variables.tf     # all input variables with descriptions
├── main.tf          # resource definitions
├── outputs.tf       # exported values
└── lambda/
    └── handler.py   # Lambda function code
```

**versions.tf template**:
```hcl
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}
```

**When to apply**: All templates. Even simple ones benefit from this structure for consistency.

---

## Pattern 8: Tunable Thresholds with Guidance

**Problem**: One threshold doesn't fit all SOC maturity levels.

**Solution**: Provide configurable thresholds with practical tuning guidance.

```hcl
variable "alert_threshold" {
  type        = number
  default     = 40
  description = "Anomaly score threshold for alerting (0-100)"
}
```

**Documentation**:
```markdown
## Practical Tuning Guidance

**Tier-1 SOC tripwire** (high volume, catch everything):
- `alert_threshold = 40`
- `alert_on_failures = true`

**High-confidence only** (low volume, high fidelity):
- `alert_threshold = 60`
- Rely on GuardDuty for anomaly signals
- Filter to specific user populations
```

**When to apply**: Any detection with configurable sensitivity.

---

## Pattern 9: Failure Event Handling

**Problem**: Failed login attempts may indicate attack reconnaissance.

**Solution**: Make failure alerting configurable.

```hcl
variable "alert_on_failures" {
  type        = bool
  default     = true
  description = "If true, unsuccessful attempts can also trigger alerts"
}
```

```hcl
event_pattern = jsonencode({
  source        = ["aws.signin"]
  "detail-type" = ["AWS Console Sign In via CloudTrail"]
  detail = {
    eventName = ["ConsoleLogin"]
    responseElements = {
      ConsoleLogin = ["Success", "Failure"]  # Include both
    }
  }
})
```

**When to apply**: Authentication events, access attempts, API calls that can fail.

---

## Pattern 10: Cost-Effective Resource Choices

**Problem**: Over-provisioned resources waste money; under-provisioned fail under load.

**Solution**: Use pay-per-request where event volume is unpredictable.

```hcl
# DynamoDB: Pay-per-request for unpredictable workloads
resource "aws_dynamodb_table" "baseline" {
  billing_mode = "PAY_PER_REQUEST"  # Not PROVISIONED
  # ...
}

# Lambda: Right-size memory based on workload
resource "aws_lambda_function" "evaluator" {
  memory_size = 256   # Sufficient for JSON parsing + DynamoDB
  timeout     = 10    # Short timeout for event-driven
}
```

**Cost estimation guidance**:
| Component | Estimate |
|-----------|----------|
| Lambda (1000 events/day) | ~$0.50/month |
| DynamoDB (1000 users baseline) | ~$1/month |
| CloudWatch Logs (30-day retention) | ~$2/month |
| SNS (email) | ~$0.10/month |
| **Total** | **~$5/month** |

---

## Implementation Checklist

When creating or improving a remediation template:

- [ ] Does raw event volume justify anomaly scoring? (Pattern 1)
- [ ] Would baseline comparison improve fidelity? (Pattern 2)
- [ ] Does business context matter? (Pattern 3)
- [ ] Are there principals/networks to allowlist? (Pattern 4)
- [ ] Does GuardDuty/SCC have relevant findings? (Pattern 5)
- [ ] Is region behaviour predictable? (Pattern 6)
- [ ] Is Terraform properly modularised? (Pattern 7)
- [ ] Are thresholds documented with tuning guidance? (Pattern 8)
- [ ] Should failures be handled differently? (Pattern 9)
- [ ] Are resource costs estimated? (Pattern 10)

---

## Template Quality Tiers

### Tier 1: Basic (Current State)
- Raw event → SNS notification
- Single inline Terraform block
- No anomaly logic

### Tier 2: Intermediate
- Event filtering in EventBridge pattern
- Separate variables/main/outputs files
- Basic threshold configuration

### Tier 3: Advanced (Target State)
- Lambda-based anomaly scoring
- DynamoDB baseline storage
- Business hours + allowlisting
- GuardDuty integration
- Multi-region guidance
- Cost estimation
- Tuning documentation

**Goal**: Migrate all high-impact techniques to Tier 3.
