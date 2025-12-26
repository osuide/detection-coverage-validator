# Remediation Template Patterns

**Document Version:** 1.3
**Last Updated:** 26 December 2025
**Classification:** Internal

This document captures lessons learned and best practices for remediation templates in the A13E Detection Coverage Validator.

---

## Table of Contents

### Infrastructure Patterns
1. [VPC Flow Logs Detection Pattern](#1-vpc-flow-logs-detection-pattern)
2. [GuardDuty Augmentation Pattern](#2-guardduty-augmentation-pattern)
3. [IAM Role Confused-Deputy Mitigation](#3-iam-role-confused-deputy-mitigation)
4. [High-Cardinality Metric Aggregation](#4-high-cardinality-metric-aggregation)
5. [SNS Topic Policy Patterns](#5-sns-topic-policy-patterns)
6. [EventBridge Best Practices](#6-eventbridge-best-practices)
7. [CloudWatch Alarm Best Practices](#7-cloudwatch-alarm-best-practices)
8. [Terraform Provider Pinning](#8-terraform-provider-pinning)
9. [HCL Syntax for EventBridge Patterns](#9-hcl-syntax-for-eventbridge-patterns)

### Lambda Detection Patterns
10. [Anomaly Scoring Over Raw Alerting](#10-anomaly-scoring-over-raw-alerting)
11. [Baseline Storage with TTL](#11-baseline-storage-with-ttl)
12. [Business Context Filtering](#12-business-context-filtering)
13. [Principal and Network Allowlisting](#13-principal-and-network-allowlisting)
14. [Multi-Region Awareness](#14-multi-region-awareness)
15. [Tunable Thresholds with Guidance](#15-tunable-thresholds-with-guidance)

---

## 1. VPC Flow Logs Detection Pattern

### Problem
VPC Flow Logs can detect network scanning and port probing, but default configurations have detection delays and parsing issues.

### Best Practices

#### 1.1 Use 1-Minute Aggregation
Reduce detection latency from 10 minutes to 1 minute:

```hcl
resource "aws_flow_log" "main" {
  vpc_id               = var.vpc_id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn

  # 1-minute aggregation for faster detection
  max_aggregation_interval = 60

  # Explicit log format for reliable parsing
  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status}"
}
```

#### 1.2 Filter by Protocol
For port scanning detection, filter on TCP (protocol=6) to reduce noise:

```hcl
resource "aws_cloudwatch_log_metric_filter" "port_scan" {
  name           = "${var.name_prefix}-rejects"
  log_group_name = aws_cloudwatch_log_group.flow_logs.name

  # Filter TCP (protocol=6) REJECT flows only
  pattern = "[version, accountid, interfaceid, srcaddr, dstaddr, srcport, dstport, protocol=6, packets, bytes, start, end, action=REJECT, logstatus]"

  metric_transformation {
    name          = "PortScanRejects"
    namespace     = "Security/NetworkScanning"
    value         = "1"
    default_value = "0"  # Important for metric math
    dimensions = {
      SourceIP = "$srcaddr"
    }
  }
}
```

#### 1.3 Use Correct Field Names
VPC Flow Logs use specific field names. Map correctly:

| Field | VPC Flow Log Name | Metric Filter Variable |
|-------|-------------------|----------------------|
| Source IP | `srcaddr` | `$srcaddr` |
| Destination IP | `dstaddr` | `$dstaddr` |
| Source Port | `srcport` | `$srcport` |
| Destination Port | `dstport` | `$dstport` |
| Protocol | `protocol` | `$protocol` |
| Action | `action` | `$action` |

---

## 2. GuardDuty Augmentation Pattern

### Problem
Heuristic VPC Flow Logs detection has high false positive rates. GuardDuty provides higher-confidence threat detection using ML and threat intelligence.

### Best Practice: Dual-Signal Architecture

Deploy both signals for comprehensive coverage:

1. **VPC Flow Logs Heuristic** = Continuity/backstop and early warning on reject storms
2. **GuardDuty** = Higher-confidence "recon/scan" classifications with ML

```hcl
# Step 1: VPC Flow Logs heuristic (fast, volume-based)
resource "aws_cloudwatch_metric_alarm" "port_scan" {
  alarm_name = "${var.name_prefix}-heuristic"
  # ... metric filter based detection
}

# Step 2: GuardDuty augmentation (high-confidence)
resource "aws_cloudwatch_event_rule" "guardduty_portscan" {
  name = "${var.name_prefix}-guardduty"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      # Filter by severity >= 4 (medium+)
      severity = [{ numeric = [">=", 4] }]
      type = [
        { prefix = "Recon:EC2/Portscan" },
        { prefix = "Recon:EC2/PortProbeUnprotectedPort" }
      ]
    }
  })
}
```

### GuardDuty Finding Types for Network Scanning

| Finding Type | Description |
|-------------|-------------|
| `Recon:EC2/Portscan` | EC2 instance is performing outbound port scans |
| `Recon:EC2/PortProbeUnprotectedPort` | Unprotected port on EC2 is being probed |
| `Recon:EC2/PortProbeEMRUnprotectedPort` | EMR cluster port is being probed |
| `UnauthorizedAccess:EC2/TorIPCaller` | API called from Tor exit node |

---

## 3. IAM Role Confused-Deputy Mitigation

### Problem
Without proper conditions, IAM roles can be assumed by unintended services (confused deputy attack).

### Best Practice: Add `aws:SourceAccount` and `aws:SourceArn` Conditions

```hcl
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "flow_logs" {
  name = "${var.name_prefix}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnLike = {
          "aws:SourceArn" = "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:vpc-flow-log/*"
        }
      }
    }]
  })
}
```

### CloudFormation Equivalent

```yaml
FlowLogRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Effect: Allow
          Principal:
            Service: vpc-flow-logs.amazonaws.com
          Action: sts:AssumeRole
          Condition:
            StringEquals:
              aws:SourceAccount: !Ref AWS::AccountId
            ArnLike:
              aws:SourceArn: !Sub arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc-flow-log/*
```

---

## 4. High-Cardinality Metric Aggregation

### Problem
When using dimensions like `SourceIP`, metrics create separate time series per IP. Simple `Sum` statistic only gets one series, not the aggregate.

### Best Practice: Use Metric Math with `SUM(SEARCH(...))`

```hcl
resource "aws_cloudwatch_metric_alarm" "port_scan" {
  alarm_name          = "${var.name_prefix}-heuristic"
  alarm_description   = "Heuristic scan signal: high-rate REJECTed flows (aggregated across SourceIP)"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = var.threshold_rejects
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  # Metric math aggregates across all SourceIP dimension values
  metric_query {
    id          = "e1"
    return_data = true
    label       = "TotalPortScanRejects"
    expression  = "SUM(SEARCH('{Security/NetworkScanning,SourceIP} MetricName=\"PortScanRejects\"', 'Sum', 300))"
  }
}
```

### Key Points
- `SEARCH(...)` finds all time series matching the pattern
- `SUM(...)` aggregates them into a single value
- Works with any high-cardinality dimension (IP, user, instance, etc.)
- `default_value = "0"` in metric transformation is required for SEARCH to work correctly

---

## 5. SNS Topic Policy Patterns

### Problem
Without proper SNS topic policies, CloudWatch alarms and EventBridge rules cannot publish to SNS topics.

### Best Practice: Scoped Policies for Both CloudWatch and EventBridge

```hcl
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Alarms
      {
        Sid       = "AllowCloudWatchAlarmsPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      # EventBridge Rules (scoped to specific rule)
      {
        Sid       = "AllowEventBridgePublishScoped"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.detection.arn
          }
        }
      }
    ]
  })
}
```

### Why Both Conditions?
- `AWS:SourceAccount` prevents cross-account abuse
- `aws:SourceArn` (EventBridge only) prevents other rules in same account from publishing

---

## 6. EventBridge Best Practices

### Required Components for Production EventBridge Rules

```hcl
data "aws_caller_identity" "current" {}

# 1. Dead Letter Queue for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600  # 14 days
}

# 2. SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
# Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html
data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.detection.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# 3. EventBridge target with retry, DLQ, and input transformer
resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.detection.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  # Retry policy: 8 attempts, 1-hour max age
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  # Dead letter queue for failed deliveries
  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  # Human-readable alert format
  input_transformer {
    input_paths = {
      time     = "$.time"
      account  = "$.account"
      region   = "$.region"
      type     = "$.detail.type"
      severity = "$.detail.severity"
    }

    input_template = <<-EOT
"Alert: Security Event Detected
time=<time> account=<account> region=<region>
type=<type> severity=<severity>"
EOT
  }
}
```

### Why the SQS Queue Policy is Required

When using EventBridge DLQ via API, CLI, or IaC (Terraform/CloudFormation), you **must** manually add a resource-based policy granting EventBridge permission to send messages. The AWS Console does this automatically, but IaC does not.

Without the policy:
- `InvocationsFailedToBeSentToDLQ` CloudWatch metric will increment
- Failed events are permanently lost
- No error is visible in Terraform plan/apply

### Checklist
- [ ] Dead Letter Queue with 14-day retention
- [ ] **SQS Queue Policy for EventBridge** (CRITICAL - often missed)
- [ ] Retry policy (8 attempts, 3600s max age)
- [ ] Input transformer for human-readable alerts
- [ ] Scoped SNS topic policy

---

## 7. CloudWatch Alarm Best Practices

### Required Settings

```hcl
resource "aws_cloudwatch_metric_alarm" "detection" {
  alarm_name          = "${var.name_prefix}-detected"
  alarm_description   = "Clear description of what this alarm detects"

  # Metric configuration
  metric_name         = "MetricName"
  namespace           = "Security/Detection"
  statistic           = "Sum"
  period              = 300           # 5 minutes recommended
  evaluation_periods  = 1
  threshold           = 50
  comparison_operator = "GreaterThanOrEqualToThreshold"

  # REQUIRED: Prevents INSUFFICIENT_DATA state
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}
```

### Key Settings Explained

| Setting | Recommended Value | Purpose |
|---------|------------------|---------|
| `period` | 300 (5 min) | Balance between speed and noise |
| `evaluation_periods` | 1 | Immediate alerting |
| `treat_missing_data` | `notBreaching` | Prevents false INSUFFICIENT_DATA |
| `comparison_operator` | `GreaterThanOrEqualToThreshold` | Clearer semantics than `GreaterThanThreshold` |

### CloudFormation Equivalent

```yaml
DetectionAlarm:
  Type: AWS::CloudWatch::Alarm
  Properties:
    AlarmName: !Sub ${NamePrefix}-detected
    MetricName: MetricName
    Namespace: Security/Detection
    Statistic: Sum
    Period: 300
    EvaluationPeriods: 1
    Threshold: 50
    ComparisonOperator: GreaterThanOrEqualToThreshold
    TreatMissingData: notBreaching
    AlarmActions:
      - !Ref AlertTopic
```

---

## 8. Terraform Provider Pinning

### Problem
Without explicit provider declarations, Terraform may resolve to unexpected provider versions, causing supply-chain drift or deployment failures.

### Best Practice: Pin All Providers Explicitly

For templates using `data "archive_file"` or other non-AWS providers, always declare them explicitly:

```hcl
terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}
```

### Common Providers in Detection Templates

| Provider | Use Case | Minimum Version |
|----------|----------|-----------------|
| `hashicorp/aws` | AWS resources | `>= 5.0` |
| `hashicorp/archive` | Zipping Lambda code | `>= 2.4.0` |
| `hashicorp/random` | Generating unique names | `>= 3.0` |
| `hashicorp/external` | Running external scripts | `>= 2.0` |

### When to Apply
- Any template using `data "archive_file"` for Lambda deployment
- Any template using `random_id` or `random_string`
- All production-grade templates

---

## 9. HCL Syntax for EventBridge Patterns

### Problem
EventBridge event patterns use keys like `detail-type` with hyphens. Questions arise about whether to quote these keys in Terraform `jsonencode`.

### Best Practice: Quote Hyphenated Keys for Clarity

While HCL allows unquoted identifiers with hyphens, quoting hyphenated keys is recommended for:
- Consistency with JSON semantics
- Clarity when reading the code
- Avoiding ambiguity with complex patterns

```hcl
# Recommended: Quoted keys for clarity
event_pattern = jsonencode({
  "source"      = ["aws.guardduty"]
  "detail-type" = ["GuardDuty Finding"]
  "detail" = {
    "type" = [{ "prefix" = "UnauthorizedAccess:" }]
  }
})

# Also valid: Unquoted (HCL native syntax)
event_pattern = jsonencode({
  source      = ["aws.guardduty"]
  detail-type = ["GuardDuty Finding"]
  detail = {
    type = [{ prefix = "UnauthorizedAccess:" }]
  }
})
```

### Key Points
- Both forms produce identical JSON output
- Quoting is required for keys starting with digits or containing special characters beyond hyphens
- For consistency across templates, prefer the quoted form
- Reference: [Terraform Syntax Documentation](https://developer.hashicorp.com/terraform/language/syntax/configuration)

---

## 10. Anomaly Scoring Over Raw Alerting

### Problem
Sending every matching event to SNS creates noise and alert fatigue.

### Solution
Use a Lambda evaluator that applies scoring logic before alerting.

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

## 11. Baseline Storage with TTL

### Problem
Can't distinguish normal from anomalous without knowing historical patterns.

### Solution
Use DynamoDB with TTL to track per-principal baselines.

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

## 12. Business Context Filtering

### Problem
Alerting on legitimate business-hours activity from known locations.

### Solution
Make business hours configurable and apply time-based suppression.

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

## 13. Principal and Network Allowlisting

### Problem
Automation accounts, break-glass principals, and corporate VPN egress trigger false positives.

### Solution
Configurable allowlists with CIDR matching.

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

## 14. Multi-Region Awareness

### Problem
Some AWS events (ConsoleLogin, global services) have unpredictable region attribution.

### Solution
Document region behaviour and provide deployment guidance.

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

## 15. Tunable Thresholds with Guidance

### Problem
One threshold doesn't fit all SOC maturity levels.

### Solution
Provide configurable thresholds with practical tuning guidance.

```hcl
variable "alert_threshold" {
  type        = number
  default     = 40
  description = "Anomaly score threshold for alerting (0-100)"
}
```

**Practical Tuning Guidance**:

| SOC Tier | Threshold | Notes |
|----------|-----------|-------|
| Tier-1 tripwire | 40 | High volume, catch everything |
| High-confidence | 60 | Low volume, high fidelity |
| Critical only | 80 | Rely on GuardDuty for most signals |

**When to apply**: Any detection with configurable sensitivity.

---

## Implementation Checklist

When creating or improving a remediation template:

### Infrastructure Patterns
- [ ] Is VPC Flow Logs using 1-minute aggregation? (Pattern 1)
- [ ] Is GuardDuty integrated for high-confidence signals? (Pattern 2)
- [ ] Are IAM roles using confused-deputy mitigation? (Pattern 3)
- [ ] Are high-cardinality dimensions using metric math? (Pattern 4)
- [ ] Are SNS policies properly scoped? (Pattern 5)
- [ ] Are EventBridge targets configured with DLQ and retry? (Pattern 6)
- [ ] **Does EventBridge DLQ have SQS queue policy?** (Pattern 6 - CRITICAL)
- [ ] Are CloudWatch alarms using treat_missing_data? (Pattern 7)
- [ ] Are Terraform providers explicitly pinned? (Pattern 8)
- [ ] Are hyphenated keys in jsonencode quoted for clarity? (Pattern 9)

### Lambda Detection Patterns
- [ ] Does raw event volume justify anomaly scoring? (Pattern 10)
- [ ] Would baseline comparison improve fidelity? (Pattern 11)
- [ ] Does business context matter? (Pattern 12)
- [ ] Are there principals/networks to allowlist? (Pattern 13)
- [ ] Is region behaviour predictable? (Pattern 14)
- [ ] Are thresholds documented with tuning guidance? (Pattern 15)

---

## Template Quality Tiers

### Tier 1: Basic
- Raw event → SNS notification
- Single inline Terraform block
- No anomaly logic

### Tier 2: Intermediate
- Event filtering in EventBridge pattern
- Proper infrastructure patterns (DLQ, retry, scoped policies)
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

---

## Templates Requiring These Patterns

### VPC Flow Logs + GuardDuty Pattern
- T1046 - Network Service Discovery (updated)
- T1040 - Network Sniffing
- T1499 - Endpoint Denial of Service
- T1498 - Network Denial of Service

### Confused-Deputy Mitigation
- Any template with IAM roles for AWS services:
  - VPC Flow Logs roles
  - Lambda execution roles
  - ECS task roles
  - CloudWatch Logs roles

### High-Cardinality Aggregation
- Any template using dimensions:
  - SourceIP, DestIP
  - InstanceId, UserId
  - PrincipalId, SessionId

---

## 8. Templates Requiring Improvement

### Priority 1: VPC Flow Logs Templates (60+ templates)

The following templates use VPC Flow Logs and should be reviewed for:
- 1-minute aggregation interval
- Confused-deputy mitigation on IAM roles
- Explicit log format
- GuardDuty augmentation where applicable

**Network Exfiltration:**
- T1011 - Exfiltration Over Other Network Medium
- T1029 - Scheduled Transfer
- T1030 - Data Transfer Size Limits
- T1041 - Exfiltration Over C2 Channel
- T1048 - Exfiltration Over Alternative Protocol (all sub-techniques)
- T1567 - Exfiltration Over Web Service (all sub-techniques)

**Network Attack/Reconnaissance:**
- T1040 - Network Sniffing
- T1498 - Network Denial of Service (all sub-techniques)
- T1499 - Endpoint Denial of Service (where applicable)
- T1557 - Adversary-in-the-Middle (all sub-techniques)
- T1595 - Active Scanning (all sub-techniques)

**Lateral Movement:**
- T1021 - Remote Services
- T1210 - Exploitation of Remote Services
- T1570 - Lateral Tool Transfer

### Priority 2: High-Cardinality Dimension Templates (UPDATED 26 Dec 2025)

Templates using dimensions like `SourceIP`, `UserARN`, `UserName` that need metric math aggregation.
These require `SUM(SEARCH(...))` pattern to properly aggregate across all dimension values.

**COMPLETED:**
- T1078.004 - Cloud Accounts (Strategy 3: User + SourceIP dimensions) - Fixed with metric_query
- T1046 - Network Service Discovery (SourceIP dimension) - Already uses SUM(SEARCH(...))

**Remaining:**
- T1059.009 - Cloud API (UserARN dimension)
- T1111 - MFA Interception (UserName dimension)

### Priority 3: IAM Role Templates

Templates with IAM roles that may need confused-deputy mitigation:
- T1027 - Obfuscated Files or Information
- T1036 - Masquerading
- T1053 - Scheduled Task/Job
- T1059.009 - Cloud API

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 25 Dec 2025 | Architecture Team | Initial release based on T1046 improvements |
| 1.1 | 26 Dec 2025 | Architecture Team | P1: Fixed alarm_actions syntax in 201 templates; P2: Applied SUM(SEARCH(...)) pattern to T1078.004, scoped SNS policies |
| 1.2 | 26 Dec 2025 | Architecture Team | Consolidated docs/architecture/REMEDIATION_TEMPLATE_PATTERNS.md; Added Lambda patterns 8-13, Implementation Checklist, Template Quality Tiers |
| 1.3 | 26 Dec 2025 | Architecture Team | Comprehensive ReAct review: Fixed duplicate treat_missing_data (95 templates), ReAct reviews for T1001/T1003/T1005 with scoped SNS/DLQ/retry; All 262 templates validated |
| 1.4 | 26 Dec 2025 | Architecture Team | Added Pattern 8 (Terraform Provider Pinning), Pattern 9 (HCL Syntax for EventBridge); Updated Pattern 6 with **critical SQS Queue Policy for EventBridge DLQ**; Renumbered Lambda patterns to 10-15 |

---

## Remaining Work (Backlog)

The following improvements have been identified but not yet implemented:

### Critical Priority
- **EventBridge DLQ SQS Queue Policy**: Templates with EventBridge DLQ need `aws_sqs_queue_policy` allowing `events.amazonaws.com` to `sqs:SendMessage`. Without this, failed events are lost silently. Reference: [AWS EventBridge DLQ Documentation](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html)

### High Priority
- **Scoped SNS Policies**: ~168 templates still need `AWS:SourceAccount` conditions added to SNS topic policies
- **DLQ/Retry for EventBridge**: ~150 templates need dead letter queues and retry policies
- **Input Transformers**: ~150 templates need human-readable input transformers on EventBridge targets
- **Terraform Provider Pinning**: Templates using `data "archive_file"` need explicit `hashicorp/archive` provider declaration

### Medium Priority
- **GuardDuty Integration**: Add GuardDuty finding types where applicable (credential access, reconnaissance, etc.)
- **CloudFormation TopicPolicy Scoping**: Add `Condition` blocks to CloudFormation SNS topic policies

### Completed This Session
| Fix | Templates |
|-----|-----------|
| `alarm_actions` syntax errors | 201 |
| Duplicate `treat_missing_data` | 95 |
| Scoped SNS policies (T1001, T1003, T1005) | 3 |
| DLQ/retry/input_transformer (T1003) | 1 |
| All templates syntax validation | 262 ✓ |
