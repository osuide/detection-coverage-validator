# Remediation Template Patterns

**Document Version:** 1.0
**Last Updated:** 25 December 2025
**Classification:** Internal

This document captures lessons learned and best practices for remediation templates in the A13E Detection Coverage Validator.

---

## Table of Contents

1. [VPC Flow Logs Detection Pattern](#1-vpc-flow-logs-detection-pattern)
2. [GuardDuty Augmentation Pattern](#2-guardduty-augmentation-pattern)
3. [IAM Role Confused-Deputy Mitigation](#3-iam-role-confused-deputy-mitigation)
4. [High-Cardinality Metric Aggregation](#4-high-cardinality-metric-aggregation)
5. [SNS Topic Policy Patterns](#5-sns-topic-policy-patterns)
6. [EventBridge Best Practices](#6-eventbridge-best-practices)
7. [CloudWatch Alarm Best Practices](#7-cloudwatch-alarm-best-practices)

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
# 1. Dead Letter Queue for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600  # 14 days
}

# 2. EventBridge target with retry, DLQ, and input transformer
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

### Checklist
- [ ] Dead Letter Queue with 14-day retention
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

### Priority 2: High-Cardinality Dimension Templates

Templates using dimensions like `SourceIP` that need metric math aggregation:
- T1078.004 - Cloud Accounts (uses SourceIP dimension)

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
