"""
T1498 - Network Denial of Service

Adversaries conduct network DoS attacks to degrade or block resource availability
by exhausting network bandwidth. Includes direct floods and reflection amplification.
Used by APT28, Lucifer malware, and NKAbuse malware.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
    CloudProvider,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1498",
    technique_name="Network Denial of Service",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1498/",
    threat_context=ThreatContext(
        description=(
            "Adversaries conduct network denial of service attacks to degrade or block "
            "the availability of targeted resources by exhausting network bandwidth. "
            "Attacks overwhelm systems with malicious traffic that exceeds capacity. "
            "May be single-source (DoS) or distributed (DDoS)."
        ),
        attacker_goal="Exhaust network bandwidth to deny service availability",
        why_technique=[
            "Disrupt business operations",
            "Political/hacktivist motivations",
            "Extortion demands",
            "Distraction during other attacks",
            "Easy to execute with available tools",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "High impact on availability. Can cause complete service outages. "
            "Relatively easy to execute with available tools and botnets. "
            "Often used for extortion or as distraction during other attacks."
        ),
        business_impact=[
            "Service unavailability",
            "Revenue loss",
            "Customer dissatisfaction",
            "Reputational damage",
            "Potential SLA violations",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1498.001", "T1498.002"],
    ),
    detection_strategies=[
        # AWS GuardDuty Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1498-aws-guardduty",
            name="AWS GuardDuty Anomaly Detection",
            description=(
                "AWS GuardDuty detects when EC2 instances are participating in denial of service attacks. These findings indicate that an instance may be compromised and being used to conduct network floods."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/DenialOfService.Dns",
                    "Backdoor:EC2/DenialOfService.Tcp",
                    "Backdoor:EC2/DenialOfService.Udp",
                    "Backdoor:EC2/DenialOfService.UdpOnTcpPorts",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for T1498

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty-T1498-Alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for GuardDuty findings
  GuardDutyRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Capture GuardDuty findings for T1498
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Backdoor:EC2/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt GuardDutyRule.Arn""",
                terraform_template="""# GuardDuty alerts for T1498

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

data "aws_caller_identity" "current" {}

# Step 1: SNS Topic
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "guardduty-t1498-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for findings
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-t1498"
  description = "Capture GuardDuty findings for T1498"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Backdoor:EC2/" }]
    }
  })
}

# Step 3: Target with DLQ and retry
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-t1498-dlq"
  message_retention_seconds = 1209600
}

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
      values   = [aws_cloudwatch_event_rule.guardduty.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "eventbridge_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

# Step 4: SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty.arn }
      }
    }]
  })
}""",
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML baselines; tune suppression rules for known benign patterns",
            detection_coverage="70% - detects anomalous behaviour but may miss attacks that blend with normal activity",
            evasion_considerations="Low-rate attacks, using legitimate traffic patterns, distributed sources",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events",
            prerequisites=[
                "AWS GuardDuty enabled",
                "CloudTrail logging active",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1498-aws-shield",
            name="AWS Shield DDoS Detection",
            description="Detect network DDoS attacks via AWS Shield Advanced metrics.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter eventName = "DDoSDetected"
| stats count(*) as attacks by bin(5m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network DDoS attacks via AWS Shield

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for DDoS alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: DDoS Attack Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Monitor DDoS detected events
  DDoSDetectedAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DDoS-Attack-Detected
      AlarmDescription: Alert on DDoS attack detection
      MetricName: DDoSDetected
      Namespace: AWS/DDoSProtection
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  # Monitor high packet rate
  HighPacketRateAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: High-Packet-Rate
      AlarmDescription: Alert on abnormally high packet rate
      MetricName: DDoSDetected
      Namespace: AWS/DDoSProtection
      Statistic: Sum
      Period: 60
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 2
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect network DDoS attacks via AWS Shield

variable "alert_email" {
  type        = string
  description = "Email address for DDoS alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "aws_sns_topic" "alerts" {
  name         = "ddos-attack-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "DDoS Attack Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Monitor DDoS detected events
resource "aws_cloudwatch_metric_alarm" "ddos_detected" {
  alarm_name          = "DDoS-Attack-Detected"
  alarm_description   = "Alert on DDoS attack detection"
  metric_name         = "DDoSDetected"
  namespace           = "AWS/DDoSProtection"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Monitor high packet rate
resource "aws_cloudwatch_metric_alarm" "high_packet_rate" {
  alarm_name          = "High-Packet-Rate"
  alarm_description   = "Alert on abnormally high packet rate"
  metric_name         = "DDoSDetected"
  namespace           = "AWS/DDoSProtection"
  statistic           = "Sum"
  period              = 60
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

# Scoped SNS topic policy
resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
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
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Network DDoS Attack Detected",
                alert_description_template="DDoS attack detected against AWS resources.",
                investigation_steps=[
                    "Verify attack source and type (volumetric, protocol, application)",
                    "Check affected resources and services",
                    "Review traffic patterns and volume",
                    "Check Shield Advanced metrics for attack details",
                    "Determine if attack is ongoing or mitigated",
                ],
                containment_actions=[
                    "Enable AWS Shield Advanced if not already active",
                    "Contact AWS Shield Response Team (SRT) if Shield Advanced enabled",
                    "Implement rate limiting at application level",
                    "Add WAF rules to block malicious patterns",
                    "Scale resources if needed to handle legitimate traffic",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Shield detection is highly accurate with low false positives",
            detection_coverage="90% - catches volumetric and protocol attacks",
            evasion_considerations="Low-and-slow attacks may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-20 (Shield Standard free, Advanced $3000/month)",
            prerequisites=["AWS Shield Standard (automatic) or Shield Advanced"],
        ),
        DetectionStrategy(
            strategy_id="t1498-aws-flowlogs",
            name="VPC Flow Logs Anomaly Detection",
            description="Detect abnormal network traffic volumes via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, bytes, packets
| filter action = "ACCEPT"
| stats sum(bytes) as total_bytes, sum(packets) as total_packets by srcaddr, bin(5m)
| filter total_bytes > 100000000 or total_packets > 100000
| sort total_bytes desc""",
                terraform_template="""# Detect network floods via VPC Flow Logs

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "network-flood-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for high traffic volume
resource "aws_cloudwatch_log_metric_filter" "high_traffic" {
  name           = "high-network-traffic"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets>100000, bytes, start, end, action=\"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "HighNetworkTraffic"
    namespace = "Security/Network"
    value     = "1"
  }
}

# Alert on high traffic volume
resource "aws_cloudwatch_metric_alarm" "network_flood" {
  alarm_name          = "Network-Flood-Detected"
  alarm_description   = "Alert on abnormally high network traffic"
  metric_name         = "HighNetworkTraffic"
  namespace           = "Security/Network"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

# Scoped SNS topic policy
resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
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
    }]
  })
}""",
                alert_severity="high",
                alert_title="Network Flood Detected",
                alert_description_template="Abnormally high network traffic from {srcaddr}.",
                investigation_steps=[
                    "Identify source IPs and patterns",
                    "Check if traffic is legitimate (e.g., backups, migrations)",
                    "Review affected destination resources",
                    "Analyse traffic protocol and ports",
                    "Check for multiple sources (DDoS vs single-source)",
                ],
                containment_actions=[
                    "Block attacking IPs via NACLs or security groups",
                    "Enable rate limiting",
                    "Contact ISP for upstream filtering",
                    "Scale resources temporarily if needed",
                    "Implement geo-blocking if applicable",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate high-volume sources (backups, CDN)",
            detection_coverage="70% - catches high-volume floods",
            evasion_considerations="Distributed low-volume attacks may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-20 depending on flow log volume",
            prerequisites=["VPC Flow Logs enabled and sent to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1498-gcp-armor-ddos",
            name="GCP Cloud Armor DDoS Detection",
            description="Detect network DDoS attacks via Cloud Armor adaptive protection.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_armor",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
jsonPayload.enforcedSecurityPolicy.name=~"ddos|adaptive"
jsonPayload.enforcedSecurityPolicy.outcome="DENY"''',
                gcp_terraform_template="""# GCP: Detect DDoS attacks via Cloud Armor

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}
variable "alert_email" {
  type        = string
  description = "Email address for DDoS alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "DDoS Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log-based metric for DDoS blocks
resource "google_logging_metric" "ddos_blocks" {
  name    = "ddos-attack-blocks"
  project = var.project_id
  filter  = <<-EOT
    resource.type="http_load_balancer"
    jsonPayload.enforcedSecurityPolicy.name=~"ddos|adaptive"
    jsonPayload.enforcedSecurityPolicy.outcome="DENY"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP of attack"
    }
  }
  label_extractors = {
    "source_ip" = "EXTRACT(jsonPayload.remoteIp)"
  }
}

# Alert on DDoS detection
resource "google_monitoring_alert_policy" "ddos_attack" {
  project      = var.project_id
  display_name = "DDoS Attack Detected"
  combiner     = "OR"

  conditions {
    display_name = "High rate of DDoS blocks"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ddos_blocks.name}\" AND resource.type=\"http_load_balancer\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "3600s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "DDoS attack detected by Cloud Armor adaptive protection. Review blocked traffic and ensure legitimate users can access services."
  }
}""",
                alert_severity="critical",
                alert_title="GCP: DDoS Attack Detected",
                alert_description_template="Cloud Armor detected and is mitigating a DDoS attack.",
                investigation_steps=[
                    "Review Cloud Armor logs for attack characteristics",
                    "Check blocked traffic patterns and source IPs",
                    "Verify legitimate users are not affected",
                    "Analyse attack vector (volumetric, protocol, application)",
                    "Check if attack is ongoing or mitigated",
                ],
                containment_actions=[
                    "Enable adaptive protection if not already active",
                    "Configure rate limiting policies",
                    "Add custom Cloud Armor rules for observed patterns",
                    "Implement geo-blocking if attack sources are regional",
                    "Scale backend services if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Cloud Armor adaptive protection has low false positives",
            detection_coverage="85% - catches most network and application-layer DDoS",
            evasion_considerations="Sophisticated low-and-slow attacks may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$20-50 depending on traffic volume",
            prerequisites=["Cloud Armor with adaptive protection enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1498-gcp-vpc-flow",
            name="GCP VPC Flow Logs Anomaly Detection",
            description="Detect abnormal network traffic volumes via VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName=~"vpc_flows"
jsonPayload.bytes_sent > 100000000""",
                gcp_terraform_template="""# GCP: Detect network floods via VPC Flow Logs

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Network Flood Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log-based metric for high traffic volume
resource "google_logging_metric" "high_traffic" {
  name    = "high-network-traffic"
  project = var.project_id
  filter  = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"vpc_flows"
    jsonPayload.bytes_sent > 100000000
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP of high traffic"
    }
  }
  label_extractors = {
    "source_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
  }
}

# Alert on network flood
resource "google_monitoring_alert_policy" "network_flood" {
  project      = var.project_id
  display_name = "Network Flood Detected"
  combiner     = "OR"

  conditions {
    display_name = "Abnormally high network traffic"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.high_traffic.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "Network flood detected via VPC Flow Logs. Investigate source IPs and traffic patterns."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Network Flood Detected",
                alert_description_template="Abnormally high network traffic detected in VPC.",
                investigation_steps=[
                    "Identify source and destination IPs",
                    "Check if traffic is legitimate",
                    "Review traffic protocol and patterns",
                    "Analyse geographical distribution of sources",
                    "Check for business impact",
                ],
                containment_actions=[
                    "Block attacking IPs via firewall rules",
                    "Enable Cloud Armor for load-balanced services",
                    "Implement rate limiting",
                    "Contact upstream provider for filtering",
                    "Scale resources if needed for legitimate traffic",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate high-volume operations",
            detection_coverage="70% - catches high-volume floods",
            evasion_considerations="Distributed low-volume attacks may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30 depending on flow log volume",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        # Azure Strategy: Network Denial of Service
        DetectionStrategy(
            strategy_id="t1498-azure",
            name="Azure Network Denial of Service Detection",
            description=(
                "Detect network DDoS attacks using Azure DDoS Protection, Network Watcher, "
                "and Defender for Cloud. Monitors for volumetric attacks, protocol attacks, "
                "and application-layer floods targeting Azure resources."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "DDOS Attack detected",
                    "DDOS Attack mitigated",
                    "Network flood attack detected",
                ],
                azure_kql_query="""// Azure DDoS Protection - Network Denial of Service Detection
// MITRE ATT&CK: T1498 - Network Denial of Service
// Detects DDoS attacks against Azure resources

// DDoS Protection alerts and mitigation events
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where Category == "DDoSProtectionNotifications" or Category == "DDoSMitigationFlowLogs"
| where Message has_any ("attack", "mitigation", "DDoS", "flood")
| project
    TimeGenerated,
    ResourceId,
    Category,
    Message,
    publicIpAddress_s,
    attackType_s,
    mitigationStatus_s,
    bytesDropped_d,
    packetsDropped_d
| order by TimeGenerated desc

// Alternative: Network Watcher flow logs for traffic anomalies
// AzureNetworkAnalytics_CL
// | where TimeGenerated > ago(1h)
// | where FlowType_s == "ExternalPublic"
// | summarize TotalBytes = sum(BytesSent_d + BytesReceived_d),
//             TotalPackets = sum(PacketsSent_d + PacketsReceived_d)
//     by bin(TimeGenerated, 5m), DestinationIP_s
// | where TotalBytes > 1000000000 or TotalPackets > 1000000
// | project TimeGenerated, DestinationIP_s, TotalBytes, TotalPackets""",
                sentinel_rule_query="""// Sentinel Analytics Rule: Network Denial of Service Detection
// MITRE ATT&CK: T1498 - Network Denial of Service
let lookback = 1h;
let traffic_threshold = 500000000;  // 500MB in 5 minutes
let packet_threshold = 500000;       // 500K packets in 5 minutes

// Detection 1: DDoS Protection alerts
let ddos_alerts = AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where Category == "DDoSProtectionNotifications"
| where Message has_any ("attack", "mitigation", "DDoS")
| extend AttackType = coalesce(attackType_s, "Unknown")
| project
    TimeGenerated,
    DetectionSource = "DDoS Protection",
    ResourceId,
    AttackType,
    MitigationStatus = mitigationStatus_s,
    PublicIP = publicIpAddress_s,
    BytesDropped = bytesDropped_d,
    PacketsDropped = packetsDropped_d,
    Severity = "High";

// Detection 2: Network traffic anomalies from flow logs
let traffic_anomalies = AzureNetworkAnalytics_CL
| where TimeGenerated > ago(lookback)
| where FlowType_s == "ExternalPublic"
| summarize
    TotalBytes = sum(BytesSent_d + BytesReceived_d),
    TotalPackets = sum(PacketsSent_d + PacketsReceived_d),
    DistinctSources = dcount(SourceIP_s)
    by bin(TimeGenerated, 5m), DestinationIP_s
| where TotalBytes > traffic_threshold or TotalPackets > packet_threshold
| extend AttackType = case(
    TotalPackets > packet_threshold and TotalBytes < traffic_threshold, "Packet Flood",
    TotalBytes > traffic_threshold and TotalPackets < packet_threshold, "Volumetric",
    "Mixed Attack")
| project
    TimeGenerated,
    DetectionSource = "Network Analytics",
    ResourceId = "",
    AttackType,
    MitigationStatus = "Detected",
    PublicIP = DestinationIP_s,
    BytesDropped = TotalBytes,
    PacketsDropped = TotalPackets,
    Severity = "Medium";

// Detection 3: Security alerts from Defender
let security_alerts = SecurityAlert
| where TimeGenerated > ago(lookback)
| where ProductName has_any ("Azure Defender", "Microsoft Defender")
| where AlertName has_any ("DDoS", "flood", "denial of service", "network attack")
| project
    TimeGenerated,
    DetectionSource = "Defender for Cloud",
    ResourceId = tostring(parse_json(ExtendedProperties)["ResourceId"]),
    AttackType = AlertName,
    MitigationStatus = Status,
    PublicIP = tostring(parse_json(ExtendedProperties)["DestinationIp"]),
    BytesDropped = 0.0,
    PacketsDropped = 0.0,
    Severity = AlertSeverity;

// Combine all detection sources
ddos_alerts
| union traffic_anomalies
| union security_alerts
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    EventCount = count(),
    DetectionSources = make_set(DetectionSource),
    AttackTypes = make_set(AttackType),
    TotalBytesDropped = sum(BytesDropped),
    TotalPacketsDropped = sum(PacketsDropped)
    by PublicIP, Severity
| project
    TimeGenerated = LastSeen,
    PublicIP,
    Severity,
    EventCount,
    FirstSeen,
    AttackTypes,
    DetectionSources,
    TotalBytesDropped,
    TotalPacketsDropped
| order by Severity asc, EventCount desc""",
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Network Denial of Service (T1498)
# Microsoft Defender detects Network Denial of Service activity

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1498-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1498"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (

                    "Network intrusion detection signature activation",
                    "Anomalous network protocol usage",
                    "Detected suspicious network activity"
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Network Denial of Service activity"
  display_name = "Defender: Network Denial of Service"
  enabled      = true

  tags = {
    "mitre-technique" = "T1498"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Network Denial of Service Detected",
                alert_description_template=(
                    "Network Denial of Service activity detected. "
                    "Caller: {Caller}. Resource: {Resource}."
                ),
                investigation_steps=[
                    "Review Azure Activity Log for full operation details",
                    "Check caller identity and verify if authorised",
                    "Review affected resources and assess impact",
                    "Check for related activities in the same time window",
                    "Verify against change management records",
                ],
                containment_actions=[
                    "Disable compromised user/service principal if unauthorised",
                    "Revoke active sessions using Entra ID",
                    "Review and restrict Azure RBAC permissions",
                    "Enable additional Defender for Cloud protections",
                    "Implement Azure Policy to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Allowlist known automation accounts and CI/CD service principals. "
                "Use Azure Policy to define expected behaviour baselines."
            ),
            detection_coverage="70% - Azure-native detection for cloud operations",
            evasion_considerations=(
                "Attackers may use legitimate credentials from expected locations. "
                "Combine with Defender for Cloud for ML-based anomaly detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-50 (Log Analytics + Defender)",
            prerequisites=[
                "Azure subscription with Log Analytics workspace",
                "Defender for Cloud enabled (recommended)",
                "Appropriate Azure RBAC permissions for deployment",
            ],
        ),
    ],
    recommended_order=[
        "t1498-aws-shield",
        "t1498-gcp-armor-ddos",
        "t1498-aws-flowlogs",
        "t1498-gcp-vpc-flow",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+30% improvement for Impact tactic",
)
