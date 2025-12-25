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
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
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

resource "google_monitoring_notification_channel" "email" {
  display_name = "DDoS Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
  project      = var.project_id
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
  display_name = "DDoS Attack Detected"
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "3600s"
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

resource "google_monitoring_notification_channel" "email" {
  display_name = "Network Flood Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
  project      = var.project_id
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
  display_name = "Network Flood Detected"
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email.id]

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
