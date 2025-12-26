"""
T1595.001 - Active Scanning: Scanning IP Blocks

Adversaries scan victim IP blocks to gather reconnaissance information during targeting.
Includes probing sequential IP ranges to identify active hosts and gather system details.
Used by Ember Bear, TeamTNT.
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
    technique_id="T1595.001",
    technique_name="Active Scanning: Scanning IP Blocks",
    tactic_ids=["TA0043"],  # Reconnaissance
    mitre_url="https://attack.mitre.org/techniques/T1595/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries scan victim IP blocks to gather reconnaissance information "
            "during the targeting phase. This involves probing sequential IP address "
            "ranges allocated to organisations to identify active hosts and gather "
            "detailed information about assigned systems through server banners and "
            "network artefacts."
        ),
        attacker_goal="Identify active IP addresses and gather reconnaissance information for targeting",
        why_technique=[
            "Identify which IP addresses are actively in use",
            "Gather detailed host information for further reconnaissance",
            "Discover opportunities for vulnerability assessment",
            "Establish operational infrastructure understanding",
            "Discover initial access points",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=6,
        severity_reasoning=(
            "Pre-compromise reconnaissance technique. While not directly harmful, "
            "scanning activity often precedes targeted attacks and indicates active "
            "threat actor interest in the organisation's infrastructure."
        ),
        business_impact=[
            "Indicates targeted reconnaissance",
            "Precedes vulnerability scanning",
            "May lead to exploitation attempts",
            "Reveals exposed infrastructure",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=[
            "T1595.002",
            "T1190",
            "T1133",
        ],  # Vulnerability Scanning, Exploit Public-Facing Application, External Remote Services
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1595.001-aws-vpc-flow",
            name="AWS VPC Flow Logs Scanning Detection",
            description="Detect IP scanning patterns via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, action
| filter action = "REJECT"
| stats count(*) as attempts, count_distinct(dstport) as unique_ports by srcaddr, bin(5m)
| filter attempts > 50 or unique_ports > 20
| sort attempts desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IP scanning via VPC Flow Logs

Parameters:
  VPCFlowLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  ScanningFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action="REJECT", flowlogstatus]'
      MetricTransformations:
        - MetricName: RejectedConnections
          MetricNamespace: Security/Scanning
          MetricValue: "1"
          DefaultValue: 0

  ScanningAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: IPScanningDetected
      MetricName: RejectedConnections
      Namespace: Security/Scanning
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect IP scanning via VPC Flow Logs

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ip-scanning-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "scanning" {
  name           = "rejected-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action=\"REJECT\", flowlogstatus]"

  metric_transformation {
    name      = "RejectedConnections"
    namespace = "Security/Scanning"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "scanning_detected" {
  alarm_name          = "IPScanningDetected"
  metric_name         = "RejectedConnections"
  namespace           = "Security/Scanning"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="IP Scanning Activity Detected",
                alert_description_template="High volume of rejected connections from {srcaddr} indicating scanning behaviour.",
                investigation_steps=[
                    "Review source IP reputation and geolocation",
                    "Analyse targeted ports and services",
                    "Check for successful connections from same source",
                    "Review other security logs for related activity",
                    "Verify if scanning progressed to exploitation attempts",
                ],
                containment_actions=[
                    "Block source IP at network perimeter",
                    "Review and harden exposed services",
                    "Enable AWS Shield for DDoS protection",
                    "Update security group rules to reduce exposure",
                    "Consider implementing AWS WAF rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune thresholds based on normal traffic patterns. Security scanners and monitoring tools may trigger false positives.",
            detection_coverage="60% - catches sequential scanning patterns",
            evasion_considerations="Slow scans distributed over time or using multiple source IPs may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["VPC Flow Logs enabled and sent to CloudWatch Logs"],
        ),
        DetectionStrategy(
            strategy_id="t1595.001-aws-guardduty",
            name="AWS GuardDuty Reconnaissance Detection",
            description="Detect scanning activity via GuardDuty findings.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Recon:EC2/PortProbeUnprotectedPort",
                    "Recon:EC2/PortProbeEMRUnprotectedPort",
                    "Recon:EC2/Portscan",
                ],
                terraform_template="""# Enable GuardDuty scanning detection

variable "alert_email" { type = string }

resource "aws_guardduty_detector" "main" {
  enable = true

  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-scanning-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for EventBridge targets
resource "aws_sqs_queue" "events_dlq" {
  name                      = "guardduty-scanning-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "events_dlq" {
  queue_url = aws_sqs_queue.events_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.events_dlq.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "guardduty_scanning" {
  name        = "guardduty-scanning-findings"
  description = "Capture GuardDuty scanning findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Recon:EC2/PortProbeUnprotectedPort",
        "Recon:EC2/PortProbeEMRUnprotectedPort",
        "Recon:EC2/Portscan"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_scanning.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.events_dlq.arn
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.guardduty_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_scanning.arn
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Port Scanning Activity Detected",
                alert_description_template="GuardDuty detected port scanning or probing activity targeting your infrastructure.",
                investigation_steps=[
                    "Review GuardDuty finding details and severity",
                    "Identify targeted resources and ports",
                    "Check source IP reputation",
                    "Review VPC Flow Logs for detailed connection patterns",
                    "Determine if scanning was successful",
                    "Check for follow-on exploitation attempts",
                ],
                containment_actions=[
                    "Block malicious IPs via NACL or security groups",
                    "Review and restrict security group rules",
                    "Enable AWS Shield Advanced if needed",
                    "Patch and harden targeted services",
                    "Consider moving services behind load balancers",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are generally reliable. Review trusted IP list configuration.",
            detection_coverage="80% - comprehensive coverage of known scanning patterns",
            evasion_considerations="Sophisticated slow scans may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="15-30 minutes",
            estimated_monthly_cost="$30-50 for GuardDuty service",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1595.001-gcp-vpc-flow",
            name="GCP VPC Flow Logs Scanning Detection",
            description="Detect IP scanning patterns via GCP VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
log_name="projects/YOUR_PROJECT/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_ip="YOUR_IP_RANGE"
jsonPayload.connection.protocol=6
NOT jsonPayload.packets_sent>10""",
                gcp_terraform_template="""# GCP: Detect IP scanning via VPC Flow Logs

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "vpc_scanning" {
  name   = "vpc-scanning-attempts"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    log_name="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.protocol=6
    NOT jsonPayload.packets_sent>10
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }
  label_extractors = {
    "source_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
  }
}

resource "google_monitoring_alert_policy" "scanning_detected" {
  display_name = "IP Scanning Activity Detected"
  combiner     = "OR"
  conditions {
    display_name = "High rate of connection attempts"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.vpc_scanning.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content = "VPC Flow Logs detected scanning activity from external source."
  }
}""",
                alert_severity="medium",
                alert_title="GCP: IP Scanning Activity Detected",
                alert_description_template="High rate of connection attempts detected in VPC Flow Logs.",
                investigation_steps=[
                    "Review VPC Flow Logs for source IP patterns",
                    "Analyse targeted ports and services",
                    "Check Cloud Logging for successful connections",
                    "Review firewall rules and their effectiveness",
                    "Verify if scanning progressed to exploitation",
                ],
                containment_actions=[
                    "Add deny rules to VPC firewall",
                    "Enable Cloud Armor if using load balancers",
                    "Review and restrict firewall rules",
                    "Consider enabling Cloud IDS for deep inspection",
                    "Harden exposed services",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on legitimate traffic patterns. Monitoring services may cause alerts.",
            detection_coverage="60% - catches sequential scanning patterns",
            evasion_considerations="Distributed or slow scanning may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1595.001-gcp-cloud-ids",
            name="GCP Cloud IDS Scanning Detection",
            description="Detect reconnaissance scanning with Cloud IDS.",
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                scc_finding_categories=[
                    "NETWORK_RECONNAISSANCE",
                    "PORT_SCAN",
                    "VULNERABILITY_SCAN",
                ],
                gcp_terraform_template="""# GCP: Deploy Cloud IDS for scanning detection

variable "project_id" { type = string }
variable "network_name" { type = string }
variable "zone" { type = string }
variable "alert_email" { type = string }

resource "google_compute_network_endpoint_group" "ids_neg" {
  name         = "cloud-ids-neg"
  network      = var.network_name
  default_port = "443"
  zone         = var.zone
}

resource "google_ids_endpoint" "scanning_detection" {
  name     = "scanning-detection-endpoint"
  location = var.zone
  network  = var.network_name
  severity = "INFORMATIONAL"

  threat_exceptions = []
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_monitoring_alert_policy" "ids_alerts" {
  display_name = "Cloud IDS Scanning Alerts"
  combiner     = "OR"
  conditions {
    display_name = "Scanning activity detected"
    condition_monitoring_query_language {
      query = <<-EOQ
        fetch ids.googleapis.com/Endpoint
        | metric 'ids.googleapis.com/endpoint/alert_count'
        | filter resource.endpoint_id == '${google_ids_endpoint.scanning_detection.name}'
        | group_by 5m, [value_alert_count_mean: mean(value.alert_count)]
        | condition value_alert_count_mean > 10
      EOQ
      duration = "300s"
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content = "Cloud IDS detected reconnaissance or scanning activity."
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Network Reconnaissance Detected",
                alert_description_template="Cloud IDS detected network scanning or reconnaissance activity.",
                investigation_steps=[
                    "Review Cloud IDS alerts and threat details",
                    "Identify targeted resources and attack patterns",
                    "Check Security Command Centre findings",
                    "Analyse VPC Flow Logs for additional context",
                    "Determine threat severity and scope",
                ],
                containment_actions=[
                    "Block malicious IPs via VPC firewall",
                    "Enable Cloud Armor rules",
                    "Harden targeted services",
                    "Review network segmentation",
                    "Consider implementing additional IDS/IPS rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Cloud IDS provides high-fidelity alerts. Configure threat exceptions as needed.",
            detection_coverage="85% - comprehensive signature-based detection",
            evasion_considerations="Encrypted traffic may reduce visibility",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$150-300+ for Cloud IDS service",
            prerequisites=[
                "Cloud IDS endpoint deployed",
                "Security Command Centre enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1595.001-aws-guardduty",
        "t1595.001-gcp-cloud-ids",
        "t1595.001-aws-vpc-flow",
        "t1595.001-gcp-vpc-flow",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+15% improvement for Reconnaissance tactic",
)
