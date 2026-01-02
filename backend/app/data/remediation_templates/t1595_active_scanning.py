"""
T1595 - Active Scanning

Adversaries execute active reconnaissance scans to gather targeting information
through direct network probing. Includes IP block scanning, vulnerability scanning,
and wordlist scanning. Used by TEMP.Veles during Triton Safety Instrumented System Attack.
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
    technique_id="T1595",
    technique_name="Active Scanning",
    tactic_ids=["TA0043"],  # Reconnaissance
    mitre_url="https://attack.mitre.org/techniques/T1595/",
    threat_context=ThreatContext(
        description=(
            "Adversaries execute active reconnaissance scans to gather targeting "
            "information through direct network probing. Unlike passive reconnaissance, "
            "active scanning probes victim infrastructure via network traffic and can "
            "utilise network protocol features such as ICMP to identify opportunities "
            "for further attacks or initial access."
        ),
        attacker_goal="Gather targeting information through active network reconnaissance",
        why_technique=[
            "Identify active hosts and services",
            "Discover vulnerabilities before exploitation",
            "Map network infrastructure",
            "Enumerate cloud resources",
            "Identify software versions and configurations",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Pre-compromise reconnaissance technique that enables subsequent attacks. "
            "Whilst occurring outside enterprise defences, successful scanning provides "
            "adversaries with detailed targeting intelligence for exploitation and initial access."
        ),
        business_impact=[
            "Exposure of infrastructure details",
            "Vulnerability enumeration",
            "Precursor to targeted attacks",
            "Cloud resource discovery",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=[
            "T1190",
            "T1210",
            "T1133",
        ],  # Exploit Public-Facing App, Exploitation of Remote Services, External Remote Services
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1595-aws-vpc-flow",
            name="AWS VPC Flow Logs - Port Scanning Detection",
            description="Detect port scanning and network reconnaissance via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, action
| filter action = "REJECT"
| stats count(*) as port_scans by srcaddr, bin(5m)
| filter port_scans > 50
| sort port_scans desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect port scanning via VPC Flow Logs

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

  PortScanFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action="REJECT", flowlogstatus]'
      MetricTransformations:
        - MetricName: RejectedConnections
          MetricNamespace: Security/NetworkScanning
          MetricValue: "1"

  PortScanAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: PortScanningDetected
      MetricName: RejectedConnections
      Namespace: Security/NetworkScanning
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect port scanning via VPC Flow Logs

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "port-scan-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "port_scans" {
  name           = "rejected-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action=REJECT, flowlogstatus]"

  metric_transformation {
    name      = "RejectedConnections"
    namespace = "Security/NetworkScanning"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "port_scanning" {
  alarm_name          = "PortScanningDetected"
  metric_name         = "RejectedConnections"
  namespace           = "Security/NetworkScanning"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

# SNS topic policy for CloudWatch alarms
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
                alert_severity="medium",
                alert_title="Port Scanning Activity Detected",
                alert_description_template="High volume of rejected connections from {srcaddr} indicating port scanning.",
                investigation_steps=[
                    "Review source IP and geolocation",
                    "Analyse scanned ports and patterns",
                    "Check for successful connections from same source",
                    "Review GuardDuty findings for correlation",
                    "Verify if source is legitimate security scanner",
                ],
                containment_actions=[
                    "Block source IP at NACL or security group",
                    "Review and harden security group rules",
                    "Enable GuardDuty if not active",
                    "Consider AWS WAF rules for web services",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised security scanners and monitoring tools",
            detection_coverage="60% - detects network-level scanning",
            evasion_considerations="Slow scanning and distributed scans may evade thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1595-aws-guardduty",
            name="AWS GuardDuty - Reconnaissance Detection",
            description="Detect reconnaissance activity via GuardDuty findings.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Recon:EC2/PortProbeUnprotectedPort",
                    "Recon:EC2/PortProbeEMRUnprotectedPort",
                    "Recon:EC2/Portscan",
                ],
                terraform_template="""# Route GuardDuty reconnaissance findings to alerts

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "guardduty-recon-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "guardduty_recon" {
  name        = "guardduty-reconnaissance"
  description = "Detect reconnaissance via GuardDuty"

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

data "aws_caller_identity" "current" {}

# DLQ for EventBridge
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-recon-dlq"
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
      values   = [aws_cloudwatch_event_rule.guardduty_recon.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "eventbridge_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# EventBridge target with DLQ and retry
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_recon.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      account  = "$.account"
      region   = "$.region"
      time     = "$.time"
      type     = "$.detail.type"
      severity = "$.detail.severity"
    }

    input_template = <<-EOT
"GuardDuty Reconnaissance Alert (T1595)
time=<time> account=<account> region=<region>
type=<type> severity=<severity>"
EOT
  }
}

# Scoped SNS topic policy
resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_recon.arn
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Network Reconnaissance Detected",
                alert_description_template="GuardDuty detected reconnaissance activity against AWS resources.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Identify targeted resources",
                    "Check VPC Flow Logs for full activity",
                    "Verify no successful exploitation occurred",
                    "Correlate with other security findings",
                ],
                containment_actions=[
                    "Block malicious IPs via NACL",
                    "Review security group configurations",
                    "Patch vulnerable services",
                    "Enable additional monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are generally reliable",
            detection_coverage="75% - comprehensive reconnaissance detection",
            evasion_considerations="Very slow or low-volume scans may not trigger findings",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-50 (GuardDuty fees)",
            prerequisites=["GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1595-aws-waf-scanner",
            name="AWS WAF - Web Vulnerability Scanner Detection",
            description="Detect web vulnerability scanning via WAF logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, httpRequest.clientIp, httpRequest.uri, httpRequest.headers
| filter httpRequest.headers.0.name = "User-Agent"
| filter httpRequest.headers.0.value like /Nmap|Nikto|sqlmap|Nessus|OpenVAS|Acunetix|Burp|ZAP/
| stats count(*) as scan_requests by httpRequest.clientIp, bin(10m)
| filter scan_requests > 10
| sort scan_requests desc""",
                terraform_template="""# Detect web vulnerability scanners via WAF

variable "waf_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "vuln-scanner-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "scanner_useragents" {
  name           = "vulnerability-scanner-detection"
  log_group_name = var.waf_log_group
  pattern        = "[Nmap, Nikto, sqlmap, Nessus, OpenVAS, Acunetix, Burp, ZAP]"

  metric_transformation {
    name      = "ScannerActivity"
    namespace = "Security/WebScanning"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "vuln_scanning" {
  alarm_name          = "VulnerabilityScanningDetected"
  metric_name         = "ScannerActivity"
  namespace           = "Security/WebScanning"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
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
                alert_title="Web Vulnerability Scanning Detected",
                alert_description_template="Vulnerability scanner detected from {clientIp}.",
                investigation_steps=[
                    "Identify scanner type from User-Agent",
                    "Review scanned endpoints and parameters",
                    "Check for successful vulnerability exploitation",
                    "Verify if authorised security assessment",
                    "Review application logs for correlation",
                ],
                containment_actions=[
                    "Block scanner IP at WAF",
                    "Review and patch identified vulnerabilities",
                    "Enable additional WAF managed rules",
                    "Implement rate limiting",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised penetration testing IPs",
            detection_coverage="65% - detects known scanner signatures",
            evasion_considerations="Custom or spoofed User-Agents will evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-25",
            prerequisites=["AWS WAF with logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1595-gcp-vpc-flow",
            name="GCP VPC Flow Logs - Port Scanning Detection",
            description="Detect port scanning via GCP VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
log_name="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port>1
jsonPayload.reporter="DEST"
-jsonPayload.connection.dest_port=(22 OR 443 OR 80)""",
                gcp_terraform_template="""# GCP: Detect port scanning via VPC Flow Logs

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "port_scanning" {
  name   = "port-scanning-activity"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    log_name="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port>1
    jsonPayload.reporter="DEST"
    -jsonPayload.connection.dest_port=(22 OR 443 OR 80)
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

resource "google_monitoring_alert_policy" "port_scan_alert" {
  project      = var.project_id
  display_name = "Port Scanning Detected"
  combiner     = "OR"
  conditions {
    display_name = "High port scan activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.port_scanning.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Port Scanning Activity",
                alert_description_template="Port scanning detected against GCP resources.",
                investigation_steps=[
                    "Review source IP and origin",
                    "Analyse targeted ports and services",
                    "Check for successful connections",
                    "Review Security Command Center",
                    "Verify firewall rule effectiveness",
                ],
                containment_actions=[
                    "Create deny firewall rule",
                    "Review and harden firewall rules",
                    "Enable Cloud Armor for web services",
                    "Implement VPC Service Controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate monitoring and authorised scanners",
            detection_coverage="60% - detects network-level scanning",
            evasion_considerations="Slow scanning may evade rate thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1595-gcp-armor-scanner",
            name="GCP Cloud Armor - Scanner Detection",
            description="Detect web scanners via Cloud Armor preconfigured rules.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
jsonPayload.enforcedSecurityPolicy.name:*
jsonPayload.enforcedSecurityPolicy.preconfiguredExprIds:"scannerdetection"
jsonPayload.enforcedSecurityPolicy.outcome="DENY"''',
                gcp_terraform_template="""# GCP: Detect web scanners via Cloud Armor

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "scanner_detection" {
  project = var.project_id
  name   = "cloud-armor-scanner-blocks"
  filter = <<-EOT
    resource.type="http_load_balancer"
    jsonPayload.enforcedSecurityPolicy.preconfiguredExprIds:"scannerdetection"
    jsonPayload.enforcedSecurityPolicy.outcome="DENY"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "scanner_activity" {
  project      = var.project_id
  display_name = "Web Scanner Activity Detected"
  combiner     = "OR"
  conditions {
    display_name = "High scanner block rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.scanner_detection.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Web Scanner Detected",
                alert_description_template="Cloud Armor detected web vulnerability scanner activity.",
                investigation_steps=[
                    "Review blocked scanner requests",
                    "Identify scanner type and source",
                    "Check for successful bypasses",
                    "Review application logs",
                    "Verify if authorised assessment",
                ],
                containment_actions=[
                    "Add custom blocking rules",
                    "Review security policy configuration",
                    "Patch identified vulnerabilities",
                    "Implement rate limiting",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Cloud Armor scanner detection is reliable",
            detection_coverage="70% - detects known scanner patterns",
            evasion_considerations="Custom scanners may evade signature detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$15-30",
            prerequisites=["Cloud Armor with scanner detection rule enabled"],
        ),
    ],
    recommended_order=[
        "t1595-aws-guardduty",
        "t1595-gcp-armor-scanner",
        "t1595-aws-vpc-flow",
        "t1595-gcp-vpc-flow",
        "t1595-aws-waf-scanner",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+15% improvement for Reconnaissance tactic",
)
