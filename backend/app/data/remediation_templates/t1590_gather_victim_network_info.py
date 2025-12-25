"""
T1590 - Gather Victim Network Information

Adversaries collect information about victim networks for targeting purposes,
including IP ranges, domain names, network topology, and security appliances.
Used by HAFNIUM, Indrik Spider, Volt Typhoon.
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
    technique_id="T1590",
    technique_name="Gather Victim Network Information",
    tactic_ids=["TA0043"],
    mitre_url="https://attack.mitre.org/techniques/T1590/",
    threat_context=ThreatContext(
        description=(
            "Adversaries collect information about victim networks including "
            "administrative data (IP ranges, domain names) and operational specifics "
            "(topology, trust dependencies, security appliances). Collection methods "
            "include active scanning, phishing for information, and accessing publicly "
            "available technical databases. This intelligence supports subsequent "
            "reconnaissance, infrastructure establishment, and initial access activities."
        ),
        attacker_goal="Gather network information to enable targeting and initial access planning",
        why_technique=[
            "Identifies attack surface and entry points",
            "Maps network topology for lateral movement planning",
            "Discovers security controls to evade",
            "Identifies trust relationships to exploit",
            "Often performed from outside organisational visibility",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Pre-compromise reconnaissance technique that enables subsequent attacks. "
            "While not directly harmful, it significantly increases the likelihood of "
            "successful initial access and targeted attacks."
        ),
        business_impact=[
            "Enables targeted attacks",
            "Reveals organisational infrastructure",
            "Exposes security control placement",
            "Facilitates social engineering",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1595", "T1592", "T1589", "T1133", "T1190"],
        often_follows=["T1591", "T1589"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1590-aws-guardduty",
            name="AWS GuardDuty Reconnaissance Detection",
            description="Detect network reconnaissance via GuardDuty findings.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.type, detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4
| filter detail.type like /Recon:EC2|Discovery:S3|UnauthorizedAccess:EC2/
| filter detail.type like /PortProbeUnprotectedPort|PortProbeEMRUnprotectedPort|Portscan/
| stats count(*) as recon_events by detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4, bin(1h)
| filter recon_events > 5
| sort recon_events desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network reconnaissance via GuardDuty

Parameters:
  GuardDutyLogGroup:
    Type: String
    Default: /aws/guardduty
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  ReconFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref GuardDutyLogGroup
      FilterPattern: '{ $.detail.type = "Recon:*" || $.detail.type = "*Portscan*" || $.detail.type = "*PortProbe*" }'
      MetricTransformations:
        - MetricName: NetworkReconnaissance
          MetricNamespace: Security/Reconnaissance
          MetricValue: "1"

  ReconAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: NetworkReconnaissanceDetected
      MetricName: NetworkReconnaissance
      Namespace: Security/Reconnaissance
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect network reconnaissance via GuardDuty

variable "guardduty_log_group" {
  type    = string
  default = "/aws/guardduty"
}
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "network-recon-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "recon" {
  name           = "network-reconnaissance"
  log_group_name = var.guardduty_log_group
  pattern        = "{ $.detail.type = \"Recon:*\" || $.detail.type = \"*Portscan*\" || $.detail.type = \"*PortProbe*\" }"

  metric_transformation {
    name      = "NetworkReconnaissance"
    namespace = "Security/Reconnaissance"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "recon_activity" {
  alarm_name          = "NetworkReconnaissanceDetected"
  metric_name         = "NetworkReconnaissance"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Network Reconnaissance Detected",
                alert_description_template="GuardDuty detected reconnaissance activity from {remoteIp}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Check source IP reputation",
                    "Identify targeted resources",
                    "Review VPC Flow Logs for scanning patterns",
                    "Check for successful access attempts",
                ],
                containment_actions=[
                    "Block source IP in NACLs/security groups",
                    "Review and harden security group rules",
                    "Enable VPC Flow Logs if not active",
                    "Verify no unauthorised access occurred",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are high-confidence detections",
            detection_coverage="60% - detects active scanning within AWS",
            evasion_considerations="Slow/distributed scans may evade thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-20",
            prerequisites=["AWS GuardDuty enabled", "CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1590-aws-vpc-flow",
            name="VPC Flow Logs Scanning Detection",
            description="Detect port scanning and network enumeration via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, action
| filter action = "REJECT"
| stats count(*) as rejected_ports, count_distinct(dstport) as unique_ports by srcaddr, dstaddr, bin(5m)
| filter unique_ports > 10
| sort unique_ports desc""",
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
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  PortScanFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action = "REJECT", log_status]'
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
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
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
  name           = "port-scanning"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action = \"REJECT\", log_status]"

  metric_transformation {
    name      = "RejectedConnections"
    namespace = "Security/NetworkScanning"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "scanning_activity" {
  alarm_name          = "PortScanningDetected"
  metric_name         = "RejectedConnections"
  namespace           = "Security/NetworkScanning"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Port Scanning Activity Detected",
                alert_description_template="High volume of rejected connections from {srcaddr} to {dstaddr}.",
                investigation_steps=[
                    "Identify source IP and destination targets",
                    "Review connection patterns and ports targeted",
                    "Check threat intelligence for source IP",
                    "Determine if scanning was successful",
                    "Review related CloudTrail events",
                ],
                containment_actions=[
                    "Block scanning IP in NACLs",
                    "Review security group configurations",
                    "Enable GuardDuty if not active",
                    "Check for any successful connections",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on normal rejected connection volume",
            detection_coverage="50% - detects scanning against AWS resources",
            evasion_considerations="Slow scans below threshold may not trigger",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-40",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1590-aws-route53",
            name="Route53 DNS Reconnaissance Detection",
            description="Detect DNS enumeration attempts via Route53 query logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, query_name, rcode
| filter rcode = "NXDOMAIN"
| stats count(*) as failed_queries, count_distinct(query_name) as unique_queries by srcaddr, bin(5m)
| filter unique_queries > 20
| sort unique_queries desc""",
                terraform_template="""# Detect DNS enumeration via Route53 query logs

variable "route53_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "dns-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "dns_enum" {
  name           = "dns-enumeration"
  log_group_name = var.route53_log_group
  pattern        = "{ $.rcode = \"NXDOMAIN\" }"

  metric_transformation {
    name      = "DNSEnumeration"
    namespace = "Security/Reconnaissance"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "dns_recon" {
  alarm_name          = "DNSReconnaissanceDetected"
  metric_name         = "DNSEnumeration"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="low",
                alert_title="DNS Enumeration Detected",
                alert_description_template="High volume of NXDOMAIN responses to {srcaddr}.",
                investigation_steps=[
                    "Review query patterns for enumeration techniques",
                    "Identify source IP and check reputation",
                    "Determine if any queries were successful",
                    "Check for zone transfer attempts",
                    "Review DNS records for sensitive information exposure",
                ],
                containment_actions=[
                    "Rate-limit DNS queries if possible",
                    "Review DNS record visibility",
                    "Consider hiding infrastructure details",
                    "Block malicious source if confirmed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on legitimate failed query volume",
            detection_coverage="40% - detects DNS enumeration patterns",
            evasion_considerations="Slow enumeration may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Route53 query logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1590-gcp-vpc-flow",
            name="GCP VPC Flow Logs Scanning Detection",
            description="Detect network scanning via GCP VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port>1024
jsonPayload.reporter="DEST"''',
                gcp_terraform_template="""# GCP: Detect network scanning via VPC Flow Logs

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "port_scanning" {
  name   = "vpc-port-scanning"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port>1024
    jsonPayload.reporter="DEST"
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

resource "google_monitoring_alert_policy" "scanning_detection" {
  display_name = "Network Scanning Detected"
  combiner     = "OR"
  conditions {
    display_name = "High scanning activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.port_scanning.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Network Scanning Detected",
                alert_description_template="Port scanning activity detected in VPC.",
                investigation_steps=[
                    "Review VPC Flow Logs for scanning patterns",
                    "Identify source and destination IPs",
                    "Check source IP reputation",
                    "Determine ports and services targeted",
                    "Review firewall rules",
                ],
                containment_actions=[
                    "Update firewall rules to block source",
                    "Review and harden security configurations",
                    "Enable Cloud Armor if applicable",
                    "Verify no successful access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on normal network activity",
            detection_coverage="50% - detects scanning within GCP",
            evasion_considerations="Slow scans may evade threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1590-gcp-cloud-dns",
            name="GCP Cloud DNS Query Analysis",
            description="Detect DNS enumeration via Cloud DNS query logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="dns_query"
resource.labels.target_type="public-zone"
jsonPayload.rdata=""
severity="ERROR"''',
                gcp_terraform_template="""# GCP: Detect DNS enumeration via Cloud DNS

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "dns_enumeration" {
  name   = "dns-enumeration-attempts"
  filter = <<-EOT
    resource.type="dns_query"
    resource.labels.target_type="public-zone"
    jsonPayload.rdata=""
    severity="ERROR"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "dns_recon" {
  display_name = "DNS Enumeration Detected"
  combiner     = "OR"
  conditions {
    display_name = "High failed query rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_enumeration.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="low",
                alert_title="GCP: DNS Enumeration Detected",
                alert_description_template="High volume of failed DNS queries detected.",
                investigation_steps=[
                    "Review query patterns",
                    "Identify source of queries",
                    "Check for successful resolutions",
                    "Review DNS zone configurations",
                    "Determine exposed information",
                ],
                containment_actions=[
                    "Review DNS record visibility",
                    "Consider private DNS zones",
                    "Implement rate limiting",
                    "Audit sensitive DNS records",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal failed query volume",
            detection_coverage="40% - detects DNS enumeration patterns",
            evasion_considerations="Slow enumeration evades rate thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud DNS query logging enabled"],
        ),
    ],
    recommended_order=[
        "t1590-aws-guardduty",
        "t1590-gcp-vpc-flow",
        "t1590-aws-vpc-flow",
        "t1590-aws-route53",
        "t1590-gcp-cloud-dns",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+15% improvement for Reconnaissance tactic",
)
