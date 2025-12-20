"""
T1041 - Exfiltration Over C2 Channel

Adversaries steal data by exfiltrating it over an existing command and control channel.
Used by Lazarus Group, APT39, Kimsuky, and over 200+ malware families.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    Campaign,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
    CloudProvider,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1041",
    technique_name="Exfiltration Over C2 Channel",
    tactic_ids=["TA0010"],  # Exfiltration
    mitre_url="https://attack.mitre.org/techniques/T1041/",
    threat_context=ThreatContext(
        description=(
            "Adversaries steal data by exfiltrating it over an existing command and control (C2) channel. "
            "Rather than establishing separate exfiltration methods, attackers encode stolen information into "
            "their normal C2 communications using the same protocol. This technique is particularly stealthy "
            "as it blends data theft with routine malware communications, making detection more challenging. "
            "In cloud environments, this manifests as compromised instances or containers sending sensitive "
            "data through established C2 connections over HTTPS, DNS, custom TCP/UDP ports, or cloud APIs."
        ),
        attacker_goal="Exfiltrate stolen data using existing command and control channels to avoid detection",
        why_technique=[
            "Blends exfiltration with normal C2 traffic",
            "Avoids creating new network connections",
            "Reduces detection surface area",
            "Leverages already-established covert channels",
            "Encrypted protocols hide data content",
            "Single channel reduces operational complexity",
        ],
        known_threat_actors=[
            "Lazarus Group",
            "APT39",
            "Kimsuky",
            "Emotet",
            "TrickBot",
            "Cobalt Strike",
        ],
        recent_campaigns=[
            Campaign(
                name="Lazarus C2 Data Theft",
                year=2024,
                description="Lazarus Group exfiltrated data across various tools and malware using established C2 channels",
                reference_url="https://attack.mitre.org/groups/G0032/",
            ),
            Campaign(
                name="APT39 C2 Communications",
                year=2024,
                description="APT39 used C2 communications for stolen data transmission in targeted operations",
                reference_url="https://attack.mitre.org/groups/G0087/",
            ),
            Campaign(
                name="Kimsuky Data Exfiltration",
                year=2023,
                description="Kimsuky employed C2 channels for systematic data theft operations",
                reference_url="https://attack.mitre.org/groups/G0094/",
            ),
        ],
        prevalence="very_common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Exfiltration over C2 channels is extremely difficult to detect as it blends seamlessly with "
            "normal malware communications. This technique is used by over 200 malware families and 100+ "
            "threat groups, making it one of the most prevalent exfiltration methods. High severity due to "
            "the challenge of distinguishing legitimate traffic from data theft, potential for large-scale "
            "data loss, and the sophistication required to detect and prevent it. The technique bypasses "
            "traditional DLP controls and network segmentation."
        ),
        business_impact=[
            "Data breach and loss of sensitive information",
            "Intellectual property theft",
            "Regulatory fines and compliance violations (GDPR, CCPA)",
            "Reputational damage and loss of customer trust",
            "Competitive disadvantage from stolen trade secrets",
            "Incident response and forensic costs",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1074", "T1560", "T1005", "T1552.001", "T1530"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Suspicious Outbound Traffic Volume
        DetectionStrategy(
            strategy_id="t1041-aws-traffic-volume",
            name="AWS Suspicious Outbound Traffic Volume Analysis",
            description="Detect unusual outbound traffic volumes from instances that may indicate C2 exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, bytes, packets, action
| filter action = "ACCEPT"
| filter dstAddr not like /^10\\./ and dstAddr not like /^172\\.1[6-9]\\./ and dstAddr not like /^192\\.168\\./
| stats sum(bytes) as total_bytes, count(*) as connections by srcAddr, dstAddr, bin(1h)
| filter total_bytes > 524288000 or connections > 500
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious outbound traffic volume indicating C2 exfiltration

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  VPCFlowLogGroup:
    Type: String
    Description: CloudWatch log group for VPC Flow Logs

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: C2 Exfiltration Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for high-volume outbound traffic
  OutboundVolumeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes > 100000000, start, end, action="ACCEPT", ...]'
      MetricTransformations:
        - MetricName: HighVolumeOutbound
          MetricNamespace: Security/C2Detection
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: Create CloudWatch alarm for threshold breach
  HighVolumeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: C2-High-Volume-Exfiltration
      AlarmDescription: Detects high-volume outbound traffic indicating C2 exfiltration
      MetricName: HighVolumeOutbound
      Namespace: Security/C2Detection
      Statistic: Sum
      Period: 3600
      Threshold: 524288000
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# Detect suspicious outbound traffic volume indicating C2 exfiltration

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch log group for VPC Flow Logs"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "c2_exfil_alerts" {
  name         = "c2-exfiltration-alerts"
  display_name = "C2 Exfiltration Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.c2_exfil_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for high-volume outbound traffic
resource "aws_cloudwatch_log_metric_filter" "outbound_volume" {
  name           = "high-volume-outbound"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes > 100000000, start, end, action=\"ACCEPT\", ...]"

  metric_transformation {
    name      = "HighVolumeOutbound"
    namespace = "Security/C2Detection"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: Create CloudWatch alarm for threshold breach
resource "aws_cloudwatch_metric_alarm" "high_volume" {
  alarm_name          = "C2-High-Volume-Exfiltration"
  alarm_description   = "Detects high-volume outbound traffic indicating C2 exfiltration"
  metric_name         = "HighVolumeOutbound"
  namespace           = "Security/C2Detection"
  statistic           = "Sum"
  period              = 3600
  threshold           = 524288000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.c2_exfil_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="High-Volume Outbound Traffic Detected",
                alert_description_template="Suspicious high-volume outbound traffic from {srcAddr} to {dstAddr}: {total_bytes} bytes in 1 hour. May indicate C2 exfiltration.",
                investigation_steps=[
                    "Identify the source instance and its purpose",
                    "Review destination IP addresses and domains",
                    "Check for known malicious IPs using threat intelligence",
                    "Examine process activity on the source instance",
                    "Review CloudTrail logs for concurrent suspicious API calls",
                    "Correlate with file access patterns on the instance",
                    "Check for recent security findings or compromised credentials",
                ],
                containment_actions=[
                    "Isolate the source instance from the network",
                    "Block destination IP addresses at security group level",
                    "Revoke IAM credentials for the instance role",
                    "Create forensic snapshots of instance volumes",
                    "Review and restrict security group egress rules",
                    "Enable AWS GuardDuty for continuous monitoring",
                    "Implement VPC Flow Logs analysis automation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate high-bandwidth operations (backups, CDN origins, data pipelines). Adjust byte thresholds based on baseline traffic patterns.",
            detection_coverage="75% - catches high-volume C2 exfiltration",
            evasion_considerations="Low and slow exfiltration, rate-limited transfers, encryption may evade volume-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-35",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs configured"],
        ),
        # Strategy 2: AWS - Unusual Protocol Usage Detection
        DetectionStrategy(
            strategy_id="t1041-aws-protocol",
            name="AWS Unusual Protocol and Port Detection",
            description="Detect connections to rare external destinations on non-standard ports indicating C2 activity.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol, bytes, action
| filter action = "ACCEPT"
| filter dstPort not in [80, 443, 22, 3389, 25, 587, 465]
| filter dstAddr not like /^10\\./ and dstAddr not like /^172\\.1[6-9]\\./ and dstAddr not like /^192\\.168\\./
| stats sum(bytes) as total_bytes, count(*) as connections by srcAddr, dstAddr, dstPort, bin(1h)
| filter total_bytes > 10485760 or connections > 100
| sort connections desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual protocol usage for C2 communications

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: Create alert topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Filter for non-standard ports
  UnusualProtocolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, srcaddr, dstaddr != 10.*, srcport, dstport != 80 && dstport != 443 && dstport != 22, protocol, packets, bytes > 1048576, ...]'
      MetricTransformations:
        - MetricName: UnusualProtocolConnections
          MetricNamespace: Security/C2Detection
          MetricValue: "1"

  # Step 3: Alert on threshold
  ProtocolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: C2-Unusual-Protocol-Detected
      MetricName: UnusualProtocolConnections
      Namespace: Security/C2Detection
      Statistic: Sum
      Period: 3600
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unusual protocol usage for C2 communications

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "c2-protocol-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Filter for non-standard ports
resource "aws_cloudwatch_log_metric_filter" "unusual_protocol" {
  name           = "unusual-protocol-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, srcaddr, dstaddr != 10.*, srcport, dstport != 80 && dstport != 443 && dstport != 22, protocol, packets, bytes > 1048576, ...]"

  metric_transformation {
    name      = "UnusualProtocolConnections"
    namespace = "Security/C2Detection"
    value     = "1"
  }
}

# Step 3: Alert on threshold
resource "aws_cloudwatch_metric_alarm" "protocol_alarm" {
  alarm_name          = "C2-Unusual-Protocol-Detected"
  metric_name         = "UnusualProtocolConnections"
  namespace           = "Security/C2Detection"
  statistic           = "Sum"
  period              = 3600
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unusual Protocol Usage Detected",
                alert_description_template="Connections to non-standard port {dstPort} detected from {srcAddr} to {dstAddr}. {connections} connections, {total_bytes} bytes transferred.",
                investigation_steps=[
                    "Identify the application using the non-standard port",
                    "Check destination IP reputation using threat intelligence",
                    "Review process network connections on source instance",
                    "Examine application logs for suspicious activity",
                    "Check for known C2 framework indicators",
                    "Correlate with security tool alerts (GuardDuty, EDR)",
                ],
                containment_actions=[
                    "Block the destination IP and port combination",
                    "Isolate the source instance",
                    "Terminate suspicious processes",
                    "Review and restrict network ACLs and security groups",
                    "Scan instance for malware and persistence mechanisms",
                    "Rotate instance credentials and access keys",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate applications using custom ports (databases, application servers, monitoring tools)",
            detection_coverage="70% - catches C2 using custom protocols",
            evasion_considerations="Using standard ports (80, 443) for C2 will evade this detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        # Strategy 3: AWS - Encrypted Connection to Rare Destinations
        DetectionStrategy(
            strategy_id="t1041-aws-rare-dest",
            name="AWS Encrypted Connection to Rare Destinations",
            description="Detect HTTPS connections to rarely-accessed external destinations following sensitive file access.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes
| filter dstPort = 443 and action = "ACCEPT"
| filter dstAddr not like /^10\\./ and dstAddr not like /^172\\.1[6-9]\\./ and dstAddr not like /^192\\.168\\./
| stats sum(bytes) as total_bytes, count_distinct(dstAddr) as unique_destinations by srcAddr, bin(6h)
| filter unique_destinations > 10 and total_bytes > 52428800
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect encrypted connections to rare external destinations

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for HTTPS to rare destinations
  RareDestinationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, srcaddr, dstaddr, srcport, dstport=443, protocol=6, packets, bytes > 10485760, ...]'
      MetricTransformations:
        - MetricName: HTTPSToRareDestinations
          MetricNamespace: Security/C2Detection
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: CloudWatch alarm
  RareDestinationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: C2-Rare-Destination-Connection
      MetricName: HTTPSToRareDestinations
      Namespace: Security/C2Detection
      Statistic: Sum
      Period: 21600
      Threshold: 52428800
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect encrypted connections to rare external destinations

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "c2-rare-destination-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for HTTPS to rare destinations
resource "aws_cloudwatch_log_metric_filter" "rare_destination" {
  name           = "https-rare-destinations"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, srcaddr, dstaddr, srcport, dstport=443, protocol=6, packets, bytes > 10485760, ...]"

  metric_transformation {
    name      = "HTTPSToRareDestinations"
    namespace = "Security/C2Detection"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "rare_destination" {
  alarm_name          = "C2-Rare-Destination-Connection"
  metric_name         = "HTTPSToRareDestinations"
  namespace           = "Security/C2Detection"
  statistic           = "Sum"
  period              = 21600
  threshold           = 52428800
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Encrypted Connections to Rare Destinations",
                alert_description_template="Instance {srcAddr} established encrypted connections to {unique_destinations} rare destinations, transferring {total_bytes} bytes.",
                investigation_steps=[
                    "Identify destination domains using DNS query logs",
                    "Check destination IP reputation and geolocation",
                    "Review recent file access patterns on the instance",
                    "Examine running processes and network connections",
                    "Check for data staging activities",
                    "Review CloudTrail for sensitive data access",
                    "Analyse SSL/TLS certificate information if available",
                ],
                containment_actions=[
                    "Isolate the instance from the network",
                    "Block identified C2 destinations",
                    "Review and restrict outbound HTTPS traffic",
                    "Enable AWS Network Firewall for deep packet inspection",
                    "Implement proxy-based egress filtering",
                    "Deploy endpoint detection and response (EDR) tools",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal HTTPS destinations; exclude CDNs, update servers, and cloud service endpoints",
            detection_coverage="65% - catches encrypted C2 exfiltration",
            evasion_considerations="Using legitimate cloud services (S3, Dropbox) for exfiltration will evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled", "DNS query logging recommended"],
        ),
        # Strategy 4: GCP - Suspicious Egress Traffic Detection
        DetectionStrategy(
            strategy_id="t1041-gcp-egress",
            name="GCP Suspicious Egress Traffic Volume",
            description="Detect unusual outbound data transfer volumes from GCP instances indicating C2 exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.src_ip=~"^10\\."
NOT jsonPayload.connection.dest_ip=~"^10\\."
NOT jsonPayload.connection.dest_ip=~"^172\\.(1[6-9]|2[0-9]|3[01])\\."
NOT jsonPayload.connection.dest_ip=~"^192\\.168\\."
jsonPayload.bytes_sent > 104857600""",
                gcp_terraform_template="""# GCP: Detect suspicious egress traffic volume

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "C2 Exfiltration Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for high egress traffic
resource "google_logging_metric" "high_egress" {
  name   = "high-egress-traffic"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.src_ip=~"^10\\."
    NOT jsonPayload.connection.dest_ip=~"^10\\."
    NOT jsonPayload.connection.dest_ip=~"^172\\.(1[6-9]|2[0-9]|3[01])\\."
    NOT jsonPayload.connection.dest_ip=~"^192\\.168\\."
    jsonPayload.bytes_sent > 104857600
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "By"
    labels {
      key         = "src_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }

  label_extractors = {
    "src_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "high_egress_alert" {
  display_name = "C2 High-Volume Exfiltration Detected"
  combiner     = "OR"

  conditions {
    display_name = "High egress traffic volume"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.high_egress.name}\" resource.type=\"gce_subnetwork\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 524288000
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    content   = "High-volume outbound traffic detected. Investigate for potential C2 exfiltration."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: High-Volume Egress Traffic Detected",
                alert_description_template="Suspicious high-volume egress traffic from {src_ip}. May indicate C2 exfiltration activity.",
                investigation_steps=[
                    "Identify the source VM instance and its workload",
                    "Review VPC Flow Logs for destination details",
                    "Check destination IPs using threat intelligence",
                    "Examine VM process activity and network connections",
                    "Review Cloud Audit Logs for sensitive data access",
                    "Check for recent security findings in Security Command Centre",
                    "Analyse SSH/RDP session logs if applicable",
                ],
                containment_actions=[
                    "Isolate the VM instance using firewall rules",
                    "Block destination IP addresses in VPC firewall",
                    "Revoke service account credentials",
                    "Create disk snapshots for forensic analysis",
                    "Review and restrict egress firewall rules",
                    "Enable Cloud IDS for network threat detection",
                    "Implement VPC Service Controls for data egress",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate high-bandwidth operations; exclude backup destinations, CDN origins, and partner integrations",
            detection_coverage="75% - catches high-volume C2 exfiltration",
            evasion_considerations="Rate-limited transfers, encryption, and legitimate service abuse may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$20-40",
            prerequisites=[
                "VPC Flow Logs enabled on subnets",
                "Cloud Logging configured",
            ],
        ),
        # Strategy 5: GCP - Unusual External API Connections
        DetectionStrategy(
            strategy_id="t1041-gcp-api",
            name="GCP Unusual External API Connections",
            description="Detect compute instances making suspicious API calls to external endpoints.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.request.@type="type.googleapis.com/compute.instances.insert"
OR protoPayload.methodName=~"compute.instances.setMetadata"''',
                gcp_terraform_template="""# GCP: Detect unusual external API connections

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for non-standard connections
resource "google_logging_metric" "unusual_connections" {
  name   = "unusual-external-connections"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    (jsonPayload.connection.dest_port != 80 AND
     jsonPayload.connection.dest_port != 443 AND
     jsonPayload.connection.dest_port != 22)
    NOT jsonPayload.connection.dest_ip=~"^10\\."
    NOT jsonPayload.connection.dest_ip=~"^172\\.(1[6-9]|2[0-9]|3[01])\\."
    NOT jsonPayload.connection.dest_ip=~"^192\\.168\\."
    jsonPayload.bytes_sent > 1048576
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "unusual_connections_alert" {
  display_name = "Unusual External Connections Detected"
  combiner     = "OR"

  conditions {
    display_name = "Non-standard port connections"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.unusual_connections.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "7200s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Unusual External Connections Detected",
                alert_description_template="Instance making connections to non-standard ports. Potential C2 activity detected.",
                investigation_steps=[
                    "Identify the source instance and workload type",
                    "Review destination IPs and ports",
                    "Check threat intelligence for known C2 infrastructure",
                    "Examine instance startup scripts and metadata",
                    "Review service account permissions",
                    "Analyse instance network tags and firewall rules",
                    "Check for container workloads if using GKE",
                ],
                containment_actions=[
                    "Isolate the instance using network tags",
                    "Block suspicious destinations in firewall rules",
                    "Review and restrict service account permissions",
                    "Delete compromised instances if necessary",
                    "Rotate all credentials and access tokens",
                    "Review organisation policies for security controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate applications using custom ports; adjust connection thresholds",
            detection_coverage="70% - catches C2 using custom protocols",
            evasion_considerations="Using standard HTTPS ports for C2 will evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled", "Cloud Audit Logs enabled"],
        ),
        # Strategy 6: GCP - Data Access Followed by Egress
        DetectionStrategy(
            strategy_id="t1041-gcp-data-egress",
            name="GCP Sensitive Data Access Followed by Network Egress",
            description="Correlate sensitive data access with subsequent network egress indicating exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''(resource.type="gcs_bucket" AND protoPayload.methodName="storage.objects.get")
OR (resource.type="bigquery_dataset" AND protoPayload.methodName="jobservice.query")
severity >= "NOTICE"''',
                gcp_terraform_template="""# GCP: Detect data access followed by egress

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Data Exfiltration Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Metric for sensitive data access
resource "google_logging_metric" "sensitive_access" {
  name   = "sensitive-data-access"
  filter = <<-EOT
    (resource.type="gcs_bucket" AND
     protoPayload.methodName="storage.objects.get" AND
     resource.labels.bucket_name=~".*sensitive.*|.*confidential.*|.*pii.*") OR
    (resource.type="bigquery_dataset" AND
     protoPayload.methodName="jobservice.query")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "Principal accessing data"
    }
  }

  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "data_access_alert" {
  display_name = "Sensitive Data Access Pattern Detected"
  combiner     = "OR"

  conditions {
    display_name = "High-frequency sensitive data access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sensitive_access.name}\""
      duration        = "1800s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "1800s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "7200s"
  }

  documentation {
    content   = "High-frequency access to sensitive data detected. Investigate for potential exfiltration via C2 channel."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Sensitive Data Access Pattern Detected",
                alert_description_template="High-frequency access to sensitive data by {principal_email}. Potential C2 exfiltration preparation.",
                investigation_steps=[
                    "Review the principal's recent data access patterns",
                    "Check for subsequent network egress from same source",
                    "Examine BigQuery query history for bulk exports",
                    "Review Cloud Storage access logs for large downloads",
                    "Correlate with VPC Flow Logs for external connections",
                    "Check Security Command Centre for related findings",
                    "Verify principal identity and authorisation",
                ],
                containment_actions=[
                    "Suspend or revoke suspicious service account keys",
                    "Enable VPC Service Controls to prevent data egress",
                    "Implement Cloud DLP for sensitive data scanning",
                    "Review and restrict IAM permissions",
                    "Enable Access Context Manager policies",
                    "Configure Cloud Storage bucket locks",
                    "Implement organisation policy constraints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Baseline legitimate data access patterns; whitelist authorised analytics and reporting jobs",
            detection_coverage="80% - catches data access correlated with exfiltration",
            evasion_considerations="Slow, intermittent access patterns may evade",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$25-50",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "VPC Flow Logs enabled",
                "Data Access audit logs enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1041-aws-traffic-volume",
        "t1041-gcp-egress",
        "t1041-aws-protocol",
        "t1041-gcp-api",
        "t1041-aws-rare-dest",
        "t1041-gcp-data-egress",
    ],
    total_effort_hours=10.0,
    coverage_improvement="+22% improvement for Exfiltration tactic detection",
)
