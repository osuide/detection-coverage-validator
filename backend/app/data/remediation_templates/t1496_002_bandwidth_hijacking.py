"""
T1496.002 - Resource Hijacking: Bandwidth Hijacking

Adversaries exploit compromised systems' network bandwidth for botnet operations,
proxyjacking, and internet scanning. Used for DDoS campaigns, selling bandwidth
to proxy services, and conducting wide-scale reconnaissance.
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
    technique_id="T1496.002",
    technique_name="Resource Hijacking: Bandwidth Hijacking",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1496/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit compromised systems' network bandwidth for "
            "resource-intensive operations including botnet operations for DDoS "
            "campaigns and malicious torrents, proxyjacking (selling victims' "
            "bandwidth and IP addresses to proxy services), and conducting wide-scale "
            "internet scanning to identify additional targets. This can lead to financial "
            "losses and reputational damage if victim bandwidth facilitates illegal activities."
        ),
        attacker_goal="Abuse network bandwidth for botnet operations, proxyjacking, and reconnaissance",
        why_technique=[
            "Monetises compromised infrastructure via proxy services",
            "Victim pays bandwidth and egress costs",
            "Distributed network conceals attacker identity",
            "Enables large-scale DDoS campaigns",
            "Facilitates internet-wide reconnaissance",
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="moderate",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Direct financial impact through bandwidth costs. Creates legal/reputational "
            "risk if victim bandwidth is used for illegal activities. Indicates broader "
            "system compromise and may degrade network performance."
        ),
        business_impact=[
            "Significant data transfer cost increases",
            "Legal/reputational risk from illegal activity",
            "Degraded network performance",
            "Indicates broader infrastructure compromise",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1190", "T1133"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1496002-aws-vpc-flow",
            name="AWS VPC Flow Logs Anomalous Traffic Detection",
            description="Detect unusual outbound traffic patterns via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, bytes, packets, action
| filter action = "ACCEPT"
| stats sum(bytes) as total_bytes, sum(packets) as total_packets by srcaddr, bin(5m)
| filter total_bytes > 1000000000  # >1GB in 5 minutes
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect bandwidth hijacking via VPC Flow Logs

Parameters:
  VPCFlowLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  HighTrafficFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes>1000000000, start, end, action="ACCEPT", flowlogstatus]'
      MetricTransformations:
        - MetricName: HighBandwidthUsage
          MetricNamespace: Security
          MetricValue: !Ref bytes

  HighTrafficAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: BandwidthHijackingDetected
      MetricName: HighBandwidthUsage
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 5000000000  # 5GB in 5 minutes
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect bandwidth hijacking via VPC Flow Logs

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "bandwidth-hijacking-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "high_bandwidth" {
  name           = "high-bandwidth-usage"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes>1000000000, start, end, action=\"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "HighBandwidthUsage"
    namespace = "Security"
    value     = "$bytes"
  }
}

resource "aws_cloudwatch_metric_alarm" "bandwidth_hijacking" {
  alarm_name          = "BandwidthHijackingDetected"
  metric_name         = "HighBandwidthUsage"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5000000000  # 5GB in 5 minutes
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Potential Bandwidth Hijacking Detected",
                alert_description_template="Instance {srcaddr} transferred {total_bytes} bytes in 5 minutes.",
                investigation_steps=[
                    "Review VPC Flow Logs for destination addresses",
                    "Check for connections to known proxy services or Tor endpoints",
                    "Identify processes generating high network traffic",
                    "Review network connections for scanning patterns (masscan, curl, wget)",
                ],
                containment_actions=[
                    "Block suspicious outbound traffic via security groups",
                    "Isolate affected instances",
                    "Terminate malicious processes",
                    "Review and rotate compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate high-bandwidth workloads (backups, data transfers)",
            detection_coverage="70% - catches sustained bandwidth abuse",
            evasion_considerations="Throttled bandwidth usage may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1496002-aws-guardduty-backdoor",
            name="GuardDuty Backdoor/Trojan Detection",
            description="Use GuardDuty to detect backdoors and trojans used for bandwidth hijacking.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "Trojan:EC2/BlackholeTraffic",
                    "UnauthorizedAccess:EC2/TorRelay",
                    "Backdoor:EC2/DenialOfService.Tcp",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty backdoor detection for bandwidth hijacking

Parameters:
  AlertEmail:
    Type: String

Resources:
  Detector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  BackdoorRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "Backdoor:EC2"
            - prefix: "Trojan:EC2"
            - "UnauthorizedAccess:EC2/TorRelay"
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# GuardDuty backdoor detection for bandwidth hijacking

variable "alert_email" { type = string }

resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_sns_topic" "alerts" {
  name = "guardduty-backdoor-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "backdoor" {
  name = "guardduty-backdoor-detection"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2" },
        { prefix = "Trojan:EC2" },
        "UnauthorizedAccess:EC2/TorRelay"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.backdoor.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Backdoor/Trojan Detected",
                alert_description_template="Backdoor or trojan activity detected on {resource}, potentially used for bandwidth hijacking.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Check for Tor relay or proxy service connections",
                    "Identify malware processes on affected instances",
                    "Review network traffic patterns for DDoS or scanning activity",
                ],
                containment_actions=[
                    "Isolate affected instances immediately",
                    "Terminate malicious processes",
                    "Block C&C server communications",
                    "Review and remediate initial access vector",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty has low false positive rate for backdoors",
            detection_coverage="85% - excellent for known backdoors and trojans",
            evasion_considerations="Novel malware variants may evade initially",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4/million events",
            prerequisites=["GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1496002-aws-suspicious-connections",
            name="AWS Suspicious Long-Lived Connections Detection",
            description="Detect suspicious long-lived network connections indicative of proxyjacking.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, start, end
| filter action = "ACCEPT"
| filter (end - start) > 3600  # Connections >1 hour
| stats count(*) as connection_count by srcaddr, dstaddr, dstport
| filter connection_count > 10
| sort connection_count desc""",
                terraform_template="""# Detect suspicious long-lived connections

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "long-lived-connection-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Use CloudWatch Insights scheduled query to detect long connections
resource "aws_cloudwatch_query_definition" "long_connections" {
  name = "suspicious-long-connections"

  log_group_names = [var.vpc_flow_log_group]

  query_string = <<-EOT
    fields @timestamp, srcaddr, dstaddr, dstport, start, end
    | filter action = "ACCEPT"
    | filter (end - start) > 3600
    | stats count(*) as connection_count by srcaddr, dstaddr, dstport
    | filter connection_count > 10
    | sort connection_count desc
  EOT
}""",
                alert_severity="medium",
                alert_title="Suspicious Long-Lived Connections Detected",
                alert_description_template="Instance {srcaddr} has {connection_count} long-lived connections to {dstaddr}.",
                investigation_steps=[
                    "Identify unsigned applications maintaining connections",
                    "Check for connections to known proxy services",
                    "Review process list for curl, wget, or custom tools",
                    "Analyse traffic patterns for proxy or botnet activity",
                ],
                containment_actions=[
                    "Block suspicious destination addresses",
                    "Terminate malicious processes",
                    "Review instance for malware",
                    "Check for compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate persistent connections (monitoring, streaming)",
            detection_coverage="60% - catches persistent proxy connections",
            evasion_considerations="Connection rotation may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1496002-gcp-network-traffic",
            name="GCP High Network Traffic Detection",
            description="Detect bandwidth hijacking via network egress metrics.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
metric.type="compute.googleapis.com/instance/network/sent_bytes_count"
metric.value > 5000000000""",
                gcp_terraform_template="""# GCP: Detect bandwidth hijacking via network egress

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_monitoring_alert_policy" "high_egress" {
  display_name = "Bandwidth Hijacking - High Network Egress"
  combiner     = "OR"
  conditions {
    display_name = "High network egress"
    condition_threshold {
      filter          = "metric.type=\"compute.googleapis.com/instance/network/sent_bytes_count\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5000000000  # 5GB in 5 minutes
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}

# Detect connections to Tor/VPN endpoints via VPC Flow Logs
resource "google_logging_metric" "suspicious_destinations" {
  name   = "suspicious-network-destinations"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.dest_port:(9001 OR 9030 OR 443)
    jsonPayload.bytes_sent > 100000000
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "suspicious_connections" {
  display_name = "Suspicious Network Destinations"
  combiner     = "OR"
  conditions {
    display_name = "High traffic to suspicious ports"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_destinations.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Bandwidth Hijacking Detected",
                alert_description_template="VM instance generating excessive network egress traffic.",
                investigation_steps=[
                    "Review VPC Flow Logs for destination addresses",
                    "Check for Tor relay or proxy service connections",
                    "Identify processes generating high traffic",
                    "Review Cloud Audit Logs for suspicious activity",
                ],
                containment_actions=[
                    "Apply restrictive firewall rules",
                    "Stop affected VM instances",
                    "Terminate malicious processes",
                    "Review and rotate compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate high-bandwidth workloads",
            detection_coverage="75% - catches significant bandwidth abuse",
            evasion_considerations="Throttled bandwidth usage may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled", "Cloud Monitoring enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1496002-container-egress",
            name="Container Excessive Egress Detection",
            description="Detect excessive outbound traffic from containerised applications.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""# For ECS/EKS - monitor network metrics
fields @timestamp, kubernetes.pod_name, kubernetes.namespace_name
| filter @message like /NetworkTx/
| stats sum(value) as total_egress by kubernetes.pod_name, bin(5m)
| filter total_egress > 1000000000
| sort total_egress desc""",
                terraform_template="""# Detect excessive container egress traffic

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "container-bandwidth-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# For ECS - monitor NetworkTxBytes metric
resource "aws_cloudwatch_metric_alarm" "ecs_high_egress" {
  alarm_name          = "ECS-HighNetworkEgress"
  metric_name         = "NetworkTxBytes"
  namespace           = "AWS/ECS"
  statistic           = "Sum"
  period              = 300
  threshold           = 5000000000  # 5GB in 5 minutes
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# For EKS - use Container Insights
# Enable Container Insights on your EKS cluster first""",
                gcp_terraform_template="""# GCP: Detect excessive container egress

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Monitor GKE container network egress
resource "google_monitoring_alert_policy" "container_egress" {
  display_name = "Container Bandwidth Hijacking"
  combiner     = "OR"
  conditions {
    display_name = "High container egress"
    condition_threshold {
      filter          = "resource.type=\"k8s_container\" AND metric.type=\"networking.googleapis.com/pod_flow/egress_bytes_count\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5000000000
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="Container Bandwidth Hijacking Detected",
                alert_description_template="Container {pod_name} generated {total_egress} bytes egress traffic.",
                investigation_steps=[
                    "Identify container image and running processes",
                    "Review container logs for suspicious activity",
                    "Check network connections to external services",
                    "Scan container image for malware or backdoors",
                ],
                containment_actions=[
                    "Stop and remove affected containers",
                    "Block container image from registry",
                    "Apply network policies to restrict egress",
                    "Review container deployment pipeline",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist containers with legitimate high bandwidth requirements",
            detection_coverage="70% - catches containerised bandwidth abuse",
            evasion_considerations="Throttled traffic or sidecar containers may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Container Insights (AWS) or GKE Monitoring (GCP)"],
        ),
    ],
    recommended_order=[
        "t1496002-aws-guardduty-backdoor",
        "t1496002-aws-vpc-flow",
        "t1496002-gcp-network-traffic",
        "t1496002-aws-suspicious-connections",
        "t1496002-container-egress",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+25% improvement for Impact tactic",
)
