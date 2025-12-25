"""
T1498.001 - Network Denial of Service: Direct Network Flood

Adversaries attempt to overwhelm target systems by sending high-volume network
traffic directly to them using stateless (UDP, ICMP) or stateful (TCP) protocols.
Botnets frequently execute these attacks from globally dispersed systems.
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
    technique_id="T1498.001",
    technique_name="Network Denial of Service: Direct Network Flood",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1498/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries attempt to overwhelm target systems by sending high-volume "
            "network traffic directly to them. The technique involves using one or more "
            "systems to transmit numerous packets toward a service's network. Both stateless "
            "protocols (UDP, ICMP) and stateful protocols (TCP) can be exploited. Botnets "
            "frequently execute these attacks, with large distributed networks generating "
            "substantial traffic from globally dispersed systems."
        ),
        attacker_goal="Reduce system availability by saturating network capacity with high-volume traffic",
        why_technique=[
            "Degrades service availability and functionality",
            "Difficult to distinguish from legitimate traffic",
            "Can be executed with minimal individual system contribution",
            "Exploits both stateless and stateful protocols",
            "Effective with distributed botnet infrastructure",
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="common",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Direct availability impact technique. Successful attacks can completely "
            "disable services and disrupt business operations. Typically requires upstream "
            "mitigation when flood volumes exceed network capacity."
        ),
        business_impact=[
            "Service unavailability",
            "Revenue loss from downtime",
            "Customer trust degradation",
            "Emergency response costs",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1595.002"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1498-001-aws-network",
            name="AWS Network Traffic Anomaly Detection",
            description="Detect abnormally high network traffic volumes via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, protocol, bytes, packets
| filter action = "ACCEPT"
| stats sum(bytes) as totalBytes, sum(packets) as totalPackets by dstAddr, protocol, bin(5m)
| filter totalPackets > 100000 or totalBytes > 100000000
| sort totalBytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network flood attacks via VPC Flow Logs

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: VPC Flow Logs CloudWatch log group
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for high traffic volumes
  HighTrafficFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport, protocol, packets>=100000, bytes, windowstart, windowend, action="ACCEPT", flowlogstatus]'
      MetricTransformations:
        - MetricName: HighNetworkTraffic
          MetricNamespace: Security/NetworkFlood
          MetricValue: !packets

  # Step 3: Create alarm for potential flood attacks
  NetworkFloodAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: NetworkFloodDetection
      MetricName: HighNetworkTraffic
      Namespace: Security/NetworkFlood
      Statistic: Sum
      Period: 300
      Threshold: 500000
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]
      AlarmDescription: Detects potential network flood attacks""",
                terraform_template="""# Detect network flood attacks via VPC Flow Logs

variable "vpc_flow_log_group" {
  type        = string
  description = "VPC Flow Logs CloudWatch log group"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "network-flood-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for high traffic volumes
resource "aws_cloudwatch_log_metric_filter" "high_traffic" {
  name           = "high-network-traffic"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets>=100000, bytes, windowstart, windowend, action=\"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "HighNetworkTraffic"
    namespace = "Security/NetworkFlood"
    value     = "$packets"
  }
}

# Step 3: Create alarm for potential flood attacks
resource "aws_cloudwatch_metric_alarm" "network_flood" {
  alarm_name          = "NetworkFloodDetection"
  metric_name         = "HighNetworkTraffic"
  namespace           = "Security/NetworkFlood"
  statistic           = "Sum"
  period              = 300
  threshold           = 500000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects potential network flood attacks"
}""",
                alert_severity="critical",
                alert_title="Network Flood Attack Detected",
                alert_description_template="Abnormally high network traffic volume detected targeting {dstAddr} using protocol {protocol}.",
                investigation_steps=[
                    "Review VPC Flow Logs for traffic patterns and source IPs",
                    "Identify targeted destinations and protocols",
                    "Check service availability and performance metrics",
                    "Analyse traffic legitimacy vs attack signatures",
                    "Review CloudWatch metrics for bandwidth saturation",
                ],
                containment_actions=[
                    "Enable AWS Shield Standard (automatic) or Shield Advanced",
                    "Configure Network ACLs to block malicious source IPs",
                    "Implement rate limiting at load balancer",
                    "Contact AWS Support for DDoS mitigation assistance",
                    "Activate CloudFront for traffic distribution",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate traffic spikes (e.g., flash sales, viral content) may trigger alerts. Baseline normal traffic patterns and adjust thresholds accordingly.",
            detection_coverage="60% - catches high-volume floods",
            evasion_considerations="Low-and-slow attacks or distributed attacks below threshold may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-40",
            prerequisites=["VPC Flow Logs enabled and sent to CloudWatch Logs"],
        ),
        DetectionStrategy(
            strategy_id="t1498-001-aws-shield",
            name="AWS Shield DDoS Event Detection",
            description="Detect DDoS events via AWS Shield Advanced metrics.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @message like /DDoS/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor AWS Shield DDoS events

Parameters:
  AlertEmail:
    Type: String
    Description: Email for DDoS alerts

Resources:
  # Step 1: Create SNS topic for DDoS alerts
  DDoSAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create CloudWatch alarm for DDoS detected events
  DDoSDetectedAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ShieldDDoSDetected
      MetricName: DDoSDetected
      Namespace: AWS/DDoSProtection
      Statistic: Sum
      Period: 60
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref DDoSAlertTopic]
      AlarmDescription: Alert when Shield detects DDoS attack

  # Step 3: Create alarm for attack volume
  AttackVolumeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighDDoSAttackVolume
      MetricName: AttackVolume
      Namespace: AWS/DDoSProtection
      Statistic: Sum
      Period: 300
      Threshold: 1000000
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref DDoSAlertTopic]
      AlarmDescription: Alert on high DDoS attack volume""",
                terraform_template="""# Monitor AWS Shield DDoS events

variable "alert_email" {
  type        = string
  description = "Email for DDoS alerts"
}

# Step 1: Create SNS topic for DDoS alerts
resource "aws_sns_topic" "ddos_alerts" {
  name = "shield-ddos-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ddos_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create CloudWatch alarm for DDoS detected events
resource "aws_cloudwatch_metric_alarm" "ddos_detected" {
  alarm_name          = "ShieldDDoSDetected"
  metric_name         = "DDoSDetected"
  namespace           = "AWS/DDoSProtection"
  statistic           = "Sum"
  period              = 60
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.ddos_alerts.arn]
  alarm_description   = "Alert when Shield detects DDoS attack"
}

# Step 3: Create alarm for attack volume
resource "aws_cloudwatch_metric_alarm" "attack_volume" {
  alarm_name          = "HighDDoSAttackVolume"
  metric_name         = "AttackVolume"
  namespace           = "AWS/DDoSProtection"
  statistic           = "Sum"
  period              = 300
  threshold           = 1000000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.ddos_alerts.arn]
  alarm_description   = "Alert on high DDoS attack volume"
}""",
                alert_severity="critical",
                alert_title="AWS Shield DDoS Attack Detected",
                alert_description_template="AWS Shield has detected a DDoS attack with volume {AttackVolume}.",
                investigation_steps=[
                    "Review AWS Shield console for attack details",
                    "Check Shield Advanced event timeline if subscribed",
                    "Review targeted resources and attack vectors",
                    "Analyse attack patterns and source geolocation",
                    "Contact AWS DDoS Response Team (Shield Advanced)",
                ],
                containment_actions=[
                    "Verify automatic Shield mitigation is active",
                    "Engage AWS DDoS Response Team (DRT) if Shield Advanced",
                    "Review and update Route 53 health checks",
                    "Scale resources if necessary",
                    "Document attack for post-incident analysis",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Shield metrics are highly accurate for actual DDoS events",
            detection_coverage="90% - Shield automatically detects most DDoS attacks",
            evasion_considerations="Application-layer attacks may not be detected by network-layer Shield Standard",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$0 (Shield Standard) or $3000+/month (Shield Advanced)",
            prerequisites=[
                "AWS Shield Standard (automatic) or Shield Advanced subscription"
            ],
        ),
        DetectionStrategy(
            strategy_id="t1498-001-gcp-armor",
            name="GCP Cloud Armor DDoS Detection",
            description="Detect DDoS attacks via Cloud Armor rate limiting and adaptive protection.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
jsonPayload.enforcedSecurityPolicy.outcome="RATE_BASED_BAN"
OR jsonPayload.statusDetails=~"denied_by_security_policy"''',
                gcp_terraform_template="""# GCP: Detect DDoS attacks via Cloud Armor

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for DDoS alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "DDoS Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
  project      = var.project_id
}

# Step 2: Create log-based metric for rate-based bans
resource "google_logging_metric" "armor_rate_bans" {
  name   = "cloud-armor-rate-bans"
  filter = <<-EOT
    resource.type="http_load_balancer"
    jsonPayload.enforcedSecurityPolicy.outcome="RATE_BASED_BAN"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "client_ip"
      value_type  = "STRING"
      description = "Client IP address"
    }
  }
  label_extractors = {
    "client_ip" = "EXTRACT(jsonPayload.remoteIp)"
  }
  project = var.project_id
}

# Step 3: Create alert policy for DDoS detection
resource "google_monitoring_alert_policy" "ddos_detection" {
  display_name = "Cloud Armor DDoS Attack Detected"
  combiner     = "OR"
  conditions {
    display_name = "High rate-based bans"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.armor_rate_bans.name}\""
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
  alert_strategy {
    auto_close = "1800s"
  }
  project = var.project_id
}""",
                alert_severity="critical",
                alert_title="GCP: DDoS Attack Detected",
                alert_description_template="Cloud Armor detected high-volume traffic from {client_ip}.",
                investigation_steps=[
                    "Review Cloud Armor security policy logs",
                    "Check load balancer metrics for traffic patterns",
                    "Analyse banned client IP addresses and geolocation",
                    "Review adaptive protection recommendations",
                    "Check backend service health and capacity",
                ],
                containment_actions=[
                    "Enable Cloud Armor adaptive protection",
                    "Implement rate limiting rules",
                    "Configure IP allow/deny lists",
                    "Scale backend services if necessary",
                    "Contact Google Cloud Support for assistance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Rate-based bans indicate legitimate high-volume traffic patterns. Review normal traffic baselines.",
            detection_coverage="80% - catches rate-based floods",
            evasion_considerations="Distributed attacks from many IPs below rate thresholds may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$20-50",
            prerequisites=["Cloud Armor security policy enabled on load balancer"],
        ),
        DetectionStrategy(
            strategy_id="t1498-001-gcp-logging",
            name="GCP Network Traffic Anomaly Detection",
            description="Detect abnormal network traffic via VPC Flow Logs analysis.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.bytes_sent > 10000000""",
                gcp_terraform_template="""# GCP: Detect network flood via VPC Flow Logs

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for network flood alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Network Flood Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
  project      = var.project_id
}

# Step 2: Create log-based metric for high traffic volume
resource "google_logging_metric" "high_network_traffic" {
  name   = "high-network-traffic"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.bytes_sent > 10000000
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "dest_ip"
      value_type  = "STRING"
      description = "Destination IP"
    }
  }
  label_extractors = {
    "dest_ip" = "EXTRACT(jsonPayload.connection.dest_ip)"
  }
  project = var.project_id
}

# Step 3: Create alert for network flood detection
resource "google_monitoring_alert_policy" "network_flood" {
  display_name = "Network Flood Attack Detected"
  combiner     = "OR"
  conditions {
    display_name = "High network traffic volume"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.high_network_traffic.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "1800s"
  }
  project = var.project_id
}""",
                alert_severity="high",
                alert_title="GCP: Network Flood Detected",
                alert_description_template="Abnormally high network traffic volume targeting {dest_ip}.",
                investigation_steps=[
                    "Review VPC Flow Logs for traffic patterns",
                    "Identify source IPs and protocols involved",
                    "Check affected instance health and performance",
                    "Analyse traffic legitimacy vs attack signatures",
                    "Review Cloud Monitoring network metrics",
                ],
                containment_actions=[
                    "Configure firewall rules to block malicious sources",
                    "Enable Cloud Armor on load balancers",
                    "Implement rate limiting",
                    "Scale resources or enable autoscaling",
                    "Contact Google Cloud Support for DDoS mitigation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate high-volume transfers may trigger alerts. Baseline normal traffic and adjust thresholds.",
            detection_coverage="65% - catches high-volume network floods",
            evasion_considerations="Low-volume distributed attacks may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-35",
            prerequisites=["VPC Flow Logs enabled for target subnets"],
        ),
    ],
    recommended_order=[
        "t1498-001-aws-shield",
        "t1498-001-gcp-armor",
        "t1498-001-aws-network",
        "t1498-001-gcp-logging",
    ],
    total_effort_hours=7.5,
    coverage_improvement="+25% improvement for Impact tactic",
)
