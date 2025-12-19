"""
T1498.002 - Network Denial of Service: Reflection Amplification

Adversaries exploit third-party servers by sending spoofed packets to generate
high-volume traffic targeting victims. Leverages protocols with disproportionately
large responses compared to requests (e.g., DNS, NTP, Memcached).
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
    technique_id="T1498.002",
    technique_name="Network Denial of Service: Reflection Amplification",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1498/002/",

    threat_context=ThreatContext(
        description=(
            "Adversaries exploit third-party servers (reflectors) by sending spoofed "
            "packets to generate high-volume traffic targeting victims. The technique "
            "leverages protocols with disproportionately large responses compared to "
            "requests, amplifying attack traffic several orders of magnitude greater "
            "than the requests sent. Common amplification protocols include DNS, NTP, "
            "and Memcached (which can amplify traffic up to 51,200x)."
        ),
        attacker_goal="Overwhelm target systems with amplified network traffic to cause denial of service",
        why_technique=[
            "Amplifies attack traffic by orders of magnitude",
            "Spoofed packets hide attacker identity",
            "Exploits publicly accessible UDP services",
            "Requires minimal attacker resources",
            "Difficult to block without affecting legitimate traffic"
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="common",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "High-impact availability attack that can overwhelm infrastructure. "
            "While not providing access or data theft, can cause significant business "
            "disruption and revenue loss. Amplification factors make small-scale attacks "
            "highly effective."
        ),
        business_impact=[
            "Service unavailability and downtime",
            "Revenue loss during outage",
            "Bandwidth costs from amplified traffic",
            "Reputation damage from service disruption"
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1595.002"]
    ),

    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1498-002-aws-vpc-outbound",
            name="AWS VPC Outbound Spoofed Traffic Detection",
            description="Detect outbound spoofed UDP traffic to known amplification protocol ports from cloud instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, srcAddr, dstAddr, dstPort, bytes, packets
| filter action = "ACCEPT" and protocol = 17
| filter dstPort in [53, 123, 11211, 161, 389, 1900]
| stats sum(bytes) as totalBytes, sum(packets) as totalPackets by srcAddr, dstPort, bin(5m)
| filter totalPackets > 1000
| sort totalBytes desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect potential reflection amplification attack sources

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: VPC Flow Logs log group name
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Detect high-volume UDP traffic to amplification ports
  AmplificationTrafficFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport=53||destport=123||destport=11211, protocol=17, packets>100, bytes, windowstart, windowend, action=ACCEPT, flowlogstatus]'
      MetricTransformations:
        - MetricName: AmplificationTraffic
          MetricNamespace: Security/DDoS
          MetricValue: !packets

  AmplificationTrafficAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: PotentialReflectionAmplification
      AlarmDescription: High-volume UDP traffic to amplification protocol ports detected
      MetricName: AmplificationTraffic
      Namespace: Security/DDoS
      Statistic: Sum
      Period: 300
      Threshold: 5000
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]''',
                terraform_template='''# Detect potential reflection amplification attack sources

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "reflection-amplification-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "amplification_traffic" {
  name           = "amplification-traffic"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport=53||destport=123||destport=11211, protocol=17, packets>100, bytes, windowstart, windowend, action=ACCEPT, flowlogstatus]"

  metric_transformation {
    name      = "AmplificationTraffic"
    namespace = "Security/DDoS"
    value     = "$packets"
  }
}

resource "aws_cloudwatch_metric_alarm" "amplification_attack" {
  alarm_name          = "PotentialReflectionAmplification"
  alarm_description   = "High-volume UDP traffic to amplification protocol ports detected"
  metric_name         = "AmplificationTraffic"
  namespace           = "Security/DDoS"
  statistic           = "Sum"
  period              = 300
  threshold           = 5000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}''',
                alert_severity="high",
                alert_title="Potential Reflection Amplification Attack Source Detected",
                alert_description_template="Instance {srcAddr} sending high-volume UDP traffic to amplification ports.",
                investigation_steps=[
                    "Identify affected EC2 instances from source IPs",
                    "Check instance for compromise indicators",
                    "Review instance creation and modification history",
                    "Analyse outbound traffic patterns and destinations",
                    "Check for unauthorised access or lateral movement"
                ],
                containment_actions=[
                    "Isolate affected instances immediately",
                    "Block outbound UDP traffic to amplification ports",
                    "Terminate compromised instances",
                    "Review security group configurations",
                    "Contact AWS abuse team if necessary"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate DNS or NTP traffic is typically much lower volume. Adjust thresholds based on environment.",
            detection_coverage="80% - catches outbound attack traffic from cloud instances",
            evasion_considerations="Attackers may use varied protocols or throttle traffic to avoid detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["VPC Flow Logs enabled with CloudWatch Logs destination"]
        ),

        DetectionStrategy(
            strategy_id="t1498-002-aws-guardduty",
            name="AWS GuardDuty DDoS Detection",
            description="Leverage AWS GuardDuty for detecting DDoS and reflection attack patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, type, severity, resource.instanceDetails.instanceId, service.action.networkConnectionAction
| filter type like /Backdoor:EC2\/DenialOfService/
| sort @timestamp desc''',
                terraform_template='''# Enable GuardDuty DDoS finding alerts

variable "alert_email" { type = string }

resource "aws_guardduty_detector" "main" {
  enable = true

  # Enable S3, Kubernetes, and Malware protection
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
}

resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-ddos-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule to catch DDoS findings
resource "aws_cloudwatch_event_rule" "ddos_findings" {
  name        = "guardduty-ddos-findings"
  description = "Capture GuardDuty DDoS findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{
        prefix = "Backdoor:EC2/DenialOfService"
      }]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ddos_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn
}''',
                alert_severity="critical",
                alert_title="GuardDuty: DDoS Activity Detected",
                alert_description_template="GuardDuty detected DDoS activity from instance {instanceId}.",
                investigation_steps=[
                    "Review GuardDuty finding details and evidence",
                    "Identify affected EC2 instances",
                    "Check instance for compromise indicators",
                    "Analyse network traffic patterns",
                    "Review CloudTrail for suspicious API activity"
                ],
                containment_actions=[
                    "Isolate affected instances immediately",
                    "Block malicious traffic via security groups",
                    "Terminate compromised instances",
                    "Rotate exposed credentials",
                    "Review and harden security configurations"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are high-confidence. Review context before acting.",
            detection_coverage="90% - GuardDuty uses ML and threat intelligence",
            evasion_considerations="Sophisticated attackers may use techniques not yet in GuardDuty signatures",
            implementation_effort=EffortLevel.LOW,
            implementation_time="15-30 minutes",
            estimated_monthly_cost="$15-50 depending on data volume",
            prerequisites=["AWS GuardDuty enabled in account"]
        ),

        DetectionStrategy(
            strategy_id="t1498-002-aws-shield",
            name="AWS Shield Advanced DDoS Metrics",
            description="Monitor AWS Shield Advanced metrics for volumetric DDoS attacks including reflection amplification.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="shield",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template='''# Monitor AWS Shield Advanced DDoS metrics

variable "protected_resource_arn" {
  type        = string
  description = "ARN of protected resource (EIP, ALB, CloudFront, etc.)"
}
variable "alert_email" { type = string }

resource "aws_sns_topic" "shield_alerts" {
  name = "shield-ddos-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.shield_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Alert on DDoS detected events
resource "aws_cloudwatch_metric_alarm" "ddos_detected" {
  alarm_name          = "ShieldDDoSDetected"
  alarm_description   = "AWS Shield detected a DDoS attack"
  metric_name         = "DDoSDetected"
  namespace           = "AWS/DDoSProtection"
  statistic           = "Sum"
  period              = 60
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  dimensions = {
    ResourceArn = var.protected_resource_arn
  }

  alarm_actions = [aws_sns_topic.shield_alerts.arn]
}

# Alert on high attack volume
resource "aws_cloudwatch_metric_alarm" "attack_volume" {
  alarm_name          = "ShieldHighAttackVolume"
  alarm_description   = "High-volume DDoS attack detected"
  metric_name         = "AttackVolume"
  namespace           = "AWS/DDoSProtection"
  statistic           = "Sum"
  period              = 300
  threshold           = 1000000000  # 1 Gbps
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  dimensions = {
    ResourceArn = var.protected_resource_arn
  }

  alarm_actions = [aws_sns_topic.shield_alerts.arn]
}''',
                alert_severity="critical",
                alert_title="AWS Shield: DDoS Attack Detected",
                alert_description_template="AWS Shield detected DDoS attack on protected resource.",
                investigation_steps=[
                    "Review AWS Shield dashboard for attack details",
                    "Check attack vector and volume metrics",
                    "Review Shield Response Team (SRT) recommendations",
                    "Analyse traffic patterns and source IPs",
                    "Check application health and availability"
                ],
                containment_actions=[
                    "Engage AWS Shield Response Team if Advanced tier",
                    "Review automatic mitigation actions taken",
                    "Implement additional Route 53 routing policies",
                    "Scale infrastructure if needed",
                    "Document attack patterns for future prevention"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="AWS Shield metrics are highly accurate. Review attack details before taking action.",
            detection_coverage="95% - Shield detects most DDoS attack types",
            evasion_considerations="Application-layer attacks may require additional WAF rules",
            implementation_effort=EffortLevel.LOW,
            implementation_time="20-30 minutes",
            estimated_monthly_cost="$3000+ for Shield Advanced subscription",
            prerequisites=["AWS Shield Advanced subscription", "Protected resources configured"]
        ),

        DetectionStrategy(
            strategy_id="t1498-002-gcp-armor-ddos",
            name="GCP Cloud Armor DDoS Detection",
            description="Detect volumetric DDoS attacks including reflection amplification via Cloud Armor adaptive protection.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
jsonPayload.enforcedSecurityPolicy.configuredAction="DENY"
jsonPayload.enforcedSecurityPolicy.name=~"ddos-protection"''',
                gcp_terraform_template='''# GCP: Detect DDoS attacks via Cloud Armor

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "DDoS Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Metric for Cloud Armor DDoS blocks
resource "google_logging_metric" "ddos_blocks" {
  name   = "cloud-armor-ddos-blocks"
  filter = <<-EOT
    resource.type="http_load_balancer"
    jsonPayload.enforcedSecurityPolicy.configuredAction="DENY"
    jsonPayload.enforcedSecurityPolicy.name=~"ddos-protection"
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
    "source_ip" = "EXTRACT(jsonPayload.httpRequest.remoteIp)"
  }
}

# Alert on high DDoS block rate
resource "google_monitoring_alert_policy" "ddos_attack" {
  display_name = "Cloud Armor DDoS Attack Detected"
  combiner     = "OR"

  conditions {
    display_name = "High DDoS block rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ddos_blocks.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 1000
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }
}

# Monitor load balancer request count for anomalies
resource "google_monitoring_alert_policy" "traffic_spike" {
  display_name = "Abnormal Traffic Spike Detected"
  combiner     = "OR"

  conditions {
    display_name = "Request rate spike"
    condition_threshold {
      filter = <<-EOT
        resource.type="https_lb_rule"
        metric.type="loadbalancing.googleapis.com/https/request_count"
      EOT
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10000  # Adjust based on normal traffic
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}''',
                alert_severity="critical",
                alert_title="GCP: DDoS Attack Detected",
                alert_description_template="Cloud Armor detected high-volume DDoS attack traffic.",
                investigation_steps=[
                    "Review Cloud Armor security policy logs",
                    "Analyse traffic sources and patterns",
                    "Check load balancer metrics and health",
                    "Review blocked request characteristics",
                    "Verify backend service availability"
                ],
                containment_actions=[
                    "Enable Cloud Armor adaptive protection if not enabled",
                    "Add rate limiting rules to security policy",
                    "Implement geo-blocking if attack is regional",
                    "Scale backend services if needed",
                    "Contact Google Cloud Support for assistance"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust rate thresholds based on normal traffic patterns. Cloud Armor adaptive protection learns over time.",
            detection_coverage="85% - effective against volumetric and protocol attacks",
            evasion_considerations="Application-layer attacks may require custom WAF rules",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$20-50 depending on traffic volume",
            prerequisites=["Cloud Armor security policy configured", "HTTPS load balancer with logging enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1498-002-gcp-vpc-flow",
            name="GCP VPC Flow Logs Amplification Detection",
            description="Detect outbound UDP traffic patterns consistent with reflection amplification attacks from GCP instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.protocol=17
jsonPayload.dest_port=(53 OR 123 OR 11211 OR 161 OR 389 OR 1900)
jsonPayload.bytes_sent>1000000''',
                gcp_terraform_template='''# GCP: Detect reflection amplification via VPC Flow Logs

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Amplification Attack Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Metric for high-volume UDP traffic to amplification ports
resource "google_logging_metric" "amplification_traffic" {
  name   = "vpc-amplification-traffic"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.protocol=17
    jsonPayload.dest_port=(53 OR 123 OR 11211 OR 161 OR 389 OR 1900)
    jsonPayload.bytes_sent>100000
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source VM IP"
    }
    labels {
      key         = "dest_port"
      value_type  = "STRING"
      description = "Destination port"
    }
  }

  label_extractors = {
    "source_ip"  = "EXTRACT(jsonPayload.connection.src_ip)"
    "dest_port"  = "EXTRACT(jsonPayload.connection.dest_port)"
  }

  value_extractor = "EXTRACT(jsonPayload.bytes_sent)"
}

# Alert on amplification traffic patterns
resource "google_monitoring_alert_policy" "amplification_attack" {
  display_name = "Reflection Amplification Attack Source Detected"
  combiner     = "OR"

  conditions {
    display_name = "High UDP traffic to amplification ports"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.amplification_traffic.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10000000  # 10 MB in 5 minutes
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.source_ip"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Potential reflection amplification attack originating from GCP instance. Investigate source VM immediately."
  }
}''',
                alert_severity="high",
                alert_title="GCP: Reflection Amplification Attack Source Detected",
                alert_description_template="GCP instance sending high-volume UDP traffic to amplification protocol ports.",
                investigation_steps=[
                    "Identify affected GCP instances from source IPs",
                    "Check instance for compromise indicators",
                    "Review instance creation and access logs",
                    "Analyse VPC flow logs for traffic patterns",
                    "Check Cloud Audit Logs for suspicious activity"
                ],
                containment_actions=[
                    "Stop affected instances immediately",
                    "Create firewall rules to block outbound UDP to amplification ports",
                    "Delete compromised instances and create new ones from clean images",
                    "Review and strengthen IAM policies",
                    "Enable VPC Service Controls if not already enabled"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate DNS resolvers or NTP servers may trigger alerts. Whitelist known legitimate sources.",
            detection_coverage="75% - catches outbound attack traffic from GCP instances",
            evasion_considerations="Attackers may distribute traffic across multiple instances or throttle to avoid thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled on subnets"]
        )
    ],

    recommended_order=[
        "t1498-002-aws-guardduty",
        "t1498-002-aws-shield",
        "t1498-002-aws-vpc-outbound",
        "t1498-002-gcp-armor-ddos",
        "t1498-002-gcp-vpc-flow"
    ],
    total_effort_hours=4.5,
    coverage_improvement="+25% improvement for Impact tactic detection"
)
