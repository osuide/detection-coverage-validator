"""
T1095 - Non-Application Layer Protocol

Adversaries use non-application layer protocols for command and control communications.
Common protocols: ICMP, UDP, raw TCP, SOCKS, Serial over LAN (SOL), VMCI.
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
    technique_id="T1095",
    technique_name="Non-Application Layer Protocol",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1095/",
    threat_context=ThreatContext(
        description=(
            "Adversaries use OSI non-application layer protocols for command and control "
            "communications between host and C2 server or amongst infected hosts within a network. "
            "Common protocols include ICMP (chosen because it is not as commonly monitored as TCP or UDP), "
            "UDP, raw TCP sockets, SOCKS proxies, Serial over LAN (SOL), and Virtual Machine Communication "
            "Interface (VMCI). VMCI in ESXi environments enables communications invisible to external "
            "monitoring tools like tcpdump, netstat, nmap, and Wireshark."
        ),
        attacker_goal="Establish covert command and control channels using protocols that evade standard network monitoring",
        why_technique=[
            "ICMP rarely monitored compared to HTTP/HTTPS traffic",
            "UDP provides connectionless communication avoiding stateful inspection",
            "Raw sockets bypass application layer detection",
            "VMCI communications invisible to standard network tools",
            "Difficult to distinguish from legitimate protocol usage",
            "Often allowed through firewalls for operational reasons",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Non-application layer protocols provide adversaries with stealthy C2 channels "
            "that bypass traditional network monitoring focused on HTTP/HTTPS traffic. ICMP "
            "is rarely blocked or monitored, making it an attractive option. VMCI-based "
            "communications in virtualised environments are completely invisible to standard "
            "network analysis tools. Over 100 threat groups use this technique, indicating "
            "widespread adoption and effectiveness."
        ),
        business_impact=[
            "Persistent undetected adversary presence",
            "Continued data exfiltration via covert channels",
            "Lateral movement and infrastructure compromise",
            "Regulatory compliance violations from undetected breaches",
            "Extended incident response and remediation costs",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1048", "T1041", "T1020"],
        often_follows=["T1078.004", "T1190", "T1210"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1095-aws-icmp",
            name="AWS ICMP Traffic Anomaly Detection",
            description="Detect unusual ICMP traffic patterns that may indicate ICMP tunnelling or C2 activity.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, protocol, packets, bytes
| filter protocol = 1 and action = "ACCEPT"
| stats sum(bytes) as total_bytes, sum(packets) as total_packets by srcAddr, dstAddr, bin(5m)
| filter total_bytes > 1000 or total_packets > 100
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: ICMP traffic anomaly detection via VPC Flow Logs

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for ICMP traffic
  ICMPTrafficFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport, protocol=1, packets>100, bytes, ...]'
      MetricTransformations:
        - MetricName: SuspiciousICMPTraffic
          MetricNamespace: Security
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: Create alarm for ICMP threshold
  ICMPAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ICMP-Tunnelling-Detected
      MetricName: SuspiciousICMPTraffic
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10000
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# ICMP traffic anomaly detection via VPC Flow Logs

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "icmp-traffic-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for ICMP traffic
resource "aws_cloudwatch_log_metric_filter" "icmp_traffic" {
  name           = "suspicious-icmp-traffic"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport, protocol=1, packets>100, bytes, ...]"

  metric_transformation {
    name      = "SuspiciousICMPTraffic"
    namespace = "Security"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: Create alarm for ICMP threshold
resource "aws_cloudwatch_metric_alarm" "icmp_traffic" {
  alarm_name          = "ICMP-Tunnelling-Detected"
  metric_name         = "SuspiciousICMPTraffic"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious ICMP Traffic Detected",
                alert_description_template="Unusual ICMP traffic from {srcAddr} to {dstAddr}: {total_bytes} bytes, {total_packets} packets in 5 minutes.",
                investigation_steps=[
                    "Identify the source and destination instances",
                    "Review ICMP packet sizes and patterns",
                    "Check for legitimate ICMP usage (ping, traceroute)",
                    "Examine instance for suspicious processes",
                    "Analyse packet payloads if captures available",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Block ICMP traffic at security group level",
                    "Isolate suspicious instances",
                    "Implement NACL rules to restrict ICMP",
                    "Enable detailed packet capture for investigation",
                    "Review and restrict ICMP permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate monitoring tools; adjust byte/packet thresholds based on environment",
            detection_coverage="70% - catches high-volume ICMP but may miss slow tunnelling",
            evasion_considerations="Low and slow ICMP tunnelling, small payload sizes",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1095-aws-raw-socket",
            name="AWS Raw Socket Usage Detection",
            description="Detect creation or usage of raw sockets which may indicate non-application layer protocol usage.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.protocol
| filter eventName in ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"]
| filter requestParameters.protocol not in [6, 17, 1]
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect raw socket and unusual protocol usage

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for unusual protocol authorisation
  RawProtocolRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - AuthorizeSecurityGroupIngress
            - AuthorizeSecurityGroupEgress
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
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
                terraform_template="""# Detect raw socket and unusual protocol usage

variable "alert_email" { type = string }

# Step 1: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "raw-protocol-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for unusual protocol
resource "aws_cloudwatch_event_rule" "raw_protocol" {
  name = "unusual-protocol-detection"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.raw_protocol.name
  arn  = aws_sns_topic.alerts.arn
}

# Step 3: SNS topic policy
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
                alert_severity="medium",
                alert_title="Unusual Protocol Authorised in Security Group",
                alert_description_template="Security group modified to allow protocol {protocol} which may indicate raw socket usage.",
                investigation_steps=[
                    "Review the security group modifications",
                    "Identify who authorised the protocol change",
                    "Verify if the protocol is required for business purposes",
                    "Check associated instances and their purpose",
                    "Examine recent activity from the modifying principal",
                ],
                containment_actions=[
                    "Revoke unauthorised protocol rules",
                    "Review and restrict security group modification permissions",
                    "Enable AWS Config rules for security group monitoring",
                    "Implement least privilege for network changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist infrastructure teams and approved protocols for specialised applications",
            detection_coverage="60% - catches security group changes but not runtime usage",
            evasion_considerations="Using existing rules, tunnelling over allowed protocols",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1095-aws-udp-anomaly",
            name="AWS UDP Traffic Anomaly Detection",
            description="Detect unusual UDP traffic patterns that may indicate non-standard C2 communications.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, packets
| filter protocol = 17 and action = "ACCEPT"
| filter dstPort not in [53, 123, 161, 162, 514, 1812, 1813]
| stats sum(bytes) as total_bytes, count(*) as connections by srcAddr, dstAddr, dstPort, bin(5m)
| filter total_bytes > 1048576 or connections > 50
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: UDP traffic anomaly detection

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
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Filter for unusual UDP traffic
  UDPFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport!=53 && dstport!=123 && dstport!=161 && dstport!=162, protocol=17, packets>50, bytes, ...]'
      MetricTransformations:
        - MetricName: UnusualUDPTraffic
          MetricNamespace: Security
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: Alert on unusual patterns
  UDPAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Unusual-UDP-Traffic
      MetricName: UnusualUDPTraffic
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1048576
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# UDP traffic anomaly detection

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "udp-traffic-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Filter for unusual UDP traffic
resource "aws_cloudwatch_log_metric_filter" "udp_traffic" {
  name           = "unusual-udp-traffic"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport!=53 && dstport!=123 && dstport!=161 && dstport!=162, protocol=17, packets>50, bytes, ...]"

  metric_transformation {
    name      = "UnusualUDPTraffic"
    namespace = "Security"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: Alert on unusual patterns
resource "aws_cloudwatch_metric_alarm" "udp_traffic" {
  alarm_name          = "Unusual-UDP-Traffic"
  metric_name         = "UnusualUDPTraffic"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1048576
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Unusual UDP Traffic Detected",
                alert_description_template="Suspicious UDP traffic from {srcAddr} to {dstAddr}:{dstPort} - {total_bytes} bytes, {connections} connections.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review the destination port and service",
                    "Check for legitimate UDP applications (VoIP, gaming, streaming)",
                    "Examine instance processes and network connections",
                    "Analyse traffic patterns and timing",
                    "Correlate with application logs",
                ],
                containment_actions=[
                    "Block suspicious UDP traffic at security group",
                    "Implement NACL rules for UDP port restrictions",
                    "Isolate source instance if malicious",
                    "Review and restrict UDP egress permissions",
                    "Enable enhanced network monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate UDP services; exclude common ports like DNS, NTP, SNMP, Syslog",
            detection_coverage="65% - catches unusual UDP but legitimate applications may trigger alerts",
            evasion_considerations="Using common UDP ports, low-volume traffic, port hopping",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1095-gcp-icmp",
            name="GCP ICMP Traffic Anomaly Detection",
            description="Detect unusual ICMP traffic patterns via VPC Flow Logs that may indicate tunnelling or C2.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.protocol=1
jsonPayload.bytes_sent>1000
| stats sum(bytes_sent) as total_bytes by src_instance, dest_ip""",
                gcp_terraform_template="""# GCP: ICMP traffic anomaly detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create log metric for ICMP traffic
resource "google_logging_metric" "icmp_traffic" {
  name   = "icmp-traffic-anomaly"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.protocol=1
    jsonPayload.bytes_sent>1000
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "icmp_traffic" {
  display_name = "ICMP Tunnelling Detected"
  combiner     = "OR"
  conditions {
    display_name = "Suspicious ICMP traffic"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.icmp_traffic.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious ICMP Traffic Detected",
                alert_description_template="Unusual ICMP traffic pattern detected with high byte count.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review ICMP packet characteristics",
                    "Check for legitimate ICMP usage",
                    "Examine instance for malware or suspicious processes",
                    "Analyse traffic timing and patterns",
                    "Review Cloud Logging for related events",
                ],
                containment_actions=[
                    "Block ICMP via VPC firewall rules",
                    "Isolate suspicious instances",
                    "Enable packet mirroring for detailed analysis",
                    "Review and restrict ICMP permissions",
                    "Implement egress firewall controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist monitoring infrastructure; tune byte thresholds for environment",
            detection_coverage="70% - catches high-volume ICMP tunnelling",
            evasion_considerations="Slow ICMP tunnelling, small payloads",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled on subnets"],
        ),
        DetectionStrategy(
            strategy_id="t1095-gcp-protocol",
            name="GCP Non-Standard Protocol Detection",
            description="Detect usage of non-standard protocols via VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.protocol NOT IN (6, 17, 1, 58)
jsonPayload.bytes_sent>0""",
                gcp_terraform_template="""# GCP: Non-standard protocol detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create metric for unusual protocols
resource "google_logging_metric" "unusual_protocol" {
  name   = "unusual-protocol-usage"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.protocol!=6
    jsonPayload.connection.protocol!=17
    jsonPayload.connection.protocol!=1
    jsonPayload.connection.protocol!=58
    jsonPayload.bytes_sent>0
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "unusual_protocol" {
  display_name = "Non-Standard Protocol Usage Detected"
  combiner     = "OR"
  conditions {
    display_name = "Unusual protocol detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.unusual_protocol.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Non-Standard Protocol Detected",
                alert_description_template="Non-standard network protocol usage detected (not TCP/UDP/ICMP).",
                investigation_steps=[
                    "Identify the specific protocol number in use",
                    "Review source and destination instances",
                    "Determine if protocol usage is authorised",
                    "Check for specialised applications requiring custom protocols",
                    "Examine instance configuration and processes",
                    "Review recent changes to firewall rules",
                ],
                containment_actions=[
                    "Block unauthorised protocols via firewall rules",
                    "Isolate instances using non-standard protocols",
                    "Review and restrict firewall rule creation permissions",
                    "Implement organisation policy for protocol restrictions",
                    "Enable enhanced flow logging for investigation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate specialised applications (GRE tunnels, OSPF, etc.)",
            detection_coverage="80% - catches most non-standard protocol usage",
            evasion_considerations="Tunnelling over TCP/UDP, using allowed protocols",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["VPC Flow Logs enabled on subnets", "Cloud Logging"],
        ),
    ],
    recommended_order=[
        "t1095-aws-icmp",
        "t1095-gcp-icmp",
        "t1095-aws-udp-anomaly",
        "t1095-aws-raw-socket",
        "t1095-gcp-protocol",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+15% improvement for Command and Control tactic",
)
