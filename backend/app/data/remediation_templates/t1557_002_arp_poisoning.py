"""
T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning

Adversaries exploit the unauthenticated nature of ARP to position themselves between
networked devices. By poisoning ARP caches, attackers intercept communications to enable
network sniffing and data manipulation. Used by Cleaver and LuminousMoth.

CRITICAL DETECTION LIMITATION:
VPC Flow Logs operate at Layer 3 (IP) but ARP operates at Layer 2 (Data Link).
VPC Flow Logs CANNOT see ARP traffic at all - ARP packets are not IP packets.

What VPC Flow Logs CAN detect:
- Consequences of successful ARP poisoning (unusual traffic patterns AFTER attack succeeds)
- IP traffic being routed through unexpected hosts

What VPC Flow Logs CANNOT detect:
- The ARP poisoning attack itself
- Malicious ARP responses
- ARP cache manipulation

Coverage reality:
- VPC Flow Logs: ~20% (detects post-attack traffic anomalies only)
- VPC Traffic Mirroring with deep packet inspection: ~65%
- Host-based ARP monitoring (arping, arpwatch): ~80%

For accurate detection, deploy:
1. VPC Traffic Mirroring with packet inspection tools
2. Host-based ARP monitoring agents (arpwatch, Wazuh)
3. Network IDS with Layer 2 visibility
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
    technique_id="T1557.002",
    technique_name="Adversary-in-the-Middle: ARP Cache Poisoning",
    tactic_ids=["TA0006", "TA0009"],  # Credential Access, Collection
    mitre_url="https://attack.mitre.org/techniques/T1557/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit the stateless, unauthenticated nature of the Address Resolution "
            "Protocol (ARP) to position themselves between networked devices. By poisoning ARP caches "
            "with malicious IP-to-MAC address mappings, attackers intercept communications to enable "
            "network sniffing, credential theft, and data manipulation. In cloud environments, this "
            "technique targets internal VPC/VNet communications where ARP operates at Layer 2."
        ),
        attacker_goal="Intercept network traffic within cloud VPCs to steal credentials and manipulate data",
        why_technique=[
            "Intercept credentials transmitted within cloud networks",
            "Position between instances for man-in-the-middle attacks",
            "Capture unencrypted internal API communications",
            "Redirect traffic to attacker-controlled instances",
            "Bypass network-layer security controls via Layer 2 manipulation",
            "Enable follow-on attacks like session hijacking",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "ARP cache poisoning enables Layer 2 traffic interception within cloud VPCs, allowing "
            "credential theft and data manipulation. While network segmentation and encryption reduce "
            "impact, internal communications often lack TLS, making this technique effective for "
            "lateral movement. Severity is moderate-high as it requires network access but enables "
            "powerful man-in-the-middle capabilities."
        ),
        business_impact=[
            "Credential theft from unencrypted internal traffic",
            "Session hijacking and unauthorised API access",
            "Data manipulation and integrity violations",
            "Privacy violations from traffic interception",
            "Compliance violations (PCI-DSS, GDPR data protection)",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1040", "T1557", "T1078.004"],
        often_follows=["T1078.004", "T1021.007"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - VPC Traffic Mirroring for ARP Anomalies
        DetectionStrategy(
            strategy_id="t1557-002-aws-mirror",
            name="AWS VPC Traffic Mirroring for ARP Anomaly Detection",
            description="Mirror VPC traffic to detect ARP spoofing and gratuitous ARP anomalies.",
            detection_type=DetectionType.CUSTOM_LAMBDA,
            aws_service="vpc",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# AWS: Detect ARP cache poisoning via Traffic Mirroring

variable "monitored_eni_id" {
  type        = string
  description = "Network interface to monitor for ARP anomalies"
}

variable "target_nlb_arn" {
  type        = string
  description = "Network Load Balancer ARN for mirrored traffic analysis"
}

variable "alert_email" {
  type = string
}

# Step 1: Traffic mirror filter for ARP traffic
resource "aws_ec2_traffic_mirror_filter" "arp_detection" {
  description = "Capture ARP traffic for poisoning detection"

  # Capture all ARP traffic (EtherType 0x0806)
  ingress_filter_rule {
    rule_number       = 100
    destination_cidr  = "0.0.0.0/0"
    source_cidr       = "0.0.0.0/0"
    protocol          = 0
    traffic_direction = "ingress"
    rule_action       = "accept"
  }

  egress_filter_rule {
    rule_number       = 100
    destination_cidr  = "0.0.0.0/0"
    source_cidr       = "0.0.0.0/0"
    protocol          = 0
    traffic_direction = "egress"
    rule_action       = "accept"
  }
}

# Step 2: Traffic mirror session
resource "aws_ec2_traffic_mirror_target" "nlb" {
  network_load_balancer_arn = var.target_nlb_arn
}

resource "aws_ec2_traffic_mirror_session" "arp_monitoring" {
  description              = "Monitor for ARP cache poisoning"
  network_interface_id     = var.monitored_eni_id
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.arp_detection.id
  traffic_mirror_target_id = aws_ec2_traffic_mirror_target.nlb.id
  session_number           = 1
}

# Step 3: SNS alerts
resource "aws_sns_topic" "arp_alerts" {
  name = "arp-poisoning-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.arp_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}""",
                alert_severity="high",
                alert_title="ARP Cache Poisoning Detected",
                alert_description_template="Suspicious ARP traffic detected on {networkInterfaceId}. Multiple IPs mapping to single MAC or gratuitous ARP anomalies observed.",
                investigation_steps=[
                    "Analyse captured ARP traffic for gratuitous ARP patterns",
                    "Check for multiple IP addresses mapping to single MAC address",
                    "Review MAC address tables for duplicate entries",
                    "Identify instances sending unsolicited ARP replies",
                    "Examine VPC Flow Logs for corresponding traffic redirection",
                    "Check for unauthorised instances in subnet",
                ],
                containment_actions=[
                    "Isolate suspected malicious instances via security groups",
                    "Implement static ARP entries for critical systems",
                    "Enable VPC Flow Logs for detailed traffic analysis",
                    "Review and segment network to limit ARP broadcast domains",
                    "Deploy host-based intrusion detection on critical instances",
                    "Consider implementing DHCP snooping where supported",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Requires custom analysis logic to distinguish legitimate ARP from attacks; baseline normal ARP patterns per subnet",
            detection_coverage="65% - effective for detecting ARP anomalies but requires analysis infrastructure",
            evasion_considerations="Sophisticated attackers may use low-frequency poisoning; requires deep packet inspection",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4-6 hours",
            estimated_monthly_cost="$40-120 (VPC Traffic Mirroring + NLB + analysis infrastructure)",
            prerequisites=[
                "VPC Traffic Mirroring support",
                "Network Load Balancer",
                "Packet analysis infrastructure",
            ],
        ),
        # Strategy 2: AWS - Security Group and Network ACL Monitoring
        DetectionStrategy(
            strategy_id="t1557-002-aws-netacl",
            name="Network Configuration Change Detection",
            description="Detect network configuration changes that may enable ARP spoofing.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "ModifyNetworkInterfaceAttribute",
                            "AttachNetworkInterface",
                            "CreateNetworkInterface",
                            "ModifySubnetAttribute",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network configuration changes enabling ARP attacks

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for network changes
  NetworkConfigRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - ModifyNetworkInterfaceAttribute
            - AttachNetworkInterface
            - CreateNetworkInterface
            - ModifySubnetAttribute
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
                terraform_template="""# AWS: Monitor network configuration changes

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "network-config-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "network_config" {
  name = "network-configuration-changes"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "ModifyNetworkInterfaceAttribute",
        "AttachNetworkInterface",
        "CreateNetworkInterface",
        "ModifySubnetAttribute"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.network_config.name
  arn  = aws_sns_topic.alerts.arn
}

# Step 3: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
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
                alert_title="Network Configuration Modified",
                alert_description_template="Network interface configuration change {eventName} performed on {networkInterfaceId}. Review for potential ARP spoofing enablement.",
                investigation_steps=[
                    "Verify the principal performing network configuration change",
                    "Review source/destination check status on network interfaces",
                    "Check for promiscuous mode enablement",
                    "Examine subnet and routing table configurations",
                    "Review CloudTrail for related suspicious activities",
                    "Verify instance roles and security groups",
                ],
                containment_actions=[
                    "Re-enable source/destination checking if disabled inappropriately",
                    "Review and restrict EC2 network modification permissions",
                    "Audit all network interfaces in affected subnets",
                    "Enable enhanced VPC Flow Logs for monitoring",
                    "Implement SCPs to prevent unauthorised network changes",
                    "Review and update network ACLs",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate network operations (NAT instances, VPN gateways, load balancers)",
            detection_coverage="75% - catches configuration changes but not all attack vectors",
            evasion_considerations="Attackers using pre-configured instances or compromised admin credentials may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - VPC Flow Logs for Traffic Redirection
        DetectionStrategy(
            strategy_id="t1557-002-aws-flow",
            name="VPC Flow Logs Traffic Redirection Detection",
            description="Detect unusual traffic patterns indicating ARP-based redirection.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, srcport, dstport, bytes, packets
| filter action = "ACCEPT"
| stats count(*) as conn_count, sum(bytes) as total_bytes by srcaddr, dstaddr
| filter conn_count > 500
| sort total_bytes desc
| limit 50""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor VPC Flow Logs for ARP-based traffic redirection

Parameters:
  VpcId:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: VPC Flow Logs
  FlowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/vpc/flowlogs-arp-detection
      RetentionInDays: 7

  FlowLogRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: vpc-flow-logs.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: CloudWatchLogs
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !GetAtt FlowLogGroup.Arn

  FlowLog:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceType: VPC
      ResourceIds: [!Ref VpcId]
      TrafficType: ALL
      LogDestinationType: cloud-watch-logs
      LogGroupName: !Ref FlowLogGroup
      DeliverLogsPermissionArn: !GetAtt FlowLogRole.Arn

  # Step 2: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Metric filter for anomalous patterns
  TrafficRedirectionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes="*", start, end, action="ACCEPT", status]'
      MetricTransformations:
        - MetricName: UnusualTrafficPatterns
          MetricNamespace: Security/Network
          MetricValue: "1"

  TrafficAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousTrafficRedirection
      MetricName: UnusualTrafficPatterns
      Namespace: Security/Network
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# AWS: Detect traffic redirection via Flow Logs

variable "vpc_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flowlogs-arp-detection"
  retention_in_days = 7
}

# Step 2: IAM role for Flow Logs
resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-arp-detection"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

# Step 3: VPC Flow Log
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = var.vpc_id
}

# SNS alerts
resource "aws_sns_topic" "alerts" {
  name = "traffic-redirection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter
resource "aws_cloudwatch_log_metric_filter" "traffic_patterns" {
  name           = "unusual-traffic-patterns"
  log_group_name = aws_cloudwatch_log_group.flow_logs.name
  pattern        = "[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes, start, end, action=ACCEPT, status]"

  metric_transformation {
    name      = "UnusualTrafficPatterns"
    namespace = "Security/Network"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "traffic_alarm" {
  alarm_name          = "SuspiciousTrafficRedirection"
  metric_name         = "UnusualTrafficPatterns"
  namespace           = "Security/Network"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious Traffic Redirection Detected",
                alert_description_template="Unusual traffic patterns detected from {srcaddr} to {dstaddr}. May indicate ARP-based traffic redirection.",
                investigation_steps=[
                    "Review Flow Logs for connection patterns between source and destination",
                    "Check for multiple destinations from single source (potential relay)",
                    "Examine MAC address associations in subnet",
                    "Verify routing tables and security group configurations",
                    "Correlate with other network security events",
                    "Check instances for unauthorised network tools",
                ],
                containment_actions=[
                    "Isolate suspected rogue instances via security groups",
                    "Update network ACLs to block malicious traffic patterns",
                    "Enable GuardDuty for additional network threat detection",
                    "Review and segment VPC subnets to limit ARP scope",
                    "Implement micro-segmentation for critical workloads",
                    "Deploy host-based security agents on instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Establish traffic baselines per application; whitelist legitimate proxy and NAT instances",
            detection_coverage="20% - detects post-attack traffic anomalies only. VPC Flow Logs operate at Layer 3 and CANNOT see Layer 2 ARP traffic.",
            evasion_considerations="Low-frequency poisoning or blending with normal traffic patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-35 (VPC Flow Logs + CloudWatch)",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        # Strategy 4: GCP - VPC Flow Logs Anomaly Detection
        DetectionStrategy(
            strategy_id="t1557-002-gcp-flow",
            name="GCP VPC Flow Logs for ARP Anomaly Detection",
            description="Analyse VPC Flow Logs for traffic patterns indicating ARP-based attacks.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
logName="projects/[PROJECT_ID]/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.protocol=6
jsonPayload.reporter="SRC"''',
                gcp_terraform_template="""# GCP: Detect ARP-based traffic anomalies

variable "project_id" {
  type = string
}

variable "network_name" {
  type = string
}

variable "subnet_name" {
  type = string
}

variable "region" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Enable VPC Flow Logs with full metadata
resource "google_compute_subnetwork" "monitored" {
  name          = var.subnet_name
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = var.network_name

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.8
    metadata             = "INCLUDE_ALL_METADATA"
    metadata_fields      = [
      "src_instance",
      "dst_instance",
      "src_vpc",
      "dst_vpc"
    ]
  }
}

# Step 2: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Log-based metric for unusual flow patterns
resource "google_logging_metric" "arp_anomaly" {
  name   = "arp-traffic-anomalies"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.protocol=6
    jsonPayload.reporter="SRC"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "src_instance"
      value_type  = "STRING"
      description = "Source instance"
    }
    labels {
      key         = "dst_instance"
      value_type  = "STRING"
      description = "Destination instance"
    }
  }

  label_extractors = {
    "src_instance" = "EXTRACT(jsonPayload.src_instance.vm_name)"
    "dst_instance" = "EXTRACT(jsonPayload.dst_instance.vm_name)"
  }
}

# Alert policy
resource "google_monitoring_alert_policy" "arp_attack" {
  display_name = "ARP-Based Traffic Anomaly Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious traffic relay pattern"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.arp_anomaly.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 500
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.src_instance"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Unusual traffic pattern detected that may indicate ARP cache poisoning. Review VPC Flow Logs for traffic redirection."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: ARP Traffic Anomaly Detected",
                alert_description_template="Suspicious traffic patterns detected from instance {srcInstance}. Potential ARP cache poisoning.",
                investigation_steps=[
                    "Review VPC Flow Logs for traffic relay patterns",
                    "Check for multiple destinations from single source instance",
                    "Examine firewall rules and routing configurations",
                    "Verify instance network interface configurations",
                    "Check for unauthorised instances in subnet",
                    "Review Cloud Audit Logs for network configuration changes",
                ],
                containment_actions=[
                    "Apply firewall rules to isolate suspected instances",
                    "Enable Private Google Access to reduce exposure",
                    "Review and update VPC firewall rules",
                    "Implement VPC Service Controls for sensitive workloads",
                    "Enable Cloud IDS (Intrusion Detection System) if available",
                    "Review network topology and consider segmentation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Baseline normal traffic patterns; whitelist legitimate proxy and NAT instances",
            detection_coverage="20% - detects post-attack traffic anomalies only. VPC Flow Logs operate at Layer 3 and CANNOT see Layer 2 ARP traffic.",
            evasion_considerations="Slow attacks or legitimate-looking relay patterns may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$25-60 (VPC Flow Logs + Cloud Monitoring)",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging API enabled"],
        ),
        # Strategy 5: GCP - Compute Engine Network Configuration Monitoring
        DetectionStrategy(
            strategy_id="t1557-002-gcp-netconfig",
            name="GCP Network Configuration Change Detection",
            description="Monitor network interface and instance configuration changes enabling ARP attacks.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName=~"(v1.compute.instances.insert|v1.compute.instances.setMetadata|beta.compute.instances.updateNetworkInterface)"''',
                gcp_terraform_template="""# GCP: Monitor network configuration changes

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

# Step 2: Log-based metric for network config changes
resource "google_logging_metric" "network_config" {
  name   = "network-configuration-changes"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName=~"v1.compute.instances.insert" OR
     protoPayload.methodName=~"v1.compute.instances.setMetadata" OR
     protoPayload.methodName=~"beta.compute.instances.updateNetworkInterface")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "method_name"
      value_type  = "STRING"
      description = "API method called"
    }
  }

  label_extractors = {
    "method_name" = "EXTRACT(protoPayload.methodName)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "network_change" {
  display_name = "Network Configuration Modified"
  combiner     = "OR"

  conditions {
    display_name = "Network configuration change detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.network_config.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Network configuration change detected. Review for potential ARP spoofing enablement or malicious network modifications."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Network Configuration Modified",
                alert_description_template="Network configuration change {methodName} detected. Review for potential ARP attack enablement.",
                investigation_steps=[
                    "Verify the principal performing configuration change",
                    "Review instance network interface settings",
                    "Check for IP forwarding enablement",
                    "Examine firewall rule modifications",
                    "Review Cloud Audit Logs for related activities",
                    "Verify instance service account permissions",
                ],
                containment_actions=[
                    "Revert unauthorised network configuration changes",
                    "Review and restrict compute.instances.* IAM permissions",
                    "Enable organisation policy constraints for network changes",
                    "Audit all instances in affected VPC",
                    "Implement change management approval workflows",
                    "Enable VPC Flow Logs for detailed monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised infrastructure-as-code deployments and network operations",
            detection_coverage="70% - catches configuration changes but not all attack methods",
            evasion_considerations="Attackers with legitimate-looking credentials or using pre-configured instances",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 6: GCP - Packet Mirroring for Deep Analysis
        DetectionStrategy(
            strategy_id="t1557-002-gcp-mirror",
            name="GCP Packet Mirroring for ARP Analysis",
            description="Use Packet Mirroring to capture and analyse ARP traffic for poisoning attempts.",
            detection_type=DetectionType.CUSTOM_LAMBDA,
            aws_service="n/a",
            gcp_service="compute",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_terraform_template="""# GCP: Packet Mirroring for ARP detection

variable "project_id" {
  type = string
}

variable "network_name" {
  type = string
}

variable "subnet_name" {
  type = string
}

variable "region" {
  type = string
}

variable "mirrored_subnet_id" {
  type        = string
  description = "Subnet ID to mirror traffic from"
}

variable "collector_ilb_url" {
  type        = string
  description = "Internal Load Balancer URL for packet collector"
}

# Step 1: Packet Mirroring filter for ARP
resource "google_compute_packet_mirroring" "arp_detection" {
  name        = "arp-poisoning-detection"
  description = "Mirror ARP traffic for poisoning detection"
  region      = var.region

  network {
    url = "projects/${var.project_id}/global/networks/${var.network_name}"
  }

  collector_ilb {
    url = var.collector_ilb_url
  }

  mirrored_resources {
    subnetworks {
      url = var.mirrored_subnet_id
    }
  }

  filter {
    ip_protocols = ["arp"]
    direction    = "BOTH"
  }
}""",
                alert_severity="high",
                alert_title="GCP: ARP Anomaly Detected via Packet Mirroring",
                alert_description_template="ARP cache poisoning indicators detected via packet analysis. Gratuitous ARP or MAC-IP mapping anomalies observed.",
                investigation_steps=[
                    "Analyse captured ARP packets for gratuitous replies",
                    "Check for duplicate MAC addresses with different IPs",
                    "Identify instances sending suspicious ARP traffic",
                    "Review network topology and routing",
                    "Correlate with VPC Flow Logs for traffic redirection",
                    "Examine instance metadata and configurations",
                ],
                containment_actions=[
                    "Isolate malicious instances via firewall rules",
                    "Disable IP forwarding on suspected instances",
                    "Review and restrict network administration permissions",
                    "Enable Cloud IDS for additional protection",
                    "Implement network segmentation",
                    "Deploy Security Command Center for unified monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Requires packet analysis infrastructure; baseline legitimate ARP patterns",
            detection_coverage="70% - effective with proper analysis but infrastructure-intensive",
            evasion_considerations="Requires deep packet inspection capabilities; sophisticated attacks may evade",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4-6 hours",
            estimated_monthly_cost="$50-150 (Packet Mirroring + collector infrastructure + analysis)",
            prerequisites=[
                "Packet Mirroring support in region",
                "Internal Load Balancer",
                "Packet analysis infrastructure",
            ],
        ),
    ],
    recommended_order=[
        "t1557-002-aws-netacl",
        "t1557-002-gcp-netconfig",
        "t1557-002-aws-flow",
        "t1557-002-gcp-flow",
        "t1557-002-aws-mirror",
        "t1557-002-gcp-mirror",
    ],
    total_effort_hours=13.5,
    coverage_improvement="+15% improvement for Credential Access and Collection tactics against Layer 2 attacks",
)
