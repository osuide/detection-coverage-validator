"""
T1040 - Network Sniffing

Adversaries passively monitor network traffic to capture sensitive data in transit.
Common targets: credentials, configuration data, network topology information.
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
    technique_id="T1040",
    technique_name="Network Sniffing",
    tactic_ids=["TA0006", "TA0009"],  # Credential Access, Collection
    mitre_url="https://attack.mitre.org/techniques/T1040/",
    threat_context=ThreatContext(
        description=(
            "Adversaries passively monitor network traffic to capture sensitive data in transit. "
            "In cloud environments, attackers leverage traffic mirroring services like AWS Traffic "
            "Mirroring or VPC flow logs to intercept credentials, API keys, and configuration data. "
            "Much of this traffic may be in cleartext due to TLS termination at load balancers."
        ),
        attacker_goal="Capture sensitive data from network traffic including credentials and API keys",
        why_technique=[
            "Passive technique difficult to detect",
            "Captures credentials transmitted over unencrypted protocols",
            "Cloud traffic mirroring provides legitimate-looking access",
            "TLS termination at load balancers exposes cleartext traffic",
            "Can reveal network topology and service architecture",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Salt Typhoon Network Surveillance",
                year=2024,
                description="Chinese state-sponsored group used packet capture tools for extensive network surveillance in telecommunications infrastructure",
                reference_url="https://attack.mitre.org/groups/G1041/",
            ),
            Campaign(
                name="APT28 Wi-Fi Pineapple Operations",
                year=2023,
                description="APT28 deployed Wi-Fi pineapple devices and Responder tool for NetBIOS poisoning to capture network credentials",
                reference_url="https://attack.mitre.org/groups/G0007/",
            ),
            Campaign(
                name="Ukraine Power Grid Attack",
                year=2015,
                description="Sandworm Team used BlackEnergy malware with network sniffer module during attacks on Ukrainian critical infrastructure",
                reference_url="https://attack.mitre.org/groups/G0034/",
            ),
        ],
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Network sniffing enables passive credential theft and reconnaissance without "
            "triggering traditional alerting. Cloud traffic mirroring services provide "
            "attackers with legitimate-seeming access to network traffic. High severity "
            "due to potential exposure of credentials, API keys, and sensitive business data."
        ),
        business_impact=[
            "Exposure of credentials and API keys",
            "Loss of sensitive business communications",
            "Compliance violations from data interception",
            "Network topology and architecture disclosure",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1552.001", "T1557"],
        often_follows=["T1078.004", "T1110"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Traffic Mirroring Session Creation
        DetectionStrategy(
            strategy_id="t1040-aws-traffic-mirror",
            name="AWS Traffic Mirroring Session Detection",
            description="Detect creation of VPC traffic mirroring sessions which could be used for network sniffing.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateTrafficMirrorSession",
                            "CreateTrafficMirrorTarget",
                            "CreateTrafficMirrorFilter",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect VPC Traffic Mirroring creation

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for traffic mirroring
  TrafficMirrorRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateTrafficMirrorSession
            - CreateTrafficMirrorTarget
            - CreateTrafficMirrorFilter
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy to allow EventBridge
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
                terraform_template="""# Detect AWS Traffic Mirroring sessions

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "traffic-mirroring-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "traffic_mirror" {
  name = "traffic-mirroring-detection"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateTrafficMirrorSession",
        "CreateTrafficMirrorTarget",
        "CreateTrafficMirrorFilter"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.traffic_mirror.name
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
                alert_severity="high",
                alert_title="AWS Traffic Mirroring Session Created",
                alert_description_template="Traffic mirroring session created for {networkInterfaceId}. This could indicate network sniffing activity.",
                investigation_steps=[
                    "Identify who created the traffic mirroring session",
                    "Review the source and target network interfaces",
                    "Check if this is authorised security monitoring",
                    "Examine the traffic mirror filter rules",
                    "Review recent authentication activity for the principal",
                ],
                containment_actions=[
                    "Delete unauthorised traffic mirroring sessions",
                    "Review and restrict ec2:CreateTrafficMirror* permissions",
                    "Enable MFA for sensitive EC2 operations",
                    "Audit all existing traffic mirroring configurations",
                    "Enable VPC Flow Logs for network monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised security monitoring and network troubleshooting teams",
            detection_coverage="95% - catches all traffic mirroring API calls",
            evasion_considerations="Attacker may use existing mirroring sessions or compromise monitoring infrastructure",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - Suspicious Network Interface Configuration
        DetectionStrategy(
            strategy_id="t1040-aws-promiscuous-mode",
            name="Promiscuous Mode Network Interface Detection",
            description="Detect EC2 instances with network interfaces potentially configured for promiscuous mode sniffing.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter eventName in ["ModifyNetworkInterfaceAttribute", "AttachNetworkInterface"]
| filter requestParameters.sourceDestCheck = false
| sort @timestamp desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network interface promiscuous mode configuration

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for source/dest check disable
  SourceDestCheckRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [ModifyNetworkInterfaceAttribute]
          requestParameters:
            sourceDestCheck: [false]
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
                terraform_template="""# Detect promiscuous mode network configuration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "promiscuous-mode-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "source_dest_check" {
  name = "network-promiscuous-mode"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["ModifyNetworkInterfaceAttribute"]
      requestParameters = {
        sourceDestCheck = [false]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.source_dest_check.name
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
                alert_title="Network Interface Source/Dest Check Disabled",
                alert_description_template="Source/destination checking disabled on network interface {networkInterfaceId}. This may enable packet sniffing.",
                investigation_steps=[
                    "Identify the EC2 instance and network interface",
                    "Check if this is a NAT instance or router (legitimate use)",
                    "Review instance security group and network ACLs",
                    "Examine CloudWatch logs for suspicious process execution",
                    "Check for installation of packet capture tools",
                ],
                containment_actions=[
                    "Re-enable source/destination checking if not required",
                    "Isolate suspicious instances from production networks",
                    "Review IAM permissions for network interface modifications",
                    "Enable detailed monitoring on affected instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist NAT instances, routers, and VPN gateways that legitimately require this configuration",
            detection_coverage="80% - catches configuration changes but not initial setup",
            evasion_considerations="Attacker may use instances already configured this way",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs"],
        ),
        # Strategy 3: AWS - VPC Flow Logs Analysis for Unusual Patterns
        DetectionStrategy(
            strategy_id="t1040-aws-flow-anomaly",
            name="VPC Flow Logs Anomaly Detection",
            description="Detect unusual network patterns in VPC Flow Logs that may indicate network sniffing or reconnaissance.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, srcport, dstport, protocol, bytes
| filter action = "ACCEPT"
| stats count() as connectionCount, sum(bytes) as totalBytes by srcaddr, dstaddr
| filter connectionCount > 1000 or totalBytes > 10000000
| sort totalBytes desc
| limit 50""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor VPC Flow Logs for anomalous traffic patterns

Parameters:
  VpcId:
    Type: String
  LogGroupName:
    Type: String
    Default: /aws/vpc/flowlogs

Resources:
  # Step 1: Enable VPC Flow Logs
  FlowLog:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceType: VPC
      ResourceIds:
        - !Ref VpcId
      TrafficType: ALL
      LogDestinationType: cloud-watch-logs
      LogGroupName: !Ref LogGroupName
      DeliverLogsPermissionArn: !GetAtt FlowLogRole.Arn

  # Step 2: IAM role for Flow Logs
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
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !Sub arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:${LogGroupName}:*

  # Step 3: CloudWatch Log Group
  FlowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Ref LogGroupName
      RetentionInDays: 7""",
                terraform_template="""# Enable VPC Flow Logs for network monitoring

variable "vpc_id" {
  type = string
}

# Step 1: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flowlogs"
  retention_in_days = 7
}

# Step 2: IAM role for Flow Logs
resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-role"

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
        "logs:CreateLogGroup",
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
}""",
                alert_severity="medium",
                alert_title="Anomalous Network Traffic Detected",
                alert_description_template="Unusual network traffic pattern detected from {srcaddr}. High connection count or data transfer may indicate reconnaissance or sniffing.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review traffic patterns and protocols used",
                    "Check if source instance has legitimate monitoring role",
                    "Examine application logs on source instance",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Apply network ACLs to restrict suspicious traffic",
                    "Enable enhanced monitoring on affected instances",
                    "Review and update security group rules",
                    "Consider isolating suspicious instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baselines for normal traffic patterns and whitelist known monitoring infrastructure",
            detection_coverage="70% - behavioural analysis may miss stealthy sniffing",
            evasion_considerations="Low-volume sniffing may not trigger anomaly thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 4: GCP - Packet Mirroring Detection
        DetectionStrategy(
            strategy_id="t1040-gcp-packet-mirror",
            name="GCP Packet Mirroring Detection",
            description="Detect creation of VPC packet mirroring policies which could be used for network sniffing.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="v1.compute.packetMirrorings.insert"
OR protoPayload.methodName="v1.compute.packetMirrorings.patch"
protoPayload.serviceName="compute.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect packet mirroring creation

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

# Step 2: Log-based metric for packet mirroring
resource "google_logging_metric" "packet_mirror" {
  name   = "packet-mirroring-creation"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName="v1.compute.packetMirrorings.insert" OR
     protoPayload.methodName="v1.compute.packetMirrorings.patch")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "packet_mirror" {
  display_name = "Packet Mirroring Configuration Detected"
  combiner     = "OR"

  conditions {
    display_name = "Packet mirroring created or modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.packet_mirror.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Packet Mirroring Policy Created",
                alert_description_template="Packet mirroring policy created or modified. This could indicate network sniffing activity.",
                investigation_steps=[
                    "Identify who created the packet mirroring policy",
                    "Review the mirrored subnets and instances",
                    "Check the collector destination configuration",
                    "Verify if this is authorised security monitoring",
                    "Examine recent authentication events for the principal",
                ],
                containment_actions=[
                    "Delete unauthorised packet mirroring policies",
                    "Review and restrict compute.packetMirrorings.* permissions",
                    "Enable organisation policy constraints for packet mirroring",
                    "Audit all existing packet mirroring configurations",
                    "Enable VPC Flow Logs for all subnets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised network security and troubleshooting teams",
            detection_coverage="95% - catches all packet mirroring API calls",
            evasion_considerations="Attacker may use existing configurations or compromise monitoring infrastructure",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - VPC Flow Logs Anomaly Detection
        DetectionStrategy(
            strategy_id="t1040-gcp-flow-anomaly",
            name="GCP VPC Flow Logs Analysis",
            description="Analyse VPC Flow Logs for unusual network patterns indicating reconnaissance or sniffing.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.protocol!=6
jsonPayload.bytes_sent>10000000""",
                gcp_terraform_template="""# GCP: Monitor VPC Flow Logs for anomalies

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

# Step 2: Log-based metric for high-volume flows
resource "google_logging_metric" "high_volume_flows" {
  name   = "high-volume-network-flows"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.bytes_sent>10000000
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "flow_anomaly" {
  display_name = "High Volume Network Flow Detected"
  combiner     = "OR"

  conditions {
    display_name = "Unusual network traffic volume"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.high_volume_flows.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Anomalous Network Traffic Detected",
                alert_description_template="High-volume or unusual network traffic pattern detected. May indicate reconnaissance or data collection.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review protocols and ports used",
                    "Check if source has legitimate monitoring function",
                    "Examine application and system logs",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Apply firewall rules to restrict suspicious traffic",
                    "Enable enhanced monitoring on affected instances",
                    "Review and update VPC firewall rules",
                    "Consider network isolation for suspicious instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish traffic baselines and whitelist legitimate high-bandwidth applications",
            detection_coverage="70% - behavioural analysis may miss low-volume sniffing",
            evasion_considerations="Stealthy sniffing with low traffic volume may avoid detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging"],
        ),
    ],
    recommended_order=[
        "t1040-aws-traffic-mirror",
        "t1040-gcp-packet-mirror",
        "t1040-aws-promiscuous-mode",
        "t1040-aws-flow-anomaly",
        "t1040-gcp-flow-anomaly",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+20% improvement for Credential Access and Collection tactics",
)
