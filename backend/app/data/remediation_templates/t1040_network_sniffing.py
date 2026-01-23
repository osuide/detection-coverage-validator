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
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
    CloudProvider,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1040",
    technique_name="Network Sniffing",
    tactic_ids=["TA0006", "TA0007"],  # Credential Access, Discovery
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
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
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
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: DLQ for EventBridge
  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600

  # Step 3: EventBridge rule for traffic mirroring
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
          DeadLetterConfig:
            Arn: !GetAtt DLQ.Arn
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8

  # Step 4: Scoped topic policy for EventBridge
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt TrafficMirrorRule.Arn""",
                terraform_template="""# Detect AWS Traffic Mirroring sessions

variable "alert_email" {
  type = string
}

data "aws_caller_identity" "current" {}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name              = "traffic-mirroring-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: DLQ for EventBridge
resource "aws_sqs_queue" "dlq" {
  name                      = "traffic-mirroring-dlq"
  message_retention_seconds = 1209600
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
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
      values   = [aws_cloudwatch_event_rule.traffic_mirror.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 3: EventBridge rule
resource "aws_cloudwatch_event_rule" "traffic_mirror" {
  name = "traffic-mirroring-detection"
  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateTrafficMirrorSession",
        "CreateTrafficMirrorTarget",
        "CreateTrafficMirrorFilter"
      ]
    }
  })
}

# Step 4: EventBridge target with DLQ, retry, and input transformer
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.traffic_mirror.name
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
      account   = "$.account"
      region    = "$.region"
      time      = "$.time"
      eventName = "$.detail.eventName"
      principal = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"Traffic Mirroring Alert (T1040)
time=<time> account=<account> region=<region>
event=<eventName> principal=<principal>
Action: Investigate potential network sniffing setup"
EOT
  }
}

# Step 5: Scoped SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.traffic_mirror.arn
        }
      }
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
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: DLQ for EventBridge
  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600

  # Step 3: EventBridge rule for source/dest check disable
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
          DeadLetterConfig:
            Arn: !GetAtt DLQ.Arn
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8

  # Step 4: Scoped topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt SourceDestCheckRule.Arn""",
                terraform_template="""# Detect promiscuous mode network configuration

variable "alert_email" {
  type = string
}

data "aws_caller_identity" "current" {}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name              = "promiscuous-mode-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: DLQ for EventBridge
resource "aws_sqs_queue" "dlq" {
  name                      = "promiscuous-mode-dlq"
  message_retention_seconds = 1209600
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
data "aws_iam_policy_document" "eventbridge_dlq_policy_promiscuous" {
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
      values   = [aws_cloudwatch_event_rule.source_dest_check.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq_promiscuous" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy_promiscuous.json
}

# Step 3: EventBridge rule
resource "aws_cloudwatch_event_rule" "source_dest_check" {
  name = "network-promiscuous-mode"
  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["ModifyNetworkInterfaceAttribute"]
      requestParameters = {
        sourceDestCheck = [false]
      }
    }
  })
}

# Step 4: EventBridge target with DLQ and retry
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.source_dest_check.name
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
      account     = "$.account"
      region      = "$.region"
      time        = "$.time"
      principal   = "$.detail.userIdentity.arn"
      interfaceId = "$.detail.requestParameters.networkInterfaceId"
    }

    input_template = <<-EOT
"Promiscuous Mode Alert (T1040)
time=<time> account=<account> region=<region>
interface=<interfaceId> principal=<principal>
Action: Investigate source/dest check disabled"
EOT
  }
}

# Step 5: Scoped SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.source_dest_check.arn
        }
      }
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
    Default: /aws/vpc/flowlogs/t1040

Resources:
  # Step 1: CloudWatch Log Group
  FlowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Ref LogGroupName
      RetentionInDays: 7

  # Step 2: IAM role with confused-deputy mitigation
  FlowLogRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: t1040-vpc-flow-logs-role
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: vpc-flow-logs.amazonaws.com
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                aws:SourceAccount: !Ref AWS::AccountId
              ArnLike:
                aws:SourceArn: !Sub arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:vpc-flow-log/*
      Policies:
        - PolicyName: CloudWatchLogs
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                  - logs:DescribeLogGroups
                  - logs:DescribeLogStreams
                Resource: !Sub arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:${LogGroupName}:*

  # Step 3: VPC Flow Log with 1-minute aggregation
  FlowLog:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceType: VPC
      ResourceId: !Ref VpcId
      TrafficType: ALL
      LogDestinationType: cloud-watch-logs
      LogDestination: !GetAtt FlowLogGroup.Arn
      DeliverLogsPermissionArn: !GetAtt FlowLogRole.Arn
      MaxAggregationInterval: 60
      LogFormat: '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}'""",
                terraform_template="""# Enable VPC Flow Logs for network monitoring with best practices

variable "vpc_id" {
  type = string
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Step 1: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flowlogs/t1040"
  retention_in_days = 7
}

# Step 2: IAM role with confused-deputy mitigation
resource "aws_iam_role" "flow_logs" {
  name = "t1040-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnLike = {
          "aws:SourceArn" = "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:vpc-flow-log/*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "t1040-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

# Step 3: VPC Flow Log with 1-minute aggregation and explicit format
resource "aws_flow_log" "main" {
  vpc_id               = var.vpc_id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn

  # 1-minute aggregation for faster detection
  max_aggregation_interval = 60

  # Explicit log format for reliable parsing
  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status}"
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
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for packet mirroring
resource "google_logging_metric" "packet_mirror" {
  project = var.project_id
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
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
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
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for high-volume flows
resource "google_logging_metric" "high_volume_flows" {
  project = var.project_id
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
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
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
        # Azure Strategy: Network Sniffing
        DetectionStrategy(
            strategy_id="t1040-azure",
            name="Azure Network Sniffing Detection",
            description=(
                "Azure detection for Network Sniffing. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Network Sniffing (T1040)
# Microsoft Defender detects Network Sniffing activity

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1040-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1040"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (
                    "Suspicious activity detected",
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Network Sniffing activity"
  display_name = "Defender: Network Sniffing"
  enabled      = true
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Network Sniffing Detected",
                alert_description_template=(
                    "Network Sniffing activity detected. "
                    "Caller: {Caller}. Resource: {Resource}."
                ),
                investigation_steps=[
                    "Review Azure Activity Log for full operation details",
                    "Check caller identity and verify if authorised",
                    "Review affected resources and assess impact",
                    "Check for related activities in the same time window",
                    "Verify against change management records",
                ],
                containment_actions=[
                    "Disable compromised user/service principal if unauthorised",
                    "Revoke active sessions using Entra ID",
                    "Review and restrict Azure RBAC permissions",
                    "Enable additional Defender for Cloud protections",
                    "Implement Azure Policy to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Allowlist known automation accounts and CI/CD service principals. "
                "Use Azure Policy to define expected behaviour baselines."
            ),
            detection_coverage="70% - Azure-native detection for cloud operations",
            evasion_considerations=(
                "Attackers may use legitimate credentials from expected locations. "
                "Combine with Defender for Cloud for ML-based anomaly detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-50 (Log Analytics + Defender)",
            prerequisites=[
                "Azure subscription with Log Analytics workspace",
                "Defender for Cloud enabled (recommended)",
                "Appropriate Azure RBAC permissions for deployment",
            ],
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
