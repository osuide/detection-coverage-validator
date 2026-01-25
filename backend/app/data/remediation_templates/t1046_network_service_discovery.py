"""
T1046 - Network Service Discovery

Adversaries attempt to enumerate services running on remote hosts and network infrastructure.
Methods include port scans, vulnerability scans, and service enumeration across cloud environments.
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
    technique_id="T1046",
    technique_name="Network Service Discovery",
    tactic_ids=["TA0007"],  # Discovery
    mitre_url="https://attack.mitre.org/techniques/T1046/",
    threat_context=ThreatContext(
        description=(
            "Adversaries attempt to enumerate services running on remote hosts to identify "
            "vulnerabilities and potential attack vectors. In cloud environments, attackers use "
            "scanning tools to discover services on EC2 instances, GCE instances, and container hosts. "
            "This reconnaissance helps attackers map the network topology, identify running services, "
            "and locate vulnerable systems for further exploitation."
        ),
        attacker_goal="Identify running services and open ports to find vulnerable systems for exploitation",
        why_technique=[
            "Identifies vulnerable services and outdated software versions",
            "Maps network topology and service architecture",
            "Locates potential entry points for lateral movement",
            "Discovers misconfigured services and exposed management interfaces",
            "Enables targeted exploitation based on discovered services",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_high",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Network service discovery is a critical reconnaissance technique that enables attackers "
            "to identify vulnerable systems and plan targeted attacks. In cloud environments, scanning "
            "activity is common but unauthorised scans can quickly map the entire infrastructure. "
            "High severity due to its role as a precursor to exploitation and lateral movement."
        ),
        business_impact=[
            "Exposure of network topology and service architecture",
            "Identification of vulnerable and outdated services",
            "Reconnaissance enabling targeted attacks",
            "Potential discovery of exposed management interfaces",
            "Privacy concerns from unauthorised network scanning",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1190", "T1210", "T1021", "T1570"],
        often_follows=["T1078.004", "T1110", "T1580"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - VPC Flow Logs Port Scanning Detection
        DetectionStrategy(
            strategy_id="t1046-aws-port-scan",
            name="AWS VPC Flow Logs Port Scanning Detection",
            description="Detect rapid sequential connection attempts across multiple ports from a single source, indicating port scanning activity.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, srcport, dstport, protocol, action
| filter action = "REJECT"
| stats count() as rejectCount, count_distinct(dstport) as uniquePorts by srcaddr, dstaddr, bin(5m)
| filter uniquePorts > 20 and rejectCount > 50
| sort rejectCount desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect port scanning activity with VPC Flow Logs and GuardDuty

Parameters:
  NamePrefix:
    Type: String
    Default: t1046-port-scan
  VpcId:
    Type: String
  AlertEmail:
    Type: String
  ThresholdRejects:
    Type: Number
    Default: 50

Resources:
  # Step 1: CloudWatch Log Group for VPC Flow Logs
  FlowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub /aws/vpc/flowlogs/${NamePrefix}
      RetentionInDays: 7

  # Step 2: IAM Role with confused-deputy mitigation
  FlowLogRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub ${NamePrefix}-vpc-flow-logs-role
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
                Resource: '*'

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
      LogFormat: '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}'

  # Step 4: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Sub ${NamePrefix}-alerts
      DisplayName: Port Scan Alerts
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 5: Metric filter for TCP REJECT flows
  PortScanMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FlowLogGroup
      FilterPattern: '[version, accountid, interfaceid, srcaddr, dstaddr, srcport, dstport, protocol=6, packets, bytes, start, end, action=REJECT, logstatus]'
      MetricTransformations:
        - MetricName: PortScanRejects
          MetricNamespace: Security/NetworkScanning
          MetricValue: '1'
          DefaultValue: 0

  # Step 6: CloudWatch alarm
  PortScanAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub ${NamePrefix}-heuristic
      AlarmDescription: High-rate REJECTed TCP flows indicating port scanning
      MetricName: PortScanRejects
      Namespace: Security/NetworkScanning
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: !Ref ThresholdRejects
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 7: GuardDuty EventBridge rule for high-confidence detection
  GuardDutyRule:
    Type: AWS::Events::Rule
    Properties:
      Name: !Sub ${NamePrefix}-guardduty
      Description: Alert on GuardDuty Recon:EC2/Portscan findings
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          severity: [{ numeric: ['>=', 4] }]
          type:
            - prefix: 'Recon:EC2/Portscan'
            - prefix: 'Recon:EC2/PortProbeUnprotectedPort'
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  # Step 8: DLQ for EventBridge
  GuardDutyDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub ${NamePrefix}-guardduty-dlq
      MessageRetentionPeriod: 1209600

  # Step 9: SNS topic policy for CloudWatch and EventBridge
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Sid: AllowCloudWatchAlarmsPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
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
                aws:SourceArn: !GetAtt GuardDutyRule.Arn""",
                terraform_template="""# AWS: Detect port scanning in VPC Flow Logs with GuardDuty augmentation

variable "name_prefix" {
  type    = string
  default = "t1046-port-scan"
}

variable "vpc_id" {
  type = string
}

variable "alert_email" {
  type = string
}

variable "threshold_rejects" {
  type    = number
  default = 50
}

variable "enable_guardduty" {
  type    = bool
  default = true
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Step 1: CloudWatch Log Group and VPC Flow Logs with confused-deputy mitigation
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flowlogs/${var.name_prefix}"
  retention_in_days = 7
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.name_prefix}-vpc-flow-logs-role"

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
  name = "${var.name_prefix}-flow-logs-policy"
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
      Resource = "*"
    }]
  })
}

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
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  display_name      = "Port Scan Alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Metric filter for TCP REJECT flows (protocol=6)
resource "aws_cloudwatch_log_metric_filter" "port_scan" {
  name           = "${var.name_prefix}-rejects"
  log_group_name = aws_cloudwatch_log_group.flow_logs.name

  # Filter TCP (protocol=6) REJECT flows only
  pattern = "[version, accountid, interfaceid, srcaddr, dstaddr, srcport, dstport, protocol=6, packets, bytes, start, end, action=REJECT, logstatus]"

  metric_transformation {
    name          = "PortScanRejects"
    namespace     = "Security/NetworkScanning"
    value         = "1"
    default_value = "0"
    dimensions = {
      SourceIP = "$srcaddr"
    }
  }
}

# Step 4: Alarm using metric math to aggregate across all SourceIP dimensions
resource "aws_cloudwatch_metric_alarm" "port_scan" {
  alarm_name          = "${var.name_prefix}-heuristic"
  alarm_description   = "Heuristic scan signal: high-rate REJECTed flows (aggregated across SourceIP)"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = var.threshold_rejects
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  # Metric math aggregates across all SourceIP dimension values
  metric_query {
    id          = "e1"
    return_data = true
    label       = "TotalPortScanRejects"
    expression  = "SUM(SEARCH('{Security/NetworkScanning,SourceIP} MetricName=\"PortScanRejects\"', 'Sum', 300))"
  }
}

# Step 5: GuardDuty integration for higher-confidence detection
resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true
}

resource "aws_cloudwatch_event_rule" "guardduty_portscan" {
  name        = "${var.name_prefix}-guardduty"
  description = "Alert on GuardDuty Recon:EC2/Portscan findings"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4] }]
      type = [
        { prefix = "Recon:EC2/Portscan" },
        { prefix = "Recon:EC2/PortProbeUnprotectedPort" }
      ]
    }
  })
}

resource "aws_sqs_queue" "guardduty_dlq" {
  name                      = "${var.name_prefix}-guardduty-dlq"
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

    resources = [aws_sqs_queue.guardduty_dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.guardduty_portscan.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.guardduty_dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_portscan.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.guardduty_dlq.arn
  }

  input_transformer {
    input_paths = {
      acct     = "$.account"
      region   = "$.region"
      time     = "$.time"
      type     = "$.detail.type"
      severity = "$.detail.severity"
      srcip    = "$.detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4"
      dstport  = "$.detail.service.action.networkConnectionAction.localPortDetails.port"
    }

    input_template = <<-EOT
"GuardDuty Recon Alert (T1046)
time=<time> account=<acct> region=<region>
type=<type> severity=<severity>
src_ip=<srcip> dst_port=<dstport>"
EOT
  }
}

# Step 6: Scoped SNS topic policy for both CloudWatch and EventBridge
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
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
      },
      {
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
            "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_portscan.arn
          }
        }
      }
    ]
  })
}""",
                alert_severity="high",
                alert_title="Port Scanning Activity Detected",
                alert_description_template="Multiple rejected connection attempts detected from {srcaddr} targeting {dstaddr} across {uniquePorts} different ports. This indicates port scanning reconnaissance.",
                investigation_steps=[
                    "Identify the source IP address and determine if it's internal or external",
                    "Check if source is an authorised security scanner",
                    "Review the target ports and protocols scanned",
                    "Examine CloudTrail logs for associated API activity",
                    "Check for successful connections following the scan attempts",
                    "Review security group rules for the targeted instances",
                ],
                containment_actions=[
                    "Block source IP using network ACLs if external attacker",
                    "Isolate compromised instance if internal source",
                    "Review and tighten security group rules",
                    "Enable GuardDuty for automated threat detection",
                    "Implement AWS Network Firewall for advanced filtering",
                    "Review IAM permissions if scanning from compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised vulnerability scanners and security assessment tools. Adjust thresholds based on environment size.",
            detection_coverage="85% - catches systematic port scanning but may miss slow, stealthy scans",
            evasion_considerations="Slow scans with delays between probes may avoid detection thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 2: AWS - GuardDuty Reconnaissance Findings
        DetectionStrategy(
            strategy_id="t1046-aws-guardduty",
            name="AWS GuardDuty Network Scanning Detection",
            description="Leverage GuardDuty's built-in detection for reconnaissance and port scanning activities.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.guardduty"],
                    "detail-type": ["GuardDuty Finding"],
                    "detail": {
                        "type": [
                            "Recon:EC2/PortProbeUnprotectedPort",
                            "Recon:EC2/PortProbeEMRUnprotectedPort",
                            "Recon:EC2/Portscan",
                            "UnauthorizedAccess:EC2/TorClient",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network scanning using GuardDuty findings

Parameters:
  NamePrefix:
    Type: String
    Default: t1046-guardduty
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty (manual step required)
  # Note: GuardDuty must be enabled through console or AWS CLI

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Sub ${NamePrefix}-alerts
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Dead letter queue
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub ${NamePrefix}-dlq
      MessageRetentionPeriod: 1209600

  # Step 4: EventBridge rule for GuardDuty findings
  GuardDutyReconRule:
    Type: AWS::Events::Rule
    Properties:
      Name: !Sub ${NamePrefix}-network-scanning
      Description: Alert on GuardDuty reconnaissance findings
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          severity:
            - numeric: ['>=', 4]
          type:
            - prefix: 'Recon:EC2/PortProbeUnprotectedPort'
            - prefix: 'Recon:EC2/PortProbeEMRUnprotectedPort'
            - prefix: 'Recon:EC2/Portscan'
            - prefix: 'UnauthorizedAccess:EC2/TorIPCaller'
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          DeadLetterConfig:
            Arn: !GetAtt DeadLetterQueue.Arn
          InputTransformer:
            InputPathsMap:
              account: $.account
              region: $.region
              time: $.time
              type: $.detail.type
              severity: $.detail.severity
              title: $.detail.title
              srcip: $.detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4
              dstport: $.detail.service.action.networkConnectionAction.localPortDetails.port
            InputTemplate: |
              "GuardDuty Network Reconnaissance Alert (T1046)
              time=<time> account=<account> region=<region>
              type=<type> severity=<severity>
              title=<title>
              src_ip=<srcip> dst_port=<dstport>"

  # Step 5: Scoped SNS topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
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
                aws:SourceArn: !GetAtt GuardDutyReconRule.Arn""",
                terraform_template="""# AWS: GuardDuty reconnaissance detection with optimised EventBridge pattern

variable "name_prefix" {
  type    = string
  default = "t1046-guardduty"
}

variable "alert_email" {
  type = string
}

variable "guardduty_min_severity" {
  type    = number
  default = 4
}

data "aws_caller_identity" "current" {}

# Step 1: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  display_name      = "GuardDuty Recon Alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule with severity filtering
resource "aws_cloudwatch_event_rule" "guardduty_recon" {
  name        = "${var.name_prefix}-network-scanning"
  description = "Alert on GuardDuty reconnaissance findings"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.guardduty_min_severity] }]
      type = [
        { prefix = "Recon:EC2/PortProbeUnprotectedPort" },
        { prefix = "Recon:EC2/PortProbeEMRUnprotectedPort" },
        { prefix = "Recon:EC2/Portscan" },
        { prefix = "UnauthorizedAccess:EC2/TorClient" }
      ]
    }
  })
}

# Step 4: DLQ for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.name_prefix}-dlq"
  message_retention_seconds = 1209600
}

# Step 5: EventBridge target with DLQ, retry, and input transformer
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
      acct     = "$.account"
      region   = "$.region"
      time     = "$.time"
      type     = "$.detail.type"
      severity = "$.detail.severity"
      title    = "$.detail.title"
      srcip    = "$.detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4"
      dstip    = "$.detail.service.action.networkConnectionAction.localIpDetails.ipAddressV4"
      dstport  = "$.detail.service.action.networkConnectionAction.localPortDetails.port"
    }

    input_template = <<-EOT
"GuardDuty Network Reconnaissance Alert (T1046)
time=<time> account=<acct> region=<region>
type=<type> severity=<severity>
title=<title>
src_ip=<srcip> dst_ip=<dstip> dst_port=<dstport>"
EOT
  }
}

# Step 6: Scoped SNS topic policy
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_recon.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Network Reconnaissance Detected",
                alert_description_template="GuardDuty detected {type} activity targeting {resource}. Severity: {severity}",
                investigation_steps=[
                    "Review the GuardDuty finding details in the console",
                    "Identify the source IP and check threat intelligence",
                    "Examine the targeted resources and ports",
                    "Check if any connections succeeded after the scan",
                    "Review CloudTrail for associated API activity",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Block malicious source IPs using network ACLs",
                    "Review and restrict security group ingress rules",
                    "Enable AWS Network Firewall for advanced protection",
                    "Implement AWS WAF for public-facing applications",
                    "Consider enabling GuardDuty Malware Protection",
                    "Review IAM policies for overly permissive network access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses threat intelligence and machine learning to minimise false positives. Whitelist known scanners if needed.",
            detection_coverage="90% - GuardDuty provides comprehensive reconnaissance detection",
            evasion_considerations="Very slow scans or scans from trusted IP ranges may avoid detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$50-200 depending on data volume",
            prerequisites=["GuardDuty enabled (30-day free trial available)"],
        ),
        # Strategy 3: AWS - Security Group Modification After Scanning
        DetectionStrategy(
            strategy_id="t1046-aws-sg-recon",
            name="Security Group Enumeration Detection",
            description="Detect API calls attempting to enumerate security group rules, which attackers use to map network access controls.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, eventName, errorCode
| filter eventName in ["DescribeSecurityGroups", "DescribeSecurityGroupRules", "DescribeInstances", "DescribeNetworkInterfaces"]
| stats count() as apiCallCount by userIdentity.principalId, sourceIPAddress, bin(5m)
| filter apiCallCount > 50
| sort apiCallCount desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect excessive security group enumeration

Parameters:
  NamePrefix:
    Type: String
    Default: t1046-sg-enum
  CloudTrailLogGroup:
    Type: String
    Default: /aws/cloudtrail/logs
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

  # Step 2: Metric filter for enumeration
  EnumerationMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = DescribeSecurityGroups) || ($.eventName = DescribeSecurityGroupRules) || ($.eventName = DescribeInstances) }'
      MetricTransformations:
        - MetricNamespace: Security/Reconnaissance
          MetricName: SecurityGroupEnumeration
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: CloudWatch alarm
  EnumerationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub ${NamePrefix}-detected
      AlarmDescription: Excessive security group enumeration detected
      MetricName: SecurityGroupEnumeration
      Namespace: Security/Reconnaissance
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 4: SNS topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Sid: AllowCloudWatchAlarmsPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# AWS: Detect security group enumeration

variable "name_prefix" {
  type    = string
  default = "t1046-sg-enum"
}

variable "cloudtrail_log_group" {
  type    = string
  default = "/aws/cloudtrail/logs"
}

variable "alert_email" {
  type = string
}

data "aws_caller_identity" "current" {}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  display_name      = "SG Enumeration Alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter
resource "aws_cloudwatch_log_metric_filter" "sg_enumeration" {
  name           = "${var.name_prefix}-detection"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ ($.eventName = DescribeSecurityGroups) || ($.eventName = DescribeSecurityGroupRules) || ($.eventName = DescribeInstances) }"

  metric_transformation {
    name          = "SecurityGroupEnumeration"
    namespace     = "Security/Reconnaissance"
    value         = "1"
    default_value = "0"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "sg_enumeration" {
  alarm_name          = "${var.name_prefix}-detected"
  alarm_description   = "Excessive security group enumeration detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SecurityGroupEnumeration"
  namespace           = "Security/Reconnaissance"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 4: Scoped SNS topic policy
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
                alert_title="Excessive Security Group Enumeration",
                alert_description_template="Principal {principalId} made {apiCallCount} security group enumeration API calls from {sourceIPAddress}. This may indicate reconnaissance activity.",
                investigation_steps=[
                    "Identify the IAM principal making the API calls",
                    "Check if this is an authorised security scanner or audit tool",
                    "Review the source IP address for suspicious activity",
                    "Examine what other API calls the principal made",
                    "Check for successful authentication from unusual locations",
                    "Review recent IAM credential activity",
                ],
                containment_actions=[
                    "Rotate credentials if compromise suspected",
                    "Apply SCPs to restrict reconnaissance API calls",
                    "Implement condition keys requiring MFA for describe operations",
                    "Review and reduce overly broad IAM policies",
                    "Enable CloudTrail Insights for anomaly detection",
                    "Consider implementing AWS Config rules for compliance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised security tools, CI/CD pipelines, and infrastructure management tools",
            detection_coverage="75% - detects API-based enumeration but not network-level scanning",
            evasion_considerations="Attackers may use stolen credentials with existing authorised access",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        # Strategy 4: GCP - VPC Flow Logs Port Scanning Detection
        DetectionStrategy(
            strategy_id="t1046-gcp-port-scan",
            name="GCP VPC Flow Logs Port Scanning Detection",
            description="Detect rapid connection attempts across multiple ports indicating port scanning in GCP networks.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port>0
jsonPayload.reporter="DEST" """,
                gcp_terraform_template="""# GCP: Detect port scanning in VPC Flow Logs

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

# Step 2: Log-based metric for port scanning
resource "google_logging_metric" "port_scan" {
  project = var.project_id
  name   = "port-scanning-detection"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.reporter="DEST"
    jsonPayload.packets_sent<5
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP performing scanning"
    }
    labels {
      key         = "dest_ip"
      value_type  = "STRING"
      description = "Destination IP being scanned"
    }
  }

  label_extractors = {
    "source_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
    "dest_ip"   = "EXTRACT(jsonPayload.connection.dest_ip)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "port_scan" {
  project      = var.project_id
  display_name = "Port Scanning Activity Detected"
  combiner     = "OR"

  conditions {
    display_name = "Multiple connection attempts to different ports"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.port_scan.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
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

  documentation {
    content = "Port scanning activity detected. Multiple rejected connections from a single source indicate reconnaissance."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Port Scanning Activity Detected",
                alert_description_template="Multiple connection attempts detected from {source_ip} targeting {dest_ip} across multiple ports. This indicates network service discovery scanning.",
                investigation_steps=[
                    "Identify the source IP and check if it's internal or external",
                    "Verify if source is an authorised security scanner",
                    "Review the target ports and services scanned",
                    "Check Cloud Audit Logs for associated API activity",
                    "Examine if any connections succeeded",
                    "Review firewall rules for the targeted instances",
                ],
                containment_actions=[
                    "Block source IP using VPC firewall rules if external",
                    "Isolate compromised instance if internal source",
                    "Review and restrict firewall ingress rules",
                    "Enable Cloud IDS for intrusion detection",
                    "Implement Cloud Armour for DDoS protection",
                    "Review service account permissions if scanning from GCP",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised vulnerability scanners and adjust thresholds for environment size",
            detection_coverage="85% - detects systematic scanning but may miss slow reconnaissance",
            evasion_considerations="Slow, distributed scans may avoid rate-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$15-40",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging"],
        ),
        # Strategy 5: GCP - API Enumeration Detection
        DetectionStrategy(
            strategy_id="t1046-gcp-api-enum",
            name="GCP Compute API Enumeration Detection",
            description="Detect excessive API calls to enumerate GCP compute resources, instances, and network configuration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="compute.googleapis.com"
(protoPayload.methodName=~"list" OR protoPayload.methodName=~"get")
(protoPayload.methodName=~"instances" OR protoPayload.methodName=~"firewalls" OR protoPayload.methodName=~"networks")""",
                gcp_terraform_template="""# GCP: Detect compute resource enumeration

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

# Step 2: Log-based metric for enumeration
resource "google_logging_metric" "compute_enumeration" {
  project = var.project_id
  name   = "compute-resource-enumeration"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName=~".*list.*" OR protoPayload.methodName=~".*get.*")
    (protoPayload.methodName=~".*instances.*" OR
     protoPayload.methodName=~".*firewalls.*" OR
     protoPayload.methodName=~".*networks.*")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal performing enumeration"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "enumeration" {
  project      = var.project_id
  display_name = "Excessive Compute Resource Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "High volume of enumeration API calls"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.compute_enumeration.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "Excessive compute resource enumeration detected. This may indicate reconnaissance activity."
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Excessive Compute Resource Enumeration",
                alert_description_template="Principal {principal} made {apiCalls} enumeration API calls. This may indicate network reconnaissance activity.",
                investigation_steps=[
                    "Identify the principal (user or service account)",
                    "Check if this is an authorised security tool or scanner",
                    "Review the source IP address for suspicious activity",
                    "Examine what other API calls were made",
                    "Check for recent authentication anomalies",
                    "Review IAM permissions for the principal",
                ],
                containment_actions=[
                    "Rotate service account keys if compromise suspected",
                    "Apply organisation policies to restrict enumeration",
                    "Implement VPC Service Controls for data perimeter",
                    "Review and reduce overly permissive IAM roles",
                    "Enable Cloud Asset Inventory for visibility",
                    "Consider implementing Context-Aware Access policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised infrastructure tools, CI/CD pipelines, and monitoring systems",
            detection_coverage="75% - detects API enumeration but not network-level scanning",
            evasion_considerations="Attackers using compromised service accounts with legitimate access may blend in",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Network Service Discovery
        DetectionStrategy(
            strategy_id="t1046-azure",
            name="Azure Network Service Discovery Detection",
            description=(
                "Azure detection for Network Service Discovery. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Network Service Discovery Detection - Azure Network Enumeration
// Technique: T1046
// Detects enumeration of NSGs, VNets, Subnets, and network scanning patterns
// Prerequisites: AzureActivity, AzureNetworkAnalytics_CL (NSG Flow Logs), AzureDiagnostics

// Define network enumeration ARM operations
let NetworkEnumOps = dynamic([
    // NSG enumeration
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/read",
    "Microsoft.Network/networkSecurityGroups/effectiveNetworkSecurityGroups/action",
    // VNet/Subnet enumeration
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/virtualNetworks/subnets/read",
    "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read",
    // Network interface discovery
    "Microsoft.Network/networkInterfaces/read",
    "Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action",
    "Microsoft.Network/networkInterfaces/effectiveRouteTable/action",
    // Public IP enumeration
    "Microsoft.Network/publicIPAddresses/read",
    // Firewall enumeration
    "Microsoft.Network/azureFirewalls/read",
    "Microsoft.Network/firewallPolicies/read",
    // Network Watcher (network analysis tools)
    "Microsoft.Network/networkWatchers/read",
    "Microsoft.Network/networkWatchers/topology/action",
    "Microsoft.Network/networkWatchers/securityGroupView/action",
    "Microsoft.Network/networkWatchers/ipFlowVerify/action",
    // Load Balancer discovery
    "Microsoft.Network/loadBalancers/read",
    "Microsoft.Network/loadBalancers/frontendIPConfigurations/read"
]);

// Primary detection: Bulk network enumeration via AzureActivity
let NetworkEnumeration = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue in (NetworkEnumOps)
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EnumOperations = count(),
    UniqueNSGs = dcountif(Resource, OperationNameValue contains "networkSecurityGroups"),
    UniqueVNets = dcountif(Resource, OperationNameValue contains "virtualNetworks"),
    OperationTypes = make_set(OperationNameValue, 15),
    ResourcesAccessed = make_set(Resource, 20)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where EnumOperations > 20 or UniqueNSGs > 5 or UniqueVNets > 3
| extend AlertType = "NetworkEnumeration";

// Detect Network Watcher reconnaissance (security analysis tools)
let NetworkWatcherRecon = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has "Microsoft.Network/networkWatchers"
| where OperationNameValue has_any ("topology", "securityGroupView", "ipFlowVerify", "nextHop")
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    WatcherOps = count(),
    Operations = make_set(OperationNameValue, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where WatcherOps > 5
| extend AlertType = "NetworkWatcherRecon";

// First-time network enumeration from new IP
let FirstTimeNetworkEnum = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue in (NetworkEnumOps)
| where ActivityStatusValue in ("Success", "Succeeded")
| join kind=leftanti (
    AzureActivity
    | where TimeGenerated between (ago(30d) .. ago(24h))
    | where OperationNameValue in (NetworkEnumOps)
    | distinct Caller, CallerIpAddress
) on Caller, CallerIpAddress
| summarize
    FirstTimeEnumOps = count(),
    Operations = make_set(OperationNameValue, 10)
    by Caller, CallerIpAddress
| where FirstTimeEnumOps > 3
| extend AlertType = "FirstTimeNetworkEnumFromNewIP";

// Combine AzureActivity-based detection signals (always available)
// Note: Port scanning detection via AzureNetworkAnalytics_CL requires Traffic Analytics
// and is implemented as a separate alert rule in Terraform
NetworkEnumeration
| union NetworkWatcherRecon
| union FirstTimeNetworkEnum
| project
    TimeGenerated,
    AlertType,
    Caller,
    SourceIP = CallerIpAddress,
    Details = pack_all()
| order by TimeGenerated desc""",
                azure_terraform_template="""# Azure Detection for Network Service Discovery
# MITRE ATT&CK: T1046
# Detects network enumeration, NSG/VNet reconnaissance, and port scanning

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
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

variable "enum_threshold" {
  type        = number
  default     = 20
  description = "Threshold for network enumeration operations"
}

variable "portscan_threshold" {
  type        = number
  default     = 100
  description = "Threshold for denied connections indicating port scanning"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "t1046-network-discovery-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "T1046Alert"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Primary Alert: Network Enumeration Detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "network_enumeration" {
  name                = "t1046-network-enumeration-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Network Service Discovery Detection - Azure Network Enumeration
// Technique: T1046
let NetworkEnumOps = dynamic([
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/read",
    "Microsoft.Network/networkSecurityGroups/effectiveNetworkSecurityGroups/action",
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/virtualNetworks/subnets/read",
    "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read",
    "Microsoft.Network/networkInterfaces/read",
    "Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Network/azureFirewalls/read",
    "Microsoft.Network/firewallPolicies/read",
    "Microsoft.Network/networkWatchers/read",
    "Microsoft.Network/networkWatchers/topology/action",
    "Microsoft.Network/networkWatchers/securityGroupView/action",
    "Microsoft.Network/loadBalancers/read"
]);
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue in (NetworkEnumOps)
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EnumOperations = count(),
    UniqueNSGs = dcountif(Resource, OperationNameValue contains "networkSecurityGroups"),
    UniqueVNets = dcountif(Resource, OperationNameValue contains "virtualNetworks"),
    OperationTypes = make_set(OperationNameValue, 15)
    by Caller, CallerIpAddress
| where EnumOperations > ${var.enum_threshold} or UniqueNSGs > 5 or UniqueVNets > 3
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects bulk enumeration of NSGs, VNets, and network resources indicating T1046 reconnaissance"
  display_name = "T1046: Network Enumeration Detected"
  enabled      = true

  tags = {
    "mitre-technique" = "T1046"
    "detection-type"  = "network-reconnaissance"
  }
}

# Alert: Network Watcher Reconnaissance
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "network_watcher_recon" {
  name                = "t1046-network-watcher-recon"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Network Watcher Security Analysis Tool Usage
// Technique: T1046
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "Microsoft.Network/networkWatchers"
| where OperationNameValue has_any ("topology", "securityGroupView", "ipFlowVerify", "nextHop")
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    WatcherOps = count(),
    Operations = make_set(OperationNameValue, 10)
    by Caller, CallerIpAddress
| where WatcherOps > 5
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects usage of Network Watcher security analysis tools for network reconnaissance"
  display_name = "T1046: Network Watcher Reconnaissance"
  enabled      = true

  tags = {
    "mitre-technique" = "T1046"
    "detection-type"  = "network-watcher-recon"
  }
}

# Alert: Port Scanning via NSG Flow Logs (requires Traffic Analytics)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "port_scanning" {
  name                = "t1046-port-scanning-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT15M"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Port Scanning Detection via NSG Flow Logs
// Technique: T1046
// Requires Traffic Analytics enabled on NSG Flow Logs
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(15m)
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| where FlowStatus_s == "D"  // Denied flows
| where FlowDirection_s == "I"  // Inbound
| summarize
    DeniedConnections = count(),
    UniqueDestPorts = dcount(DestPort_d),
    DestPorts = make_set(DestPort_d, 50)
    by SrcIP_s, DestIP_s
| where DeniedConnections > ${var.portscan_threshold} or UniqueDestPorts > 20
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects port scanning activity via NSG Flow Logs denied connections"
  display_name = "T1046: Port Scanning Detected"
  enabled      = true

  tags = {
    "mitre-technique" = "T1046"
    "detection-type"  = "port-scanning"
  }
}

# Alert: First-time Network Enumeration from New IP
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "first_time_enum" {
  name                = "t1046-first-time-network-enum"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT15M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 3

  criteria {
    query = <<-QUERY
// First-time Network Enumeration from New IP
// Technique: T1046
let NetworkEnumOps = dynamic([
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/networkWatchers/topology/action"
]);
let RecentActivity = AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue in (NetworkEnumOps)
| where ActivityStatusValue in ("Success", "Succeeded");
let HistoricalCallers = AzureActivity
| where TimeGenerated between (ago(30d) .. ago(1h))
| where OperationNameValue in (NetworkEnumOps)
| distinct Caller, CallerIpAddress;
RecentActivity
| join kind=leftanti HistoricalCallers on Caller, CallerIpAddress
| summarize
    FirstTimeEnumOps = count(),
    Operations = make_set(OperationNameValue, 10)
    by Caller, CallerIpAddress
| where FirstTimeEnumOps > 3
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects first-time network enumeration from new caller/IP combination"
  display_name = "T1046: First-time Network Enumeration"
  enabled      = true

  tags = {
    "mitre-technique" = "T1046"
    "detection-type"  = "first-time-activity"
  }
}

output "network_enumeration_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.network_enumeration.id
}

output "network_watcher_recon_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.network_watcher_recon.id
}

output "port_scanning_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.port_scanning.id
}

output "first_time_enum_alert_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.first_time_enum.id
}""",
                alert_severity="high",
                alert_title="Azure: Network Service Discovery Detected",
                alert_description_template=(
                    "Network Service Discovery activity detected. "
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
        "t1046-aws-guardduty",
        "t1046-gcp-port-scan",
        "t1046-aws-port-scan",
        "t1046-aws-sg-recon",
        "t1046-gcp-api-enum",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+25% improvement for Discovery tactic coverage",
)
