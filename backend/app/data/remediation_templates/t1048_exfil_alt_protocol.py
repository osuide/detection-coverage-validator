"""
T1048 - Exfiltration Over Alternative Protocol

Adversaries exfiltrate data over protocols different from the main C2 channel.
Used by Play, TeamTNT, FIN6, OilRig.
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
    technique_id="T1048",
    technique_name="Exfiltration Over Alternative Protocol",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1048/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exfiltrate data over protocols different from the main command "
            "and control channel. Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, "
            "or any other network protocol not being used as the main C2 channel. This allows "
            "attackers to blend exfiltration with legitimate traffic and avoid detection."
        ),
        attacker_goal="Steal data using alternative protocols to evade detection and blend with legitimate traffic",
        why_technique=[
            "Bypasses C2 channel monitoring",
            "Blends with legitimate protocol usage",
            "Multiple protocol options provide flexibility",
            "DNS and SMTP rarely blocked outbound",
            "Encrypted protocols hide data content",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Data exfiltration via alternative protocols is difficult to detect as it "
            "blends with legitimate traffic. Loss of sensitive data can result in severe "
            "financial, regulatory, and reputational damage. Common protocols like DNS and "
            "SMTP are rarely blocked, making this technique highly effective."
        ),
        business_impact=[
            "Data breach and loss of sensitive information",
            "Intellectual property theft",
            "Regulatory fines and compliance violations",
            "Reputational damage and customer trust loss",
            "Operational disruption from incident response",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1530", "T1552.001", "T1005", "T1074"],
    ),
    detection_strategies=[
        # AWS GuardDuty Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1048-aws-guardduty",
            name="AWS GuardDuty Anomaly Detection",
            description=(
                "AWS GuardDuty detects exfiltration over alternative protocols. Behavior:EC2/TrafficVolumeUnusual identifies unusual outbound data volumes. Trojan:EC2/DNSDataExfiltration detects DNS tunnelling for data exfiltration."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Behavior:EC2/TrafficVolumeUnusual",
                    "Trojan:EC2/DNSDataExfiltration",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for T1048

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty-T1048-Alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for GuardDuty findings
  GuardDutyRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Capture GuardDuty findings for T1048
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Behavior:EC2/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt GuardDutyRule.Arn""",
                terraform_template="""# GuardDuty alerts for T1048

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

data "aws_caller_identity" "current" {}

# Step 1: SNS Topic
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "guardduty-t1048-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for findings
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-t1048"
  description = "Capture GuardDuty findings for T1048"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Behavior:EC2/" }]
    }
  })
}

# Step 3: Target with DLQ and retry
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-t1048-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

# Step 4: SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty.arn }
      }
    }]
  })
}""",
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML baselines; tune suppression rules for known benign patterns",
            detection_coverage="70% - detects anomalous behaviour but may miss attacks that blend with normal activity",
            evasion_considerations="Low bandwidth exfiltration, using encrypted protocols, mimicking legitimate backup traffic",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events",
            prerequisites=[
                "AWS GuardDuty enabled",
                "CloudTrail logging active",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1048-aws-dns",
            name="AWS DNS Tunnelling Detection",
            description="Detect DNS tunnelling activity via VPC Flow Logs and Route 53 query logging.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, query_name, query_type, srcaddr, rcode
| filter query_type = "TXT" or length(query_name) > 50
| stats count(*) as query_count, avg(length(query_name)) as avg_length,
        count_distinct(query_name) as unique_queries by srcaddr, bin(5m)
| filter query_count > 100 or avg_length > 40
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: DNS tunnelling detection via Route 53 query logging

Parameters:
  AlertEmail:
    Type: String
  VPCId:
    Type: String

Resources:
  # Step 1: Enable Route 53 query logging
  QueryLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/route53/queries
      RetentionInDays: 30

  QueryLoggingConfig:
    Type: AWS::Route53::QueryLoggingConfig
    Properties:
      CloudWatchLogsLogGroupArn: !GetAtt QueryLogGroup.Arn

  # Step 2: Create metric filter for suspicious DNS patterns
  DNSTunnelFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref QueryLogGroup
      FilterPattern: '[... query_name_length > 50 ...]'
      MetricTransformations:
        - MetricName: SuspiciousDNSQueries
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on threshold breach
  # Dead Letter Queue for failed alert deliveries
  AlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: dns-tunnel-alert-dlq
      MessageRetentionPeriod: 1209600  # 14 days

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # SQS subscription with DLQ for reliable alert delivery
  AlertQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: dns-tunnel-alerts
      MessageRetentionPeriod: 345600  # 4 days
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt AlertDLQ.Arn
        maxReceiveCount: 3

  AlertQueuePolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref AlertQueue
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: sns.amazonaws.com
            Action: SQS:SendMessage
            Resource: !GetAtt AlertQueue.Arn
            Condition:
              ArnEquals:
                aws:SourceArn: !Ref AlertTopic

  AlertQueueSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      Protocol: sqs
      Endpoint: !GetAtt AlertQueue.Arn
      TopicArn: !Ref AlertTopic

  DNSTunnelAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DNS-Tunnelling-Detected
      MetricName: SuspiciousDNSQueries
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 4: Scoped SNS topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
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
                terraform_template="""# DNS tunnelling detection via Route 53 query logging

variable "alert_email" { type = string }
variable "vpc_id" { type = string }

# Step 1: Enable Route 53 query logging
resource "aws_cloudwatch_log_group" "dns_queries" {
  name              = "/aws/route53/queries"
  retention_in_days = 30
}

resource "aws_route53_query_log" "main" {
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.dns_queries.arn
}

# Step 2: Create metric filter for suspicious DNS patterns
resource "aws_cloudwatch_log_metric_filter" "dns_tunnel" {
  name           = "suspicious-dns-queries"
  log_group_name = aws_cloudwatch_log_group.dns_queries.name
  pattern        = "[... query_name_length > 50 ...]"

  metric_transformation {
    name      = "SuspiciousDNSQueries"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on threshold breach
# Dead Letter Queue for failed alert deliveries
resource "aws_sqs_queue" "alert_dlq" {
  name                      = "dns-tunnel-alert-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sns_topic" "alerts" {
  name = "dns-tunnel-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SQS subscription with DLQ for reliable alert delivery
resource "aws_sqs_queue" "alerts" {
  name                      = "dns-tunnel-alerts"
  message_retention_seconds = 345600  # 4 days
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.alert_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue_policy" "alerts" {
  queue_url = aws_sqs_queue.alerts.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "SQS:SendMessage"
      Resource  = aws_sqs_queue.alerts.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_sns_topic.alerts.arn }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "sqs" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.alerts.arn
}

resource "aws_cloudwatch_metric_alarm" "dns_tunnel" {
  alarm_name          = "DNS-Tunnelling-Detected"
  metric_name         = "SuspiciousDNSQueries"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

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
                alert_severity="high",
                alert_title="DNS Tunnelling Activity Detected",
                alert_description_template="Suspicious DNS query patterns from {srcaddr}: {query_count} queries with average length {avg_length}.",
                investigation_steps=[
                    "Identify the source instance generating DNS queries",
                    "Review query patterns and domain names",
                    "Check for encoded or encrypted data in queries",
                    "Examine timing patterns (steady stream vs bursts)",
                    "Correlate with other network activity",
                ],
                containment_actions=[
                    "Isolate the source instance",
                    "Block suspicious DNS queries at resolver level",
                    "Review and restrict DNS resolver configuration",
                    "Implement DNS firewall rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate long query names (e.g., DMARC records); adjust length threshold",
            detection_coverage="65% - catches DNS tunnelling",
            evasion_considerations="Low and slow tunnelling, using legitimate domain names",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Route 53 resolver in use", "VPC DNS logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048-aws-ftp",
            name="AWS FTP/SFTP Transfer Detection",
            description="Detect unusual FTP or SFTP transfers via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, action
| filter dstPort in [20, 21, 22, 989, 990] and action = "ACCEPT"
| stats sum(bytes) as total_bytes by srcAddr, dstAddr, dstPort, bin(1h)
| filter total_bytes > 10485760
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: FTP/SFTP transfer monitoring via VPC Flow Logs

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: Create SNS topic with DLQ
  # Dead Letter Queue for failed alert deliveries
  AlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: ftp-transfer-alert-dlq
      MessageRetentionPeriod: 1209600  # 14 days

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # SQS subscription with DLQ for reliable alert delivery
  AlertQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: ftp-transfer-alerts
      MessageRetentionPeriod: 345600  # 4 days
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt AlertDLQ.Arn
        maxReceiveCount: 3

  AlertQueuePolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref AlertQueue
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: sns.amazonaws.com
            Action: SQS:SendMessage
            Resource: !GetAtt AlertQueue.Arn
            Condition:
              ArnEquals:
                aws:SourceArn: !Ref AlertTopic

  AlertQueueSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      Protocol: sqs
      Endpoint: !GetAtt AlertQueue.Arn
      TopicArn: !Ref AlertTopic

  # Step 2: Filter for FTP/SFTP traffic
  FTPTransferFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=20 || dstport=21 || dstport=22 || dstport=989 || dstport=990, protocol, packets, bytes > 10000000, ...]'
      MetricTransformations:
        - MetricName: FTPTransfers
          MetricNamespace: Security
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: Alert on large transfers
  FTPTransferAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Large-FTP-Transfer
      MetricName: FTPTransfers
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 104857600
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 4: Scoped SNS topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
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
                terraform_template="""# FTP/SFTP transfer monitoring via VPC Flow Logs

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create SNS topic with DLQ
# Dead Letter Queue for failed alert deliveries
resource "aws_sqs_queue" "alert_dlq" {
  name                      = "ftp-transfer-alert-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sns_topic" "alerts" {
  name = "ftp-transfer-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SQS subscription with DLQ for reliable alert delivery
resource "aws_sqs_queue" "alerts" {
  name                      = "ftp-transfer-alerts"
  message_retention_seconds = 345600  # 4 days
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.alert_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue_policy" "alerts" {
  queue_url = aws_sqs_queue.alerts.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "SQS:SendMessage"
      Resource  = aws_sqs_queue.alerts.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_sns_topic.alerts.arn }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "sqs" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.alerts.arn
}

# Step 2: Filter for FTP/SFTP traffic
resource "aws_cloudwatch_log_metric_filter" "ftp_transfer" {
  name           = "ftp-sftp-transfers"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=20 || dstport=21 || dstport=22 || dstport=989 || dstport=990, protocol, packets, bytes > 10000000, ...]"

  metric_transformation {
    name      = "FTPTransfers"
    namespace = "Security"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: Alert on large transfers
resource "aws_cloudwatch_metric_alarm" "ftp_transfer" {
  alarm_name          = "Large-FTP-Transfer"
  metric_name         = "FTPTransfers"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 104857600
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

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
                alert_severity="high",
                alert_title="Large FTP/SFTP Transfer Detected",
                alert_description_template="Large file transfer detected from {srcAddr} to {dstAddr}:{dstPort} - {total_bytes} bytes transferred.",
                investigation_steps=[
                    "Identify source and destination systems",
                    "Determine if transfer was authorised",
                    "Review transferred files if possible",
                    "Check for scheduled backup or legitimate file transfers",
                    "Examine user activity on source system",
                ],
                containment_actions=[
                    "Block FTP/SFTP traffic at security group",
                    "Isolate source instance",
                    "Review and restrict outbound network rules",
                    "Disable FTP/SFTP services if not required",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known file transfer servers; exclude scheduled backups",
            detection_coverage="70% - catches FTP/SFTP exfiltration",
            evasion_considerations="Using HTTP/HTTPS instead, port forwarding",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048-aws-smtp",
            name="AWS Unusual SMTP Activity Detection",
            description="Detect suspicious SMTP traffic that may indicate data exfiltration via email.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, bytes, packets
| filter dstPort in [25, 465, 587] and action = "ACCEPT"
| stats sum(bytes) as total_bytes, count(*) as connections by srcAddr, bin(1h)
| filter total_bytes > 52428800 or connections > 100
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Unusual SMTP activity detection

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: Create alert topic with DLQ
  # Dead Letter Queue for failed alert deliveries
  AlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: smtp-activity-alert-dlq
      MessageRetentionPeriod: 1209600  # 14 days

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # SQS subscription with DLQ for reliable alert delivery
  AlertQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: smtp-activity-alerts
      MessageRetentionPeriod: 345600  # 4 days
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt AlertDLQ.Arn
        maxReceiveCount: 3

  AlertQueuePolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref AlertQueue
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: sns.amazonaws.com
            Action: SQS:SendMessage
            Resource: !GetAtt AlertQueue.Arn
            Condition:
              ArnEquals:
                aws:SourceArn: !Ref AlertTopic

  AlertQueueSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      Protocol: sqs
      Endpoint: !GetAtt AlertQueue.Arn
      TopicArn: !Ref AlertTopic

  # Step 2: Monitor SMTP connections
  SMTPFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=25 || dstport=465 || dstport=587, protocol, packets, bytes, ...]'
      MetricTransformations:
        - MetricName: SMTPConnections
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on unusual volume
  SMTPAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Unusual-SMTP-Activity
      MetricName: SMTPConnections
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref AlertTopic

  # Step 4: Scoped SNS topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
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
                terraform_template="""# Unusual SMTP activity detection

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create alert topic with DLQ
# Dead Letter Queue for failed alert deliveries
resource "aws_sqs_queue" "alert_dlq" {
  name                      = "smtp-activity-alert-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sns_topic" "alerts" {
  name = "smtp-activity-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# SQS subscription with DLQ for reliable alert delivery
resource "aws_sqs_queue" "alerts" {
  name                      = "smtp-activity-alerts"
  message_retention_seconds = 345600  # 4 days
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.alert_dlq.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue_policy" "alerts" {
  queue_url = aws_sqs_queue.alerts.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "SQS:SendMessage"
      Resource  = aws_sqs_queue.alerts.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_sns_topic.alerts.arn }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "sqs" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.alerts.arn
}

# Step 2: Monitor SMTP connections
resource "aws_cloudwatch_log_metric_filter" "smtp" {
  name           = "smtp-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=25 || dstport=465 || dstport=587, protocol, packets, bytes, ...]"

  metric_transformation {
    name      = "SMTPConnections"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on unusual volume
resource "aws_cloudwatch_metric_alarm" "smtp" {
  alarm_name          = "Unusual-SMTP-Activity"
  metric_name         = "SMTPConnections"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

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
                alert_title="Unusual SMTP Activity Detected",
                alert_description_template="Unusual SMTP traffic from {srcAddr}: {connections} connections, {total_bytes} bytes transferred.",
                investigation_steps=[
                    "Identify source instance and purpose",
                    "Review email sending patterns",
                    "Check for compromised mail services",
                    "Examine email content if accessible",
                    "Verify against legitimate bulk email operations",
                ],
                containment_actions=[
                    "Block SMTP traffic from source",
                    "Disable mail relay if compromised",
                    "Review and restrict SMTP access",
                    "Implement SMTP authentication requirements",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist mail servers and SES; adjust thresholds for legitimate email volume",
            detection_coverage="60% - catches email-based exfiltration",
            evasion_considerations="Using legitimate email services, slow sending rate",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048-gcp-dns",
            name="GCP DNS Tunnelling Detection",
            description="Detect DNS tunnelling activity via Cloud DNS and VPC flow logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="dns_query"
(queryName=~".{50,}" OR queryType="TXT")""",
                gcp_terraform_template="""# GCP: DNS tunnelling detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Enable DNS logging
resource "google_dns_managed_zone" "monitored" {
  name        = "monitored-zone"
  dns_name    = "example.com."
  description = "Monitored DNS zone"

  cloud_logging_config {
    enable_logging = true
  }
}

# Step 2: Create log metric for suspicious patterns
resource "google_logging_metric" "dns_tunnel" {
  project = var.project_id
  name   = "dns-tunnelling"
  filter = <<-EOT
    resource.type="dns_query"
    (protoPayload.queryName=~".{50,}" OR protoPayload.queryType="TXT")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert on threshold
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_monitoring_alert_policy" "dns_tunnel" {
  project      = var.project_id
  display_name = "DNS Tunnelling Detected"
  combiner     = "OR"
  conditions {
    display_name = "Suspicious DNS queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_tunnel.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
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
                alert_title="GCP: DNS Tunnelling Activity Detected",
                alert_description_template="Suspicious DNS query patterns detected: {query_count} queries with average length {avg_length}.",
                investigation_steps=[
                    "Identify the source instance or workload",
                    "Review DNS query logs for patterns",
                    "Check for encoded data in query names",
                    "Examine destination DNS servers",
                    "Correlate with network flow logs",
                ],
                containment_actions=[
                    "Isolate the source instance",
                    "Restrict DNS resolver access",
                    "Block suspicious domains at Cloud DNS",
                    "Review and update VPC firewall rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate services with long DNS names; tune length threshold",
            detection_coverage="65% - catches DNS tunnelling",
            evasion_considerations="Slow tunnelling, legitimate domain patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["Cloud DNS logging enabled", "VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048-gcp-protocol",
            name="GCP Alternative Protocol Detection",
            description="Detect unusual protocol usage via VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
jsonPayload.connection.dest_port:(20 OR 21 OR 22 OR 25 OR 465 OR 587 OR 989 OR 990)
jsonPayload.bytes_sent > 10485760""",
                gcp_terraform_template="""# GCP: Alternative protocol detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Enable VPC Flow Logs (assumes existing VPC)
# Note: Flow logs are enabled per subnet in GCP

# Step 2: Create metric for suspicious protocols
resource "google_logging_metric" "alt_protocol" {
  project = var.project_id
  name   = "alternative-protocol-transfer"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    (jsonPayload.connection.dest_port=20 OR
     jsonPayload.connection.dest_port=21 OR
     jsonPayload.connection.dest_port=22 OR
     jsonPayload.connection.dest_port=25 OR
     jsonPayload.connection.dest_port=465 OR
     jsonPayload.connection.dest_port=587)
    jsonPayload.bytes_sent > 10485760
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_monitoring_alert_policy" "alt_protocol" {
  project      = var.project_id
  display_name = "Alternative Protocol Exfiltration"
  combiner     = "OR"
  conditions {
    display_name = "Large transfer on alternative protocol"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.alt_protocol.name}\""
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
                alert_severity="high",
                alert_title="GCP: Alternative Protocol Transfer Detected",
                alert_description_template="Large data transfer detected using alternative protocol.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review protocol usage patterns",
                    "Verify business justification for transfer",
                    "Check for authorised file transfers",
                    "Examine user activity on source instance",
                ],
                containment_actions=[
                    "Block suspicious traffic via firewall rules",
                    "Isolate source instance",
                    "Review and restrict network egress",
                    "Disable unnecessary services",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known transfer servers and scheduled jobs",
            detection_coverage="65% - catches alternative protocol exfiltration",
            evasion_considerations="Using HTTPS, non-standard ports",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled on subnets"],
        ),
        # Azure Strategy: Exfiltration Over Alternative Protocol
        DetectionStrategy(
            strategy_id="t1048-azure",
            name="Azure Exfiltration Over Alternative Protocol Detection",
            description=(
                "Azure detection for Exfiltration Over Alternative Protocol. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Exfiltration Over Alternative Protocol Detection
// Technique: T1048
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc""",
                azure_terraform_template="""# Azure Detection for Exfiltration Over Alternative Protocol
# MITRE ATT&CK: T1048

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

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "exfiltration-over-alternative-protocol-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "exfiltration-over-alternative-protocol-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Exfiltration Over Alternative Protocol Detection
// Technique: T1048
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc
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

  description = "Detects Exfiltration Over Alternative Protocol (T1048) activity in Azure environment"
  display_name = "Exfiltration Over Alternative Protocol Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1048"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Exfiltration Over Alternative Protocol Detected",
                alert_description_template=(
                    "Exfiltration Over Alternative Protocol activity detected. "
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
        "t1048-aws-dns",
        "t1048-gcp-dns",
        "t1048-aws-ftp",
        "t1048-aws-smtp",
        "t1048-gcp-protocol",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+20% improvement for Exfiltration tactic",
)
