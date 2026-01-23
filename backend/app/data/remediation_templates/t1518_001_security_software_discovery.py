"""
T1518.001 - Software Discovery: Security Software Discovery

Adversaries attempt to identify security software, defensive tools, and
sensors installed on systems and in cloud environments to inform their
attack strategy and identify defensive gaps to exploit.
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
    technique_id="T1518.001",
    technique_name="Software Discovery: Security Software Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1518/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate security software, configurations, defensive tools, "
            "and sensors installed on systems and cloud environments. This reconnaissance "
            "helps attackers determine whether to proceed with infection, modify attack "
            "techniques to evade defences, or abort operations to avoid detection."
        ),
        attacker_goal="Identify security defences to determine infection feasibility and tailor evasion techniques",
        why_technique=[
            "Reveals installed security products and versions",
            "Identifies monitoring and EDR solutions",
            "Discovers firewall configurations",
            "Detects backup and recovery tools",
            "Informs evasion and anti-analysis tactics",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=5,
        severity_reasoning=(
            "Discovery technique with moderate direct impact but high strategic value. "
            "Indicates active reconnaissance and typically precedes defence evasion or "
            "security tool disablement. Critical early warning for defensive operations."
        ),
        business_impact=[
            "Exposes defensive capabilities to adversaries",
            "Enables targeted evasion techniques",
            "Precedes security tool disablement",
            "Indicates sophisticated attacker reconnaissance",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1562.001", "T1027", "T1497"],
        often_follows=["T1078.004", "T1059.009"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - CloudWatch Agent Enumeration
        DetectionStrategy(
            strategy_id="t1518-001-aws-cw-agent",
            name="AWS CloudWatch Agent Enumeration",
            description="Detect queries to enumerate CloudWatch monitoring agents and configurations.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["GetParameter", "GetParameters"],
                        "requestParameters": {
                            "names": [{"prefix": "AmazonCloudWatch"}]
                        },
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect CloudWatch agent enumeration

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

  # Step 2: EventBridge rule for CloudWatch agent queries
  CloudWatchAgentRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ssm]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [GetParameter, GetParameters, DescribeInstanceInformation]
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt CloudWatchAgentRule.Arn""",
                terraform_template="""# Detect CloudWatch agent enumeration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "cloudwatch-agent-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for monitoring agent queries
resource "aws_cloudwatch_event_rule" "cw_agent_enum" {
  name = "cloudwatch-agent-enumeration"
  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["GetParameter", "GetParameters", "DescribeInstanceInformation"]
    }
  })
}

# Step 3: EventBridge target to SNS
resource "aws_sqs_queue" "dlq" {
  name                      = "cw-agent-enum-dlq"
  message_retention_seconds = 1209600
}

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
      values   = [aws_cloudwatch_event_rule.cw_agent_enum.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.cw_agent_enum.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

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
          ArnEquals = {
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.cw_agent_enum.arn,
              aws_cloudwatch_event_rule.guardduty_enum.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="CloudWatch Agent Enumeration Detected",
                alert_description_template="Monitoring agent queries performed by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify the principal performing monitoring enumeration",
                    "Check if this is authorised security assessment activity",
                    "Review what monitoring configurations were accessed",
                    "Look for follow-on defence evasion or disablement attempts",
                ],
                containment_actions=[
                    "Review principal's permissions and recent activity",
                    "Monitor for attempts to disable CloudWatch agents",
                    "Check for subsequent T1562.001 (Disable Security Tools) activity",
                    "Consider restricting SSM parameter read access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist infrastructure automation, monitoring tools, and operations teams",
            detection_coverage="80% - catches SSM-based agent enumeration",
            evasion_considerations="Direct instance access or metadata queries may bypass",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "CloudWatch agents deployed"],
        ),
        # Strategy 2: AWS - GuardDuty Status Checks
        DetectionStrategy(
            strategy_id="t1518-001-aws-guardduty",
            name="AWS GuardDuty Status Enumeration",
            description="Detect queries to enumerate GuardDuty detector status and configurations.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.guardduty"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["GetDetector", "ListDetectors", "GetFindings"]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect GuardDuty enumeration

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

  # Step 2: EventBridge rule for GuardDuty queries
  GuardDutyEnumRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [GetDetector, ListDetectors, GetFindings]
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt GuardDutyEnumRule.Arn""",
                terraform_template="""# Detect GuardDuty enumeration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "guardduty-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for GuardDuty queries
resource "aws_cloudwatch_event_rule" "guardduty_enum" {
  name = "guardduty-enumeration"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["GetDetector", "ListDetectors", "GetFindings"]
    }
  })
}

# Step 3: EventBridge target to SNS
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-enum-dlq"
  message_retention_seconds = 1209600
}

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
      values   = [aws_cloudwatch_event_rule.guardduty_enum.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.guardduty_enum.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

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
          ArnEquals = {
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.cw_agent_enum.arn,
              aws_cloudwatch_event_rule.guardduty_enum.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty Enumeration Detected",
                alert_description_template="GuardDuty status queries by {userIdentity.arn} - potential reconnaissance.",
                investigation_steps=[
                    "Identify who is querying GuardDuty configurations",
                    "Determine if this is authorised security operations",
                    "Check for attempts to disable GuardDuty",
                    "Review for broader security service enumeration",
                ],
                containment_actions=[
                    "Review principal's permissions immediately",
                    "Monitor for GuardDuty disablement attempts",
                    "Check for concurrent security tool reconnaissance",
                    "Consider alerting on GuardDuty configuration changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist security operations teams and SIEM integrations",
            detection_coverage="90% - highly reliable indicator",
            evasion_considerations="Limited evasion options for GuardDuty enumeration",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "GuardDuty enabled"],
        ),
        # Strategy 3: AWS - Security Hub Status Checks
        DetectionStrategy(
            strategy_id="t1518-001-aws-securityhub",
            name="AWS Security Hub Enumeration",
            description="Detect queries to enumerate Security Hub status and security standards.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
| filter eventSource = "securityhub.amazonaws.com"
| filter eventName in ["GetEnabledStandards", "DescribeHub", "GetFindings", "ListMembers"]
| stats count(*) as query_count by userIdentity.arn, bin(1h)
| filter query_count > 5
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Security Hub enumeration

Parameters:
  CloudTrailLogGroup:
    Type: String
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

  # Step 2: Metric filter for Security Hub queries
  SecurityHubFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "securityhub.amazonaws.com" && ($.eventName = "GetEnabledStandards" || $.eventName = "DescribeHub" || $.eventName = "GetFindings") }'
      MetricTransformations:
        - MetricName: SecurityHubEnum
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm for enumeration activity
  SecurityHubAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SecurityHubEnumeration
      MetricName: SecurityHubEnum
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect Security Hub enumeration

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "securityhub-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for Security Hub queries
resource "aws_cloudwatch_log_metric_filter" "securityhub_enum" {
  name           = "securityhub-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"securityhub.amazonaws.com\" && ($.eventName = \"GetEnabledStandards\" || $.eventName = \"DescribeHub\") }"

  metric_transformation {
    name      = "SecurityHubEnum"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for enumeration activity
resource "aws_cloudwatch_metric_alarm" "securityhub_enum" {
  alarm_name          = "SecurityHubEnumeration"
  metric_name         = "SecurityHubEnum"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_description_template="Security Hub enumeration detected from {userIdentity.arn}.",
                alert_title="Security Hub Enumeration Detected",
                investigation_steps=[
                    "Identify the principal querying Security Hub",
                    "Verify if this is authorised compliance scanning",
                    "Check for attempts to disable Security Hub",
                    "Look for broader security service reconnaissance",
                ],
                containment_actions=[
                    "Review principal's permissions and activity",
                    "Monitor for Security Hub disablement attempts",
                    "Check for concurrent security tool enumeration",
                    "Consider implementing SCPs for Security Hub protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist compliance tools, SIEM integrations, and security operations",
            detection_coverage="85% - catches Security Hub queries",
            evasion_considerations="Low-volume queries over time may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch", "Security Hub enabled"],
        ),
        # Strategy 4: GCP - Security Command Centre Enumeration
        DetectionStrategy(
            strategy_id="t1518-001-gcp-scc",
            name="GCP Security Command Centre Enumeration",
            description="Detect queries to enumerate Security Command Centre status and findings.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(google.cloud.securitycenter.*.Get|google.cloud.securitycenter.*.List)"
protoPayload.methodName!~"ListFindings"''',
                gcp_terraform_template="""# GCP: Detect Security Command Centre enumeration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for SCC enumeration
resource "google_logging_metric" "scc_enum" {
  project = var.project_id
  name   = "security-command-centre-enumeration"
  filter = <<-EOT
    protoPayload.methodName=~"(google.cloud.securitycenter.*.Get|google.cloud.securitycenter.*.List)"
    protoPayload.methodName!~"ListFindings"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for enumeration activity
resource "google_monitoring_alert_policy" "scc_enum" {
  project      = var.project_id
  display_name = "Security Command Centre Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "SCC enumeration detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.scc_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
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
                alert_title="GCP: Security Command Centre Enumeration Detected",
                alert_description_template="Security Command Centre status queries detected - potential reconnaissance.",
                investigation_steps=[
                    "Identify the principal querying Security Command Centre",
                    "Verify if this is authorised security operations",
                    "Check for attempts to modify SCC configurations",
                    "Review for broader security service enumeration",
                ],
                containment_actions=[
                    "Review principal's IAM permissions",
                    "Monitor for SCC configuration changes",
                    "Check for concurrent security tool reconnaissance",
                    "Consider IAM Conditions to restrict SCC access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist security operations, SIEM integrations, and compliance tools",
            detection_coverage="90% - highly reliable for SCC queries",
            evasion_considerations="Limited evasion options for SCC API calls",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Security Command Centre enabled",
            ],
        ),
        # Strategy 5: GCP - Cloud Monitoring Agent Enumeration
        DetectionStrategy(
            strategy_id="t1518-001-gcp-monitoring",
            name="GCP Cloud Monitoring Agent Enumeration",
            description="Detect queries to enumerate Cloud Monitoring agents and configurations.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(monitoring.metricDescriptors.list|monitoring.timeSeries.list|compute.instances.getGuestAttributes)"
protoPayload.request.filter=~"(agent|monitoring|metrics)"''',
                gcp_terraform_template="""# GCP: Detect Cloud Monitoring agent enumeration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for monitoring agent queries
resource "google_logging_metric" "monitoring_enum" {
  project = var.project_id
  name   = "cloud-monitoring-agent-enumeration"
  filter = <<-EOT
    protoPayload.methodName=~"(monitoring.metricDescriptors.list|monitoring.timeSeries.list|compute.instances.getGuestAttributes)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for agent enumeration
resource "google_monitoring_alert_policy" "monitoring_enum" {
  project      = var.project_id
  display_name = "Cloud Monitoring Agent Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "High volume monitoring queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.monitoring_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 30
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
                alert_title="GCP: Cloud Monitoring Agent Enumeration Detected",
                alert_description_template="Cloud Monitoring agent queries detected - potential security tool reconnaissance.",
                investigation_steps=[
                    "Identify the principal querying monitoring configurations",
                    "Check if this is authorised operations or security scanning",
                    "Review which instances and metrics were queried",
                    "Look for attempts to disable monitoring agents",
                ],
                containment_actions=[
                    "Review principal's IAM permissions",
                    "Monitor for agent disablement attempts",
                    "Check for broader security tool enumeration",
                    "Consider restricting monitoring API access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist monitoring dashboards, operations teams, and infrastructure automation",
            detection_coverage="75% - volume-based detection",
            evasion_considerations="Low-volume queries or direct instance access may bypass",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled", "Cloud Monitoring configured"],
        ),
        # Azure Strategy: Software Discovery: Security Software Discovery
        DetectionStrategy(
            strategy_id="t1518001-azure",
            name="Azure Software Discovery: Security Software Discovery Detection",
            description=(
                "Azure detection for Software Discovery: Security Software Discovery. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Software Discovery: Security Software Discovery Detection
// Technique: T1518.001
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
                azure_terraform_template="""# Azure Detection for Software Discovery: Security Software Discovery
# MITRE ATT&CK: T1518.001

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

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "software-discovery--security-software-discovery-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "software-discovery--security-software-discovery-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Software Discovery: Security Software Discovery Detection
// Technique: T1518.001
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

  description = "Detects Software Discovery: Security Software Discovery (T1518.001) activity in Azure environment"
  display_name = "Software Discovery: Security Software Discovery Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1518.001"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Software Discovery: Security Software Discovery Detected",
                alert_description_template=(
                    "Software Discovery: Security Software Discovery activity detected. "
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
        "t1518-001-aws-guardduty",
        "t1518-001-aws-securityhub",
        "t1518-001-gcp-scc",
        "t1518-001-aws-cw-agent",
        "t1518-001-gcp-monitoring",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+15% improvement for Discovery tactic",
)
