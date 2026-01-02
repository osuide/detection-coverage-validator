"""
T1562.001 - Impair Defences: Disable or Modify Tools

Adversaries may disable security tools to avoid detection and prevention of their activities.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1562.001",
    technique_name="Impair Defences: Disable or Modify Tools",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1562/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may disable or modify security tools to evade detection. "
            "In AWS, this includes disabling CloudTrail, GuardDuty, Config, or Security Hub, "
            "as well as modifying logging configurations to reduce visibility."
        ),
        attacker_goal="Eliminate or reduce security visibility to conduct undetected operations",
        why_technique=[
            "Allows subsequent malicious activities to go undetected",
            "Reduces forensic evidence available for investigation",
            "Creates blind spots in security monitoring",
            "Often automated as first step after gaining access",
            "Can be done quickly with appropriate IAM permissions",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Disabling security tools is a critical indicator of malicious intent. "
            "This technique enables all subsequent attack phases to proceed undetected. "
            "Immediate investigation and response is essential."
        ),
        business_impact=[
            "Complete loss of security visibility",
            "Inability to detect ongoing attacks",
            "Compliance violations (many frameworks require continuous monitoring)",
            "Extended attacker dwell time",
            "Difficulty in forensic investigation and incident response",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1530", "T1552", "T1537"],
        often_follows=["T1078", "T1098"],
    ),
    detection_strategies=[
        # Strategy 1: GuardDuty
        DetectionStrategy(
            strategy_id="t1562001-guardduty",
            name="GuardDuty Stealth Detection",
            description=(
                "AWS GuardDuty automatically detects attempts to disable or evade "
                "security monitoring, including GuardDuty itself."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Stealth:IAMUser/CloudTrailLoggingDisabled",
                    "Stealth:S3/ServerAccessLoggingDisabled",
                    "Stealth:IAMUser/PasswordPolicyChange",
                    "Stealth:IAMUser/CloudTrailLoggingDisabled",
                    "DefenseEvasion:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty + email alerts for security tool tampering

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty (detects security tool tampering)
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Dead letter queue for failed event deliveries
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600

  # Step 3: Route stealth/evasion findings to email
  StealthFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Stealth:IAMUser"
            - prefix: "DefenseEvasion:IAMUser"
      Targets:
        - Id: Email
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn

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
                aws:SourceArn: !GetAtt StealthFindingsRule.Arn""",
                terraform_template="""# GuardDuty + email alerts for security tool tampering

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty (detects security tool tampering)
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "guardduty-stealth-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead letter queue for failed event deliveries
resource "aws_sqs_queue" "event_dlq" {
  name                      = "guardduty-stealth-dlq"
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

    resources = [aws_sqs_queue.event_dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.stealth_findings.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq_policy" {
  queue_url = aws_sqs_queue.event_dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 3: Route stealth/evasion findings to email
resource "aws_cloudwatch_event_rule" "stealth_findings" {
  name = "guardduty-stealth-alerts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Stealth:IAMUser" },
        { prefix = "DefenseEvasion:IAMUser" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.stealth_findings.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age_in_seconds      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
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

resource "aws_sns_topic_policy" "allow_eventbridge" {
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
            "aws:SourceArn" = aws_cloudwatch_event_rule.stealth_findings.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Security Tool Tampering Detected",
                alert_description_template=(
                    "GuardDuty detected an attempt to disable or modify security tools: {finding_type}. "
                    "Principal: {principal}. This is a critical security event requiring immediate response."
                ),
                investigation_steps=[
                    "Identify the IAM principal that made the change",
                    "Review all API calls from this principal in the last 24 hours",
                    "Check if the change was authorised and documented",
                    "Verify the current state of all security services",
                    "Look for lateral movement or data access after the change",
                ],
                containment_actions=[
                    "Immediately re-enable any disabled security services",
                    "Disable or quarantine the IAM principal",
                    "Revoke all active sessions for the principal",
                    "Enable additional logging and monitoring",
                    "Initiate incident response procedures",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised maintenance windows and known admin accounts",
            detection_coverage="80% - covers most stealth activities",
            evasion_considerations="Attackers may attempt to disable GuardDuty first",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events",
            prerequisites=["AWS account with appropriate IAM permissions"],
        ),
        # Strategy 2: CloudTrail Monitoring
        DetectionStrategy(
            strategy_id="t1562001-cloudtrail-disable",
            name="CloudTrail Disable/Modify Detection",
            description=(
                "Monitor for API calls that stop, delete, or modify CloudTrail trails, "
                "which would eliminate audit visibility."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.cloudtrail"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["cloudtrail.amazonaws.com"],
                        "eventName": [
                            "StopLogging",
                            "DeleteTrail",
                            "UpdateTrail",
                            "PutEventSelectors",
                        ],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: CloudTrail tampering detection

Parameters:
  SNSTopicArn:
    Type: String

Resources:
  # Dead letter queue for failed event deliveries
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600

  CloudTrailTamperingRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1562-CloudTrailTampering
      Description: Detect attempts to disable or modify CloudTrail
      EventPattern:
        source:
          - aws.cloudtrail
        detail-type:
          - "AWS API Call via CloudTrail"
        detail:
          eventSource:
            - cloudtrail.amazonaws.com
          eventName:
            - StopLogging
            - DeleteTrail
            - UpdateTrail
            - PutEventSelectors
      State: ENABLED
      Targets:
        - Id: SNSAlert
          Arn: !Ref SNSTopicArn
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn""",
                alert_severity="critical",
                alert_title="CloudTrail Tampering Detected",
                alert_description_template=(
                    "User {user} attempted to {eventName} on CloudTrail. "
                    "This could indicate an attempt to disable audit logging. "
                    "Source IP: {sourceIPAddress}."
                ),
                investigation_steps=[
                    "Verify if this was an authorised change",
                    "Check the current state of all CloudTrail trails",
                    "Review recent activity from the IAM principal",
                    "Look for other security service modifications",
                    "Assess what visibility was lost and for how long",
                ],
                containment_actions=[
                    "Re-enable CloudTrail logging immediately",
                    "Lock down the IAM principal's access",
                    "Enable CloudTrail Insights for anomaly detection",
                    "Consider enabling multi-region trail with organisation-level controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Create exceptions for planned maintenance; use SCP to prevent trail deletion",
            detection_coverage="95% - near-complete coverage for CloudTrail modifications",
            evasion_considerations="Attackers may modify event selectors rather than stopping logging entirely",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "EventBridge configured"],
        ),
        # Strategy 3: GuardDuty Disable Detection
        DetectionStrategy(
            strategy_id="t1562001-guardduty-disable",
            name="GuardDuty Disable Detection",
            description=(
                "Detect attempts to disable GuardDuty or remove member accounts from "
                "the GuardDuty organisation."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.guardduty"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["guardduty.amazonaws.com"],
                        "eventName": [
                            "DeleteDetector",
                            "DisassociateFromMasterAccount",
                            "DisassociateMembers",
                            "StopMonitoringMembers",
                            "UpdateDetector",
                        ],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty tampering detection

Parameters:
  SNSTopicArn:
    Type: String

Resources:
  # Dead letter queue for failed event deliveries
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600

  GuardDutyTamperingRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1562-GuardDutyTampering
      Description: Detect attempts to disable or modify GuardDuty
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - "AWS API Call via CloudTrail"
        detail:
          eventSource:
            - guardduty.amazonaws.com
          eventName:
            - DeleteDetector
            - DisassociateFromMasterAccount
            - DisassociateMembers
            - StopMonitoringMembers
            - UpdateDetector
      State: ENABLED
      Targets:
        - Id: SNSAlert
          Arn: !Ref SNSTopicArn
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn""",
                alert_severity="critical",
                alert_title="GuardDuty Tampering Detected",
                alert_description_template=(
                    "User {user} attempted to {eventName} on GuardDuty. "
                    "This is a critical attempt to disable threat detection. "
                    "Source IP: {sourceIPAddress}."
                ),
                investigation_steps=[
                    "Verify if this was an authorised change",
                    "Check the current state of GuardDuty across all regions",
                    "Review all API calls from this principal",
                    "Look for concurrent attempts to disable other security services",
                    "Check for any GuardDuty findings before the disable attempt",
                ],
                containment_actions=[
                    "Re-enable GuardDuty immediately",
                    "Lock the offending IAM principal",
                    "Review and strengthen SCPs to prevent GuardDuty deletion",
                    "Enable delegated administrator for centralised control",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Use SCPs to prevent GuardDuty deletion; whitelist specific admin roles",
            detection_coverage="95% - excellent coverage for GuardDuty modifications",
            evasion_considerations="Attackers may attempt to modify findings rather than disable",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$2-5",
            prerequisites=["GuardDuty enabled", "EventBridge configured"],
        ),
        # Strategy 4: Config and Security Hub Monitoring
        DetectionStrategy(
            strategy_id="t1562001-config-securityhub",
            name="Config and Security Hub Disable Detection",
            description=(
                "Monitor for attempts to disable AWS Config or Security Hub, "
                "which provide compliance and security posture visibility."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventSource, eventName, sourceIPAddress
| filter eventSource in ["config.amazonaws.com", "securityhub.amazonaws.com"]
| filter eventName in ["StopConfigurationRecorder", "DeleteConfigurationRecorder",
    "DeleteDeliveryChannel", "DisableSecurityHub", "DeleteMembers",
    "DisassociateFromMasterAccount", "UpdateSecurityHubConfiguration"]
| sort @timestamp desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Config and Security Hub tampering detection

Parameters:
  CloudTrailLogGroup:
    Type: String
  SNSTopicArn:
    Type: String

Resources:
  ConfigTamperingFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "config.amazonaws.com" || $.eventSource = "securityhub.amazonaws.com") && ($.eventName = "StopConfigurationRecorder" || $.eventName = "DeleteConfigurationRecorder" || $.eventName = "DisableSecurityHub") }'
      MetricTransformations:
        - MetricName: SecurityServiceTampering
          MetricNamespace: Security/T1562
          MetricValue: "1"

  ConfigTamperingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1562-ConfigSecurityHubTampering
      AlarmDescription: Attempt to disable Config or Security Hub
      MetricName: SecurityServiceTampering
      Namespace: Security/T1562
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn""",
                alert_severity="critical",
                alert_title="Config/Security Hub Tampering Detected",
                alert_description_template=(
                    "User {user} attempted to disable or modify {eventSource}. "
                    "Operation: {eventName}. This is a critical security event."
                ),
                investigation_steps=[
                    "Verify if this was an authorised administrative action",
                    "Check the current state of Config and Security Hub",
                    "Review the IAM principal's recent activity",
                    "Look for patterns indicating credential compromise",
                    "Assess compliance impact of any gap in monitoring",
                ],
                containment_actions=[
                    "Re-enable Config and Security Hub immediately",
                    "Quarantine the IAM principal",
                    "Implement SCPs to prevent future disable attempts",
                    "Review and update IAM policies to least privilege",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist specific admin roles; use change management process",
            detection_coverage="90% - covers Config and Security Hub modifications",
            evasion_considerations="Attackers may modify rules rather than disable entirely",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
    ],
    recommended_order=[
        "t1562001-guardduty",
        "t1562001-cloudtrail-disable",
        "t1562001-guardduty-disable",
        "t1562001-config-securityhub",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+40% improvement for Defence Evasion tactic",
)
