"""
T1098 - Account Manipulation

Adversaries may manipulate accounts to maintain access to victim systems.
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
    technique_id="T1098",
    technique_name="Account Manipulation",
    tactic_ids=["TA0003", "TA0004"],  # Persistence, Privilege Escalation
    mitre_url="https://attack.mitre.org/techniques/T1098/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may manipulate accounts to maintain access to victim systems. "
            "This includes adding credentials to existing accounts, modifying permissions, "
            "creating new access keys, or adding accounts to privileged groups."
        ),
        attacker_goal="Establish persistent access by modifying or creating account credentials",
        why_technique=[
            "Provides backup access if primary credentials are revoked",
            "Enables privilege escalation through permission changes",
            "Creates additional attack paths that may go unnoticed",
            "Access keys can be used externally without console access",
            "Changes may persist through normal password rotations",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Account manipulation is a critical persistence technique. "
            "Changes to IAM can provide long-term access and enable privilege escalation. "
            "Detection is essential to prevent attacker persistence."
        ),
        business_impact=[
            "Persistent unauthorised access to cloud resources",
            "Privilege escalation leading to full environment compromise",
            "Difficulty in fully remediating incidents",
            "Compliance violations for unauthorised access changes",
            "Potential for future attacks using hidden access",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1530", "T1537", "T1562"],
        often_follows=["T1078", "T1110"],
    ),
    detection_strategies=[
        # Strategy 1: GuardDuty IAM Anomalies
        DetectionStrategy(
            strategy_id="t1098-guardduty",
            name="GuardDuty IAM Anomaly Detection",
            description=(
                "AWS GuardDuty detects anomalous IAM activity including unusual "
                "API calls and potential credential manipulation."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Persistence:IAMUser/AnomalousBehavior",
                    "PrivilegeEscalation:IAMUser/AnomalousBehavior",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty + email alerts for IAM anomalies

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty (detects IAM anomalies automatically)
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

  # Dead Letter Queue for failed alert deliveries
  AlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: guardduty-iam-alerts-dlq
      MessageRetentionPeriod: 1209600  # 14 days

  # Step 3: Route IAM findings to email with retry/DLQ
  IAMFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Persistence:IAMUser"
            - prefix: "PrivilegeEscalation:IAMUser"
            - prefix: "CredentialAccess:IAMUser"
      Targets:
        - Id: Email
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt AlertDLQ.Arn

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublish
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt IAMFindingsRule.Arn""",
                terraform_template="""# GuardDuty + email alerts for IAM anomalies

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty (detects IAM anomalies automatically)
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "guardduty-iam-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed alert deliveries
resource "aws_sqs_queue" "alert_dlq" {
  name                      = "guardduty-iam-alerts-dlq"
  message_retention_seconds = 1209600  # 14 days
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

    resources = [aws_sqs_queue.alert_dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.iam_findings.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.alert_dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 3: Route IAM findings to email with retry/DLQ
resource "aws_cloudwatch_event_rule" "iam_findings" {
  name = "guardduty-iam-alerts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Persistence:IAMUser" },
        { prefix = "PrivilegeEscalation:IAMUser" },
        { prefix = "CredentialAccess:IAMUser" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.iam_findings.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.alert_dlq.arn
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
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.iam_findings.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: IAM Anomaly Detected",
                alert_description_template=(
                    "GuardDuty detected anomalous IAM activity: {finding_type}. "
                    "Principal: {principal}. This may indicate account manipulation."
                ),
                investigation_steps=[
                    "Review the specific IAM changes made by the principal",
                    "Check if new access keys or credentials were created",
                    "Verify if permissions were escalated",
                    "Review the principal's recent activity pattern",
                    "Contact the account owner to verify legitimacy",
                ],
                containment_actions=[
                    "Revoke any newly created access keys",
                    "Remove unauthorised permission changes",
                    "Disable the affected IAM user if compromised",
                    "Review and restrict IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known automation accounts and admin roles",
            detection_coverage="60% - covers anomalous IAM behaviour",
            evasion_considerations="Slow, gradual permission changes may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events",
            prerequisites=["AWS account with appropriate IAM permissions"],
        ),
        # Strategy 2: Access Key Creation
        DetectionStrategy(
            strategy_id="t1098-access-key-creation",
            name="IAM Access Key Creation Monitoring",
            description=(
                "Monitor for creation of new IAM access keys, which could provide "
                "persistent API access to adversaries."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["iam.amazonaws.com"],
                        "eventName": [
                            "CreateAccessKey",
                            "CreateLoginProfile",
                            "UpdateLoginProfile",
                        ],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: IAM access key creation monitoring

Parameters:
  SNSTopicArn:
    Type: String

Resources:
  # Dead Letter Queue for failed alert deliveries
  AccessKeyAlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: t1098-access-key-alerts-dlq
      MessageRetentionPeriod: 1209600  # 14 days

  AccessKeyCreationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1098-AccessKeyCreation
      Description: Detect IAM access key and credential creation
      EventPattern:
        source:
          - aws.iam
        detail-type:
          - "AWS API Call via CloudTrail"
        detail:
          eventSource:
            - iam.amazonaws.com
          eventName:
            - CreateAccessKey
            - CreateLoginProfile
            - UpdateLoginProfile
      State: ENABLED
      Targets:
        - Id: SNSAlert
          Arn: !Ref SNSTopicArn
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt AccessKeyAlertDLQ.Arn""",
                terraform_template="""# IAM access key creation monitoring

variable "sns_topic_arn" {
  type        = string
  description = "ARN of SNS topic for alerts"
}

# Dead Letter Queue for failed alert deliveries
resource "aws_sqs_queue" "access_key_alert_dlq" {
  name                      = "t1098-access-key-alerts-dlq"
  message_retention_seconds = 1209600  # 14 days
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
data "aws_iam_policy_document" "access_key_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.access_key_alert_dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.access_key_creation.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "access_key_dlq" {
  queue_url = aws_sqs_queue.access_key_alert_dlq.url
  policy    = data.aws_iam_policy_document.access_key_dlq_policy.json
}

resource "aws_cloudwatch_event_rule" "access_key_creation" {
  name        = "T1098-AccessKeyCreation"
  description = "Detect IAM access key and credential creation"

  event_pattern = jsonencode({
    source = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "CreateAccessKey",
        "CreateLoginProfile",
        "UpdateLoginProfile"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "access_key_sns" {
  rule      = aws_cloudwatch_event_rule.access_key_creation.name
  target_id = "SNSAlert"
  arn       = var.sns_topic_arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.access_key_alert_dlq.arn
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

}""",
                alert_severity="high",
                alert_title="IAM Credential Creation Detected",
                alert_description_template=(
                    "User {user} performed {eventName} for account {targetUser}. "
                    "Source IP: {sourceIPAddress}. Verify this is an authorised change."
                ),
                investigation_steps=[
                    "Verify if the credential creation was authorised",
                    "Check who requested the new credentials",
                    "Review the target account's current access keys",
                    "Determine if this follows normal provisioning procedures",
                    "Check for other suspicious activity from the source IP",
                ],
                containment_actions=[
                    "Delete any unauthorised access keys",
                    "Disable login profiles created without authorisation",
                    "Review and update IAM policies for least privilege",
                    "Implement SCP controls for credential creation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist automated provisioning systems; use change management tickets",
            detection_coverage="95% - complete coverage for credential creation",
            evasion_considerations="Attackers may use existing overly permissive accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "EventBridge configured"],
        ),
        # Strategy 3: Permission Escalation
        DetectionStrategy(
            strategy_id="t1098-permission-escalation",
            name="IAM Permission Escalation Detection",
            description=(
                "Monitor for IAM policy changes that could indicate privilege escalation, "
                "including attaching policies or adding users to groups."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["iam.amazonaws.com"],
                        "eventName": [
                            "AttachUserPolicy",
                            "AttachRolePolicy",
                            "AttachGroupPolicy",
                            "PutUserPolicy",
                            "PutRolePolicy",
                            "PutGroupPolicy",
                            "AddUserToGroup",
                            "CreatePolicyVersion",
                            "SetDefaultPolicyVersion",
                        ],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: IAM permission escalation detection

Parameters:
  SNSTopicArn:
    Type: String

Resources:
  # Dead Letter Queue for failed alert deliveries
  PermissionEscalationAlertDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: t1098-permission-escalation-dlq
      MessageRetentionPeriod: 1209600  # 14 days

  PermissionEscalationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1098-PermissionEscalation
      Description: Detect IAM permission changes
      EventPattern:
        source:
          - aws.iam
        detail-type:
          - "AWS API Call via CloudTrail"
        detail:
          eventSource:
            - iam.amazonaws.com
          eventName:
            - AttachUserPolicy
            - AttachRolePolicy
            - AttachGroupPolicy
            - PutUserPolicy
            - PutRolePolicy
            - PutGroupPolicy
            - AddUserToGroup
            - CreatePolicyVersion
            - SetDefaultPolicyVersion
      State: ENABLED
      Targets:
        - Id: SNSAlert
          Arn: !Ref SNSTopicArn
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt PermissionEscalationAlertDLQ.Arn""",
                terraform_template="""# IAM permission escalation detection

variable "sns_topic_arn" {
  type        = string
  description = "ARN of SNS topic for alerts"
}

# Dead Letter Queue for failed alert deliveries
resource "aws_sqs_queue" "permission_escalation_dlq" {
  name                      = "t1098-permission-escalation-dlq"
  message_retention_seconds = 1209600  # 14 days
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
data "aws_iam_policy_document" "permission_escalation_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.permission_escalation_dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.permission_escalation.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "permission_escalation_dlq" {
  queue_url = aws_sqs_queue.permission_escalation_dlq.url
  policy    = data.aws_iam_policy_document.permission_escalation_dlq_policy.json
}

resource "aws_cloudwatch_event_rule" "permission_escalation" {
  name        = "T1098-PermissionEscalation"
  description = "Detect IAM permission changes"

  event_pattern = jsonencode({
    source = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "AddUserToGroup",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "permission_escalation_sns" {
  rule      = aws_cloudwatch_event_rule.permission_escalation.name
  target_id = "SNSAlert"
  arn       = var.sns_topic_arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.permission_escalation_dlq.arn
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

}""",
                alert_severity="high",
                alert_title="IAM Permission Change Detected",
                alert_description_template=(
                    "User {user} performed {eventName}. Target: {target}. "
                    "This may indicate privilege escalation. Source IP: {sourceIPAddress}."
                ),
                investigation_steps=[
                    "Review the specific permissions added",
                    "Determine if the change was authorised via change management",
                    "Check if sensitive permissions (IAM, KMS, etc.) were added",
                    "Verify the principal making the change",
                    "Look for patterns indicating privilege escalation chain",
                ],
                containment_actions=[
                    "Revert unauthorised permission changes",
                    "Review all policies attached to the affected entity",
                    "Implement approval workflows for IAM changes",
                    "Consider using AWS Organisations SCPs to limit changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Integrate with change management; whitelist IaC deployment roles",
            detection_coverage="90% - excellent coverage for permission changes",
            evasion_considerations="Using existing permissions rather than adding new ones",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "EventBridge configured"],
        ),
        # Strategy 4: Comprehensive IAM Change Monitoring
        DetectionStrategy(
            strategy_id="t1098-iam-changes",
            name="Comprehensive IAM Change Analysis",
            description=(
                "Use CloudWatch Logs Insights to analyse patterns of IAM changes "
                "that may indicate account manipulation."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventName, sourceIPAddress,
       requestParameters.userName as targetUser, requestParameters.roleName as targetRole,
       requestParameters.policyArn as policy
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["CreateUser", "CreateRole", "CreateAccessKey", "CreateLoginProfile",
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "AddUserToGroup", "UpdateAssumeRolePolicy"]
| stats count(*) as change_count, count_distinct(eventName) as unique_actions
  by user, sourceIPAddress, bin(1h) as hour_window
| filter change_count >= 5 or unique_actions >= 3
| sort change_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Comprehensive IAM change monitoring

Parameters:
  CloudTrailLogGroup:
    Type: String
  SNSTopicArn:
    Type: String

Resources:
  IAMChangeMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "iam.amazonaws.com" && ($.eventName = "CreateUser" || $.eventName = "CreateAccessKey" || $.eventName = "AttachUserPolicy" || $.eventName = "AttachRolePolicy") }'
      MetricTransformations:
        - MetricName: IAMChanges
          MetricNamespace: Security/T1098
          MetricValue: "1"

  IAMChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1098-ExcessiveIAMChanges
      AlarmDescription: Multiple IAM changes detected in short time
      MetricName: IAMChanges
      Namespace: Security/T1098
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn""",
                alert_severity="high",
                alert_title="Excessive IAM Changes Detected",
                alert_description_template=(
                    "User {user} made {change_count} IAM changes ({unique_actions} unique actions) in 1 hour. "
                    "Source IP: {sourceIPAddress}. This may indicate account manipulation."
                ),
                investigation_steps=[
                    "List all IAM changes made by the user in the time window",
                    "Determine if changes were part of authorised provisioning",
                    "Check for patterns (e.g., creating user then escalating permissions)",
                    "Review the resources created or modified",
                    "Verify the source IP is expected for administrative tasks",
                ],
                containment_actions=[
                    "Temporarily restrict the user's IAM permissions",
                    "Review and revert unauthorised changes",
                    "Implement stricter IAM permission boundaries",
                    "Enable IAM Access Analyser for external access detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal IAM change patterns; exclude IaC deployments",
            detection_coverage="85% - catches patterns of account manipulation",
            evasion_considerations="Very slow, gradual changes spread over time",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Strategy 5: GCP IAM Policy Changes
        DetectionStrategy(
            strategy_id="t1098-gcp-iam-changes",
            name="GCP IAM Policy Change Detection",
            description=(
                "Detect IAM policy changes that grant elevated permissions in GCP. "
                "Monitors SetIamPolicy calls that add Owner, Editor, or sensitive roles "
                "to projects, folders, and organisations."
            ),
            detection_type=DetectionType.GCP_LOG_METRIC,
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName=~"SetIamPolicy"
protoPayload.serviceName="cloudresourcemanager.googleapis.com"
protoPayload.request.policy.bindings.role=~"(roles/owner|roles/editor|roles/iam.securityAdmin|roles/resourcemanager.organizationAdmin)"
severity>=NOTICE""",
                terraform_template="""# GCP IAM Policy Change Detection for T1098
# Detects SetIamPolicy calls that grant elevated permissions

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "T1098 Account Manipulation Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for IAM policy changes
resource "google_logging_metric" "iam_policy_changes" {
  project     = var.project_id
  name        = "t1098-iam-policy-changes"
  description = "Detects SetIamPolicy calls granting elevated permissions"
  filter      = <<-EOT
    protoPayload.methodName=~"SetIamPolicy"
    protoPayload.serviceName="cloudresourcemanager.googleapis.com"
    protoPayload.request.policy.bindings.role=~"(roles/owner|roles/editor|roles/iam.securityAdmin|roles/resourcemanager.organizationAdmin)"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "actor"
      value_type  = "STRING"
      description = "Principal making the change"
    }
    labels {
      key         = "role"
      value_type  = "STRING"
      description = "Role being granted"
    }
  }

  label_extractors = {
    "actor" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "role"  = "EXTRACT(protoPayload.request.policy.bindings.role)"
  }
}

# Alert policy for IAM changes
resource "google_monitoring_alert_policy" "iam_policy_alert" {
  project      = var.project_id
  display_name = "T1098: Elevated IAM Permissions Granted"
  combiner     = "OR"

  conditions {
    display_name = "IAM Policy Change Detected"

    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/${google_logging_metric.iam_policy_changes.name}\\" AND resource.type=\\"global\\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Elevated IAM permissions were granted via SetIamPolicy. Actor: $${metric.labels.actor}, Role: $${metric.labels.role}. Investigate immediately for potential account manipulation (MITRE T1098)."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Elevated IAM Permissions Granted",
                alert_description_template=(
                    "SetIamPolicy was used to grant elevated permissions ({role}) "
                    "by {actor}. This may indicate privilege escalation or account manipulation."
                ),
                investigation_steps=[
                    "Identify the resource where permissions were changed",
                    "Review the IAM binding changes in Cloud Audit Logs",
                    "Determine if the actor is authorised to make such changes",
                    "Check if the change follows change management procedures",
                    "Review the source IP and user agent of the request",
                    "Investigate what the newly-privileged identity has done since",
                ],
                containment_actions=[
                    "Revert the IAM policy change immediately",
                    "Disable or restrict the actor's permissions",
                    "Review all resources the new principal has accessed",
                    "Implement IAM Recommender to identify over-privileged accounts",
                    "Enable Organisation Policy constraints for IAM",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Whitelist Terraform/Deployment service accounts; "
                "exclude changes during scheduled maintenance windows"
            ),
            detection_coverage="90% - detects direct privilege escalation via IAM",
            evasion_considerations=(
                "Attackers may grant less obvious roles like custom roles; "
                "monitor all SetIamPolicy calls, not just privileged roles"
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-15 (Cloud Monitoring)",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Admin Activity logs (enabled by default)",
            ],
        ),
        # Strategy 6: GCP Service Account Key Creation
        DetectionStrategy(
            strategy_id="t1098-gcp-sa-key",
            name="GCP Service Account Key Creation Monitoring",
            description=(
                "Detect creation of service account keys which provide persistent "
                "credential access. Key creation is a common persistence mechanism."
            ),
            detection_type=DetectionType.GCP_LOG_METRIC,
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
protoPayload.serviceName="iam.googleapis.com"
severity>=NOTICE""",
                terraform_template="""# GCP Service Account Key Creation Detection for T1098
# Detects when service account keys are created (persistence mechanism)

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "T1098 SA Key Creation Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for SA key creation
resource "google_logging_metric" "sa_key_creation" {
  project     = var.project_id
  name        = "t1098-sa-key-creation"
  description = "Detects service account key creation"
  filter      = <<-EOT
    protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
    protoPayload.serviceName="iam.googleapis.com"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "actor"
      value_type  = "STRING"
      description = "Principal creating the key"
    }
    labels {
      key         = "service_account"
      value_type  = "STRING"
      description = "Service account for which key was created"
    }
  }

  label_extractors = {
    "actor"           = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "service_account" = "EXTRACT(protoPayload.request.name)"
  }
}

# Alert policy
resource "google_monitoring_alert_policy" "sa_key_alert" {
  project      = var.project_id
  display_name = "T1098: Service Account Key Created"
  combiner     = "OR"

  conditions {
    display_name = "SA Key Creation Detected"

    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/${google_logging_metric.sa_key_creation.name}\\" AND resource.type=\\"global\\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "A service account key was created by $${metric.labels.actor} for $${metric.labels.service_account}. Service account keys provide persistent access and should be avoided in favour of Workload Identity. Investigate for potential account manipulation (MITRE T1098)."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Service Account Key Created",
                alert_description_template=(
                    "Service account key created by {actor} for {service_account}. "
                    "Keys provide persistent access and are a common persistence mechanism."
                ),
                investigation_steps=[
                    "Identify the service account and its permissions",
                    "Determine if the actor is authorised to create keys",
                    "Check if the SA key creation follows security policies",
                    "Review the service account's IAM bindings",
                    "Check for any API usage from the new key",
                ],
                containment_actions=[
                    "Delete the service account key immediately",
                    "Review the service account's permissions",
                    "Disable the service account if compromised",
                    "Implement Organisation Policy to prevent key creation",
                    "Migrate to Workload Identity where possible",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist automation accounts that legitimately create keys; "
                "use Organisation Policy to prevent key creation where not needed"
            ),
            detection_coverage="95% - catches all service account key creation",
            evasion_considerations=(
                "Attackers may use existing keys rather than creating new ones; "
                "combine with key usage monitoring"
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "IAM Admin Activity logs (enabled by default)",
            ],
        ),
        # Strategy 7: GCP Service Account Impersonation Permissions
        DetectionStrategy(
            strategy_id="t1098-gcp-sa-impersonation",
            name="GCP Service Account Impersonation Detection",
            description=(
                "Detect when permissions are granted that allow service account "
                "impersonation (iam.serviceAccounts.actAs, getAccessToken, signBlob). "
                "These permissions enable privilege escalation."
            ),
            detection_type=DetectionType.GCP_LOG_METRIC,
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="SetIamPolicy"
protoPayload.request.policy.bindings.role=~"(serviceAccountUser|serviceAccountTokenCreator|serviceAccountKeyAdmin|workloadIdentityUser)"
severity>=NOTICE""",
                terraform_template="""# GCP Service Account Impersonation Permission Detection for T1098
# Detects grants of SA impersonation permissions (privilege escalation vector)

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "T1098 SA Impersonation Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric
resource "google_logging_metric" "sa_impersonation" {
  project     = var.project_id
  name        = "t1098-sa-impersonation-grants"
  description = "Detects grants of service account impersonation permissions"
  filter      = <<-EOT
    protoPayload.methodName="SetIamPolicy"
    protoPayload.request.policy.bindings.role=~"(serviceAccountUser|serviceAccountTokenCreator|serviceAccountKeyAdmin|workloadIdentityUser)"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "actor"
      value_type  = "STRING"
      description = "Principal granting the permission"
    }
    labels {
      key         = "role"
      value_type  = "STRING"
      description = "Impersonation role granted"
    }
  }

  label_extractors = {
    "actor" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "role"  = "EXTRACT(protoPayload.request.policy.bindings.role)"
  }
}

# Alert policy
resource "google_monitoring_alert_policy" "sa_impersonation_alert" {
  project      = var.project_id
  display_name = "T1098: SA Impersonation Permission Granted"
  combiner     = "OR"

  conditions {
    display_name = "SA Impersonation Permission Granted"

    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/${google_logging_metric.sa_impersonation.name}\\" AND resource.type=\\"global\\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Service account impersonation permission ($${metric.labels.role}) was granted by $${metric.labels.actor}. This allows privilege escalation via service account impersonation. Investigate for MITRE T1098 Account Manipulation."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Service Account Impersonation Permission Granted",
                alert_description_template=(
                    "Service account impersonation permission ({role}) was granted by {actor}. "
                    "This is a critical privilege escalation vector."
                ),
                investigation_steps=[
                    "Identify who was granted the impersonation permission",
                    "Determine if this follows change management procedures",
                    "Review the service account's permissions (blast radius)",
                    "Check if the actor is authorised to grant this permission",
                    "Investigate any impersonation activity that has occurred",
                ],
                containment_actions=[
                    "Revoke the impersonation permission immediately",
                    "Review all actions taken via impersonation",
                    "Implement Organisation Policy to restrict SA impersonation",
                    "Enable IAM Conditions for time-limited access",
                    "Audit all identities with impersonation permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Whitelist legitimate CI/CD pipelines that require impersonation; "
                "implement approval workflows for impersonation permissions"
            ),
            detection_coverage="95% - catches all impersonation permission grants",
            evasion_considerations=(
                "Attackers may use existing impersonation permissions; "
                "combine with impersonation activity monitoring"
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Admin Activity logs (enabled by default)",
            ],
        ),
    ],
    recommended_order=[
        "t1098-guardduty",
        "t1098-gcp-iam-changes",
        "t1098-gcp-sa-impersonation",
        "t1098-gcp-sa-key",
        "t1098-access-key-creation",
        "t1098-permission-escalation",
        "t1098-iam-changes",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+35% improvement for Persistence tactic",
)
