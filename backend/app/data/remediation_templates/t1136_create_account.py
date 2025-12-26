"""
T1136 - Create Account

Adversaries create accounts to maintain persistent access to victim systems.
Account creation may be used for establishing secondary credentialled access that
does not require deployment of persistent remote access tools to the victim system.
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
    technique_id="T1136",
    technique_name="Create Account",
    tactic_ids=["TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1136/",
    threat_context=ThreatContext(
        description=(
            "Adversaries create new accounts (local, domain, or cloud) to maintain "
            "persistent access to victim systems without requiring remote access tools. "
            "These accounts may be created on local systems, in Active Directory domains, "
            "or within cloud environments. Attackers often name these accounts to blend "
            "with legitimate users or system accounts, making detection challenging."
        ),
        attacker_goal="Establish persistent credentialled access through new account creation",
        why_technique=[
            "Provides persistent access without malware deployment",
            "New accounts can evade detection on compromised credentials",
            "Accounts blend with legitimate users when named appropriately",
            "Multiple accounts provide backup access paths",
            "Cloud accounts can be restricted to specific services to minimise detection",
            "Domain accounts enable lateral movement across networks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Account creation is a critical persistence technique used by advanced threat actors. "
            "New accounts provide reliable backdoor access that often persists through initial "
            "remediation efforts. In cloud environments, shadow admin accounts are particularly "
            "dangerous as they may go unnoticed for extended periods whilst providing broad access."
        ),
        business_impact=[
            "Persistent unauthorised access to systems and data",
            "Difficult incident remediation if backdoor accounts are missed",
            "Lateral movement enabling broader compromise",
            "Compliance violations from unauthorised account creation",
            "Potential for privilege escalation to administrator level",
            "Data exfiltration through persistent access channels",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1098", "T1078", "T1530", "T1087"],
        often_follows=["T1078", "T1110", "T1190", "T1566"],
    ),
    detection_strategies=[
        # AWS GuardDuty Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1136-aws-guardduty",
            name="AWS GuardDuty Anomaly Detection",
            description=(
                "AWS GuardDuty detects anomalous account creation patterns. Persistence:IAMUser/AnomalousBehavior identifies when CreateUser, CreateAccessKey, or similar APIs are invoked in unusual patterns suggesting unauthorised persistence establishment."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Persistence:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for T1136

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty-T1136-Alerts
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
      Description: Capture GuardDuty findings for T1136
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Persistence:IAMUser/"
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# GuardDuty alerts for T1136

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: SNS Topic
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "guardduty-t1136-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for findings
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-t1136"
  description = "Capture GuardDuty findings for T1136"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Persistence:IAMUser/" }]
    }
  })
}

# Step 3: Target with DLQ and retry
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-t1136-dlq"
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
            evasion_considerations="Creating accounts during business hours, using naming conventions that match legitimate accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events",
            prerequisites=[
                "AWS GuardDuty enabled",
                "CloudTrail logging active",
            ],
        ),
        # Strategy 1: AWS - IAM User Creation
        DetectionStrategy(
            strategy_id="t1136-aws-user-creation",
            name="AWS IAM User Creation Detection",
            description=(
                "Monitor CloudTrail for IAM user creation events to detect when new "
                "accounts are established in AWS environments."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["iam.amazonaws.com"],
                        "eventName": ["CreateUser", "CreateGroup"],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM user and group creation for T1136

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

  # Step 2: Dead Letter Queue for failed deliveries
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: iam-account-creation-alerts-dlq
      MessageRetentionPeriod: 1209600

  # Step 3: EventBridge rule to detect account creation
  AccountCreationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1136-IAMAccountCreation
      Description: Detect IAM user and group creation
      EventPattern:
        source:
          - aws.iam
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventSource:
            - iam.amazonaws.com
          eventName:
            - CreateUser
            - CreateGroup
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
              eventName: $.detail.eventName
              userName: $.detail.requestParameters.userName
              userArn: $.detail.userIdentity.arn
              sourceIp: $.detail.sourceIPAddress
            InputTemplate: |
              "IAM Account Creation Alert (T1136)"
              "Time: <time>"
              "Account: <account> | Region: <region>"
              "Event: <eventName>"
              "New User/Group: <userName>"
              "Created By: <userArn>"
              "Source IP: <sourceIp>"
              "Action: Verify this account creation was authorised"

  # Step 4: SNS topic policy to allow EventBridge
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
                aws:SourceArn: !GetAtt AccountCreationRule.Arn

  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref DeadLetterQueue
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt DeadLetterQueue.Arn""",
                terraform_template="""# Detect IAM user and group creation for T1136

variable "alert_email" {
  type = string
}

data "aws_caller_identity" "current" {}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name              = "iam-account-creation-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Dead Letter Queue for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "iam-account-creation-alerts-dlq"
  message_retention_seconds = 1209600
}

# Step 3: EventBridge rule to detect account creation
resource "aws_cloudwatch_event_rule" "account_creation" {
  name        = "T1136-IAMAccountCreation"
  description = "Detect IAM user and group creation"

  event_pattern = jsonencode({
    source        = ["aws.iam"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["CreateUser", "CreateGroup"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.account_creation.name
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
      userName  = "$.detail.requestParameters.userName"
      userArn   = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
    }

    input_template = <<-EOT
"IAM Account Creation Alert (T1136)
Time: <time>
Account: <account> | Region: <region>
Event: <eventName>
New User/Group: <userName>
Created By: <userArn>
Source IP: <sourceIp>
Action: Verify this account creation was authorised"
EOT
  }
}

# Step 4: SNS topic policy to allow EventBridge
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.account_creation.arn
        }
      }
    }]
  })
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="AWS: IAM Account Created",
                alert_description_template=(
                    "New IAM account created: {userName}. Created by: {userIdentity.arn}. "
                    "Source IP: {sourceIPAddress}. Verify this account creation was authorised."
                ),
                investigation_steps=[
                    "Verify the account creation was authorised via change management",
                    "Identify who created the account and their source IP address",
                    "Review the new account's permissions and group memberships",
                    "Check if access keys or login profiles were created for the account",
                    "Review naming patterns to identify potential shadow accounts",
                    "Check for immediate suspicious activity from the new account",
                ],
                containment_actions=[
                    "Delete unauthorised IAM users immediately",
                    "Review and remove any permissions granted to the account",
                    "Delete any access keys created for the unauthorised account",
                    "Audit the creator's recent activity for other malicious actions",
                    "Implement approval workflows for IAM user creation",
                    "Enable AWS Organisations SCPs to restrict account creation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised provisioning systems and HR onboarding automation",
            detection_coverage="95% - catches all IAM user and group creation events",
            evasion_considerations="Attackers cannot evade this detection without alternative persistence methods",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "EventBridge configured"],
        ),
        # Strategy 2: AWS - Root User Equivalent Detection
        DetectionStrategy(
            strategy_id="t1136-aws-admin-account",
            name="AWS Administrator Account Creation Detection",
            description=(
                "Detect when new IAM users are created with administrative privileges, "
                "which pose the highest risk for persistent backdoor access."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.userName, userIdentity.arn, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateUser"
| join on requestParameters.userName
  (fields requestParameters.userName, requestParameters.policyArn, requestParameters.groupName
   | filter eventName in ["AttachUserPolicy", "AddUserToGroup"]
   | filter requestParameters.policyArn like /AdministratorAccess/
      or requestParameters.groupName like /Admin/)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect creation of IAM users with admin privileges

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

  # Step 2: Metric filter for admin account creation
  AdminAccountFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "CreateUser") || ($.eventName = "AttachUserPolicy" && $.requestParameters.policyArn = "*AdministratorAccess*") || ($.eventName = "AddUserToGroup" && $.requestParameters.groupName = "*Admin*") }'
      MetricTransformations:
        - MetricName: AdminAccountCreation
          MetricNamespace: Security/T1136
          MetricValue: "1"

  # Step 3: Alarm for admin account creation
  AdminAccountAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1136-AdminAccountCreation
      AlarmDescription: New user created with admin privileges
      MetricName: AdminAccountCreation
      Namespace: Security/T1136
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect creation of IAM users with admin privileges

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "admin-account-creation-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for admin account creation
resource "aws_cloudwatch_log_metric_filter" "admin_account" {
  name           = "admin-account-creation"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"CreateUser\") || ($.eventName = \"AttachUserPolicy\" && $.requestParameters.policyArn = \"*AdministratorAccess*\") || ($.eventName = \"AddUserToGroup\" && $.requestParameters.groupName = \"*Admin*\") }"

  metric_transformation {
    name      = "AdminAccountCreation"
    namespace = "Security/T1136"
    value     = "1"
  }
}

# Step 3: Alarm for admin account creation
resource "aws_cloudwatch_metric_alarm" "admin_account" {
  alarm_name          = "T1136-AdminAccountCreation"
  alarm_description   = "New user created with admin privileges"
  metric_name         = "AdminAccountCreation"
  namespace           = "Security/T1136"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="AWS: Administrator Account Created",
                alert_description_template=(
                    "New IAM user {userName} was created with administrator privileges. "
                    "Created by: {userArn}. This poses significant security risk."
                ),
                investigation_steps=[
                    "Immediately verify if the admin account creation was authorised",
                    "Review the change management process for this creation",
                    "Check the account creator's legitimacy and permissions",
                    "Review all actions taken by the new admin account",
                    "Identify any data or resources accessed by the account",
                    "Check for other accounts created by the same principal",
                ],
                containment_actions=[
                    "Immediately remove administrator permissions if unauthorised",
                    "Delete the account if it's a confirmed backdoor",
                    "Revoke all access keys and login profiles",
                    "Review and audit all admin accounts in the environment",
                    "Implement mandatory approval for admin account creation",
                    "Enable MFA enforcement for all admin accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Integrate with ITSM ticketing systems to validate authorised admin provisioning",
            detection_coverage="90% - catches admin privilege assignment patterns",
            evasion_considerations="Attackers may use custom policies instead of AdministratorAccess",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch Logs"],
        ),
        # Strategy 3: GCP - Service Account Creation
        DetectionStrategy(
            strategy_id="t1136-gcp-service-account",
            name="GCP Service Account Creation Detection",
            description=(
                "Monitor GCP Cloud Audit Logs for service account creation, which adversaries "
                "may use to establish persistent programmatic access."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.iam.admin.v1.CreateServiceAccount"
OR protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"''',
                gcp_terraform_template="""# GCP: Detect service account creation for T1136

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - T1136"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for service account creation
resource "google_logging_metric" "sa_creation" {
  name   = "service-account-creation"
  filter = <<-EOT
    protoPayload.methodName="google.iam.admin.v1.CreateServiceAccount"
    OR protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "Email of the principal creating the account"
    }
  }

  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for service account creation
resource "google_monitoring_alert_policy" "sa_creation" {
  display_name = "T1136: Service Account Created"
  combiner     = "OR"

  conditions {
    display_name = "Service account or key created"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_creation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = <<-EOT
      A new service account or service account key was created.

      Investigation steps:
      1. Verify the creation was authorised
      2. Review the principal who created the account
      3. Check the permissions assigned to the service account
      4. Review any immediate activity from the new account
    EOT
  }
}""",
                alert_severity="high",
                alert_title="GCP: Service Account Created",
                alert_description_template=(
                    "New service account created in project {resource.labels.project_id}. "
                    "Created by: {protoPayload.authenticationInfo.principalEmail}. "
                    "Account: {protoPayload.response.email}."
                ),
                investigation_steps=[
                    "Verify the service account creation was authorised",
                    "Identify the principal who created the account",
                    "Review IAM roles and permissions assigned to the service account",
                    "Check if service account keys were created",
                    "Review the service account's activity in Cloud Audit Logs",
                    "Verify naming conventions match organisational standards",
                ],
                containment_actions=[
                    "Delete unauthorised service accounts immediately",
                    "Revoke all service account keys for suspicious accounts",
                    "Remove IAM role bindings for the service account",
                    "Audit the creator's permissions and recent activity",
                    "Enable organisation policies to restrict service account creation",
                    "Implement approval workflows for service account creation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD pipelines and Terraform automation service accounts",
            detection_coverage="95% - catches all service account creation events",
            evasion_considerations="Cannot evade without alternative persistence methods",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled", "Admin Activity logs enabled"],
        ),
        # Strategy 4: GCP - Privileged Service Account Detection
        DetectionStrategy(
            strategy_id="t1136-gcp-privileged-account",
            name="GCP Privileged Service Account Detection",
            description=(
                "Detect when service accounts are granted high-privilege roles such as "
                "Owner, Editor, or custom admin roles that could enable broad compromise."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="SetIamPolicy"
AND protoPayload.serviceData.policyDelta.bindingDeltas.role=~"roles/(owner|editor|iam.serviceAccountAdmin|iam.securityAdmin)"
AND protoPayload.serviceData.policyDelta.bindingDeltas.member=~"serviceAccount:.*"
AND protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"''',
                gcp_terraform_template="""# GCP: Detect privileged service account creation

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Privileged Accounts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for privileged role assignment
resource "google_logging_metric" "privileged_sa" {
  name   = "privileged-service-account-creation"
  filter = <<-EOT
    protoPayload.methodName="SetIamPolicy"
    AND protoPayload.serviceData.policyDelta.bindingDeltas.role=~"roles/(owner|editor|iam.serviceAccountAdmin|iam.securityAdmin)"
    AND protoPayload.serviceData.policyDelta.bindingDeltas.member=~"serviceAccount:.*"
    AND protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "role"
      value_type  = "STRING"
      description = "Privileged role granted"
    }
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "Principal granting the role"
    }
  }

  label_extractors = {
    "role"            = "EXTRACT(protoPayload.serviceData.policyDelta.bindingDeltas.role)"
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for privileged account creation
resource "google_monitoring_alert_policy" "privileged_sa" {
  display_name = "T1136: Privileged Service Account Created"
  combiner     = "OR"

  conditions {
    display_name = "Privileged role granted to service account"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.privileged_sa.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
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
    content = <<-EOT
      A service account was granted a privileged role (Owner, Editor, or admin role).

      This is CRITICAL - investigate immediately:
      1. Verify the role assignment was authorised
      2. Check who granted the permissions
      3. Review the service account's immediate activity
      4. Determine if this violates least privilege principles
    EOT
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Privileged Service Account Created",
                alert_description_template=(
                    "Service account granted privileged role {role}. "
                    "Granted by: {principalEmail}. This provides broad access and poses significant risk."
                ),
                investigation_steps=[
                    "Immediately verify if the privileged role assignment was authorised",
                    "Review the service account's intended purpose and required permissions",
                    "Check who granted the privileged role and their authority level",
                    "Review all actions taken by the service account since creation",
                    "Identify any data or resources accessed with elevated permissions",
                    "Check for other service accounts created or modified by the same principal",
                ],
                containment_actions=[
                    "Immediately revoke privileged roles if unauthorised",
                    "Apply principle of least privilege with minimal required roles",
                    "Delete the service account if it's confirmed malicious",
                    "Revoke all service account keys",
                    "Implement organisation policies to restrict privileged role assignment",
                    "Enable mandatory approval for owner/editor role grants",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised infrastructure-as-code deployments with documented justification",
            detection_coverage="90% - catches major privileged role assignments",
            evasion_considerations="Attackers may use combinations of lower-privilege roles or custom roles",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Data Access logs enabled for IAM",
            ],
        ),
        # Strategy 5: Account Creation Pattern Analysis
        DetectionStrategy(
            strategy_id="t1136-pattern-analysis",
            name="Suspicious Account Creation Pattern Detection",
            description=(
                "Detect patterns of rapid account creation or accounts created outside "
                "normal business processes that may indicate automated backdoor creation."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as creator, requestParameters.userName as newUser, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName = "CreateUser"
| stats count(*) as users_created, count_distinct(requestParameters.userName) as unique_users,
        min(@timestamp) as first_creation, max(@timestamp) as last_creation
  by creator, sourceIPAddress, bin(1h) as time_window
| filter users_created >= 3
| sort users_created desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious account creation patterns

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

  # Step 2: Metric filter for rapid account creation
  RapidCreationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "iam.amazonaws.com" && $.eventName = "CreateUser" }'
      MetricTransformations:
        - MetricName: UserCreationRate
          MetricNamespace: Security/T1136
          MetricValue: "1"

  # Step 3: Alarm for excessive account creation
  RapidCreationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1136-RapidAccountCreation
      AlarmDescription: Multiple user accounts created rapidly
      MetricName: UserCreationRate
      Namespace: Security/T1136
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect suspicious account creation patterns

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "account-creation-pattern-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for rapid account creation
resource "aws_cloudwatch_log_metric_filter" "rapid_creation" {
  name           = "user-creation-rate"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"iam.amazonaws.com\" && $.eventName = \"CreateUser\" }"

  metric_transformation {
    name      = "UserCreationRate"
    namespace = "Security/T1136"
    value     = "1"
  }
}

# Step 3: Alarm for excessive account creation
resource "aws_cloudwatch_metric_alarm" "rapid_creation" {
  alarm_name          = "T1136-RapidAccountCreation"
  alarm_description   = "Multiple user accounts created rapidly"
  metric_name         = "UserCreationRate"
  namespace           = "Security/T1136"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious Account Creation Pattern",
                alert_description_template=(
                    "Rapid account creation detected: {users_created} users created by {creator} "
                    "from {sourceIPAddress} within 1 hour. This may indicate automated backdoor creation."
                ),
                investigation_steps=[
                    "Review all accounts created in the time window",
                    "Check naming patterns for suspicious or generic names",
                    "Verify if bulk creation aligns with onboarding processes",
                    "Review the creator's authority and typical behaviour",
                    "Check if accounts were immediately granted permissions",
                    "Look for correlation with other security events",
                ],
                containment_actions=[
                    "Disable all newly created accounts pending investigation",
                    "Review and remove permissions from suspicious accounts",
                    "Delete confirmed unauthorised accounts",
                    "Implement rate limiting for account creation",
                    "Require multi-party approval for bulk account operations",
                    "Review the creator's account for compromise",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist scheduled onboarding processes and account migration activities",
            detection_coverage="75% - catches automated and bulk account creation patterns",
            evasion_considerations="Slow, deliberate account creation over extended periods may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail logging to CloudWatch Logs",
                "Baseline of normal account creation rate",
            ],
        ),
    ],
    recommended_order=[
        "t1136-aws-user-creation",
        "t1136-gcp-service-account",
        "t1136-aws-admin-account",
        "t1136-gcp-privileged-account",
        "t1136-pattern-analysis",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+22% improvement for Persistence tactic",
)
