"""
T1531 - Account Access Removal

Adversaries delete or lock accounts to disrupt availability.
Used by LAPSUS$, Akira ransomware, and other destructive actors.
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
    technique_id="T1531",
    technique_name="Account Access Removal",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1531/",
    threat_context=ThreatContext(
        description=(
            "Adversaries delete, lock, or modify accounts to prevent legitimate "
            "access. In cloud environments, this includes deleting IAM users, "
            "revoking permissions, or changing credentials."
        ),
        attacker_goal="Lock out legitimate users to disrupt operations",
        why_technique=[
            "Prevents incident response",
            "Maximises ransomware impact",
            "Extends dwell time",
            "Creates chaos for defenders",
            "May be final attack stage",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Critical impact - locks out legitimate administrators. "
            "Prevents incident response. Often paired with ransomware."
        ),
        business_impact=[
            "Loss of administrative access",
            "Delayed incident response",
            "Extended outage",
            "Recovery complications",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078.004", "T1485", "T1486"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1531-aws-userdelete",
            name="AWS IAM User Deletion Detection",
            description="Detect deletion of IAM users.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "DeleteUser",
                            "DeleteLoginProfile",
                            "DeactivateMFADevice",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM user deletion

Parameters:
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  UserDeleteRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [DeleteUser, DeleteLoginProfile, DeactivateMFADevice]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

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
                aws:SourceArn: !GetAtt UserDeleteRule.Arn""",
                terraform_template="""# Detect IAM user deletion

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "user-deletion-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "user_delete" {
  name = "iam-user-deletion"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = { eventName = ["DeleteUser", "DeleteLoginProfile", "DeactivateMFADevice"] }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "user-delete-dlq"
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
      values   = [aws_cloudwatch_event_rule.user_delete.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.user_delete.name
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
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
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
            "aws:SourceArn" = aws_cloudwatch_event_rule.user_delete.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="IAM User Deleted",
                alert_description_template="IAM user {userName} deleted by {userIdentity.arn}.",
                investigation_steps=[
                    "Verify deletion was authorised",
                    "Check for other deletions",
                    "Review remaining admin accounts",
                    "Check for ransomware indicators",
                ],
                containment_actions=[
                    "Recreate deleted users from backup",
                    "Use break-glass account",
                    "Review all IAM changes",
                    "Initiate incident response",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="User deletion is typically rare",
            detection_coverage="95% - catches all deletions",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1531-gcp-userremove",
            name="GCP IAM Member Removal Detection",
            description="Detect removal of IAM members or service accounts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="google.iam.admin.v1.DeleteServiceAccount"
OR (protoPayload.methodName="SetIamPolicy" AND protoPayload.request.policy.bindings:*)""",
                gcp_terraform_template="""# GCP: Detect account removal

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "account_removal" {
  project = var.project_id
  name   = "account-access-removal"
  filter = <<-EOT
    protoPayload.methodName="google.iam.admin.v1.DeleteServiceAccount"
    OR protoPayload.methodName="DeleteUser"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "account_removal" {
  project      = var.project_id
  display_name = "Account Access Removal"
  combiner     = "OR"
  conditions {
    display_name = "Account deleted"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.account_removal.name}\""
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
                alert_severity="critical",
                alert_title="GCP: Account Removed",
                alert_description_template="Account or service account was deleted.",
                investigation_steps=[
                    "Verify deletion was authorised",
                    "Check for other deletions",
                    "Review remaining admins",
                    "Check for ransomware",
                ],
                containment_actions=[
                    "Restore accounts",
                    "Use break-glass access",
                    "Review all IAM changes",
                    "Initiate incident response",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Account deletion is rare",
            detection_coverage="95% - catches deletions",
            evasion_considerations="Cannot evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Account Access Removal
        DetectionStrategy(
            strategy_id="t1531-azure",
            name="Azure Account Access Removal Detection",
            description=(
                "Monitor account access removal. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Account Access Removal Detection
// Technique: T1531
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.Authorization/roleAssignments/delete"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| project
    TimeGenerated,
    SubscriptionId,
    ResourceGroup,
    Resource,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    Properties
| order by TimeGenerated desc""",
                azure_activity_operations=[
                    "Microsoft.Authorization/roleAssignments/delete"
                ],
                azure_terraform_template="""# Azure Detection for Account Access Removal
# MITRE ATT&CK: T1531

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
  name                = "account-access-removal-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "account-access-removal-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Account Access Removal Detection
// Technique: T1531
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.Authorization/roleAssignments/delete"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| project
    TimeGenerated,
    SubscriptionId,
    ResourceGroup,
    Resource,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    ActivityStatusValue,
    Properties
| order by TimeGenerated desc
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

  description = "Detects Account Access Removal (T1531) activity in Azure environment"
  display_name = "Account Access Removal Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1531"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Account Access Removal Detected",
                alert_description_template=(
                    "Account Access Removal activity detected. "
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
    recommended_order=["t1531-aws-userdelete", "t1531-gcp-userremove"],
    total_effort_hours=1.5,
    coverage_improvement="+18% improvement for Impact tactic",
)
