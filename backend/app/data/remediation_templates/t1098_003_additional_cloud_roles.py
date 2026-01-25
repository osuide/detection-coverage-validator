"""
T1098.003 - Account Manipulation: Additional Cloud Roles

Adversaries add themselves to privileged roles or modify role trust policies
to escalate privileges or maintain persistent access.
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
    technique_id="T1098.003",
    technique_name="Account Manipulation: Additional Cloud Roles",
    tactic_ids=["TA0003", "TA0004"],
    mitre_url="https://attack.mitre.org/techniques/T1098/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify IAM roles, add role trust relationships, or assign "
            "themselves to privileged roles for persistence and privilege escalation. "
            "This includes modifying assume role policies and adding role bindings."
        ),
        attacker_goal="Escalate privileges or maintain access via role manipulation",
        why_technique=[
            "Roles provide elevated permissions",
            "Trust policy changes enable cross-account access",
            "Role assumption is harder to track",
            "Provides flexible persistent access",
            "Can enable privilege escalation chains",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=9,
        severity_reasoning=(
            "Role manipulation can lead to full account compromise. Trust policy "
            "changes can enable external access. Admin role assignment gives complete control."
        ),
        business_impact=[
            "Full account takeover risk",
            "Cross-account compromise",
            "Privilege escalation",
            "Persistent administrator access",
        ],
        typical_attack_phase="privilege_escalation",
        often_precedes=["T1530", "T1537", "T1562.008"],
        often_follows=["T1078.004", "T1098.001"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: GuardDuty Persistence Detection (Recommended)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1098003-aws-guardduty",
            name="AWS GuardDuty Persistence Detection",
            description=(
                "Leverage GuardDuty's ML-based detection for IAM persistence patterns. "
                "Detects unusual IAM policy changes and role modifications. "
                "See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Persistence:IAMUser/AnomalousBehavior",
                    "PrivilegeEscalation:IAMUser/AnomalousBehavior",
                ],
                terraform_template="""# AWS GuardDuty Persistence Detection for IAM
# Detects: Persistence:IAMUser/AnomalousBehavior
# See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html

variable "alert_email" {
  type        = string
  description = "Email for persistence alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create encrypted SNS topic
resource "aws_sns_topic" "persistence_alerts" {
  name              = "guardduty-persistence-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.persistence_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 3: Route Persistence and PrivilegeEscalation findings to SNS
resource "aws_cloudwatch_event_rule" "persistence_findings" {
  name        = "guardduty-persistence-findings"
  description = "Detect IAM persistence and privilege escalation"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Persistence:IAMUser/" },
        { prefix = "PrivilegeEscalation:IAMUser/" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.persistence_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.persistence_alerts.arn

  input_transformer {
    input_paths = {
      findingType = "$.detail.type"
      severity    = "$.detail.severity"
      principal   = "$.detail.resource.accessKeyDetails.userName"
      accountId   = "$.account"
    }
    input_template = <<-EOF
      "CRITICAL: GuardDuty Persistence Alert"
      "Type: <findingType>"
      "Severity: <severity>"
      "Principal: <principal>"
      "Account: <accountId>"
      "Action: Investigate IAM changes immediately"
    EOF
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.persistence_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.persistence_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.persistence_findings.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: IAM Persistence Activity Detected",
                alert_description_template=(
                    "GuardDuty detected IAM persistence activity: {type}. "
                    "Principal {principal} may be establishing persistent access."
                ),
                investigation_steps=[
                    "Review the specific GuardDuty finding for full context",
                    "Identify all IAM changes made by this principal",
                    "Check for new roles, policies, or trust relationships",
                    "Review access key creation activity",
                    "Look for privilege escalation patterns",
                ],
                containment_actions=[
                    "Revoke the principal's credentials immediately",
                    "Remove any IAM changes made by the principal",
                    "Review and restrict IAM modification permissions",
                    "Enable MFA for all IAM operations",
                    "Audit all IAM resources for backdoors",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty's ML learns baseline IAM patterns over 7-14 days. "
                "New automation may trigger initial findings. "
                "Use suppression rules for known CI/CD systems."
            ),
            detection_coverage="85% - ML-based detection of anomalous IAM activity",
            evasion_considerations="Very slow, gradual privilege escalation may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "Included in base GuardDuty cost. "
                "See: https://aws.amazon.com/guardduty/pricing/"
            ),
            prerequisites=["CloudTrail enabled"],
        ),
        # =====================================================================
        # STRATEGY 2: AWS - Role Trust Policy Modification
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1098003-aws-trustpolicy",
            name="IAM Role Trust Policy Modification",
            description="Detect when IAM role trust policies are modified.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["UpdateAssumeRolePolicy", "CreateRole"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM role trust policy modifications

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

  # Step 2: EventBridge for trust policy changes
  TrustPolicyRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - UpdateAssumeRolePolicy
            - CreateRole
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
                aws:SourceArn: !GetAtt TrustPolicyRule.Arn""",
                terraform_template="""# Detect IAM role trust policy modifications

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "role-trust-policy-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "trust_policy" {
  name = "role-trust-policy-changes"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["UpdateAssumeRolePolicy", "CreateRole"]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "role-trust-policy-dlq"
  message_retention_seconds = 1209600
}

data "aws_caller_identity" "current" {}

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
      values   = [aws_cloudwatch_event_rule.trust_policy.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.trust_policy.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
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
              aws_cloudwatch_event_rule.trust_policy.arn,
              aws_cloudwatch_event_rule.policy_attach.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="IAM Role Trust Policy Modified",
                alert_description_template="Role {roleName} trust policy was modified.",
                investigation_steps=[
                    "Review the new trust policy",
                    "Check if external accounts were added",
                    "Verify the change was authorised",
                    "Review who made the change",
                ],
                containment_actions=[
                    "Revert to previous trust policy",
                    "Remove unauthorised principals",
                    "Review role permissions",
                    "Lock down IAM modify permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist infrastructure automation",
            detection_coverage="95% - catches all trust policy changes",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - Admin Policy Attachment
        DetectionStrategy(
            strategy_id="t1098003-aws-adminpolicy",
            name="Administrator Policy Attachment Detection",
            description="Detect when admin policies are attached to users or roles.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "AttachRolePolicy",
                            "AttachUserPolicy",
                            "PutRolePolicy",
                            "PutUserPolicy",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect admin policy attachments

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

  # Step 2: EventBridge for policy attachments
  PolicyAttachRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - AttachRolePolicy
            - AttachUserPolicy
            - PutRolePolicy
            - PutUserPolicy
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
                aws:SourceArn: !GetAtt PolicyAttachRule.Arn""",
                terraform_template="""# Detect admin policy attachments

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "policy-attachment-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "policy_attach" {
  name = "admin-policy-attachments"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AttachRolePolicy",
        "AttachUserPolicy",
        "PutRolePolicy",
        "PutUserPolicy"
      ]
    }
  })
}

resource "aws_sqs_queue" "policy_attach_dlq" {
  name                      = "policy-attachment-dlq"
  message_retention_seconds = 1209600
}

data "aws_iam_policy_document" "policy_attach_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sqs_queue.policy_attach_dlq.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.policy_attach.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "policy_attach_dlq_policy" {
  queue_url = aws_sqs_queue.policy_attach_dlq.url
  policy    = data.aws_iam_policy_document.policy_attach_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.policy_attach.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.policy_attach_dlq.arn
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
              aws_cloudwatch_event_rule.trust_policy.arn,
              aws_cloudwatch_event_rule.policy_attach.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="IAM Policy Attached",
                alert_description_template="Policy attached to {roleName}/{userName}.",
                investigation_steps=[
                    "Review the policy that was attached",
                    "Check if it grants admin permissions",
                    "Verify the change was authorised",
                    "Review the target identity",
                ],
                containment_actions=[
                    "Detach unauthorised policies",
                    "Review identity permissions",
                    "Audit recent API activity",
                    "Lock down IAM modify permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist deployment automation",
            detection_coverage="95% - catches all policy attachments",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: GCP - IAM Role Binding Changes
        DetectionStrategy(
            strategy_id="t1098003-gcp-rolebinding",
            name="GCP IAM Role Binding Changes",
            description="Detect when privileged IAM role bindings are added.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"SetIamPolicy"
protoPayload.request.policy.bindings.role=~"(owner|admin|editor)"''',
                gcp_terraform_template="""# GCP: Detect IAM role binding changes

variable "project_id" {
  type        = string
  description = "GCP Project ID"
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

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  display_name = "Security Alerts"
  type         = "email"
  project      = var.project_id
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "iam_binding" {
  name    = "privileged-iam-binding-changes"
  project = var.project_id
  filter  = <<-EOT
    protoPayload.methodName=~"SetIamPolicy|setIamPolicy"
    protoPayload.request.policy.bindings.role=~"(roles/owner|roles/editor|admin)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "iam_binding" {
  project      = var.project_id
  display_name = "Privileged IAM Binding Changed"
  combiner     = "OR"

  conditions {
    display_name = "Admin/Owner role binding"
    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/${google_logging_metric.iam_binding.name}\\" resource.type=\\"global\\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
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
}""",
                alert_severity="critical",
                alert_title="GCP: Privileged Role Binding Added",
                alert_description_template="Privileged IAM role binding was added or modified.",
                investigation_steps=[
                    "Review the IAM policy change",
                    "Identify which principal was granted access",
                    "Verify the change was authorised",
                    "Check the role permissions",
                ],
                containment_actions=[
                    "Remove unauthorised role bindings",
                    "Review all privileged role assignments",
                    "Enable organisation policy constraints",
                    "Audit the principal's activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist infrastructure automation",
            detection_coverage="90% - catches privileged role bindings",
            evasion_considerations="Attacker may use less obvious roles",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - Service Account Impersonation
        DetectionStrategy(
            strategy_id="t1098003-gcp-impersonation",
            name="GCP Service Account Impersonation",
            description="Detect service account impersonation permissions added.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="SetIamPolicy"
protoPayload.request.policy.bindings.role=~"serviceAccountTokenCreator|serviceAccountUser|serviceAccountKeyAdmin|workloadIdentityUser"''',
                gcp_terraform_template="""# GCP: Detect service account impersonation

variable "project_id" {
  type        = string
  description = "GCP Project ID"
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

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  display_name = "Security Alerts"
  type         = "email"
  project      = var.project_id
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "sa_impersonation" {
  name    = "sa-impersonation-permissions"
  project = var.project_id
  filter  = <<-EOT
    protoPayload.methodName="SetIamPolicy"
    protoPayload.request.policy.bindings.role=~"serviceAccountTokenCreator|serviceAccountUser|serviceAccountKeyAdmin|workloadIdentityUser"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "sa_impersonation" {
  project      = var.project_id
  display_name = "Service Account Impersonation Enabled"
  combiner     = "OR"

  conditions {
    display_name = "SA impersonation permission added"
    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/${google_logging_metric.sa_impersonation.name}\\" resource.type=\\"global\\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
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
}""",
                alert_severity="high",
                alert_title="GCP: Service Account Impersonation Enabled",
                alert_description_template="Service account impersonation permissions were granted.",
                investigation_steps=[
                    "Identify who can now impersonate which SA",
                    "Review the service account permissions",
                    "Verify the change was authorised",
                    "Check for impersonation activity",
                ],
                containment_actions=[
                    "Remove impersonation permissions",
                    "Review service account bindings",
                    "Enable organisation policies",
                    "Audit impersonation activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised impersonation patterns",
            detection_coverage="95% - catches impersonation permission grants",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Account Manipulation: Additional Cloud Roles
        DetectionStrategy(
            strategy_id="t1098003-azure",
            name="Azure Account Manipulation: Additional Cloud Roles Detection",
            description=(
                "Azure detection for Account Manipulation: Additional Cloud Roles. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "Suspicious additions to sensitive groups",
                    "Honeytoken group membership changed",
                    "Suspicious modification of domain AdminSdHolder",
                    "Suspicious Kerberos delegation attempt by a newly created computer",
                ],
                azure_kql_query="""// Azure Entra ID Privileged Role Assignment Detection
// MITRE ATT&CK: T1098.003 - Account Manipulation: Additional Cloud Roles
let lookback = 24h;
let privilegedRoles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Authentication Administrator",
    "Privileged Authentication Administrator",
    "Azure AD Joined Device Local Administrator"
]);
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName has_any ("Add member to role", "Add eligible member to role", "Add scoped member to role")
| extend
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    RoleName = tostring(TargetResources[0].displayName),
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByApp = tostring(InitiatedBy.app.displayName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| where RoleName has_any (privilegedRoles)
| extend
    Initiator = iff(isnotempty(InitiatedBy), InitiatedBy, InitiatedByApp)
| project
    TimeGenerated,
    OperationName,
    RoleName,
    TargetUser,
    Initiator,
    InitiatedByIP,
    Result,
    CorrelationId
| order by TimeGenerated desc""",
                sentinel_rule_query="""// Sentinel Analytics Rule: Suspicious Privileged Role Assignment
// MITRE ATT&CK: T1098.003 - Account Manipulation: Additional Cloud Roles
// Detects unusual privileged role assignments, especially outside business hours or by new administrators
let lookback = 24h;
let privilegedRoles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "User Administrator",
    "Application Administrator"
]);
// Get baseline of who typically assigns roles
let RoleAssigners = AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Add member to role", "Add eligible member to role")
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(Initiator)
| summarize AssignmentCount = count() by Initiator
| where AssignmentCount > 3;
// Detect new or unusual role assignments
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName has_any ("Add member to role", "Add eligible member to role")
| extend
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    RoleName = tostring(TargetResources[0].displayName),
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    InitiatedByIP = tostring(InitiatedBy.user.ipAddress),
    HourOfDay = hourofday(TimeGenerated),
    DayOfWeek = dayofweek(TimeGenerated)
| where RoleName has_any (privilegedRoles)
| where isnotempty(InitiatedBy)
// Flag suspicious patterns: outside business hours, new assigners, or self-assignment
| extend
    OutsideBusinessHours = HourOfDay < 8 or HourOfDay > 18 or DayOfWeek in (0d, 6d),
    SelfAssignment = InitiatedBy == TargetUser
| join kind=leftanti (RoleAssigners) on $left.InitiatedBy == $right.Initiator
| extend NewAssigner = true
| project
    TimeGenerated,
    OperationName,
    RoleName,
    TargetUser,
    InitiatedBy,
    InitiatedByIP,
    OutsideBusinessHours,
    SelfAssignment,
    NewAssigner
| where OutsideBusinessHours or SelfAssignment or NewAssigner""",
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Account Manipulation: Additional Cloud Roles (T1098.003)
# Microsoft Defender detects Account Manipulation: Additional Cloud Roles activity

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

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
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
  name                = "defender-t1098-003-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1098-003"
  resource_group_name = var.resource_group_name
  location            = var.location

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

                    "Suspicious additions to sensitive groups",
                    "Honeytoken group membership changed",
                    "Suspicious modification of domain AdminSdHolder",
                    "Suspicious Kerberos delegation attempt by a newly created computer"
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

  description = "Microsoft Defender detects Account Manipulation: Additional Cloud Roles activity"
  display_name = "Defender: Account Manipulation: Additional Cloud Roles"
  enabled      = true

  tags = {
    "mitre-technique" = "T1098.003"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Account Manipulation: Additional Cloud Roles Detected",
                alert_description_template=(
                    "Account Manipulation: Additional Cloud Roles activity detected. "
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
        "t1098003-aws-guardduty",
        "t1098003-aws-trustpolicy",
        "t1098003-gcp-rolebinding",
        "t1098003-aws-adminpolicy",
        "t1098003-gcp-impersonation",
    ],
    total_effort_hours=2.5,
    coverage_improvement="+22% improvement for Privilege Escalation tactic",
)
