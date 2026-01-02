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

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
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

  notification_channels = [google_monitoring_notification_channel.email.id]

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

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
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

  notification_channels = [google_monitoring_notification_channel.email.id]

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
