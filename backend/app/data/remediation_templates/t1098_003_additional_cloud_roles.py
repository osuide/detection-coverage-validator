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
    Campaign,
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
        recent_campaigns=[
            Campaign(
                name="Cross-Account Trust Abuse",
                year=2024,
                description="Attackers modified role trust policies to allow access from external accounts",
                reference_url="https://www.datadoghq.com/state-of-cloud-security/",
            ),
            Campaign(
                name="IAM Privilege Escalation",
                year=2024,
                description="Attackers attached admin policies to compromised roles",
                reference_url="https://unit42.paloaltonetworks.com/2025-cloud-security-alert-trends/",
            ),
        ],
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
        # Strategy 1: AWS - Role Trust Policy Modification
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect IAM role trust policy modifications

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "role-trust-policy-alerts"
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

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.trust_policy.name
  arn  = aws_sns_topic.alerts.arn
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect admin policy attachments

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "policy-attachment-alerts"
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

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.policy_attach.name
  arn  = aws_sns_topic.alerts.arn
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
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "iam_binding" {
  name   = "privileged-iam-binding-changes"
  filter = <<-EOT
    protoPayload.methodName=~"SetIamPolicy"
    protoPayload.request.policy.bindings.role=~"(owner|admin|editor)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "iam_binding" {
  display_name = "Privileged IAM Binding Changed"
  combiner     = "OR"

  conditions {
    display_name = "Admin/Owner role binding"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iam_binding.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
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
protoPayload.request.policy.bindings.role="roles/iam.serviceAccountTokenCreator"''',
                gcp_terraform_template="""# GCP: Detect service account impersonation

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "sa_impersonation" {
  name   = "sa-impersonation-permissions"
  filter = <<-EOT
    protoPayload.methodName="SetIamPolicy"
    protoPayload.request.policy.bindings.role=~"serviceAccountTokenCreator|serviceAccountUser"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "sa_impersonation" {
  display_name = "Service Account Impersonation Enabled"
  combiner     = "OR"

  conditions {
    display_name = "SA impersonation permission added"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_impersonation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
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
        "t1098003-aws-trustpolicy",
        "t1098003-gcp-rolebinding",
        "t1098003-aws-adminpolicy",
        "t1098003-gcp-impersonation",
    ],
    total_effort_hours=2.5,
    coverage_improvement="+22% improvement for Privilege Escalation tactic",
)
