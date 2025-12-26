"""
T1666 - Modify Cloud Resource Hierarchy

Adversaries modify hierarchical structures in cloud environments to evade
security controls and organisational policies.
Used to bypass security controls via LeaveOrganization, CreateAccount.
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
    technique_id="T1666",
    technique_name="Modify Cloud Resource Hierarchy",
    tactic_ids=["TA0005"],  # Defense Evasion
    mitre_url="https://attack.mitre.org/techniques/T1666/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify hierarchical structures in cloud infrastructure "
            "environments to bypass security defences. Cloud providers organise "
            "resources hierarchically—AWS uses organisational structures with "
            "multiple accounts, whilst Azure employs management groups. Attackers "
            "may use AWS LeaveOrganization to remove accounts from organisational "
            "policies, or CreateAccount to establish new accounts that bypass "
            "existing security controls."
        ),
        attacker_goal="Modify cloud resource hierarchy to bypass security controls and organisational policies",
        why_technique=[
            "Removes accounts from Service Control Policies (SCPs)",
            "Bypasses organisational security guardrails",
            "Enables creation of unmonitored resources",
            "Evades centralised logging and monitoring",
            "Difficult to detect without specific monitoring",
        ],
        known_threat_actors=[],  # No specific threat actors documented in MITRE
        recent_campaigns=[],  # No specific campaigns documented in MITRE
        prevalence="rare",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Modifying cloud resource hierarchy enables adversaries to bypass "
            "organisational security controls and policies. This technique allows "
            "attackers to evade detection and create unmonitored resources, making "
            "it a significant threat requiring immediate detection and response."
        ),
        business_impact=[
            "Bypass of security controls and policies",
            "Loss of centralised governance",
            "Creation of unmonitored resources",
            "Potential compliance violations",
            "Extended attacker persistence",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1578.002", "T1530", "T1537"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - LeaveOrganization Detection
        DetectionStrategy(
            strategy_id="t1666-aws-leave-org",
            name="AWS LeaveOrganization Detection",
            description="Detect when an account attempts to leave the AWS Organisation.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.organizations"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["LeaveOrganization"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect AWS LeaveOrganization attempts

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

  # Step 2: EventBridge rule for LeaveOrganization
  LeaveOrgRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.organizations]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [LeaveOrganization]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: SNS topic policy
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
                terraform_template="""# Detect AWS LeaveOrganization attempts

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "leave-organization-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for LeaveOrganization
resource "aws_cloudwatch_event_rule" "leave_org" {
  name = "leave-organization-detection"
  event_pattern = jsonencode({
    source      = ["aws.organizations"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["LeaveOrganization"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.leave_org.name
  arn  = aws_sns_topic.alerts.arn
}

# Step 3: SNS topic policy
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
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="AWS Account Leaving Organisation",
                alert_description_template="Account {accountId} attempted to leave the AWS Organisation.",
                investigation_steps=[
                    "Identify the principal that initiated LeaveOrganization",
                    "Verify if the action was authorised",
                    "Check if Service Control Policies blocked the action",
                    "Review recent activity on the affected account",
                    "Assess what security controls may have been bypassed",
                ],
                containment_actions=[
                    "Block LeaveOrganization via Service Control Policy",
                    "Revoke credentials of compromised principal",
                    "Re-invite the account to the organisation if removed",
                    "Review and strengthen IAM permissions",
                    "Enable preventative SCPs across organisation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="LeaveOrganization should be rare; whitelist authorised account management processes",
            detection_coverage="95% - catches all LeaveOrganization API calls",
            evasion_considerations="Cannot evade if CloudTrail is logging to management account",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=[
                "CloudTrail enabled in organisation",
                "EventBridge in management account",
            ],
        ),
        # Strategy 2: AWS - CreateAccount Monitoring
        DetectionStrategy(
            strategy_id="t1666-aws-create-account",
            name="AWS CreateAccount Monitoring",
            description="Monitor suspicious account creation in AWS Organisations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.accountName, responseElements.createAccountStatus.accountId
| filter eventName = "CreateAccount"
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor AWS CreateAccount API calls

Parameters:
  OrganizationTrailLogGroup:
    Type: String
    Description: CloudTrail log group for organisation trail
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

  # Step 2: Metric filter for CreateAccount
  CreateAccountFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref OrganizationTrailLogGroup
      FilterPattern: '{ $.eventName = "CreateAccount" }'
      MetricTransformations:
        - MetricName: CreateAccountCalls
          MetricNamespace: Security/Organizations
          MetricValue: "1"

  # Step 3: Alarm on CreateAccount
  CreateAccountAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnauthorizedAccountCreation
      MetricName: CreateAccountCalls
      Namespace: Security/Organizations
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Monitor AWS CreateAccount API calls

variable "organization_trail_log_group" {
  type        = string
  description = "CloudTrail log group for organisation trail"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "create-account-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for CreateAccount
resource "aws_cloudwatch_log_metric_filter" "create_account" {
  name           = "create-account-calls"
  log_group_name = var.organization_trail_log_group
  pattern        = "{ $.eventName = \"CreateAccount\" }"

  metric_transformation {
    name      = "CreateAccountCalls"
    namespace = "Security/Organizations"
    value     = "1"
  }
}

# Step 3: Alarm on CreateAccount
resource "aws_cloudwatch_metric_alarm" "create_account" {
  alarm_name          = "UnauthorizedAccountCreation"
  metric_name         = "CreateAccountCalls"
  namespace           = "Security/Organizations"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="AWS Account Created in Organisation",
                alert_description_template="New AWS account {accountName} created by {principalId}.",
                investigation_steps=[
                    "Verify if account creation was authorised",
                    "Identify the principal that created the account",
                    "Review the account configuration and resources",
                    "Check if Service Control Policies apply to new account",
                    "Assess if account creation was part of attack chain",
                ],
                containment_actions=[
                    "Suspend unauthorised new accounts",
                    "Apply restrictive Service Control Policies",
                    "Review and strengthen CreateAccount permissions",
                    "Enable preventative SCPs to block resource creation",
                    "Audit all accounts in organisation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised account creation processes and automation",
            detection_coverage="90% - catches CreateAccount API calls",
            evasion_considerations="Legitimate account creation may blend in with authorised processes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail organisation trail with CloudWatch Logs"],
        ),
        # Strategy 3: AWS - MoveAccount Detection
        DetectionStrategy(
            strategy_id="t1666-aws-move-account",
            name="AWS MoveAccount Detection",
            description="Detect when accounts are moved between organisational units.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.organizations"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["MoveAccount"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect AWS MoveAccount API calls

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

  # Step 2: EventBridge rule for MoveAccount
  MoveAccountRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.organizations]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [MoveAccount]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: SNS topic policy
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
                terraform_template="""# Detect AWS MoveAccount API calls

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "move-account-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for MoveAccount
resource "aws_cloudwatch_event_rule" "move_account" {
  name = "move-account-detection"
  event_pattern = jsonencode({
    source      = ["aws.organizations"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["MoveAccount"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.move_account.name
  arn  = aws_sns_topic.alerts.arn
}

# Step 3: SNS topic policy
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
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="AWS Account Moved Between OUs",
                alert_description_template="Account {accountId} moved to different organisational unit.",
                investigation_steps=[
                    "Identify source and destination organisational units",
                    "Verify if the move was authorised",
                    "Check Service Control Policy differences between OUs",
                    "Review the principal that initiated the move",
                    "Assess security implications of new OU placement",
                ],
                containment_actions=[
                    "Move account back to appropriate OU",
                    "Review and restrict MoveAccount permissions",
                    "Audit organisational unit structure",
                    "Apply compensating controls if SCPs were bypassed",
                    "Enable preventative controls via SCPs",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised organisational restructuring activities",
            detection_coverage="95% - catches all MoveAccount API calls",
            evasion_considerations="Cannot evade if CloudTrail is properly configured",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled in organisation"],
        ),
        # Strategy 4: GCP - Project Transfer Detection
        DetectionStrategy(
            strategy_id="t1666-gcp-project-move",
            name="GCP Project Movement Detection",
            description="Detect when GCP projects are moved between folders or organisations.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="SetIamPolicy" OR protoPayload.methodName="MoveProject"
resource.type="project"''',
                gcp_terraform_template="""# GCP: Detect project movement and hierarchy changes

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

# Step 2: Log-based metric for project movement
resource "google_logging_metric" "project_move" {
  name   = "project-hierarchy-changes"
  filter = <<-EOT
    protoPayload.methodName="MoveProject" OR
    (protoPayload.methodName="SetIamPolicy" AND resource.type="project")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "project_move" {
  display_name = "GCP Project Hierarchy Modified"
  combiner     = "OR"

  conditions {
    display_name = "Project moved or permissions changed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.project_move.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Project Hierarchy Modified",
                alert_description_template="GCP project hierarchy was modified or project was moved.",
                investigation_steps=[
                    "Identify which project was moved",
                    "Review source and destination folders/organisations",
                    "Verify the principal that initiated the change",
                    "Check organisation policy differences",
                    "Assess security implications of new location",
                ],
                containment_actions=[
                    "Move project back to authorised location",
                    "Review and restrict resourcemanager permissions",
                    "Audit folder and organisation structure",
                    "Apply organisation policies to enforce hierarchy",
                    "Enable organisation policy constraints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal project administration and whitelist authorised changes",
            detection_coverage="85% - catches project movement and major IAM changes",
            evasion_considerations="Legitimate project moves may blend with authorised activities",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - Organisation Policy Changes
        DetectionStrategy(
            strategy_id="t1666-gcp-org-policy",
            name="GCP Organisation Policy Modification",
            description="Detect modifications to GCP organisation policies that affect resource hierarchy.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="cloudresourcemanager.googleapis.com"
protoPayload.methodName=~"SetOrgPolicy|DeleteOrgPolicy|ClearOrgPolicy"''',
                gcp_terraform_template="""# GCP: Detect organisation policy modifications

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

# Step 2: Log-based metric for org policy changes
resource "google_logging_metric" "org_policy_change" {
  name   = "organization-policy-changes"
  filter = <<-EOT
    protoPayload.serviceName="cloudresourcemanager.googleapis.com"
    protoPayload.methodName=~"(SetOrgPolicy|DeleteOrgPolicy|ClearOrgPolicy)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "org_policy" {
  display_name = "GCP Organisation Policy Modified"
  combiner     = "OR"

  conditions {
    display_name = "Organisation policy changed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.org_policy_change.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="critical",
                alert_title="GCP: Organisation Policy Modified",
                alert_description_template="GCP organisation policy was modified or deleted.",
                investigation_steps=[
                    "Review which organisation policy was changed",
                    "Identify the principal making the change",
                    "Assess security impact of policy modification",
                    "Check if policy relaxation enables attacks",
                    "Review recent resource creation activity",
                ],
                containment_actions=[
                    "Restore original organisation policies",
                    "Restrict orgpolicy permissions to minimal principals",
                    "Enable organisation policy constraints on policies",
                    "Review and audit all organisation-level changes",
                    "Implement preventative controls via locked policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised policy management processes",
            detection_coverage="90% - catches organisation policy API calls",
            evasion_considerations="Attacker may use compromised admin account with policy permissions",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1666-aws-leave-org",
        "t1666-gcp-org-policy",
        "t1666-aws-move-account",
        "t1666-gcp-project-move",
        "t1666-aws-create-account",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+20% improvement for Defence Evasion tactic",
)
