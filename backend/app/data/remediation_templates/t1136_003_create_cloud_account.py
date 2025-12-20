"""
T1136.003 - Create Account: Cloud Account

Adversaries create new cloud accounts (IAM users, service accounts) to
maintain persistent access and avoid detection on existing accounts.
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
    technique_id="T1136.003",
    technique_name="Create Account: Cloud Account",
    tactic_ids=["TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1136/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries create new IAM users, service accounts, or federated identities "
            "to maintain persistent access. Shadow admin accounts often go unnoticed "
            "and provide reliable backdoor access."
        ),
        attacker_goal="Create backdoor accounts for persistent access",
        why_technique=[
            "New accounts avoid detection on compromised users",
            "Shadow admins persist after initial remediation",
            "Service accounts blend with automation",
            "Federated users may bypass MFA",
            "Multiple accounts complicate forensics",
        ],
        known_threat_actors=["APT29", "Scattered Spider", "Lapsus$"],
        recent_campaigns=[
            Campaign(
                name="Shadow Admin Accounts",
                year=2024,
                description="Attackers created hidden admin accounts during compromises for persistent access",
                reference_url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a",
            ),
            Campaign(
                name="Service Account Backdoors",
                year=2024,
                description="Attackers created service accounts named similarly to legitimate automation",
                reference_url="https://unit42.paloaltonetworks.com/2025-cloud-security-alert-trends/",
            ),
        ],
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Backdoor accounts provide reliable persistent access. Shadow admins "
            "are often missed during incident remediation. New accounts can be "
            "difficult to distinguish from legitimate ones."
        ),
        business_impact=[
            "Persistent backdoor access",
            "Difficult incident remediation",
            "Ongoing compromise risk",
            "Compliance violations",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1098.001", "T1530"],
        often_follows=["T1078.004", "T1098.003"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - IAM User Creation
        DetectionStrategy(
            strategy_id="t1136003-aws-createuser",
            name="IAM User Creation Detection",
            description="Detect when new IAM users are created.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["CreateUser"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM user creation

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

  # Step 2: EventBridge for user creation
  UserCreateRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [CreateUser]
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
                terraform_template="""# Detect IAM user creation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "iam-user-creation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "user_create" {
  name = "iam-user-creation"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["CreateUser"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.user_create.name
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
                alert_title="IAM User Created",
                alert_description_template="New IAM user {userName} was created.",
                investigation_steps=[
                    "Verify the user creation was authorised",
                    "Check who created the user",
                    "Review permissions assigned to new user",
                    "Check for access key creation",
                ],
                containment_actions=[
                    "Delete unauthorised users",
                    "Review and remove admin permissions",
                    "Audit the creator's activity",
                    "Review all recent user creations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist HR/provisioning automation",
            detection_coverage="95% - catches all CreateUser calls",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - IAM User with Admin
        DetectionStrategy(
            strategy_id="t1136003-aws-adminuser",
            name="Admin User Creation Detection",
            description="Detect new IAM users with admin privileges.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.userName, userIdentity.arn
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["CreateUser", "AttachUserPolicy", "PutUserPolicy"]
| filter requestParameters.policyArn like /AdministratorAccess/ or requestParameters.policyDocument like /"*"/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect admin user creation

Parameters:
  CloudTrailLogGroup:
    Type: String
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

  # Step 2: Metric filter for admin policy attachments
  AdminUserFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "AttachUserPolicy" && $.requestParameters.policyArn = "*AdministratorAccess*" }'
      MetricTransformations:
        - MetricName: AdminUserCreated
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  AdminUserAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: AdminUserCreated
      MetricName: AdminUserCreated
      Namespace: Security
      Statistic: Sum
      Period: 60
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect admin user creation

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "admin-user-creation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "admin_user" {
  name           = "admin-user-created"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"AttachUserPolicy\" && $.requestParameters.policyArn = \"*AdministratorAccess*\" }"

  metric_transformation {
    name      = "AdminUserCreated"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "admin_user" {
  alarm_name          = "AdminUserCreated"
  metric_name         = "AdminUserCreated"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 60
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Admin User Created",
                alert_description_template="User {userName} was granted administrator access.",
                investigation_steps=[
                    "Verify admin access was authorised",
                    "Check who granted admin permissions",
                    "Review user's immediate activity",
                    "Check for data access patterns",
                ],
                containment_actions=[
                    "Remove admin permissions immediately",
                    "Disable or delete the user",
                    "Audit all admin users",
                    "Review creator's permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised admin provisioning",
            detection_coverage="90% - catches admin policy attachments",
            evasion_considerations="Attacker may use custom policies",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 3: GCP - Service Account Creation
        DetectionStrategy(
            strategy_id="t1136003-gcp-serviceaccount",
            name="GCP Service Account Creation",
            description="Detect when new service accounts are created.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.iam.admin.v1.CreateServiceAccount"''',
                gcp_terraform_template="""# GCP: Detect service account creation

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
resource "google_logging_metric" "sa_creation" {
  name   = "service-account-creation"
  filter = <<-EOT
    protoPayload.methodName="google.iam.admin.v1.CreateServiceAccount"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "sa_creation" {
  display_name = "Service Account Created"
  combiner     = "OR"

  conditions {
    display_name = "SA creation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_creation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Service Account Created",
                alert_description_template="New service account was created.",
                investigation_steps=[
                    "Verify service account creation was authorised",
                    "Check who created the service account",
                    "Review permissions assigned",
                    "Check for key creation",
                ],
                containment_actions=[
                    "Delete unauthorised service accounts",
                    "Remove assigned permissions",
                    "Audit the creator's activity",
                    "Review all recent SA creations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD and automation",
            detection_coverage="95% - catches all SA creation",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - Federated Identity Creation
        DetectionStrategy(
            strategy_id="t1136003-gcp-federated",
            name="GCP Federated Identity Detection",
            description="Detect new workload identity federation setups.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"CreateWorkloadIdentityPool|CreateWorkloadIdentityPoolProvider"''',
                gcp_terraform_template="""# GCP: Detect federated identity creation

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
resource "google_logging_metric" "wif_creation" {
  name   = "workload-identity-federation"
  filter = <<-EOT
    protoPayload.methodName=~"CreateWorkloadIdentityPool|CreateWorkloadIdentityPoolProvider"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "wif_creation" {
  display_name = "Workload Identity Federation Created"
  combiner     = "OR"

  conditions {
    display_name = "WIF pool or provider created"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.wif_creation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Federated Identity Configured",
                alert_description_template="Workload Identity Federation was configured.",
                investigation_steps=[
                    "Review the federation configuration",
                    "Check which external provider was added",
                    "Verify the change was authorised",
                    "Review attribute mappings",
                ],
                containment_actions=[
                    "Delete unauthorised WIF pools",
                    "Review all federated identities",
                    "Enable organisation policies",
                    "Audit federation activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="WIF creation is relatively rare",
            detection_coverage="95% - catches all WIF creation",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1136003-aws-createuser",
        "t1136003-gcp-serviceaccount",
        "t1136003-aws-adminuser",
        "t1136003-gcp-federated",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+18% improvement for Persistence tactic",
)
