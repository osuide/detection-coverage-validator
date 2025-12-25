"""
T1069.003 - Permission Groups Discovery: Cloud Groups

Adversaries enumerate IAM groups, roles, and permission sets to
understand privilege structures and identify escalation paths.
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
    technique_id="T1069.003",
    technique_name="Permission Groups Discovery: Cloud Groups",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1069/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate IAM groups, roles, and permission sets to "
            "understand privilege structures. This helps identify which groups "
            "have elevated privileges and potential escalation paths."
        ),
        attacker_goal="Map group/role structures to identify privilege escalation paths",
        why_technique=[
            "Reveals high-privilege groups",
            "Identifies group membership patterns",
            "Shows role trust relationships",
            "Enables targeted privilege escalation",
            "Maps administrative boundaries",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "Discovery technique with low direct impact but important for "
            "understanding attack progression. Often precedes privilege escalation."
        ),
        business_impact=[
            "Reveals privileged group structures",
            "Enables targeted attacks on high-value groups",
            "Indicates reconnaissance activity",
            "Early warning opportunity",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1098.003", "T1078.004"],
        often_follows=["T1087.004", "T1078.004"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Group/Role Enumeration
        DetectionStrategy(
            strategy_id="t1069003-aws-groupenum",
            name="IAM Group/Role Enumeration Detection",
            description="Detect bulk IAM group and role listing.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["ListGroups", "ListRoles", "ListGroupsForUser", "ListAttachedGroupPolicies", "ListRolePolicies"]
| stats count(*) as enum_count by userIdentity.arn, bin(1h)
| filter enum_count > 15
| sort enum_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM group enumeration

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
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter
  GroupEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "iam.amazonaws.com" && ($.eventName = "ListGroups" || $.eventName = "ListRoles" || $.eventName = "ListGroupsForUser") }'
      MetricTransformations:
        - MetricName: GroupEnumeration
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  GroupEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: GroupEnumeration
      MetricName: GroupEnumeration
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 25
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect IAM group enumeration

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "group-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "group_enum" {
  name           = "group-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"iam.amazonaws.com\" && ($.eventName = \"ListGroups\" || $.eventName = \"ListRoles\") }"

  metric_transformation {
    name      = "GroupEnumeration"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "group_enum" {
  alarm_name          = "GroupEnumeration"
  metric_name         = "GroupEnumeration"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 25
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="IAM Group/Role Enumeration",
                alert_description_template="High volume of IAM group/role queries from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who is enumerating groups",
                    "Check if this is authorised security scanning",
                    "Review what group data was accessed",
                    "Look for follow-on privilege escalation",
                ],
                containment_actions=[
                    "Review user's permissions",
                    "Monitor for privilege escalation",
                    "Consider limiting IAM read access",
                    "Audit group memberships",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CSPM and security tools",
            detection_coverage="80% - volume-based",
            evasion_considerations="Slow enumeration may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 2: GCP - IAM Group Enumeration
        DetectionStrategy(
            strategy_id="t1069003-gcp-groupenum",
            name="GCP IAM Group Enumeration Detection",
            description="Detect enumeration of GCP groups and role bindings.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(ListGroups|GetGroup|ListMembers|GetIamPolicy)"''',
                gcp_terraform_template="""# GCP: Detect IAM group enumeration

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
resource "google_logging_metric" "group_enum" {
  name   = "group-enumeration"
  filter = <<-EOT
    protoPayload.methodName=~"(ListGroups|GetGroup|ListMembers|GetIamPolicy)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "group_enum" {
  display_name = "IAM Group Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "High volume group queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.group_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: IAM Group Enumeration",
                alert_description_template="High volume of IAM group queries detected.",
                investigation_steps=[
                    "Identify the principal enumerating groups",
                    "Check if authorised security scanning",
                    "Review what group data was accessed",
                    "Look for privilege escalation attempts",
                ],
                containment_actions=[
                    "Review principal's permissions",
                    "Monitor for role changes",
                    "Audit group memberships",
                    "Consider IAM Conditions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist security tools",
            detection_coverage="75% - volume-based",
            evasion_considerations="Slow enumeration may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=["t1069003-aws-groupenum", "t1069003-gcp-groupenum"],
    total_effort_hours=2.0,
    coverage_improvement="+12% improvement for Discovery tactic",
)
