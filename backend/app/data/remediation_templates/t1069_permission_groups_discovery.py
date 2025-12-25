"""
T1069 - Permission Groups Discovery

Adversaries attempt to discover group and permission settings to identify
available user accounts, group memberships, and elevated permissions within
a compromised environment.
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
    technique_id="T1069",
    technique_name="Permission Groups Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1069/",
    threat_context=ThreatContext(
        description=(
            "Adversaries attempt to discover group and permission settings to identify "
            "available user accounts, group memberships, and elevated permissions within "
            "a compromised environment. This reconnaissance helps inform subsequent targeting, "
            "lateral movement, and privilege escalation activities. Adversaries may enumerate "
            "local groups, domain groups, and cloud groups to understand privilege structures "
            "and identify potential escalation paths."
        ),
        attacker_goal="Map permission structures and identify high-privilege groups for targeting",
        why_technique=[
            "Identifies high-privilege groups and accounts",
            "Reveals group membership patterns",
            "Maps administrative boundaries",
            "Enables targeted privilege escalation",
            "Informs lateral movement planning",
            "Discovers role trust relationships",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=5,
        severity_reasoning=(
            "Discovery technique with moderate direct impact but critical for understanding "
            "attack progression. Frequently observed in post-compromise reconnaissance and "
            "almost always precedes privilege escalation or lateral movement. The increasing "
            "trend correlates with cloud adoption where group enumeration is often easier "
            "and more valuable to attackers."
        ),
        business_impact=[
            "Reveals organisational privilege structures",
            "Enables targeted attacks on high-value groups",
            "Indicates active reconnaissance activity",
            "Provides early warning opportunity",
            "Precursor to privilege escalation",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1098", "T1098.003", "T1078.004", "T1069.003"],
        often_follows=["T1087", "T1087.004", "T1078"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - IAM Group/Role Enumeration
        DetectionStrategy(
            strategy_id="t1069-aws-groupenum",
            name="AWS IAM Group/Role Enumeration Detection",
            description=(
                "Detect bulk enumeration of IAM groups, roles, and permission sets. "
                "Monitors for high volumes of IAM listing operations that indicate "
                "reconnaissance activity."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, userAgent
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["ListGroups", "ListRoles", "ListUsers", "ListGroupsForUser",
    "ListAttachedGroupPolicies", "ListRolePolicies", "ListUserPolicies",
    "GetGroupPolicy", "GetRolePolicy", "GetUserPolicy", "ListPolicies"]
| stats count(*) as enum_count by userIdentity.arn, sourceIPAddress, bin(1h)
| filter enum_count > 20
| sort enum_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM permission groups discovery attempts

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  GroupDiscoveryAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      DisplayName: IAM Group Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for group enumeration
  GroupEnumerationMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "iam.amazonaws.com" && ($.eventName = "ListGroups" || $.eventName = "ListRoles" || $.eventName = "ListUsers" || $.eventName = "ListGroupsForUser" || $.eventName = "ListAttachedGroupPolicies" || $.eventName = "GetGroupPolicy") }'
      MetricTransformations:
        - MetricName: IAMGroupEnumeration
          MetricNamespace: Security/Discovery
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: CloudWatch alarm for high-volume enumeration
  GroupEnumerationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: IAM-Group-Enumeration-Detected
      AlarmDescription: High volume of IAM group/role enumeration detected
      MetricName: IAMGroupEnumeration
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 3600
      Threshold: 30
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref GroupDiscoveryAlertTopic

Outputs:
  AlarmArn:
    Description: CloudWatch Alarm ARN
    Value: !GetAtt GroupEnumerationAlarm.Arn
  TopicArn:
    Description: SNS Topic ARN
    Value: !Ref GroupDiscoveryAlertTopic""",
                terraform_template="""# AWS: Detect IAM permission groups discovery

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "group_discovery_alerts" {
  name         = "iam-group-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "IAM Group Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.group_discovery_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for group enumeration
resource "aws_cloudwatch_log_metric_filter" "group_enumeration" {
  name           = "iam-group-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"iam.amazonaws.com\" && ($.eventName = \"ListGroups\" || $.eventName = \"ListRoles\" || $.eventName = \"ListUsers\" || $.eventName = \"ListGroupsForUser\" || $.eventName = \"ListAttachedGroupPolicies\" || $.eventName = \"GetGroupPolicy\") }"

  metric_transformation {
    name      = "IAMGroupEnumeration"
    namespace = "Security/Discovery"
    value     = "1"
    default_value = 0
  }
}

# Step 3: CloudWatch alarm for high-volume enumeration
resource "aws_cloudwatch_metric_alarm" "group_enumeration" {
  alarm_name          = "IAM-Group-Enumeration-Detected"
  alarm_description   = "High volume of IAM group/role enumeration detected"
  metric_name         = "IAMGroupEnumeration"
  namespace           = "Security/Discovery"
  statistic           = "Sum"
  period              = 3600
  threshold           = 30
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.group_discovery_alerts.arn]

  tags = {
    MitreTechnique = "T1069"
    Severity       = "Medium"
  }
}

output "alarm_arn" {
  description = "CloudWatch Alarm ARN"
  value       = aws_cloudwatch_metric_alarm.group_enumeration.arn
}

output "topic_arn" {
  description = "SNS Topic ARN"
  value       = aws_sns_topic.group_discovery_alerts.arn
}""",
                alert_severity="medium",
                alert_title="IAM Permission Groups Discovery Detected",
                alert_description_template=(
                    "High volume of IAM group/role enumeration operations detected from "
                    "{userIdentity.arn} ({sourceIPAddress}). This may indicate reconnaissance "
                    "activity to identify privilege escalation paths."
                ),
                investigation_steps=[
                    "Identify the principal performing the enumeration (check userIdentity.arn)",
                    "Determine if this is authorised security scanning or legitimate CSPM activity",
                    "Review the source IP address and user agent for suspicious patterns",
                    "Check what specific groups and roles were enumerated",
                    "Look for follow-on privilege escalation attempts (T1098, T1098.003)",
                    "Review CloudTrail logs for other suspicious activities from the same principal",
                    "Verify whether the principal has legitimate need for broad IAM visibility",
                ],
                containment_actions=[
                    "Review and restrict the principal's IAM permissions if unauthorised",
                    "Enable CloudTrail event notifications for sensitive IAM actions",
                    "Monitor for privilege escalation attempts",
                    "Consider implementing IAM Access Analyzer",
                    "Audit group memberships and role assignments",
                    "Apply least privilege principles to IAM read permissions",
                    "Document legitimate security scanning activity for future reference",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist known security tools (AWS Config, Security Hub, CSPM solutions). "
                "Adjust threshold based on environment size and legitimate administrative activity. "
                "Consider time-of-day patterns for scheduled security scans."
            ),
            detection_coverage="80% - Catches bulk enumeration but may miss slow, methodical reconnaissance",
            evasion_considerations=(
                "Attackers can evade by slowing down enumeration to stay below thresholds. "
                "Consider implementing time-window analysis. Attackers may also use legitimate "
                "security tools or spread enumeration across multiple compromised accounts."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-15 (depending on log volume)",
            prerequisites=[
                "CloudTrail enabled with management events",
                "CloudTrail logs delivered to CloudWatch Logs",
                "SNS topic and email subscription configured",
            ],
        ),
        # Strategy 2: GCP - IAM Group/Role Enumeration
        DetectionStrategy(
            strategy_id="t1069-gcp-groupenum",
            name="GCP IAM Group/Role Enumeration Detection",
            description=(
                "Detect enumeration of GCP groups, role bindings, and IAM policies. "
                "Monitors for high volumes of IAM listing operations across projects and organisations."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="audited_resource"
protoPayload.methodName=~"(ListGroups|GetGroup|ListMembers|GetIamPolicy|ListRoles|GetRole|TestIamPermissions|QueryGrantableRoles)"
protoPayload.serviceName="iam.googleapis.com" OR protoPayload.serviceName="cloudresourcemanager.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect IAM permission groups discovery

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "security_email" {
  project      = var.project_id
  display_name = "Security Alerts Email"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }

  user_labels = {
    purpose = "security"
  }
}

# Step 2: Log-based metric for group enumeration
resource "google_logging_metric" "iam_group_enumeration" {
  project = var.project_id
  name    = "iam-group-enumeration"

  filter = <<-EOT
    resource.type="audited_resource"
    protoPayload.methodName=~"(ListGroups|GetGroup|ListMembers|GetIamPolicy|ListRoles|GetRole|TestIamPermissions|QueryGrantableRoles)"
    (protoPayload.serviceName="iam.googleapis.com" OR protoPayload.serviceName="cloudresourcemanager.googleapis.com")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal performing enumeration"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for high-volume enumeration
resource "google_monitoring_alert_policy" "iam_group_enumeration" {
  project      = var.project_id
  display_name = "IAM Permission Groups Discovery Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume of IAM group enumeration"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iam_group_enumeration.name}\" resource.type=\"audited_resource\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_email.id]

  alert_strategy {
    auto_close = "604800s"  # 7 days
  }

  documentation {
    content   = "High volume of IAM group/role enumeration detected. This may indicate reconnaissance activity (MITRE T1069)."
    mime_type = "text/markdown"
  }

  user_labels = {
    mitre_technique = "t1069"
    severity        = "medium"
  }
}

output "metric_name" {
  description = "Log-based metric name"
  value       = google_logging_metric.iam_group_enumeration.name
}

output "alert_policy_name" {
  description = "Alert policy name"
  value       = google_monitoring_alert_policy.iam_group_enumeration.name
}""",
                alert_severity="medium",
                alert_title="GCP: IAM Permission Groups Discovery Detected",
                alert_description_template=(
                    "High volume of IAM group/role enumeration operations detected. "
                    "This may indicate reconnaissance activity to map permission structures."
                ),
                investigation_steps=[
                    "Identify the principal performing the enumeration (check principalEmail)",
                    "Determine if this is authorised security scanning activity",
                    "Review the source IP address and user agent",
                    "Check what specific resources were queried (projects, folders, organisation)",
                    "Look for follow-on privilege escalation or role binding modifications",
                    "Review Cloud Audit Logs for other suspicious activities from the same principal",
                    "Verify whether the principal has legitimate need for broad IAM visibility",
                ],
                containment_actions=[
                    "Review and restrict the principal's IAM permissions if unauthorised",
                    "Monitor for IAM policy or role binding modifications",
                    "Audit group memberships and role assignments",
                    "Consider implementing IAM Conditions to restrict enumeration",
                    "Enable VPC Service Controls for additional protection",
                    "Apply least privilege principles to IAM read permissions",
                    "Document legitimate security scanning for future reference",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist known security tools and CSPM solutions. Adjust threshold based on "
                "organisation size and legitimate administrative patterns. Consider excluding "
                "scheduled security scans and compliance checks."
            ),
            detection_coverage="75% - Catches bulk enumeration but may miss slow reconnaissance",
            evasion_considerations=(
                "Attackers can evade by slowing enumeration rate or spreading across multiple "
                "compromised accounts. Consider implementing anomaly detection for baseline deviation. "
                "Attackers may also use legitimate GCP tools or services."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20 (depending on log volume)",
            prerequisites=[
                "Cloud Audit Logs enabled (Admin Read, Data Read)",
                "Cloud Logging API enabled",
                "Cloud Monitoring API enabled",
                "Appropriate IAM permissions for log-based metrics",
            ],
        ),
        # Strategy 3: AWS - Cross-Account Group Enumeration
        DetectionStrategy(
            strategy_id="t1069-aws-crossaccount",
            name="Cross-Account Permission Enumeration Detection",
            description=(
                "Detect attempts to enumerate groups and roles across multiple AWS accounts, "
                "which may indicate lateral reconnaissance in multi-account environments."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, recipientAccountId, sourceIPAddress
| filter eventSource = "sts.amazonaws.com"
| filter eventName = "AssumeRole"
| stats count(*) as assume_count by userIdentity.arn, bin(1h)
| filter assume_count > 10
| sort assume_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect cross-account permission enumeration

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for cross-account alerts
  CrossAccountAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Cross-Account Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for cross-account enumeration
  CrossAccountEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "sts.amazonaws.com" && $.eventName = "AssumeRole" }'
      MetricTransformations:
        - MetricName: CrossAccountAssumeRole
          MetricNamespace: Security/Discovery
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alarm for high-volume cross-account activity
  CrossAccountEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Cross-Account-Permission-Enumeration
      AlarmDescription: High volume of cross-account role assumption detected
      MetricName: CrossAccountAssumeRole
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 3600
      Threshold: 15
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions:
        - !Ref CrossAccountAlertTopic

Outputs:
  AlarmArn:
    Value: !GetAtt CrossAccountEnumAlarm.Arn
  TopicArn:
    Value: !Ref CrossAccountAlertTopic""",
                terraform_template="""# AWS: Detect cross-account permission enumeration

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for cross-account alerts
resource "aws_sns_topic" "cross_account_alerts" {
  name         = "cross-account-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Cross-Account Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.cross_account_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for cross-account enumeration
resource "aws_cloudwatch_log_metric_filter" "cross_account_enum" {
  name           = "cross-account-permission-enum"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"sts.amazonaws.com\" && $.eventName = \"AssumeRole\" }"

  metric_transformation {
    name      = "CrossAccountAssumeRole"
    namespace = "Security/Discovery"
    value     = "1"
    default_value = 0
  }
}

# Step 3: Alarm for high-volume cross-account activity
resource "aws_cloudwatch_metric_alarm" "cross_account_enum" {
  alarm_name          = "Cross-Account-Permission-Enumeration"
  alarm_description   = "High volume of cross-account role assumption detected"
  metric_name         = "CrossAccountAssumeRole"
  namespace           = "Security/Discovery"
  statistic           = "Sum"
  period              = 3600
  threshold           = 15
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.cross_account_alerts.arn]

  tags = {
    MitreTechnique = "T1069"
    Severity       = "High"
  }
}

output "alarm_arn" {
  value = aws_cloudwatch_metric_alarm.cross_account_enum.arn
}

output "topic_arn" {
  value = aws_sns_topic.cross_account_alerts.arn
}""",
                alert_severity="high",
                alert_title="Cross-Account Permission Enumeration Detected",
                alert_description_template=(
                    "High volume of cross-account role assumption detected from {userIdentity.arn}. "
                    "This may indicate lateral reconnaissance across AWS accounts."
                ),
                investigation_steps=[
                    "Identify which roles were assumed and in which accounts",
                    "Check if this is legitimate cross-account administrative activity",
                    "Review the trust policies of the assumed roles",
                    "Look for subsequent enumeration or privilege escalation in target accounts",
                    "Check for data exfiltration attempts after role assumption",
                    "Verify the source principal has legitimate need for cross-account access",
                ],
                containment_actions=[
                    "Review and restrict cross-account trust relationships",
                    "Implement external ID requirements for cross-account roles",
                    "Add condition keys to role trust policies (IP, MFA)",
                    "Monitor assumed roles for suspicious activity",
                    "Consider implementing AWS Control Tower guardrails",
                    "Audit and document all legitimate cross-account access patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Whitelist legitimate cross-account automation and management tools. "
                "Adjust threshold based on organisation's multi-account architecture."
            ),
            detection_coverage="85% - Strong coverage for cross-account reconnaissance",
            evasion_considerations=(
                "Limited evasion options for cross-account access. Attackers would need to "
                "slow down significantly or use multiple compromised identities."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail enabled across all accounts",
                "Multi-account CloudTrail aggregation configured",
                "STS events logged in CloudWatch",
            ],
        ),
    ],
    recommended_order=[
        "t1069-aws-groupenum",
        "t1069-gcp-groupenum",
        "t1069-aws-crossaccount",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+15% improvement for Discovery tactic coverage",
)
