"""
T1556.009 - Modify Authentication Process: Conditional Access Policies

Adversaries disable or modify conditional access policies to maintain persistent
access to compromised accounts by bypassing MFA, IP restrictions, and device controls.
Used by Scattered Spider, Storm-0501.
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
    technique_id="T1556.009",
    technique_name="Modify Authentication Process: Conditional Access Policies",
    tactic_ids=["TA0003", "TA0006"],  # Persistence, Credential Access
    mitre_url="https://attack.mitre.org/techniques/T1556/009/",
    threat_context=ThreatContext(
        description=(
            "Adversaries disable or modify conditional access policies to maintain "
            "persistent access to compromised accounts. These policies enforce additional "
            "verification layers including IP allowlisting, device enrolment status, MFA "
            "requirements, and risk-based metrics. By adding trusted IP ranges, removing "
            "MFA requirements, or allowing additional unused/unsupported cloud regions, "
            "attackers bypass defensive controls and ensure continued account access."
        ),
        attacker_goal="Maintain persistent access by weakening or disabling conditional access controls",
        why_technique=[
            "Bypasses MFA and device compliance requirements",
            "Enables access from unauthorised locations",
            "Difficult to detect without policy auditing",
            "Allows access from previously blocked regions",
            "Maintains persistence after initial compromise",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "High severity as it enables persistent access and bypasses critical "
            "authentication controls. Difficult to detect and enables long-term "
            "unauthorised access to cloud environments."
        ),
        business_impact=[
            "Persistent unauthorised access",
            "Bypass of MFA and security controls",
            "Regulatory compliance violations",
            "Long-term data exfiltration risk",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1098", "T1098.001", "T1098.003"],
        often_follows=["T1078.004", "T1110", "T1621"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1556.009-aws-iam-policy",
            name="AWS IAM Policy Condition Modifications",
            description="Detect modifications to IAM policy conditions that control access based on IP, region, or MFA.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.policyArn, eventName
| filter eventName in ["PutUserPolicy", "PutGroupPolicy", "PutRolePolicy", "CreatePolicy", "CreatePolicyVersion"]
| filter requestParameters.policyDocument like /Condition|IpAddress|MultiFactorAuthPresent|aws:RequestedRegion/
| stats count(*) as modifications by userIdentity.principalId, eventName, bin(1h)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM policy condition modifications that may weaken access controls

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: iam-policy-condition-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for IAM policy modifications
  IAMPolicyConditionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "PutUserPolicy") || ($.eventName = "PutGroupPolicy") || ($.eventName = "PutRolePolicy") || ($.eventName = "CreatePolicy") || ($.eventName = "CreatePolicyVersion") }'
      MetricTransformations:
        - MetricName: IAMPolicyConditionChanges
          MetricNamespace: Security/IAM
          MetricValue: "1"

  # Alarm for policy modifications
  IAMPolicyConditionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: IAMPolicyConditionModifications
      AlarmDescription: Alert on IAM policy condition modifications
      MetricName: IAMPolicyConditionChanges
      Namespace: Security/IAM
      Statistic: Sum
      Period: 300
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]
      TreatMissingData: notBreaching""",
                terraform_template="""# Detect IAM policy condition modifications in AWS

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "iam-policy-condition-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for IAM policy modifications
resource "aws_cloudwatch_log_metric_filter" "iam_policy_conditions" {
  name           = "iam-policy-condition-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"PutUserPolicy\") || ($.eventName = \"PutGroupPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"CreatePolicyVersion\") }"

  metric_transformation {
    name      = "IAMPolicyConditionChanges"
    namespace = "Security/IAM"
    value     = "1"
  }
}

# Alarm for policy modifications
resource "aws_cloudwatch_metric_alarm" "iam_policy_modifications" {
  alarm_name          = "IAMPolicyConditionModifications"
  alarm_description   = "Alert on IAM policy condition modifications"
  metric_name         = "IAMPolicyConditionChanges"
  namespace           = "Security/IAM"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="IAM Policy Condition Modification Detected",
                alert_description_template="IAM policy condition modified by {principalId} - review for weakened access controls.",
                investigation_steps=[
                    "Review the policy document changes in CloudTrail",
                    "Check if MFA or IP conditions were removed",
                    "Verify the identity making the changes",
                    "Check for unusual source IP or region",
                    "Review other recent IAM changes by the same principal",
                    "Validate if changes align with approved change requests",
                ],
                containment_actions=[
                    "Revert unauthorised policy changes immediately",
                    "Rotate credentials for the compromised account",
                    "Enable MFA if not already enforced",
                    "Review and restrict IAM policy modification permissions",
                    "Implement SCPs to prevent condition removal",
                    "Review all recent authentication attempts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate policy updates occur during security hardening and operational changes",
            detection_coverage="70% - detects policy modifications but requires manual review of changes",
            evasion_considerations="Attackers may make gradual changes or use less obvious policy weakening",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with log delivery to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1556.009-aws-scp-bypass",
            name="AWS Service Control Policy Modifications",
            description="Detect changes to SCPs that enforce conditional access requirements at the organisation level.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.organizations"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["UpdatePolicy", "DetachPolicy", "DeletePolicy"]
                    },
                },
                terraform_template="""# Detect AWS Organisations SCP modifications

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "scp-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for SCP modifications
resource "aws_cloudwatch_event_rule" "scp_changes" {
  name        = "scp-policy-modifications"
  description = "Detect Service Control Policy modifications"

  event_pattern = jsonencode({
    source      = ["aws.organizations"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["UpdatePolicy", "DetachPolicy", "DeletePolicy"]
    }
  })
}

# EventBridge target to SNS
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.scp_changes.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn
}

# SNS topic policy to allow EventBridge
resource "aws_sns_topic_policy" "default" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}""",
                alert_severity="critical",
                alert_title="Service Control Policy Modification Detected",
                alert_description_template="SCP modified or detached - potential weakening of organisation-wide security controls.",
                investigation_steps=[
                    "Review the SCP changes in AWS Organisations console",
                    "Identify what controls were removed or weakened",
                    "Verify the identity and source of the change",
                    "Check for other suspicious Organisations API calls",
                    "Review affected accounts and OUs",
                    "Validate against approved change management",
                ],
                containment_actions=[
                    "Immediately revert unauthorised SCP changes",
                    "Re-attach detached SCPs",
                    "Rotate credentials for the management account",
                    "Review and restrict Organisations permissions",
                    "Enable MFA for management account access",
                    "Implement approval workflows for SCP changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="SCP changes are infrequent and should be well-documented",
            detection_coverage="90% - highly reliable for detecting SCP modifications",
            evasion_considerations="Requires access to management account, making it harder to evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "AWS Organisations enabled",
                "CloudTrail in management account",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1556.009-gcp-iam-conditions",
            name="GCP IAM Policy Condition Modifications",
            description="Detect modifications to GCP IAM policy conditions that control access based on IP, device, or context.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"SetIamPolicy|UpdateIamPolicy"
protoPayload.request.policy.bindings.condition!=""''',
                gcp_terraform_template="""# GCP: Detect IAM policy condition modifications

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Log-based metric for IAM condition changes
resource "google_logging_metric" "iam_condition_changes" {
  name   = "iam-condition-modifications"
  filter = <<-EOT
    protoPayload.methodName=~"SetIamPolicy|UpdateIamPolicy"
    protoPayload.request.policy.bindings.condition!=""
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal making the change"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }

  project = var.project_id
}

# Alert policy for IAM condition modifications
resource "google_monitoring_alert_policy" "iam_condition_alerts" {
  display_name = "IAM Condition Policy Modifications"
  combiner     = "OR"

  conditions {
    display_name = "IAM conditions modified"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iam_condition_changes.name}\" resource.type=\"global\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 1

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "604800s"  # 7 days
  }

  project = var.project_id
}""",
                alert_severity="high",
                alert_title="GCP IAM Condition Modification Detected",
                alert_description_template="IAM policy condition modified in GCP - review for weakened access controls.",
                investigation_steps=[
                    "Review the IAM policy changes in Cloud Logging",
                    "Check which conditions were added, modified, or removed",
                    "Verify the principal making the changes",
                    "Check for IP address or device trust condition removals",
                    "Review other IAM changes by the same principal",
                    "Validate against approved change requests",
                ],
                containment_actions=[
                    "Revert unauthorised IAM policy changes",
                    "Rotate credentials for compromised accounts",
                    "Review and restrict IAM admin roles",
                    "Implement organisation policies for IAM constraints",
                    "Enable context-aware access policies",
                    "Review recent authentication logs",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="IAM policy updates occur during legitimate security configuration changes",
            detection_coverage="70% - detects condition modifications but requires review of actual changes",
            evasion_considerations="Attackers may make subtle changes or use less obvious weakening methods",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Logging enabled",
                "Admin Activity audit logs enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1556.009-gcp-context-aware",
            name="GCP Context-Aware Access Policy Changes",
            description="Detect modifications to GCP Context-Aware Access policies that control access based on user context.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="access_policy"
protoPayload.methodName=~"CreateAccessLevel|UpdateAccessLevel|DeleteAccessLevel|CreateServicePerimeter|UpdateServicePerimeter"''',
                gcp_terraform_template="""# GCP: Detect Context-Aware Access policy modifications

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "CAA Policy Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Log-based metric for CAA policy changes
resource "google_logging_metric" "caa_policy_changes" {
  name   = "context-aware-access-modifications"
  filter = <<-EOT
    resource.type="access_policy"
    protoPayload.methodName=~"CreateAccessLevel|UpdateAccessLevel|DeleteAccessLevel|CreateServicePerimeter|UpdateServicePerimeter"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "method"
      value_type  = "STRING"
      description = "API method called"
    }
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal making the change"
    }
  }

  label_extractors = {
    "method"    = "EXTRACT(protoPayload.methodName)"
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }

  project = var.project_id
}

# Alert policy for CAA modifications
resource "google_monitoring_alert_policy" "caa_modifications" {
  display_name = "Context-Aware Access Policy Changes"
  combiner     = "OR"

  conditions {
    display_name = "CAA policies modified"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.caa_policy_changes.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_DELTA"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "604800s"
  }

  project = var.project_id
}""",
                alert_severity="critical",
                alert_title="GCP Context-Aware Access Policy Modified",
                alert_description_template="Context-Aware Access policy or service perimeter modified - potential security control bypass.",
                investigation_steps=[
                    "Review the access level or service perimeter changes",
                    "Check if IP ranges or device requirements were relaxed",
                    "Verify the principal making the modifications",
                    "Review affected resources within service perimeters",
                    "Check for deletion of access levels",
                    "Validate against approved security changes",
                ],
                containment_actions=[
                    "Immediately revert unauthorised CAA changes",
                    "Restore deleted access levels or perimeters",
                    "Rotate credentials for Access Context Manager admins",
                    "Review and restrict Access Context Manager permissions",
                    "Re-enforce strict IP and device policies",
                    "Audit all resources within affected perimeters",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="CAA policy changes are infrequent and typically well-documented",
            detection_coverage="90% - highly reliable for detecting CAA policy modifications",
            evasion_considerations="Requires elevated privileges, making it harder to execute undetected",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Context-Aware Access configured",
                "Admin Activity audit logs enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1556.009-aws-scp-bypass",
        "t1556.009-gcp-context-aware",
        "t1556.009-aws-iam-policy",
        "t1556.009-gcp-iam-conditions",
    ],
    total_effort_hours=2.5,
    coverage_improvement="+25% improvement for Persistence and Credential Access tactics",
)
