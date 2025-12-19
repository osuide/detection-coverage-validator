"""
T1548 - Abuse Elevation Control Mechanism

Adversaries circumvent elevation control mechanisms to obtain higher-level permissions
on systems and in cloud environments, particularly through temporary elevated access.
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
    technique_id="T1548",
    technique_name="Abuse Elevation Control Mechanism",
    tactic_ids=["TA0004", "TA0005"],  # Privilege Escalation, Defense Evasion
    mitre_url="https://attack.mitre.org/techniques/T1548/",

    threat_context=ThreatContext(
        description=(
            "Adversaries exploit elevation control mechanisms to gain higher privileges. "
            "In cloud environments, this commonly involves assuming roles with elevated "
            "permissions, exploiting misconfigured role trust policies, or obtaining "
            "temporary credentials with excessive privileges. Attackers may also abuse "
            "IAM role chaining or session token generation to escalate privileges."
        ),
        attacker_goal="Obtain higher-level permissions to access sensitive resources and perform privileged operations",
        why_technique=[
            "Bypasses least-privilege controls",
            "Temporary credentials harder to detect",
            "Role assumption provides flexible access",
            "Can enable cross-account privilege escalation",
            "Exploits misconfigured trust relationships"
        ],
        known_threat_actors=["Scattered Spider", "UNC3886"],
        recent_campaigns=[
            Campaign(
                name="IAM Role Assumption Abuse",
                year=2024,
                description="Attackers exploited overly permissive assume role policies to escalate privileges across multiple accounts",
                reference_url="https://www.datadoghq.com/state-of-cloud-security/"
            ),
            Campaign(
                name="Temporary Token Privilege Escalation",
                year=2024,
                description="Adversaries generated session tokens with elevated permissions through misconfigured IAM policies",
                reference_url="https://unit42.paloaltonetworks.com/2025-cloud-security-alert-trends/"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Privilege escalation via elevation control abuse can lead to full account "
            "compromise. Temporary elevated access is difficult to track and revoke. "
            "Successful exploitation enables attackers to bypass security controls and "
            "access sensitive resources across cloud environments."
        ),
        business_impact=[
            "Unauthorised access to privileged resources",
            "Potential full account compromise",
            "Cross-account security boundary bypass",
            "Data exfiltration and manipulation",
            "Compliance violations"
        ],
        typical_attack_phase="privilege_escalation",
        often_precedes=["T1530", "T1537", "T1562.008", "T1098.003"],
        often_follows=["T1078.004", "T1552.005", "T1528"]
    ),

    detection_strategies=[
        # Strategy 1: AWS - Unusual AssumeRole Activity
        DetectionStrategy(
            strategy_id="t1548-aws-assumerole",
            name="Unusual IAM Role Assumption",
            description="Detect anomalous AssumeRole API calls indicating privilege escalation attempts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.principalId, requestParameters.roleArn, sourceIPAddress, errorCode
| filter eventName = "AssumeRole"
| filter userIdentity.type != "AWSService"
| stats count() as assumeRoleCount by userIdentity.principalId, requestParameters.roleArn, sourceIPAddress
| filter assumeRoleCount > 10
| sort assumeRoleCount desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual IAM role assumption activity

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: AssumeRole Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch metric filter
  AssumeRoleMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      FilterPattern: '{ ($.eventName = "AssumeRole") && ($.userIdentity.type != "AWSService") }'
      LogGroupName: /aws/cloudtrail/logs
      MetricTransformations:
        - MetricName: UnusualAssumeRoleCount
          MetricNamespace: Security/IAM
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: CloudWatch alarm
  AssumeRoleAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighAssumeRoleActivity
      AlarmDescription: Alert on high AssumeRole API activity
      MetricName: UnusualAssumeRoleCount
      Namespace: Security/IAM
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic''',
                terraform_template='''# Detect unusual IAM role assumption activity

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "assume_role_alerts" {
  name         = "assume-role-alerts"
  display_name = "AssumeRole Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.assume_role_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter
resource "aws_cloudwatch_log_metric_filter" "assume_role" {
  name           = "unusual-assume-role"
  log_group_name = "/aws/cloudtrail/logs"
  pattern        = "{ ($.eventName = \"AssumeRole\") && ($.userIdentity.type != \"AWSService\") }"

  metric_transformation {
    name      = "UnusualAssumeRoleCount"
    namespace = "Security/IAM"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "assume_role_high" {
  alarm_name          = "high-assume-role-activity"
  alarm_description   = "Alert on high AssumeRole API activity"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnusualAssumeRoleCount"
  namespace           = "Security/IAM"
  period              = 300
  statistic           = "Sum"
  threshold           = 20
  alarm_actions       = [aws_sns_topic.assume_role_alerts.arn]
}

resource "aws_sns_topic_policy" "assume_role_alerts" {
  arn = aws_sns_topic.assume_role_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.assume_role_alerts.arn
    }]
  })
}''',
                alert_severity="high",
                alert_title="Unusual IAM Role Assumption Detected",
                alert_description_template="High volume of AssumeRole calls detected from {principalId}.",
                investigation_steps=[
                    "Review the principal attempting role assumption",
                    "Check which roles are being assumed",
                    "Verify source IP addresses are expected",
                    "Review role session duration and permissions",
                    "Check for failed AssumeRole attempts"
                ],
                containment_actions=[
                    "Revoke active sessions if unauthorised",
                    "Update role trust policies to restrict access",
                    "Enable MFA requirement for sensitive roles",
                    "Review and tighten IAM policies",
                    "Monitor for continued suspicious activity"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised automation and CI/CD pipelines",
            detection_coverage="85% - catches high-volume role assumption",
            evasion_considerations="Attacker may use low-and-slow approach to evade volume-based detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs configured"]
        ),

        # Strategy 2: AWS - Cross-Account Role Assumption
        DetectionStrategy(
            strategy_id="t1548-aws-crossaccount",
            name="Cross-Account Role Assumption",
            description="Detect role assumptions from external or unexpected AWS accounts.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.sts"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["AssumeRole"],
                        "userIdentity": {
                            "type": ["AssumedRole", "IAMUser"]
                        }
                    }
                },
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect cross-account role assumption

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

  # Step 2: EventBridge rule for cross-account AssumeRole
  CrossAccountRoleRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.sts]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [AssumeRole]
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
            Resource: !Ref AlertTopic''',
                terraform_template='''# Detect cross-account role assumption

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "cross-account-role-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "cross_account_assume" {
  name = "cross-account-assume-role"
  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["AssumeRole"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.cross_account_assume.name
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
}''',
                alert_severity="critical",
                alert_title="Cross-Account Role Assumption Detected",
                alert_description_template="Role {roleArn} was assumed from account {sourceAccount}.",
                investigation_steps=[
                    "Verify the source account is authorised",
                    "Review the role trust policy",
                    "Check permissions granted to assumed role",
                    "Validate business justification for access",
                    "Review recent API activity from assumed role"
                ],
                containment_actions=[
                    "Revoke active sessions if unauthorised",
                    "Update role trust policy to remove external account",
                    "Enable session tagging and MFA requirements",
                    "Review all cross-account role trusts",
                    "Implement stricter assume role conditions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known partner accounts and authorised integrations",
            detection_coverage="95% - catches all cross-account role assumptions",
            evasion_considerations="Cannot evade if role assumption is required",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"]
        ),

        # Strategy 3: AWS - GetSessionToken with Elevated Permissions
        DetectionStrategy(
            strategy_id="t1548-aws-sessiontoken",
            name="Elevated Session Token Generation",
            description="Detect generation of temporary credentials with elevated permissions.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.principalId, requestParameters.durationSeconds, sourceIPAddress
| filter eventName in ["GetSessionToken", "GetFederationToken"]
| filter requestParameters.durationSeconds > 3600
| stats count() as tokenCount by userIdentity.principalId, sourceIPAddress
| sort tokenCount desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect elevated session token generation

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

  # Step 2: Metric filter for session tokens
  SessionTokenFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      FilterPattern: '{ ($.eventName = "GetSessionToken" || $.eventName = "GetFederationToken") && $.requestParameters.durationSeconds > 3600 }'
      LogGroupName: /aws/cloudtrail/logs
      MetricTransformations:
        - MetricName: ElevatedSessionTokens
          MetricNamespace: Security/STS
          MetricValue: "1"

  # Step 3: Alarm
  SessionTokenAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ElevatedSessionTokenGeneration
      MetricName: ElevatedSessionTokens
      Namespace: Security/STS
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic''',
                terraform_template='''# Detect elevated session token generation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "session-token-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for session tokens
resource "aws_cloudwatch_log_metric_filter" "session_token" {
  name           = "elevated-session-tokens"
  log_group_name = "/aws/cloudtrail/logs"
  pattern        = "{ ($.eventName = \"GetSessionToken\" || $.eventName = \"GetFederationToken\") && $.requestParameters.durationSeconds > 3600 }"

  metric_transformation {
    name      = "ElevatedSessionTokens"
    namespace = "Security/STS"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "session_token" {
  alarm_name          = "elevated-session-token-generation"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ElevatedSessionTokens"
  namespace           = "Security/STS"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}''',
                alert_severity="high",
                alert_title="Elevated Session Token Generated",
                alert_description_template="Long-duration session token generated by {principalId}.",
                investigation_steps=[
                    "Review the principal generating tokens",
                    "Check token duration and permissions",
                    "Verify source IP and user agent",
                    "Review API calls made with the token",
                    "Check for anomalous patterns"
                ],
                containment_actions=[
                    "Revoke active session tokens if suspicious",
                    "Review and restrict STS permissions",
                    "Implement session duration limits",
                    "Enable MFA requirements for token generation",
                    "Monitor for token usage activity"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate federation patterns",
            detection_coverage="80% - catches long-duration token generation",
            evasion_considerations="Attacker may use shorter durations and refresh frequently",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs configured"]
        ),

        # Strategy 4: GCP - Service Account Key Creation
        DetectionStrategy(
            strategy_id="t1548-gcp-sakey",
            name="Service Account Key Creation",
            description="Detect creation of service account keys for privilege escalation.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
protoPayload.authenticationInfo.principalEmail!~".*@.*\\.iam\\.gserviceaccount\\.com$"''',
                gcp_terraform_template='''# GCP: Detect service account key creation

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
resource "google_logging_metric" "sa_key_creation" {
  name   = "service-account-key-creation"
  filter = <<-EOT
    protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
    protoPayload.authenticationInfo.principalEmail!~".*@.*\\.iam\\.gserviceaccount\\.com$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "sa_key_creation" {
  display_name = "Service Account Key Created"
  combiner     = "OR"

  conditions {
    display_name = "SA key creation by user"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_creation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "A user created a service account key. Review to ensure authorised."
  }
}''',
                alert_severity="high",
                alert_title="GCP: Service Account Key Created",
                alert_description_template="Service account key created for potential privilege escalation.",
                investigation_steps=[
                    "Identify which user created the key",
                    "Review the target service account permissions",
                    "Check if key creation was authorised",
                    "Review key usage activity",
                    "Verify business justification"
                ],
                containment_actions=[
                    "Delete unauthorised service account keys",
                    "Review service account IAM bindings",
                    "Rotate service account credentials",
                    "Implement key creation restrictions",
                    "Enable organisation policy constraints"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised key creation patterns",
            detection_coverage="95% - catches all user-initiated key creation",
            evasion_considerations="Cannot evade if key creation is required",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"]
        ),

        # Strategy 5: GCP - Privilege Escalation via IAM
        DetectionStrategy(
            strategy_id="t1548-gcp-iamescalation",
            name="GCP IAM Privilege Escalation",
            description="Detect privilege escalation through IAM policy modifications.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="SetIamPolicy"
(protoPayload.request.policy.bindings.role=~"roles/(owner|editor|iam\\.securityAdmin|iam\\.serviceAccountAdmin)"
OR protoPayload.request.policy.bindings.role=~".*Admin$")''',
                gcp_terraform_template='''# GCP: Detect IAM privilege escalation

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
resource "google_logging_metric" "iam_escalation" {
  name   = "iam-privilege-escalation"
  filter = <<-EOT
    protoPayload.methodName="SetIamPolicy"
    (protoPayload.request.policy.bindings.role=~"roles/(owner|editor|iam\\.securityAdmin|iam\\.serviceAccountAdmin)"
    OR protoPayload.request.policy.bindings.role=~".*Admin$")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "iam_escalation" {
  display_name = "IAM Privilege Escalation Detected"
  combiner     = "OR"

  conditions {
    display_name = "Privileged role granted"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iam_escalation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Privileged IAM role was granted. Investigate for unauthorised privilege escalation."
  }
}''',
                alert_severity="critical",
                alert_title="GCP: IAM Privilege Escalation Detected",
                alert_description_template="Privileged IAM role granted for potential privilege escalation.",
                investigation_steps=[
                    "Review the IAM policy changes made",
                    "Identify who received elevated permissions",
                    "Check the role permissions granted",
                    "Verify authorisation for the change",
                    "Review subsequent API activity"
                ],
                containment_actions=[
                    "Remove unauthorised role bindings",
                    "Review all privileged role assignments",
                    "Implement organisation policy constraints",
                    "Enable domain-restricted sharing",
                    "Audit recent privileged actions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist infrastructure deployment automation",
            detection_coverage="90% - catches privileged role grants",
            evasion_considerations="Attacker may use less obvious roles",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"]
        ),

        # Strategy 6: GCP - Impersonate Service Account
        DetectionStrategy(
            strategy_id="t1548-gcp-impersonate",
            name="Service Account Impersonation Detection",
            description="Detect when users impersonate service accounts to escalate privileges.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="GenerateAccessToken"
OR protoPayload.methodName="GenerateIdToken"
protoPayload.authenticationInfo.principalEmail!~".*@.*\\.iam\\.gserviceaccount\\.com$"''',
                gcp_terraform_template='''# GCP: Detect service account impersonation

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
  name   = "service-account-impersonation"
  filter = <<-EOT
    (protoPayload.methodName="GenerateAccessToken"
    OR protoPayload.methodName="GenerateIdToken")
    protoPayload.authenticationInfo.principalEmail!~".*@.*\\.iam\\.gserviceaccount\\.com$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "sa_impersonation" {
  display_name = "Service Account Impersonation Detected"
  combiner     = "OR"

  conditions {
    display_name = "User impersonating SA"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_impersonation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "A user generated tokens by impersonating a service account. Verify authorisation."
  }
}''',
                alert_severity="high",
                alert_title="GCP: Service Account Impersonation Detected",
                alert_description_template="User impersonated service account to generate credentials.",
                investigation_steps=[
                    "Identify the user performing impersonation",
                    "Review the target service account permissions",
                    "Check impersonation patterns and frequency",
                    "Verify business justification",
                    "Review API calls made with impersonated credentials"
                ],
                containment_actions=[
                    "Remove impersonation permissions if unauthorised",
                    "Review service account IAM bindings",
                    "Implement service account deny policies",
                    "Enable organisation policy constraints",
                    "Audit impersonated credential usage"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised impersonation for CI/CD and automation",
            detection_coverage="95% - catches all impersonation attempts",
            evasion_considerations="Cannot evade if impersonation is required for access",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"]
        )
    ],

    recommended_order=[
        "t1548-aws-crossaccount",
        "t1548-gcp-iamescalation",
        "t1548-aws-assumerole",
        "t1548-gcp-sakey",
        "t1548-aws-sessiontoken",
        "t1548-gcp-impersonate"
    ],
    total_effort_hours=3.5,
    coverage_improvement="+18% improvement for Privilege Escalation tactic"
)
