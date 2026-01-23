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
            "Exploits misconfigured trust relationships",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
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
            "Compliance violations",
        ],
        typical_attack_phase="privilege_escalation",
        often_precedes=["T1530", "T1537", "T1562.008", "T1098.003"],
        often_follows=["T1078.004", "T1552.005", "T1528"],
    ),
    detection_strategies=[
        # AWS GuardDuty Detection (Recommended)
        DetectionStrategy(
            strategy_id="t1548-aws-guardduty",
            name="AWS GuardDuty Anomaly Detection",
            description=(
                "AWS GuardDuty detects privilege escalation attempts. PrivilegeEscalation:IAMUser/AnomalousBehavior identifies when APIs like AssociateIamInstanceProfile, AddUserToGroup, or AttachRolePolicy are called in patterns suggesting unauthorised privilege elevation."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "PrivilegeEscalation:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for T1548

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty-T1548-Alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for GuardDuty findings
  GuardDutyRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Capture GuardDuty findings for T1548
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "PrivilegeEscalation:IAMUser/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
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
                aws:SourceArn: !GetAtt GuardDutyRule.Arn""",
                terraform_template="""# GuardDuty alerts for T1548

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

data "aws_caller_identity" "current" {}

# Step 1: SNS Topic
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "guardduty-t1548-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for findings
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "guardduty-t1548"
  description = "Capture GuardDuty findings for T1548"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "PrivilegeEscalation:IAMUser/" }]
    }
  })
}

# Step 3: Target with DLQ and retry
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-t1548-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

# Step 4: SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnEquals    = { "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty.arn }
      }
    }]
  })
}""",
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML baselines; tune suppression rules for known benign patterns",
            detection_coverage="70% - detects anomalous behaviour but may miss attacks that blend with normal activity",
            evasion_considerations="Gradual privilege escalation, using legitimate automation, mimicking normal admin operations",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events",
            prerequisites=[
                "AWS GuardDuty enabled",
                "CloudTrail logging active",
            ],
        ),
        # Strategy 1: AWS - Unusual AssumeRole Activity
        DetectionStrategy(
            strategy_id="t1548-aws-assumerole",
            name="Unusual IAM Role Assumption",
            description="Detect anomalous AssumeRole API calls indicating privilege escalation attempts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.roleArn, sourceIPAddress, errorCode
| filter eventName = "AssumeRole"
| filter userIdentity.type != "AWSService"
| stats count() as assumeRoleCount by userIdentity.principalId, requestParameters.roleArn, sourceIPAddress
| filter assumeRoleCount > 10
| sort assumeRoleCount desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
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
      KmsMasterKeyId: alias/aws/sns
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
      TreatMissingData: notBreaching

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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect unusual IAM role assumption activity

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "assume_role_alerts" {
  name         = "assume-role-alerts"
  kms_master_key_id = "alias/aws/sns"
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
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.assume_role_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "assume_role_alerts" {
  arn = aws_sns_topic.assume_role_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.assume_role_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Unusual IAM Role Assumption Detected",
                alert_description_template="High volume of AssumeRole calls detected from {principalId}.",
                investigation_steps=[
                    "Review the principal attempting role assumption",
                    "Check which roles are being assumed",
                    "Verify source IP addresses are expected",
                    "Review role session duration and permissions",
                    "Check for failed AssumeRole attempts",
                ],
                containment_actions=[
                    "Revoke active sessions if unauthorised",
                    "Update role trust policies to restrict access",
                    "Enable MFA requirement for sensitive roles",
                    "Review and tighten IAM policies",
                    "Monitor for continued suspicious activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised automation and CI/CD pipelines",
            detection_coverage="85% - catches high-volume role assumption",
            evasion_considerations="Attacker may use low-and-slow approach to evade volume-based detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs configured"],
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
                        "userIdentity": {"type": ["AssumedRole", "IAMUser"]},
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect cross-account role assumption

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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt CrossAccountRoleRule.Arn""",
                terraform_template="""# Detect cross-account role assumption

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "cross-account-role-alerts"
  kms_master_key_id = "alias/aws/sns"
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

# DLQ for failed events
resource "aws_sqs_queue" "dlq" {
  name                      = "cross-account-assume-role-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.cross_account_assume.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.cross_account_assume.name
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
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.cross_account_assume.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Cross-Account Role Assumption Detected",
                alert_description_template="Role {roleArn} was assumed from account {sourceAccount}.",
                investigation_steps=[
                    "Verify the source account is authorised",
                    "Review the role trust policy",
                    "Check permissions granted to assumed role",
                    "Validate business justification for access",
                    "Review recent API activity from assumed role",
                ],
                containment_actions=[
                    "Revoke active sessions if unauthorised",
                    "Update role trust policy to remove external account",
                    "Enable session tagging and MFA requirements",
                    "Review all cross-account role trusts",
                    "Implement stricter assume role conditions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known partner accounts and authorised integrations",
            detection_coverage="95% - catches all cross-account role assumptions",
            evasion_considerations="Cannot evade if role assumption is required",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
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
                query="""fields @timestamp, userIdentity.principalId, requestParameters.durationSeconds, sourceIPAddress
| filter eventName in ["GetSessionToken", "GetFederationToken"]
| filter requestParameters.durationSeconds > 3600
| stats count() as tokenCount by userIdentity.principalId, sourceIPAddress
| sort tokenCount desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect elevated session token generation

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
      TreatMissingData: notBreaching

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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect elevated session token generation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "session-token-alerts"
  kms_master_key_id = "alias/aws/sns"
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
  treat_missing_data  = "notBreaching"

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
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Elevated Session Token Generated",
                alert_description_template="Long-duration session token generated by {principalId}.",
                investigation_steps=[
                    "Review the principal generating tokens",
                    "Check token duration and permissions",
                    "Verify source IP and user agent",
                    "Review API calls made with the token",
                    "Check for anomalous patterns",
                ],
                containment_actions=[
                    "Revoke active session tokens if suspicious",
                    "Review and restrict STS permissions",
                    "Implement session duration limits",
                    "Enable MFA requirements for token generation",
                    "Monitor for token usage activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate federation patterns",
            detection_coverage="80% - catches long-duration token generation",
            evasion_considerations="Attacker may use shorter durations and refresh frequently",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs configured"],
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
                gcp_terraform_template="""# GCP: Detect service account key creation

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "sa_key_creation" {
  project = var.project_id
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
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "A user created a service account key. Review to ensure authorised."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Service Account Key Created",
                alert_description_template="Service account key created for potential privilege escalation.",
                investigation_steps=[
                    "Identify which user created the key",
                    "Review the target service account permissions",
                    "Check if key creation was authorised",
                    "Review key usage activity",
                    "Verify business justification",
                ],
                containment_actions=[
                    "Delete unauthorised service account keys",
                    "Review service account IAM bindings",
                    "Rotate service account credentials",
                    "Implement key creation restrictions",
                    "Enable organisation policy constraints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised key creation patterns",
            detection_coverage="95% - catches all user-initiated key creation",
            evasion_considerations="Cannot evade if key creation is required",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
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
                gcp_logging_query="""protoPayload.methodName="SetIamPolicy"
(protoPayload.request.policy.bindings.role=~"roles/(owner|editor|iam\\.securityAdmin|iam\\.serviceAccountAdmin)"
OR protoPayload.request.policy.bindings.role=~".*Admin$")""",
                gcp_terraform_template="""# GCP: Detect IAM privilege escalation

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "iam_escalation" {
  project = var.project_id
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
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "Privileged IAM role was granted. Investigate for unauthorised privilege escalation."
  }
}""",
                alert_severity="critical",
                alert_title="GCP: IAM Privilege Escalation Detected",
                alert_description_template="Privileged IAM role granted for potential privilege escalation.",
                investigation_steps=[
                    "Review the IAM policy changes made",
                    "Identify who received elevated permissions",
                    "Check the role permissions granted",
                    "Verify authorisation for the change",
                    "Review subsequent API activity",
                ],
                containment_actions=[
                    "Remove unauthorised role bindings",
                    "Review all privileged role assignments",
                    "Implement organisation policy constraints",
                    "Enable domain-restricted sharing",
                    "Audit recent privileged actions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist infrastructure deployment automation",
            detection_coverage="90% - catches privileged role grants",
            evasion_considerations="Attacker may use less obvious roles",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
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
                gcp_terraform_template="""# GCP: Detect service account impersonation

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s3" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "sa_impersonation" {
  project = var.project_id
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
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email_s3.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "A user generated tokens by impersonating a service account. Verify authorisation."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Service Account Impersonation Detected",
                alert_description_template="User impersonated service account to generate credentials.",
                investigation_steps=[
                    "Identify the user performing impersonation",
                    "Review the target service account permissions",
                    "Check impersonation patterns and frequency",
                    "Verify business justification",
                    "Review API calls made with impersonated credentials",
                ],
                containment_actions=[
                    "Remove impersonation permissions if unauthorised",
                    "Review service account IAM bindings",
                    "Implement service account deny policies",
                    "Enable organisation policy constraints",
                    "Audit impersonated credential usage",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised impersonation for CI/CD and automation",
            detection_coverage="95% - catches all impersonation attempts",
            evasion_considerations="Cannot evade if impersonation is required for access",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Abuse Elevation Control Mechanism
        DetectionStrategy(
            strategy_id="t1548-azure",
            name="Azure Abuse Elevation Control Mechanism Detection",
            description=(
                "Monitor privilege elevation attempts. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Abuse Elevation Control Mechanism Detection
// Technique: T1548
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.Authorization/elevateAccess/action"
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
                    "Microsoft.Authorization/elevateAccess/action"
                ],
                azure_terraform_template="""# Azure Detection for Abuse Elevation Control Mechanism
# MITRE ATT&CK: T1548

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
  name                = "abuse-elevation-control-mechanism-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "abuse-elevation-control-mechanism-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Abuse Elevation Control Mechanism Detection
// Technique: T1548
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.Authorization/elevateAccess/action"
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

  description = "Detects Abuse Elevation Control Mechanism (T1548) activity in Azure environment"
  display_name = "Abuse Elevation Control Mechanism Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1548"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Abuse Elevation Control Mechanism Detected",
                alert_description_template=(
                    "Abuse Elevation Control Mechanism activity detected. "
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
        "t1548-aws-crossaccount",
        "t1548-gcp-iamescalation",
        "t1548-aws-assumerole",
        "t1548-gcp-sakey",
        "t1548-aws-sessiontoken",
        "t1548-gcp-impersonate",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+18% improvement for Privilege Escalation tactic",
)
