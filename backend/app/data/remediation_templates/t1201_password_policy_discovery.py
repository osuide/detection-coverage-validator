"""
T1201 - Password Policy Discovery

Adversaries gather information about password policies to craft targeted
dictionary and brute-force attacks that comply with policy requirements.
Used by Chimera, OilRig, Turla in Operation CuckooBees.
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
    technique_id="T1201",
    technique_name="Password Policy Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1201/",
    threat_context=ThreatContext(
        description=(
            "Adversaries gather information about an organisation's password policies "
            "to craft targeted dictionary and brute-force attacks that comply with policy "
            "requirements. This includes minimum length, complexity, age, and history requirements "
            "across Windows, Linux, macOS, and cloud platforms."
        ),
        attacker_goal="Discover password policies to optimise credential attacks",
        why_technique=[
            "Reduces brute-force attack time by targeting valid formats",
            "Enables policy-compliant password spraying",
            "Reveals weak security posture",
            "Available via native commands on all platforms",
            "Low detection risk for reconnaissance",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "Discovery technique that enables more effective password attacks. "
            "Low immediate impact but facilitates credential compromise."
        ),
        business_impact=[
            "Precursor to credential attacks",
            "Intelligence gathering for targeted attacks",
            "Reveals security posture weaknesses",
            "Enables optimised password spraying",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1110.003", "T1110.004", "T1078"],
        often_follows=["T1078", "T1059"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1201-aws-api",
            name="AWS GetAccountPasswordPolicy API Calls",
            description="Detect AWS IAM password policy discovery via API calls.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, errorCode
| filter eventName = "GetAccountPasswordPolicy"
| stats count(*) as calls by userIdentity.principalId, sourceIPAddress, bin(1h)
| filter calls > 2
| sort calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect AWS password policy discovery attempts

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for GetAccountPasswordPolicy API calls
  PasswordPolicyDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "GetAccountPasswordPolicy" }'
      MetricTransformations:
        - MetricName: PasswordPolicyDiscovery
          MetricNamespace: Security/Discovery
          MetricValue: "1"

  # Step 3: Create alarm for suspicious activity
  PasswordPolicyDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: PasswordPolicyDiscoveryDetected
      AlarmDescription: Multiple password policy discovery attempts detected
      MetricName: PasswordPolicyDiscovery
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 300
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect AWS password policy discovery attempts

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "password-policy-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for GetAccountPasswordPolicy API calls
resource "aws_cloudwatch_log_metric_filter" "password_policy_discovery" {
  name           = "password-policy-discovery"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"GetAccountPasswordPolicy\" }"

  metric_transformation {
    name      = "PasswordPolicyDiscovery"
    namespace = "Security/Discovery"
    value     = "1"
  }
}

# Step 3: Create alarm for suspicious activity
resource "aws_cloudwatch_metric_alarm" "password_policy_discovery" {
  alarm_name          = "PasswordPolicyDiscoveryDetected"
  alarm_description   = "Multiple password policy discovery attempts detected"
  metric_name         = "PasswordPolicyDiscovery"
  namespace           = "Security/Discovery"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="AWS Password Policy Discovery Detected",
                alert_description_template="User {principalId} queried password policy from {sourceIPAddress}.",
                investigation_steps=[
                    "Identify the user or role making the API call",
                    "Review user's recent activity and access patterns",
                    "Check if the call is from expected IP/location",
                    "Look for subsequent credential attack attempts",
                    "Review CloudTrail for other reconnaissance activities",
                ],
                containment_actions=[
                    "Review IAM user/role permissions",
                    "Consider restricting GetAccountPasswordPolicy access",
                    "Enable MFA if not already enabled",
                    "Monitor for password spray or brute-force attempts",
                    "Reset credentials if compromise suspected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate security tools may query this. Whitelist known security scanners.",
            detection_coverage="80% - catches AWS API-based discovery",
            evasion_considerations="Adversaries with existing access may use assumed roles",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch Logs"],
        ),
        DetectionStrategy(
            strategy_id="t1201-aws-ec2-commands",
            name="Windows Password Policy Commands on EC2",
            description="Detect password policy discovery commands on Windows EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.eventName, detail.commandName, detail.instanceId
| filter detail.eventName = "SendCommand"
| filter detail.commandName like /net accounts|Get-ADDefaultDomainPasswordPolicy|secedit/
| stats count(*) as executions by detail.instanceId, detail.commandName, bin(1h)
| sort executions desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Windows password policy discovery commands

Parameters:
  EventBusName:
    Type: String
    Default: default
    Description: EventBridge bus name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for SSM Run Command
  PasswordCommandRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Detect password policy discovery commands
      EventBusName: !Ref EventBusName
      EventPattern:
        source: [aws.ssm]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [SendCommand]
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: PasswordDiscoveryTarget

  # Step 3: Allow EventBridge to publish to SNS
  SNSTopicPolicy:
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
                terraform_template="""# Detect Windows password policy discovery commands

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "password-command-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for SSM Run Command
resource "aws_cloudwatch_event_rule" "password_commands" {
  name        = "detect-password-policy-commands"
  description = "Detect password policy discovery commands"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand"]
    }
  })
}

# DLQ for failed EventBridge deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "password-command-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "dlq_policy" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.password_commands.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.password_commands.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Step 3: Allow EventBridge to publish to SNS
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "default" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.password_commands.arn
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Windows Password Policy Discovery Command Executed",
                alert_description_template="Password policy command executed on instance {instanceId}.",
                investigation_steps=[
                    "Identify who executed the command via CloudTrail",
                    "Review SSM Session Manager logs for full command output",
                    "Check if instance is part of legitimate security scanning",
                    "Look for subsequent authentication attempts",
                    "Review instance for other reconnaissance activities",
                ],
                containment_actions=[
                    "Isolate instance if compromise suspected",
                    "Review SSM permissions and access",
                    "Enable CloudWatch Logs for Session Manager",
                    "Check for unauthorised users or processes",
                    "Reset passwords if necessary",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate administrators may check policies. Review context and user.",
            detection_coverage="60% - requires SSM/CloudWatch agent",
            evasion_considerations="Direct instance access bypasses this detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["SSM agent on instances", "CloudTrail logging"],
        ),
        DetectionStrategy(
            strategy_id="t1201-gcp-logging",
            name="GCP Policy Discovery via Cloud Logging",
            description="Detect password policy discovery in GCP environments.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"google.admin.AdminService.getPasswordPolicy|google.iam.admin.v1.GetIamPolicy"
OR
textPayload=~"gcloud organizations get-iam-policy|gcloud iam service-accounts get-iam-policy"''',
                gcp_terraform_template="""# GCP: Detect password policy discovery attempts

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Password Policy Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Create log-based metric for policy discovery
resource "google_logging_metric" "password_policy_discovery" {
  name   = "password-policy-discovery"
  filter = <<-EOT
    protoPayload.methodName=~"google.admin.AdminService.getPasswordPolicy|google.iam.admin.v1.GetIamPolicy"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User making the request"
    }
  }
  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for suspicious activity
resource "google_monitoring_alert_policy" "password_policy_discovery" {
  display_name = "Password Policy Discovery Detected"
  combiner     = "OR"
  conditions {
    display_name = "Multiple policy queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.password_policy_discovery.name}\" resource.type=\"global\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP Password Policy Discovery Detected",
                alert_description_template="User queried password or IAM policies multiple times.",
                investigation_steps=[
                    "Identify the user from Cloud Audit Logs",
                    "Review user's recent GCP activity",
                    "Check if queries are from expected source IP",
                    "Look for subsequent credential attacks",
                    "Review IAM permissions granted to user",
                ],
                containment_actions=[
                    "Review and restrict IAM permissions",
                    "Enable MFA for affected accounts",
                    "Monitor for password spray attempts",
                    "Review organisation password policies",
                    "Suspend account if compromise suspected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Security tools and administrators may legitimately query policies. Review context.",
            detection_coverage="70% - catches GCP policy queries",
            evasion_considerations="Service accounts may be used to evade user-based detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1201-gcp-compute",
            name="GCP Compute Instance Password Policy Commands",
            description="Detect password policy discovery commands on GCP Compute instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(textPayload=~"net accounts|chage -l|pwpolicy getaccountpolicies|/etc/pam.d/common-password"
OR jsonPayload.message=~"net accounts|chage -l|pwpolicy getaccountpolicies")""",
                gcp_terraform_template="""# GCP: Detect password policy commands on Compute instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Compute Password Discovery Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Create log-based metric for password commands
resource "google_logging_metric" "password_commands" {
  name   = "password-policy-commands"
  filter = <<-EOT
    resource.type="gce_instance"
    (textPayload=~"net accounts|chage -l|pwpolicy getaccountpolicies|/etc/pam.d/common-password"
    OR jsonPayload.message=~"net accounts|chage -l|pwpolicy getaccountpolicies")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance executing commands"
    }
  }
  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy for command execution
resource "google_monitoring_alert_policy" "password_commands" {
  display_name = "Password Policy Commands Detected"
  combiner     = "OR"
  conditions {
    display_name = "Password discovery command executed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.password_commands.name}\" resource.type=\"global\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP Password Policy Command Executed",
                alert_description_template="Password policy discovery command executed on instance.",
                investigation_steps=[
                    "Identify the instance and user from logs",
                    "Review OS logs for full command context",
                    "Check if instance runs security scanning tools",
                    "Look for other reconnaissance activities",
                    "Review SSH access logs and users",
                ],
                containment_actions=[
                    "Review instance access and permissions",
                    "Check for unauthorised SSH keys",
                    "Enable OS logging if not configured",
                    "Isolate instance if compromise suspected",
                    "Review and rotate credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Requires OS logging agent. Legitimate admins may check policies.",
            detection_coverage="50% - requires logging agent installation",
            evasion_considerations="Requires Cloud Logging agent; direct access bypasses detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging agent on Compute instances"],
        ),
    ],
    recommended_order=[
        "t1201-aws-api",
        "t1201-gcp-logging",
        "t1201-aws-ec2-commands",
        "t1201-gcp-compute",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+15% improvement for Discovery tactic",
)
