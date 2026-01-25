"""
T1585 - Establish Accounts

Adversaries create and cultivate accounts on various services to build personas
supporting their operations. Includes social media, email, and cloud accounts.
Used by APT17, Kimsuky, Ember Bear, Fox Kitten.
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
    technique_id="T1585",
    technique_name="Establish Accounts",
    tactic_ids=["TA0042"],
    mitre_url="https://attack.mitre.org/techniques/T1585/",
    threat_context=ThreatContext(
        description=(
            "Adversaries create and cultivate accounts on various services including "
            "social media, email platforms, and cloud providers to support operations. "
            "This enables social engineering, phishing campaigns, and abuse of free trial "
            "cloud services for infrastructure acquisition."
        ),
        attacker_goal="Establish credible online personas and acquire cloud resources for malicious operations",
        why_technique=[
            "Build credibility for social engineering",
            "Enable phishing campaigns via email accounts",
            "Abuse free trial cloud services",
            "Create personas on code repositories",
            "Establish communication channels for ransomware",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Pre-compromise technique that enables downstream attacks. Difficult to detect "
            "as activity occurs outside enterprise visibility. Focus on cloud account abuse "
            "and anomalous authentication patterns."
        ),
        business_impact=[
            "Enabler for phishing campaigns",
            "Cloud resource abuse and costs",
            "Brand impersonation risk",
            "Social engineering targeting",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1566.001", "T1566.002", "T1078.004"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1585-aws-trial-abuse",
            name="AWS Trial Account Abuse Detection",
            description="Detect suspicious patterns in new AWS account creation and trial service usage.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, sourceIPAddress, userAgent
| filter eventName like /CreateAccount|SignIn/
| filter userIdentity.type = "Root"
| stats count(*) as events by sourceIPAddress, userAgent, bin(1h)
| filter events > 5
| sort events desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious AWS account creation patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId

  # Detect multiple account creations from same IP
  SuspiciousAccountFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "CreateAccount" || $.eventName = "ConsoleLogin" && $.userIdentity.type = "Root" }'
      MetricTransformations:
        - MetricName: NewAccountActivity
          MetricNamespace: Security/AccountAbuse
          MetricValue: "1"

  SuspiciousAccountAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousAWSAccountCreation
      MetricName: NewAccountActivity
      Namespace: Security/AccountAbuse
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious AWS account creation patterns

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "account-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Detect multiple account creations from same IP
resource "aws_cloudwatch_log_metric_filter" "suspicious_accounts" {
  name           = "suspicious-account-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"CreateAccount\" || ($.eventName = \"ConsoleLogin\" && $.userIdentity.type = \"Root\") }"

  metric_transformation {
    name      = "NewAccountActivity"
    namespace = "Security/AccountAbuse"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "account_abuse" {
  alarm_name          = "SuspiciousAWSAccountCreation"
  metric_name         = "NewAccountActivity"
  namespace           = "Security/AccountAbuse"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious AWS Account Activity Detected",
                alert_description_template="Unusual account creation or root login patterns from {sourceIPAddress}.",
                investigation_steps=[
                    "Review source IP geolocation and reputation",
                    "Check account creation velocity",
                    "Verify account ownership and legitimacy",
                    "Review resource provisioning in new accounts",
                ],
                containment_actions=[
                    "Suspend suspicious accounts",
                    "Enable MFA requirements",
                    "Implement account creation approval process",
                    "Review and limit trial service quotas",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="May trigger during legitimate organisation onboarding; adjust threshold for your environment",
            detection_coverage="40% - limited to AWS account activity",
            evasion_considerations="Adversaries using distributed IPs or legitimate trial usage patterns",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1585-aws-free-tier",
            name="AWS Free Tier Service Abuse",
            description="Detect unusual usage of AWS free tier services that may indicate trial abuse.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, requestParameters.instanceType, sourceIPAddress
| filter eventName like /RunInstances|CreateFunction|CreateDBInstance/
| filter userIdentity.accountId like /-trial|-free/
| stats count(*) as resources by userIdentity.accountId, eventName, bin(1h)
| filter resources > 3
| sort resources desc""",
                terraform_template="""# Detect abuse of AWS free tier services

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "free-tier-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "free_tier_abuse" {
  name           = "free-tier-resource-creation"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"RunInstances\" || $.eventName = \"CreateFunction\" || $.eventName = \"CreateDBInstance\" }"

  metric_transformation {
    name      = "FreeTierResourceCreation"
    namespace = "Security/AccountAbuse"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "rapid_provisioning" {
  alarm_name          = "RapidResourceProvisioning"
  metric_name         = "FreeTierResourceCreation"
  namespace           = "Security/AccountAbuse"
  statistic           = "Sum"
  period              = 900
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Rapid Free Tier Resource Provisioning",
                alert_description_template="Unusual volume of resource creation in account {accountId}.",
                investigation_steps=[
                    "Review account creation date and ownership",
                    "Check resource types and configurations",
                    "Verify business justification",
                    "Review billing alerts and usage",
                ],
                containment_actions=[
                    "Implement service quotas",
                    "Enable billing alerts",
                    "Review and terminate unauthorised resources",
                    "Require approval for new accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on legitimate development activity",
            detection_coverage="50% - focuses on compute resource creation",
            evasion_considerations="Slow resource provisioning or use of non-free tier services",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "AWS Budgets configured"],
        ),
        DetectionStrategy(
            strategy_id="t1585-gcp-trial-abuse",
            name="GCP Trial Account Abuse Detection",
            description="Detect suspicious patterns in GCP trial account usage and resource provisioning.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.insert"
protoPayload.authenticationInfo.principalEmail=~".*trial.*|.*test.*"''',
                gcp_terraform_template="""# GCP: Detect trial account abuse

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Trial Abuse Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Detect rapid instance creation in trial accounts
resource "google_logging_metric" "trial_instances" {
  project = var.project_id
  name   = "trial-instance-creation"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="v1.compute.instances.insert"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "account"
      value_type  = "STRING"
      description = "Account creating instances"
    }
  }
  label_extractors = {
    "account" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

resource "google_monitoring_alert_policy" "trial_abuse" {
  project      = var.project_id
  display_name = "GCP Trial Account Abuse"
  combiner     = "OR"
  conditions {
    display_name = "Rapid instance creation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.trial_instances.name}\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP Trial Account Abuse Detected",
                alert_description_template="Unusual resource provisioning in trial account.",
                investigation_steps=[
                    "Review account creation date and ownership",
                    "Check instance types and regions",
                    "Verify legitimate business use",
                    "Review billing and quotas",
                ],
                containment_actions=[
                    "Suspend suspicious projects",
                    "Implement resource quotas",
                    "Enable budget alerts",
                    "Review IAM policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust for legitimate testing and development activity",
            detection_coverage="45% - focuses on compute resources",
            evasion_considerations="Adversaries using realistic account names or slow provisioning",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled", "Budget alerts configured"],
        ),
        DetectionStrategy(
            strategy_id="t1585-aws-iam-abuse",
            name="Unusual IAM User Creation Patterns",
            description="Detect suspicious IAM user and access key creation that may indicate account establishment.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, requestParameters.userName, sourceIPAddress
| filter eventName in ["CreateUser", "CreateAccessKey", "CreateLoginProfile"]
| stats count(*) as created by sourceIPAddress, userIdentity.principalId, bin(1h)
| filter created > 3
| sort created desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious IAM user creation patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId

  IAMUserCreationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "CreateUser" || $.eventName = "CreateAccessKey" || $.eventName = "CreateLoginProfile" }'
      MetricTransformations:
        - MetricName: IAMUserCreation
          MetricNamespace: Security/AccountAbuse
          MetricValue: "1"

  RapidIAMCreationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: RapidIAMUserCreation
      MetricName: IAMUserCreation
      Namespace: Security/AccountAbuse
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious IAM user creation patterns

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "iam-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "iam_creation" {
  name           = "iam-user-creation"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"CreateUser\" || $.eventName = \"CreateAccessKey\" || $.eventName = \"CreateLoginProfile\" }"

  metric_transformation {
    name      = "IAMUserCreation"
    namespace = "Security/AccountAbuse"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "rapid_iam_creation" {
  alarm_name          = "RapidIAMUserCreation"
  metric_name         = "IAMUserCreation"
  namespace           = "Security/AccountAbuse"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious IAM User Creation Activity",
                alert_description_template="Rapid IAM user/key creation from {principalId}.",
                investigation_steps=[
                    "Review created user names and permissions",
                    "Check source IP and user agent",
                    "Verify business justification",
                    "Review access key usage patterns",
                ],
                containment_actions=[
                    "Disable suspicious IAM users and keys",
                    "Review and revoke excessive permissions",
                    "Enable CloudTrail for all regions",
                    "Implement IAM approval workflows",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="May trigger during legitimate onboarding; baseline normal activity",
            detection_coverage="55% - focuses on IAM user creation",
            evasion_considerations="Slow user creation or use of existing compromised accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled across all regions"],
        ),
        # Azure Strategy: Establish Accounts
        DetectionStrategy(
            strategy_id="t1585-azure",
            name="Azure Establish Accounts Detection",
            description=(
                "Azure detection for Establish Accounts. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Establish Accounts (T1585)
# Microsoft Defender detects Establish Accounts activity

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
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1585-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1585"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (
                    "Suspicious activity detected",
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Establish Accounts activity"
  display_name = "Defender: Establish Accounts"
  enabled      = true

  tags = {
    "mitre-technique" = "T1585"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Establish Accounts Detected",
                alert_description_template=(
                    "Establish Accounts activity detected. "
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
        "t1585-aws-trial-abuse",
        "t1585-gcp-trial-abuse",
        "t1585-aws-iam-abuse",
        "t1585-aws-free-tier",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+15% improvement for Resource Development tactic",
)
