"""
T1578.005 - Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations

Adversaries modify cloud compute settings to affect infrastructure size, locations,
and available resources for defence evasion. Includes quota adjustments, tenant-wide
policies, and regional deployment settings.
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
    technique_id="T1578.005",
    technique_name="Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations",
    tactic_ids=["TA0005"],  # Defense Evasion
    mitre_url="https://attack.mitre.org/techniques/T1578/005/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify cloud compute configuration settings to affect "
            "infrastructure size, locations, and available resources. These changes "
            "may include quota adjustments, subscription associations, tenant-wide "
            "policies, or regional deployment settings, enabling resource abuse "
            "without detection."
        ),
        attacker_goal="Evade detection by modifying cloud compute configurations to enable resource abuse",
        why_technique=[
            "Increase service quotas to support resource hijacking",
            "Modify tenant policies to allow larger deployments",
            "Enable new regions for unauthorised resource creation",
            "Bypass security controls through policy weakening",
            "Avoid suspicion by staying within modified quotas",
        ],
        known_threat_actors=[],  # No verified threat actors in MITRE data
        recent_campaigns=[],  # No verified campaigns in MITRE data
        prevalence="uncommon",
        trend="emerging",
        severity_score=7,
        severity_reasoning=(
            "Enables resource abuse and defence evasion through administrative "
            "configuration changes. Requires elevated permissions but can lead to "
            "significant unauthorised resource consumption and weakened security posture."
        ),
        business_impact=[
            "Unauthorised resource consumption",
            "Increased cloud costs",
            "Weakened security controls",
            "Compliance violations",
            "Cryptomining and resource hijacking",
        ],
        typical_attack_phase="defense_evasion",
        often_precedes=["T1496", "T1496"],  # Resource hijacking, cryptomining
        often_follows=["T1098", "T1078.004"],  # Account manipulation, cloud accounts
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1578-005-aws-quota",
            name="AWS Service Quota Modification Detection",
            description="Detect unauthorised service quota increase requests and approvals.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.serviceCode, requestParameters.quotaCode
| filter eventName = "RequestServiceQuotaIncrease"
| stats count(*) as requests by userIdentity.principalId, requestParameters.serviceCode, bin(24h)
| sort requests desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect service quota modification attempts

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
      TopicName: service-quota-alerts
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

  # Step 2: Create metric filter for quota changes
  QuotaChangeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "RequestServiceQuotaIncrease" || $.eventName = "PutServiceQuotaIncreaseRequestIntoTemplate" }'
      MetricTransformations:
        - MetricName: ServiceQuotaChanges
          MetricNamespace: Security/Compute
          MetricValue: "1"

  # Step 3: Create alarm for quota modification
  QuotaChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnauthorisedQuotaModification
      AlarmDescription: Alert on service quota modification requests
      MetricName: ServiceQuotaChanges
      Namespace: Security/Compute
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# AWS: Detect service quota modifications

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
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

data "aws_caller_identity" "current" {}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "quota_alerts" {
  name = "service-quota-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.quota_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.quota_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.quota_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for quota changes
resource "aws_cloudwatch_log_metric_filter" "quota_changes" {
  name           = "service-quota-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"RequestServiceQuotaIncrease\" || $.eventName = \"PutServiceQuotaIncreaseRequestIntoTemplate\" }"

  metric_transformation {
    name      = "ServiceQuotaChanges"
    namespace = "Security/Compute"
    value     = "1"
  }
}

# Step 3: Create alarm for quota modifications
resource "aws_cloudwatch_metric_alarm" "quota_modification" {
  alarm_name          = "UnauthorisedQuotaModification"
  alarm_description   = "Alert on service quota modification requests"
  metric_name         = "ServiceQuotaChanges"
  namespace           = "Security/Compute"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.quota_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Service Quota Modification Detected",
                alert_description_template="Service quota change requested by {principalId} for {serviceCode}.",
                investigation_steps=[
                    "Identify the principal requesting quota changes",
                    "Review the specific services and quotas requested",
                    "Check if request aligns with authorised changes",
                    "Review recent resource creation following approval",
                    "Examine account activity for suspicious behaviour",
                ],
                containment_actions=[
                    "Deny unauthorised quota increase requests",
                    "Revert approved quota changes if malicious",
                    "Restrict Service Quotas permissions",
                    "Review and terminate suspicious resources",
                    "Enable SCPs to limit quota modifications",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate quota requests occur during scaling; maintain approved change list",
            detection_coverage="85% - captures quota API calls",
            evasion_considerations="Adversaries may use compromised authorised accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled and logging to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1578-005-aws-ec2-limits",
            name="AWS EC2 Instance Limit Modifications",
            description="Detect changes to EC2 instance limits and regional configurations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.instanceType, responseElements.vCpuLimit
| filter eventName = "ModifyInstanceAttribute" or eventName = "ModifyReservedInstances"
| filter responseElements.vCpuLimit exists or requestParameters.attribute = "instanceType"
| stats count(*) as modifications by userIdentity.principalId, bin(24h)
| sort modifications desc""",
                terraform_template="""# AWS: Detect EC2 instance limit modifications

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
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

data "aws_caller_identity" "current" {}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "ec2_limit_alerts" {
  name = "ec2-limit-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.ec2_limit_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ec2_limit_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ec2_limit_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for EC2 limit changes
resource "aws_cloudwatch_log_metric_filter" "ec2_limits" {
  name           = "ec2-limit-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"ModifyInstanceAttribute\" || $.eventName = \"ModifyReservedInstances\" }"

  metric_transformation {
    name      = "EC2LimitChanges"
    namespace = "Security/Compute"
    value     = "1"
  }
}

# Step 3: Create alarm for EC2 limit modifications
resource "aws_cloudwatch_metric_alarm" "ec2_limit_change" {
  alarm_name          = "EC2LimitModification"
  alarm_description   = "Alert on EC2 instance limit modifications"
  metric_name         = "EC2LimitChanges"
  namespace           = "Security/Compute"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.ec2_limit_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="EC2 Instance Limit Modified",
                alert_description_template="EC2 instance configuration changed by {principalId}.",
                investigation_steps=[
                    "Review the specific instance modifications",
                    "Check if changes align with capacity planning",
                    "Examine account for recent privilege escalation",
                    "Review subsequent EC2 instance launches",
                    "Verify business justification for changes",
                ],
                containment_actions=[
                    "Revert unauthorised instance modifications",
                    "Restrict EC2 modification permissions",
                    "Review and terminate suspicious instances",
                    "Implement SCPs for instance type restrictions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Instance modifications common during operations; filter known admin accounts",
            detection_coverage="70% - captures instance modification events",
            evasion_considerations="Legitimate-looking changes may blend with normal operations",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled and logging to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1578-005-gcp-quota",
            name="GCP Quota Modification Detection",
            description="Detect unauthorised GCP quota and organisation policy changes.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName=("cloudquotas.googleapis.com.QuotaPreference.CreateQuotaPreference" OR
"cloudquotas.googleapis.com.QuotaPreference.UpdateQuotaPreference" OR
"orgpolicy.googleapis.com.OrgPolicy.SetOrgPolicy")
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Detect quota and policy modifications

variable "project_id" {
  type        = string
  description = "GCP project ID"
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

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Quota Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for quota changes
resource "google_logging_metric" "quota_changes" {
  project = var.project_id
  name   = "quota-modifications"
  filter = <<-EOT
    protoPayload.methodName=("cloudquotas.googleapis.com.QuotaPreference.CreateQuotaPreference" OR
    "cloudquotas.googleapis.com.QuotaPreference.UpdateQuotaPreference" OR
    "orgpolicy.googleapis.com.OrgPolicy.SetOrgPolicy")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for quota modifications
resource "google_monitoring_alert_policy" "quota_modification" {
  project      = var.project_id
  display_name = "Quota Modification Detected"
  combiner     = "OR"
  conditions {
    display_name = "Quota or policy change detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.quota_changes.name}\""
      duration        = "60s"
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
}""",
                alert_severity="high",
                alert_title="GCP Quota Modification Detected",
                alert_description_template="Quota or organisation policy modified in GCP project.",
                investigation_steps=[
                    "Identify the principal making quota changes",
                    "Review specific quotas or policies modified",
                    "Check for alignment with approved changes",
                    "Examine subsequent resource creation patterns",
                    "Review IAM permissions for quota management",
                ],
                containment_actions=[
                    "Revert unauthorised quota changes",
                    "Restrict quota management permissions",
                    "Review and delete suspicious resources",
                    "Implement organisation policy constraints",
                    "Enable VPC Service Controls for protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate quota requests occur; maintain approved change baseline",
            detection_coverage="85% - captures quota API calls",
            evasion_considerations="Compromised admin accounts may make authorised-looking changes",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Admin Activity"],
        ),
        DetectionStrategy(
            strategy_id="t1578-005-gcp-compute-policy",
            name="GCP Compute Engine Policy Changes",
            description="Detect modifications to Compute Engine organisation policies and constraints.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="orgpolicy.googleapis.com.OrgPolicy.SetOrgPolicy"
protoPayload.resourceName=~"compute"
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Detect Compute Engine policy modifications

variable "project_id" {
  type        = string
  description = "GCP project ID"
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

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Compute Policy Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for policy changes
resource "google_logging_metric" "compute_policy_changes" {
  project = var.project_id
  name   = "compute-policy-modifications"
  filter = <<-EOT
    protoPayload.methodName="orgpolicy.googleapis.com.OrgPolicy.SetOrgPolicy"
    protoPayload.resourceName=~"compute"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "compute_policy_alert" {
  project      = var.project_id
  display_name = "Compute Policy Modification"
  combiner     = "OR"
  conditions {
    display_name = "Compute organisation policy changed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.compute_policy_changes.name}\""
      duration        = "60s"
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
}""",
                alert_severity="high",
                alert_title="GCP Compute Policy Modified",
                alert_description_template="Compute Engine organisation policy modified.",
                investigation_steps=[
                    "Identify who modified the policy",
                    "Review specific policy constraints changed",
                    "Check if changes weaken security controls",
                    "Examine for subsequent VM size increases",
                    "Verify business justification",
                ],
                containment_actions=[
                    "Revert unauthorised policy changes",
                    "Restrict organisation policy permissions",
                    "Review recently created compute resources",
                    "Implement mandatory policy constraints",
                    "Enable change approval workflows",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Policy changes are infrequent; review all modifications",
            detection_coverage="80% - captures policy API calls",
            evasion_considerations="May be performed by legitimate administrators",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Admin Activity"],
        ),
        # Azure Strategy: Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations
        DetectionStrategy(
            strategy_id="t1578005-azure",
            name="Azure Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations Detection",
            description=(
                "Azure detection for Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations
// MITRE ATT&CK: T1578.005
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources""",
                azure_terraform_template="""# Azure Detection for Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations
# MITRE ATT&CK: T1578.005

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

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "modify-cloud-compute-infrastructure--modify-cloud--alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "modify-cloud-compute-infrastructure--modify-cloud--detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations
// MITRE ATT&CK: T1578.005
let lookback = 24h;
let threshold = 5;
AzureActivity
| where TimeGenerated > ago(lookback)
| where CategoryValue == "Administrative"
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    EventCount = count(),
    DistinctOperations = dcount(OperationNameValue),
    Operations = make_set(OperationNameValue, 20),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| where EventCount > threshold
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName,
    AccountDomain,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    EventCount,
    DistinctOperations,
    Operations,
    Resources
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

  description = "Detects Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations (T1578.005) activity in Azure environment"
  display_name = "Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1578.005"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations Detected",
                alert_description_template=(
                    "Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations activity detected. "
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
        "t1578-005-aws-quota",
        "t1578-005-gcp-quota",
        "t1578-005-aws-ec2-limits",
        "t1578-005-gcp-compute-policy",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+25% improvement for Defence Evasion tactic",
)
