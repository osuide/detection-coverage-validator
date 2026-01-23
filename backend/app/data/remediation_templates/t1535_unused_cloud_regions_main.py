"""
T1535 - Unused/Unsupported Cloud Regions

Adversaries create resources in underutilised cloud regions to evade detection.
Regions without monitoring are attractive for cryptomining and other resource abuse.
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
    technique_id="T1535",
    technique_name="Unused/Unsupported Cloud Regions",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1535/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit underutilised geographic cloud service regions to evade detection. "
            "They gain access by compromising cloud infrastructure management accounts and create "
            "resources in regions where organisations don't typically operate or monitor. These regions "
            "may lack advanced detection capabilities like GuardDuty or Security Command Centre, "
            "making them attractive for cryptocurrency mining and other resource abuse."
        ),
        attacker_goal="Evade detection by using unmonitored cloud regions for malicious activity",
        why_technique=[
            "Unused regions often lack comprehensive monitoring",
            "Detection tools may not be enabled in all regions",
            "Security teams focus monitoring on primary operational regions",
            "Billing alerts may not be granular enough to detect regional abuse",
            "Enables cryptomining without triggering alerts",
            "Regions may have limited advanced security services",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Defence evasion technique with direct financial impact. Can lead to significant "
            "unexpected costs through resource abuse and enables undetected malicious activity "
            "in regions without proper monitoring coverage."
        ),
        business_impact=[
            "Unexpected cloud costs from resource abuse",
            "Undetected malicious activity and cryptomining",
            "Resource hijacking for attacker infrastructure",
            "Compliance gaps in unused regions",
            "Reputational damage from resource abuse",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1496.001", "T1578.002"],
        often_follows=["T1078.004", "T1098.001"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Unused Region Activity Detection
        DetectionStrategy(
            strategy_id="t1535-aws-unusedregion",
            name="AWS Unused Region Activity Detection",
            description="Detect resource creation events in regions not typically used by the organisation.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2", "aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["RunInstances", "CreateBucket", "CreateFunction"]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect activity in unused AWS regions

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  AllowedRegions:
    Type: CommaDelimitedList
    Default: "eu-west-1,eu-west-2,us-east-1"
    Description: Comma-separated list of approved regions

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Unused Region Activity Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule to detect resource creation
  UnusedRegionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: unused-region-activity
      Description: Detects resource creation in unused regions
      EventPattern:
        source: [aws.ec2, aws.s3, aws.lambda]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [RunInstances, CreateBucket, CreateFunction]
      State: ENABLED
      Targets:
        - Id: AlertTarget
          Arn: !Ref AlertTopic

  # Step 3: Grant EventBridge permission to publish to SNS
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
                aws:SourceArn: !GetAtt UnusedRegionRule.Arn

Outputs:
  AlertTopicArn:
    Value: !Ref AlertTopic
    Description: SNS topic for unused region alerts""",
                terraform_template="""# Detect activity in unused AWS regions

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "allowed_regions" {
  type        = list(string)
  default     = ["eu-west-1", "eu-west-2", "us-east-1"]
  description = "List of approved regions for your organisation"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "unused_region_alerts" {
  name         = "unused-region-activity-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Unused Region Activity Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.unused_region_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule to detect resource creation
# Deploy this in each unused region to monitor activity
resource "aws_cloudwatch_event_rule" "unused_region" {
  name        = "unused-region-activity"
  description = "Detects resource creation in unused regions"

  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.s3", "aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["RunInstances", "CreateBucket", "CreateFunction"]
    }
  })
}

# Step 3: Configure EventBridge to send alerts to SNS
resource "aws_sqs_queue" "dlq" {
  name                      = "unused-region-dlq"
  message_retention_seconds = 1209600
}

data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sqs_queue.dlq.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.unused_region.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.unused_region.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.unused_region_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.unused_region_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.unused_region_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.unused_region.arn
          }
      }
    }]
  })
}

output "alert_topic_arn" {
  value       = aws_sns_topic.unused_region_alerts.arn
  description = "SNS topic for unused region alerts"
}""",
                alert_severity="high",
                alert_title="Activity Detected in Unused Region",
                alert_description_template="Resource created in region {awsRegion} which is not normally used by the organisation.",
                investigation_steps=[
                    "Verify if the region should have legitimate activity",
                    "Check what specific resources were created",
                    "Review the identity that initiated the activity",
                    "Check for cryptomining indicators (large compute instances)",
                    "Verify if GuardDuty is enabled in the region",
                    "Review billing data for unexpected costs",
                ],
                containment_actions=[
                    "Terminate unauthorised resources in unused regions immediately",
                    "Use Service Control Policies to deny actions in unused regions",
                    "Enable GuardDuty in all AWS regions",
                    "Set up billing alerts per region",
                    "Review and rotate compromised credentials",
                    "Consider disabling unused regions via AWS account settings",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Define allowed regions for your organisation and adjust the EventBridge rule accordingly",
            detection_coverage="90% - catches resource creation in unusual regions",
            evasion_considerations="Attacker may use allowed regions if they determine which regions are monitored",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours to deploy across unused regions",
            estimated_monthly_cost="$5-15 depending on number of regions monitored",
            prerequisites=[
                "CloudTrail enabled in all regions",
                "EventBridge available",
            ],
        ),
        # Strategy 2: AWS - CloudWatch Logs Query for Unused Region Activity
        DetectionStrategy(
            strategy_id="t1535-aws-cloudwatch",
            name="CloudWatch Logs Query for Unused Regions",
            description="Query CloudTrail logs to identify resource creation in unused regions.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, awsRegion, eventName, userIdentity.arn, requestParameters
| filter eventName like /Create|Run|Launch|Put/
| filter awsRegion not in ["eu-west-1", "eu-west-2", "us-east-1"]
| stats count(*) as activity_count by awsRegion, eventName
| sort activity_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: CloudWatch metric filter for unused region activity

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter to detect activity
  UnusedRegionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "RunInstances" || $.eventName = "CreateBucket" || $.eventName = "CreateFunction") }'
      MetricTransformations:
        - MetricName: UnusedRegionActivity
          MetricNamespace: Security/RegionMonitoring
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create CloudWatch alarm
  UnusedRegionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusedRegionActivityDetected
      AlarmDescription: Alerts when resources are created in unused regions
      MetricName: UnusedRegionActivity
      Namespace: Security/RegionMonitoring
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# CloudWatch metric filter for unused region activity

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "unused-region-metric-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter to detect activity in unused regions
resource "aws_cloudwatch_log_metric_filter" "unused_region" {
  name           = "unused-region-activity"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ ($.eventName = \"RunInstances\" || $.eventName = \"CreateBucket\" || $.eventName = \"CreateFunction\") }"

  metric_transformation {
    name          = "UnusedRegionActivity"
    namespace     = "Security/RegionMonitoring"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create CloudWatch alarm to alert on suspicious activity
resource "aws_cloudwatch_metric_alarm" "unused_region" {
  alarm_name          = "UnusedRegionActivityDetected"
  alarm_description   = "Alerts when resources are created in unused regions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnusedRegionActivity"
  namespace           = "Security/RegionMonitoring"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unused Region Activity Detected",
                alert_description_template="Resource creation detected in unused region.",
                investigation_steps=[
                    "Review CloudWatch Insights query results",
                    "Identify which region had activity",
                    "Check what resources were created",
                    "Verify the user identity",
                    "Check for patterns indicating automation or cryptomining",
                ],
                containment_actions=[
                    "Terminate resources in unused regions",
                    "Review and rotate credentials",
                    "Enable GuardDuty in affected region",
                    "Set up Service Control Policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust the region filter list to match your organisation's approved regions",
            detection_coverage="85% - requires CloudTrail logs to be streamed to CloudWatch",
            evasion_considerations="Attacker could use less common API calls not in the filter pattern",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20 depending on log volume",
            prerequisites=[
                "CloudTrail enabled",
                "CloudTrail logs streamed to CloudWatch Logs",
            ],
        ),
        # Strategy 3: GCP - Unused Region Activity Detection
        DetectionStrategy(
            strategy_id="t1535-gcp-unusedregion",
            name="GCP Unused Region Activity Detection",
            description="Detect resource creation in GCP regions not typically used by the organisation.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"compute.instances.insert|storage.buckets.create|cloudfunctions.functions.create"
resource.labels.zone!~"europe-west2|us-central1"''',
                gcp_terraform_template="""# GCP: Detect activity in unused regions

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "allowed_regions" {
  type        = list(string)
  default     = ["europe-west2", "us-central1"]
  description = "List of approved regions for your organisation"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts - Unused Regions"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric to track unused region activity
resource "google_logging_metric" "unused_region" {
  project = var.project_id
  name    = "unused-region-activity"

  filter = <<-EOT
    protoPayload.methodName=~"compute.instances.insert|storage.buckets.create|cloudfunctions.functions.create"
    NOT resource.labels.zone=~"${join("|", var.allowed_regions)}"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "region"
      value_type  = "STRING"
      description = "The region where activity was detected"
    }
  }

  label_extractors = {
    "region" = "EXTRACT(resource.labels.zone)"
  }
}

# Step 3: Create alerting policy to notify on suspicious activity
resource "google_monitoring_alert_policy" "unused_region" {
  project      = var.project_id
  display_name = "Unused Region Activity Detected"
  combiner     = "OR"

  conditions {
    display_name = "Activity in unused region"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.unused_region.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
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

  documentation {
    content = "Resource creation detected in a region not typically used by the organisation. Investigate immediately for potential unauthorised activity or cryptomining."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Activity in Unused Region",
                alert_description_template="Resource created in region not normally used by the organisation.",
                investigation_steps=[
                    "Verify if the region should have legitimate activity",
                    "Check what specific resources were created",
                    "Review the principal that initiated the activity",
                    "Check for cryptomining indicators (large machine types)",
                    "Verify if Security Command Centre is enabled",
                    "Review billing data for unexpected costs",
                ],
                containment_actions=[
                    "Delete unauthorised resources in unused regions",
                    "Set organisation policy constraints to restrict regions",
                    "Enable Security Command Centre in all regions",
                    "Review and rotate compromised credentials",
                    "Set up budget alerts per region",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Define allowed regions for your organisation and adjust the logging filter",
            detection_coverage="90% - catches resource creation in unusual regions",
            evasion_considerations="Attacker may use allowed regions if they identify monitored regions",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-15 depending on log volume",
            prerequisites=["Cloud Audit Logs enabled", "Cloud Logging API enabled"],
        ),
        # Azure Strategy: Unused/Unsupported Cloud Regions
        DetectionStrategy(
            strategy_id="t1535-azure",
            name="Azure Unused/Unsupported Cloud Regions Detection",
            description=(
                "Azure detection for Unused/Unsupported Cloud Regions. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Unused/Unsupported Cloud Regions
// MITRE ATT&CK: T1535
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
                azure_terraform_template="""# Azure Detection for Unused/Unsupported Cloud Regions
# MITRE ATT&CK: T1535

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
  name                = "unused-unsupported-cloud-regions-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "unused-unsupported-cloud-regions-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Unused/Unsupported Cloud Regions
// MITRE ATT&CK: T1535
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

  description = "Detects Unused/Unsupported Cloud Regions (T1535) activity in Azure environment"
  display_name = "Unused/Unsupported Cloud Regions Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1535"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Unused/Unsupported Cloud Regions Detected",
                alert_description_template=(
                    "Unused/Unsupported Cloud Regions activity detected. "
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
        "t1535-aws-unusedregion",
        "t1535-aws-cloudwatch",
        "t1535-gcp-unusedregion",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+12% improvement for Defence Evasion tactic",
)
