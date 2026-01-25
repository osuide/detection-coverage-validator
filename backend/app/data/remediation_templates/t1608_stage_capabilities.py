"""
T1608 - Stage Capabilities

Adversaries upload, install, or configure capabilities on controlled infrastructure
to support targeting operations. Includes malware staging, tool deployment, and
infrastructure preparation.
Used by Mustang Panda.
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
    technique_id="T1608",
    technique_name="Stage Capabilities",
    tactic_ids=["TA0042"],
    mitre_url="https://attack.mitre.org/techniques/T1608/",
    threat_context=ThreatContext(
        description=(
            "Adversaries upload, install, or configure capabilities on infrastructure "
            "they control to support targeting operations. This includes staging malware, "
            "tools, digital certificates, drive-by targets, phishing links, and SEO poisoning. "
            "Infrastructure may be personally controlled servers, cloud platforms (GitHub, Pastebin), "
            "PaaS offerings (Heroku, Google App Engine, Azure App Service), or compromised websites."
        ),
        attacker_goal="Stage attack infrastructure and capabilities for future targeting operations",
        why_technique=[
            "Prepares infrastructure for attack execution",
            "Separates capability development from deployment",
            "Leverages cloud platforms for hosting",
            "Enables rapid deployment when targeting",
            "Reduces detection during initial staging",
            "Facilitates distributed attack infrastructure",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Resource Development technique that occurs outside organisational boundaries. "
            "Whilst difficult to detect directly, staging capabilities is a critical precursor "
            "to targeted attacks. Detection requires monitoring for abnormal cloud resource usage "
            "and external threat intelligence integration."
        ),
        business_impact=[
            "Precursor to targeted attacks",
            "Indicates active targeting preparation",
            "May abuse organisational cloud resources",
            "Enables sophisticated attack campaigns",
            "Facilitates multi-stage attacks",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1566", "T1189", "T1190", "T1204"],
        often_follows=["T1583", "T1584", "T1585", "T1586", "T1587"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1608-aws-s3-staging",
            name="AWS S3 Unauthorised Public Bucket Detection",
            description="Detect S3 buckets made public that may be used for staging capabilities.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, requestParameters.bucketName, userIdentity.principalId, eventName
| filter eventName like /PutBucketAcl|PutBucketPolicy|PutBucketPublicAccessBlock/
| filter requestParameters.accessControlList.grant.grantee.uri = "http://acs.amazonaws.com/groups/global/AllUsers"
   or requestParameters.publicAccessBlockConfiguration.blockPublicAcls = false
| stats count(*) as public_changes by requestParameters.bucketName, userIdentity.principalId
| sort public_changes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 buckets made public for staging capabilities

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

  S3PublicAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "PutBucketAcl" || $.eventName = "PutBucketPolicy") && $.requestParameters.accessControlList.grant.grantee.uri = "http://acs.amazonaws.com/groups/global/AllUsers" }'
      MetricTransformations:
        - MetricName: S3PublicAccess
          MetricNamespace: Security
          MetricValue: "1"

  S3PublicAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3BucketMadePublic
      MetricName: S3PublicAccess
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect S3 buckets made public for staging

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "s3-public-staging-alerts"
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

resource "aws_cloudwatch_log_metric_filter" "s3_public" {
  name           = "s3-public-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"PutBucketAcl\" || $.eventName = \"PutBucketPolicy\") && $.requestParameters.accessControlList.grant.grantee.uri = \"http://acs.amazonaws.com/groups/global/AllUsers\" }"

  metric_transformation {
    name      = "S3PublicAccess"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_staging" {
  alarm_name          = "S3BucketMadePublic"
  metric_name         = "S3PublicAccess"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="S3 Bucket Made Public",
                alert_description_template="S3 bucket {bucketName} made public by {principalId}.",
                investigation_steps=[
                    "Identify which bucket was made public",
                    "Review objects in the bucket for suspicious content",
                    "Check who made the change and verify authorisation",
                    "Review bucket access logs for unusual activity",
                    "Check for recently uploaded malware or tools",
                ],
                containment_actions=[
                    "Revert bucket to private if unauthorised",
                    "Review and remove suspicious objects",
                    "Enable S3 Block Public Access",
                    "Review IAM permissions for the principal",
                    "Enable S3 Object Lock if needed",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known legitimate public buckets (e.g., static website hosting)",
            detection_coverage="40% - only detects cloud staging in AWS S3",
            evasion_considerations="Adversaries may use private buckets, other cloud providers, or external infrastructure",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging enabled", "S3 data events logged"],
        ),
        DetectionStrategy(
            strategy_id="t1608-aws-lambda-staging",
            name="AWS Lambda Unauthorised Deployment Detection",
            description="Detect unauthorised Lambda function deployments that may stage capabilities.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.functionName, eventName
| filter eventName like /CreateFunction|UpdateFunctionCode/
| stats count(*) as deployments by userIdentity.principalId, requestParameters.functionName, bin(1h)
| filter deployments > 5
| sort deployments desc""",
                terraform_template="""# Detect suspicious Lambda deployments

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "lambda-staging-alerts"
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

resource "aws_cloudwatch_log_metric_filter" "lambda_deploy" {
  name           = "lambda-deployments"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"CreateFunction\" || $.eventName = \"UpdateFunctionCode\" }"

  metric_transformation {
    name      = "LambdaDeployments"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_staging" {
  alarm_name          = "SuspiciousLambdaDeployment"
  metric_name         = "LambdaDeployments"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious Lambda Function Deployment",
                alert_description_template="Multiple Lambda deployments by {principalId}.",
                investigation_steps=[
                    "Review Lambda function code for malicious content",
                    "Check function permissions and execution role",
                    "Verify deploying principal is authorised",
                    "Review function invocation logs",
                    "Check for unusual network connections",
                ],
                containment_actions=[
                    "Delete unauthorised functions",
                    "Review and restrict Lambda deployment permissions",
                    "Enable Lambda code signing",
                    "Review VPC and network configurations",
                    "Audit IAM roles attached to functions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on normal deployment patterns",
            detection_coverage="35% - only detects serverless staging in AWS",
            evasion_considerations="Adversaries may use other compute services or external infrastructure",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1608-aws-ec2-staging",
            name="AWS EC2 Instance Unusual Network Activity",
            description="Detect EC2 instances with unusual outbound connections indicating staging server behaviour.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, bytes
| filter action = "ACCEPT"
| filter dstport in [80, 443, 8080, 8443]
| stats sum(bytes) as total_bytes, count(*) as connections by srcaddr, bin(1h)
| filter total_bytes > 10000000 or connections > 1000
| sort total_bytes desc""",
                terraform_template="""# Detect EC2 staging server activity

variable "vpc_flow_logs_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "alerts" {
  name = "ec2-staging-alerts"
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

resource "aws_cloudwatch_log_metric_filter" "high_traffic" {
  name           = "high-outbound-traffic"
  log_group_name = var.vpc_flow_logs_group
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes > 10000000, windowstart, windowend, action=\"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "HighOutboundTraffic"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "staging_server" {
  alarm_name          = "EC2StagingServerActivity"
  metric_name         = "HighOutboundTraffic"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="EC2 Instance Unusual Network Activity",
                alert_description_template="High outbound traffic from {srcaddr}.",
                investigation_steps=[
                    "Identify the EC2 instance generating traffic",
                    "Review instance purpose and ownership",
                    "Check destination IPs and domains",
                    "Review instance for malicious files or tools",
                    "Check CloudTrail for instance creation/modification",
                ],
                containment_actions=[
                    "Isolate suspicious instances",
                    "Review and restrict security group rules",
                    "Take instance snapshot for forensics",
                    "Terminate unauthorised instances",
                    "Review IAM permissions for instance launch",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Baseline normal traffic patterns and adjust thresholds per environment",
            detection_coverage="30% - only detects high-traffic staging servers",
            evasion_considerations="Low-traffic staging or external infrastructure will evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1608-gcp-storage-staging",
            name="GCP Cloud Storage Unauthorised Public Bucket Detection",
            description="Detect Cloud Storage buckets made public that may be used for staging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName=~"storage.setIamPermissions|storage.buckets.setIamPolicy"
protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
protoPayload.serviceData.policyDelta.bindingDeltas.member="allUsers"''',
                gcp_terraform_template="""# GCP: Detect Cloud Storage buckets made public

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "public_bucket" {
  project = var.project_id
  name   = "public-storage-bucket"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName=~"storage.setIamPermissions|storage.buckets.setIamPolicy"
    protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
    protoPayload.serviceData.policyDelta.bindingDeltas.member="allUsers"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "storage_staging" {
  project      = var.project_id
  display_name = "Cloud Storage Staging Detection"
  combiner     = "OR"
  conditions {
    display_name = "Public bucket created"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.public_bucket.name}\""
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
                alert_severity="medium",
                alert_title="GCP: Cloud Storage Bucket Made Public",
                alert_description_template="Cloud Storage bucket made publicly accessible.",
                investigation_steps=[
                    "Identify which bucket was made public",
                    "Review objects for malicious content",
                    "Check who made the change",
                    "Review bucket access logs",
                    "Check for recently uploaded files",
                ],
                containment_actions=[
                    "Revert bucket to private access",
                    "Remove suspicious objects",
                    "Review IAM permissions",
                    "Enable uniform bucket-level access",
                    "Enable Object Versioning for recovery",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known legitimate public buckets",
            detection_coverage="40% - only detects GCP cloud staging",
            evasion_considerations="Adversaries may use private buckets or external infrastructure",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1608-gcp-functions-staging",
            name="GCP Cloud Functions Unauthorised Deployment Detection",
            description="Detect unauthorised Cloud Functions deployments that may stage capabilities.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
protoPayload.methodName=~"google.cloud.functions.v1.CloudFunctionsService.CreateFunction|google.cloud.functions.v1.CloudFunctionsService.UpdateFunction"''',
                gcp_terraform_template="""# GCP: Detect Cloud Functions deployment for staging

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "function_deploy" {
  project = var.project_id
  name   = "cloud-function-deployments"
  filter = <<-EOT
    resource.type="cloud_function"
    protoPayload.methodName=~"google.cloud.functions.v1.CloudFunctionsService.CreateFunction|google.cloud.functions.v1.CloudFunctionsService.UpdateFunction"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "function_staging" {
  project      = var.project_id
  display_name = "Cloud Functions Staging Detection"
  combiner     = "OR"
  conditions {
    display_name = "Multiple function deployments"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_deploy.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
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
                alert_severity="medium",
                alert_title="GCP: Suspicious Cloud Functions Deployment",
                alert_description_template="Multiple Cloud Functions deployments detected.",
                investigation_steps=[
                    "Review function source code",
                    "Check function permissions and service account",
                    "Verify deploying principal is authorised",
                    "Review function execution logs",
                    "Check for unusual network access",
                ],
                containment_actions=[
                    "Delete unauthorised functions",
                    "Restrict Cloud Functions deployment permissions",
                    "Review service account permissions",
                    "Enable VPC Service Controls",
                    "Audit IAM bindings",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on deployment frequency",
            detection_coverage="35% - only detects GCP serverless staging",
            evasion_considerations="Adversaries may use other compute services or external infrastructure",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Stage Capabilities
        DetectionStrategy(
            strategy_id="t1608-azure",
            name="Azure Stage Capabilities Detection",
            description=(
                "Azure detection for Stage Capabilities. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Stage Capabilities (T1608)
# Microsoft Defender detects Stage Capabilities activity

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
  name                = "defender-t1608-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1608"
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

  description = "Microsoft Defender detects Stage Capabilities activity"
  display_name = "Defender: Stage Capabilities"
  enabled      = true

  tags = {
    "mitre-technique" = "T1608"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Stage Capabilities Detected",
                alert_description_template=(
                    "Stage Capabilities activity detected. "
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
        "t1608-aws-s3-staging",
        "t1608-gcp-storage-staging",
        "t1608-aws-lambda-staging",
        "t1608-gcp-functions-staging",
        "t1608-aws-ec2-staging",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+15% improvement for Resource Development tactic",
)
