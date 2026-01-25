"""
T1583.006 - Acquire Infrastructure: Web Services

Adversaries register for web-based services during targeting to support later
attack stages. Popular platforms like Google, GitHub, and Twitter are abused
because they blend operations into expected network traffic.
Used by APT17, APT28, APT29, APT32, Lazarus Group, Kimsuky, MuddyWater.
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
    technique_id="T1583.006",
    technique_name="Acquire Infrastructure: Web Services",
    tactic_ids=["TA0042"],
    mitre_url="https://attack.mitre.org/techniques/T1583/006/",
    threat_context=ThreatContext(
        description=(
            "Adversaries register for web-based services during the targeting phase "
            "to support later attack stages. Popular platforms like Google Drive, GitHub, "
            "Dropbox, and social media are abused because they blend malicious operations "
            "into expected network traffic. This approach allows threat actors to obscure "
            "connections to their infrastructure for C2, data exfiltration, and malware hosting."
        ),
        attacker_goal="Register web services to support command and control, data exfiltration, or malware hosting",
        why_technique=[
            "Blends into normal network traffic",
            "Trusted domains bypass security controls",
            "Free and easy to register",
            "Difficult to block legitimate services",
            "Provides plausible deniability",
            "Often has generous bandwidth/storage",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Occurs during pre-compromise phase, making direct prevention difficult. "
            "Successful abuse can enable sophisticated C2 channels and data exfiltration "
            "that bypasses traditional security controls. Detection relies on post-compromise indicators."
        ),
        business_impact=[
            "Enables covert command and control",
            "Facilitates data exfiltration",
            "Difficult to detect and block",
            "Increases attack sophistication",
            "Complicates incident response",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1102", "T1567", "T1071"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1583-006-aws-cloudtrail-web",
            name="AWS CloudTrail Unusual Web Service Access",
            description="Detect unusual access patterns to known cloud storage and web services from AWS resources.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, sourceIPAddress, userAgent, requestParameters.bucketName, eventName
| filter eventSource = "s3.amazonaws.com"
| filter eventName IN ["PutObject", "GetObject", "ListBucket"]
| filter requestParameters.bucketName not like /^(your-org|company|internal)/
| filter userAgent like /(aws-cli|boto3|curl|wget|powershell)/
| stats count(*) as requests by sourceIPAddress, userAgent, bin(1h)
| filter requests > 100
| sort requests desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious web service usage patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for alerts

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

  WebServiceAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "s3.amazonaws.com") && ($.userAgent = "*curl*" || $.userAgent = "*wget*" || $.userAgent = "*powershell*") }'
      MetricTransformations:
        - MetricName: SuspiciousWebServiceAccess
          MetricNamespace: Security/WebServices
          MetricValue: "1"

  WebServiceAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousWebServiceAccess
      MetricName: SuspiciousWebServiceAccess
      Namespace: Security/WebServices
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious web service access patterns

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "web_service_alerts" {
  name = "web-service-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.web_service_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.web_service_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.web_service_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "web_service_access" {
  name           = "suspicious-web-service-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.userAgent = \"*curl*\" || $.userAgent = \"*wget*\" || $.userAgent = \"*powershell*\") }"

  metric_transformation {
    name      = "SuspiciousWebServiceAccess"
    namespace = "Security/WebServices"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "web_service_abuse" {
  alarm_name          = "SuspiciousWebServiceAccess"
  metric_name         = "SuspiciousWebServiceAccess"
  namespace           = "Security/WebServices"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.web_service_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious Web Service Access Detected",
                alert_description_template="Unusual web service access from {sourceIPAddress} using {userAgent}.",
                investigation_steps=[
                    "Review the source IP and associated AWS resources",
                    "Check if the user agent matches expected tools",
                    "Examine the accessed buckets and objects",
                    "Correlate with other suspicious activities",
                    "Review IAM credentials and access patterns",
                ],
                containment_actions=[
                    "Disable compromised IAM credentials",
                    "Block suspicious IP addresses",
                    "Review S3 bucket policies",
                    "Enable MFA for sensitive operations",
                    "Implement SCPs to restrict external services",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter out legitimate automation and backup tools. Adjust user agent patterns for your environment.",
            detection_coverage="40% - detects automated tool usage but misses browser-based access",
            evasion_considerations="Attackers can use legitimate browsers or custom user agents to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "CloudWatch Logs integration",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1583-006-aws-vpc-flow",
            name="AWS VPC Flow Logs Web Service Detection",
            description="Detect connections to known cloud storage and file-sharing services via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, bytes
| filter dstaddr like /dropbox|github|pastebin|telegram|discord/
| stats sum(bytes) as totalBytes by srcaddr, dstaddr, bin(1h)
| filter totalBytes > 100000000
| sort totalBytes desc""",
                terraform_template="""# Detect high-volume connections to web services

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "web_service_traffic" {
  name = "web-service-traffic-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.web_service_traffic.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.web_service_traffic.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.web_service_traffic.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "web_service_connections" {
  name           = "web-service-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action, flowlogstatus]"

  metric_transformation {
    name      = "WebServiceConnections"
    namespace = "Security/Network"
    value     = "$bytes"
  }
}

resource "aws_cloudwatch_metric_alarm" "high_web_service_traffic" {
  alarm_name          = "HighWebServiceTraffic"
  metric_name         = "WebServiceConnections"
  namespace           = "Security/Network"
  statistic           = "Sum"
  period              = 300
  threshold           = 100000000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.web_service_traffic.arn]
}""",
                alert_severity="medium",
                alert_title="High-Volume Web Service Traffic",
                alert_description_template="Significant data transfer to web service from {srcaddr}.",
                investigation_steps=[
                    "Identify the source instance or resource",
                    "Review the destination service",
                    "Check volume and frequency of transfers",
                    "Correlate with authorised activities",
                    "Review instance security and access logs",
                ],
                containment_actions=[
                    "Isolate affected instances",
                    "Block unauthorised destinations via NACLs",
                    "Review and rotate credentials",
                    "Implement DLP controls",
                    "Enable GuardDuty for enhanced detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Exclude known legitimate backup and sync services. Adjust byte thresholds based on baseline.",
            detection_coverage="50% - detects high-volume transfers but requires DNS resolution for accuracy",
            evasion_considerations="Small, frequent transfers may evade volume-based detection. Encrypted traffic hides content.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled", "DNS logging for resolution"],
        ),
        DetectionStrategy(
            strategy_id="t1583-006-gcp-cloud-logging",
            name="GCP Cloud Logging Web Service Access",
            description="Detect unusual access to cloud storage and web services from GCP resources.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName=~"storage.objects.(get|create|list)"
protoPayload.requestMetadata.callerSuppliedUserAgent=~"(curl|wget|powershell|python-requests)"
severity>="WARNING"''',
                gcp_terraform_template="""# GCP: Detect suspicious web service access

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Web Service Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "web_service_access" {
  project = var.project_id
  name   = "suspicious-web-service-access"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName=~"storage.objects.(get|create|list)"
    protoPayload.requestMetadata.callerSuppliedUserAgent=~"(curl|wget|powershell|python-requests)"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "web_service_abuse" {
  project      = var.project_id
  display_name = "Suspicious Web Service Access"
  combiner     = "OR"
  conditions {
    display_name = "High access rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.web_service_access.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
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
                alert_title="GCP: Suspicious Web Service Access",
                alert_description_template="Unusual web service access detected in GCP project.",
                investigation_steps=[
                    "Review the service account or user",
                    "Check the accessed buckets and objects",
                    "Examine user agent and request patterns",
                    "Correlate with authorised activities",
                    "Review IAM permissions and policies",
                ],
                containment_actions=[
                    "Disable compromised service accounts",
                    "Review and tighten IAM policies",
                    "Enable VPC Service Controls",
                    "Implement organisation policies",
                    "Enable Data Loss Prevention scanning",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known automation tools and CI/CD pipelines. Adjust user agent patterns.",
            detection_coverage="45% - detects automated access but not browser-based",
            evasion_considerations="Custom user agents and browser-based access evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["Cloud Logging enabled", "Storage audit logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1583-006-gcp-vpc-flow",
            name="GCP VPC Flow Logs External Service Detection",
            description="Monitor network connections to external web services from GCP resources.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName=~".*vpc_flows.*"
jsonPayload.connection.dest_ip=~"(.*dropbox.*|.*github.*|.*pastebin.*|.*telegram.*)"
jsonPayload.bytes_sent > 100000000""",
                gcp_terraform_template="""# GCP: Monitor high-volume web service connections

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Network Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "web_service_traffic" {
  project = var.project_id
  name   = "high-web-service-traffic"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~".*vpc_flows.*"
    jsonPayload.bytes_sent > 100000000
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "By"
  }
  value_extractor = "EXTRACT(jsonPayload.bytes_sent)"
}

resource "google_monitoring_alert_policy" "high_traffic" {
  project      = var.project_id
  display_name = "High Web Service Traffic"
  combiner     = "OR"
  conditions {
    display_name = "Large data transfer"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.web_service_traffic.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100000000
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_SUM"
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
                alert_title="GCP: High-Volume Web Service Traffic",
                alert_description_template="Significant data transfer to external web service detected.",
                investigation_steps=[
                    "Identify source VM or service",
                    "Review destination service",
                    "Check data volume and patterns",
                    "Correlate with business activities",
                    "Review VM security and access",
                ],
                containment_actions=[
                    "Isolate affected VMs",
                    "Configure firewall rules to block",
                    "Review and rotate credentials",
                    "Enable VPC Service Controls",
                    "Implement DLP policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Baseline normal traffic patterns and exclude legitimate services. Adjust threshold.",
            detection_coverage="50% - volume-based detection misses small transfers",
            evasion_considerations="Low-and-slow exfiltration evades volume thresholds. Encrypted tunnels hide destinations.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$20-35",
            prerequisites=["VPC Flow Logs enabled", "Cloud DNS logging"],
        ),
        # Azure Strategy: Acquire Infrastructure: Web Services
        DetectionStrategy(
            strategy_id="t1583006-azure",
            name="Azure Acquire Infrastructure: Web Services Detection",
            description=(
                "Azure detection for Acquire Infrastructure: Web Services. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "Communication with suspicious domain identified by threat intelligence",
                    "Anonymity network activity",
                    "Communication with suspicious algorithmically generated domain",
                ],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Acquire Infrastructure: Web Services (T1583.006)
# Microsoft Defender detects Acquire Infrastructure: Web Services activity

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
  name                = "defender-t1583-006-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1583-006"
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

                    "Communication with suspicious domain identified by threat intelligence",
                    "Anonymity network activity",
                    "Communication with suspicious algorithmically generated domain"
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

  description = "Microsoft Defender detects Acquire Infrastructure: Web Services activity"
  display_name = "Defender: Acquire Infrastructure: Web Services"
  enabled      = true

  tags = {
    "mitre-technique" = "T1583.006"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Acquire Infrastructure: Web Services Detected",
                alert_description_template=(
                    "Acquire Infrastructure: Web Services activity detected. "
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
        "t1583-006-aws-cloudtrail-web",
        "t1583-006-gcp-cloud-logging",
        "t1583-006-aws-vpc-flow",
        "t1583-006-gcp-vpc-flow",
    ],
    total_effort_hours=10.0,
    coverage_improvement="+15% improvement for Resource Development tactic detection",
)
