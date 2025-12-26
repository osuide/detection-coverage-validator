"""
T1588.002 - Obtain Capabilities: Tool

Adversaries acquire software tools to support malicious operations. These tools
differ from malware as they weren't designed for harm but are repurposed by
threat actors. Used by APT29, APT32, APT41, Lazarus Group, FIN7, Wizard Spider.
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
    technique_id="T1588.002",
    technique_name="Obtain Capabilities: Tool",
    tactic_ids=["TA0042"],
    mitre_url="https://attack.mitre.org/techniques/T1588/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries acquire software tools—whether open or closed source, free or "
            "commercial—to support malicious operations. These tools differ from malware "
            "in that they weren't originally designed for harmful purposes but are "
            "repurposed by threat actors. Common tools include Cobalt Strike, Mimikatz, "
            "PowerSploit, BloodHound, and Metasploit. Detection focuses on identifying "
            "tool-related indicators post-compromise such as watermarks, compilation times, "
            "and configuration patterns."
        ),
        attacker_goal="Acquire legitimate tools to support post-compromise operations and evade detection",
        why_technique=[
            "Tools appear legitimate reducing detection risk",
            "Widely available for free or purchase",
            "Extensively documented with tutorials",
            "Can blend with legitimate admin tools",
            "Cracked versions bypass licence restrictions",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Whilst tool acquisition occurs pre-compromise, successful detection of tool "
            "indicators can reveal active compromises. Tools like Cobalt Strike and Mimikatz "
            "are consistently used in high-impact ransomware and APT campaigns."
        ),
        business_impact=[
            "Enables credential theft and lateral movement",
            "Facilitates ransomware deployment",
            "Supports long-term persistent access",
            "Enables cloud infrastructure compromise",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1059", "T1003", "T1078", "T1069"],
        often_follows=["T1583", "T1584"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1588-002-aws-guardduty",
            name="AWS GuardDuty Tool Behaviour Detection",
            description="Detect suspicious tool execution patterns via GuardDuty findings.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.type, detail.service.action.actionType, detail.resource.instanceDetails.instanceId
| filter detail.type like /CryptoCurrency|Backdoor|Trojan|Behavior/
| filter detail.service.action.actionType = "NETWORK_CONNECTION"
| stats count(*) as findings by detail.resource.instanceDetails.instanceId, detail.type, bin(1h)
| sort findings desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect malicious tool execution via GuardDuty

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: malicious-tool-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule to catch GuardDuty findings
  GuardDutyToolRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-tool-detection
      Description: Detect malicious tool execution patterns
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Backdoor:"
            - prefix: "Trojan:"
            - prefix: "Behavior:"
            - prefix: "CryptoCurrency:"
      State: ENABLED
      Targets:
        - Arn: !Ref SecurityAlertTopic
          Id: SNSTarget

  # Step 3: Grant EventBridge permission to publish to SNS
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref SecurityAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic""",
                terraform_template="""# Detect malicious tool execution via GuardDuty

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "security_alerts" {
  name = "malicious-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule to catch GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_tools" {
  name        = "guardduty-tool-detection"
  description = "Detect malicious tool execution patterns"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:" },
        { prefix = "Trojan:" },
        { prefix = "Behavior:" },
        { prefix = "CryptoCurrency:" }
      ]
    }
  })
}

# Step 3: Send findings to SNS topic
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_tools.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.security_alerts.arn
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.security_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Malicious Tool Activity Detected",
                alert_description_template="GuardDuty detected suspicious tool behaviour on instance {instanceId}.",
                investigation_steps=[
                    "Review GuardDuty finding details and severity",
                    "Examine process execution history on affected instance",
                    "Check for known tool signatures (Mimikatz, Cobalt Strike watermarks)",
                    "Review network connections and data exfiltration attempts",
                    "Analyse authentication logs for credential access",
                ],
                containment_actions=[
                    "Isolate affected instances from network",
                    "Terminate suspicious processes",
                    "Rotate credentials accessed by affected systems",
                    "Review IAM permissions for compromised resources",
                    "Snapshot instance for forensic analysis",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are pre-tuned by AWS threat intelligence",
            detection_coverage="60% - catches known tool signatures and behaviours",
            evasion_considerations="Custom-compiled tools without signatures may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$0 (GuardDuty charges apply separately)",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1588-002-aws-s3-download",
            name="AWS S3 Suspicious Tool Downloads",
            description="Detect downloads of known tool packages from S3.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudtrail",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.bucketName, requestParameters.key
| filter eventName = "GetObject"
| filter requestParameters.key like /mimikatz|cobalt|meterpreter|empire|bloodhound|sharphound|rubeus|powersploit|invoke-/i
| stats count(*) as downloads by userIdentity.principalId, requestParameters.key, bin(1h)
| sort downloads desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious tool downloads from S3

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
      TopicName: s3-tool-download-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for suspicious downloads
  SuspiciousDownloadFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "GetObject") && ($.requestParameters.key = "*mimikatz*" || $.requestParameters.key = "*cobalt*" || $.requestParameters.key = "*meterpreter*" || $.requestParameters.key = "*bloodhound*" || $.requestParameters.key = "*rubeus*") }'
      MetricTransformations:
        - MetricName: SuspiciousToolDownloads
          MetricNamespace: Security/Tools
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for tool downloads
  ToolDownloadAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousS3ToolDownloads
      AlarmDescription: Alert on downloads of known attack tools
      MetricName: SuspiciousToolDownloads
      Namespace: Security/Tools
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# Detect suspicious tool downloads from S3

variable "cloudtrail_log_group" {
  description = "CloudTrail log group name"
  type        = string
}

variable "alert_email" {
  description = "Email address for alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "tool_download_alerts" {
  name = "s3-tool-download-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.tool_download_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious downloads
resource "aws_cloudwatch_log_metric_filter" "suspicious_downloads" {
  name           = "suspicious-tool-downloads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"GetObject\") && ($.requestParameters.key = \"*mimikatz*\" || $.requestParameters.key = \"*cobalt*\" || $.requestParameters.key = \"*meterpreter*\" || $.requestParameters.key = \"*bloodhound*\" || $.requestParameters.key = \"*rubeus*\") }"

  metric_transformation {
    name          = "SuspiciousToolDownloads"
    namespace     = "Security/Tools"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for tool downloads
resource "aws_cloudwatch_metric_alarm" "tool_downloads" {
  alarm_name          = "SuspiciousS3ToolDownloads"
  alarm_description   = "Alert on downloads of known attack tools"
  metric_name         = "SuspiciousToolDownloads"
  namespace           = "Security/Tools"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.tool_download_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Suspicious Tool Download from S3",
                alert_description_template="User {principalId} downloaded potential attack tool: {key}",
                investigation_steps=[
                    "Identify the IAM principal who downloaded the tool",
                    "Review CloudTrail logs for associated activity",
                    "Check if tool was executed on EC2 instances",
                    "Examine destination IP addresses and data transfers",
                    "Review S3 bucket access policies and permissions",
                ],
                containment_actions=[
                    "Suspend compromised IAM credentials",
                    "Remove suspicious files from S3",
                    "Review and restrict S3 bucket access policies",
                    "Scan instances for tool execution evidence",
                    "Enable S3 Object Lock for critical buckets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude security team buckets and legitimate penetration testing activities",
            detection_coverage="50% - catches known tool names in S3 downloads",
            evasion_considerations="Renamed files or encrypted archives will evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail with S3 data events enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1588-002-gcp-asset-inventory",
            name="GCP Asset Inventory Suspicious Software",
            description="Detect known attack tools installed on GCP instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_asset_inventory",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.insert"
protoPayload.request.metadata.items.key="startup-script"
(protoPayload.request.metadata.items.value=~"mimikatz" OR
 protoPayload.request.metadata.items.value=~"cobalt" OR
 protoPayload.request.metadata.items.value=~"meterpreter" OR
 protoPayload.request.metadata.items.value=~"bloodhound" OR
 protoPayload.request.metadata.items.value=~"empire")""",
                gcp_terraform_template="""# GCP: Detect suspicious tool installation

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email address for alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Team Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for suspicious tool installation
resource "google_logging_metric" "suspicious_tools" {
  project = var.project_id
  name    = "suspicious-tool-installation"
  filter  = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="v1.compute.instances.insert"
    protoPayload.request.metadata.items.key="startup-script"
    (protoPayload.request.metadata.items.value=~"mimikatz" OR
     protoPayload.request.metadata.items.value=~"cobalt" OR
     protoPayload.request.metadata.items.value=~"meterpreter" OR
     protoPayload.request.metadata.items.value=~"bloodhound" OR
     protoPayload.request.metadata.items.value=~"empire")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_name"
      value_type  = "STRING"
      description = "Instance with suspicious software"
    }
  }

  label_extractors = {
    instance_name = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "tool_installation" {
  project      = var.project_id
  display_name = "Suspicious Tool Installation"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious tool detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_tools.name}\" resource.type=\"gce_instance\""
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
    auto_close = "86400s"  # 24 hours
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious Tool Installation Detected",
                alert_description_template="Known attack tool detected on GCP instance in startup script.",
                investigation_steps=[
                    "Review instance creation logs and initiating principal",
                    "Examine instance metadata and startup scripts",
                    "Check for network connections from instance",
                    "Review IAM permissions for instance service account",
                    "Analyse other instances in same project for similar activity",
                ],
                containment_actions=[
                    "Stop affected GCP instances immediately",
                    "Disable compromised service accounts",
                    "Review and restrict VPC firewall rules",
                    "Take instance snapshots for forensics",
                    "Audit project-wide IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised security testing projects",
            detection_coverage="55% - detects tools in startup scripts and metadata",
            evasion_considerations="Post-deployment installations may not be detected",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging API enabled", "Compute Engine API enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1588-002-gcp-storage-download",
            name="GCP Cloud Storage Suspicious Downloads",
            description="Detect downloads of known attack tools from Cloud Storage.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_storage",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.get"
(protoPayload.resourceName=~"mimikatz" OR
 protoPayload.resourceName=~"cobalt" OR
 protoPayload.resourceName=~"meterpreter" OR
 protoPayload.resourceName=~"bloodhound" OR
 protoPayload.resourceName=~"sharphound" OR
 protoPayload.resourceName=~"rubeus" OR
 protoPayload.resourceName=~"powersploit")""",
                gcp_terraform_template="""# GCP: Detect suspicious tool downloads from Cloud Storage

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email address for alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for suspicious downloads
resource "google_logging_metric" "tool_downloads" {
  project = var.project_id
  name    = "suspicious-storage-downloads"
  filter  = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.get"
    (protoPayload.resourceName=~"mimikatz" OR
     protoPayload.resourceName=~"cobalt" OR
     protoPayload.resourceName=~"meterpreter" OR
     protoPayload.resourceName=~"bloodhound" OR
     protoPayload.resourceName=~"sharphound" OR
     protoPayload.resourceName=~"rubeus" OR
     protoPayload.resourceName=~"powersploit")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for downloads
resource "google_monitoring_alert_policy" "storage_downloads" {
  project      = var.project_id
  display_name = "Suspicious Cloud Storage Downloads"
  combiner     = "OR"

  conditions {
    display_name = "Known tool downloaded"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.tool_downloads.name}\""
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
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious Tool Downloaded from Cloud Storage",
                alert_description_template="Known attack tool downloaded from Cloud Storage bucket.",
                investigation_steps=[
                    "Identify the principal who downloaded the file",
                    "Review access logs for the storage bucket",
                    "Check where the file was downloaded to (instance, local)",
                    "Examine other activity from the same principal",
                    "Review bucket IAM policies and permissions",
                ],
                containment_actions=[
                    "Suspend compromised user accounts",
                    "Remove suspicious objects from buckets",
                    "Restrict bucket access with IAM conditions",
                    "Enable uniform bucket-level access",
                    "Review and rotate service account keys",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude security research and authorised red team storage locations",
            detection_coverage="50% - detects downloads with tool names in file paths",
            evasion_considerations="Obfuscated filenames and encrypted archives evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Storage data access logs enabled"],
        ),
    ],
    recommended_order=[
        "t1588-002-aws-guardduty",
        "t1588-002-gcp-asset-inventory",
        "t1588-002-aws-s3-download",
        "t1588-002-gcp-storage-download",
    ],
    total_effort_hours=3.0,
    coverage_improvement="+15% improvement for Resource Development tactic",
)
