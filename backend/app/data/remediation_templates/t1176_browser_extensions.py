"""
T1176 - Browser Extensions (Software Extensions)

Adversaries abuse browser extensions to establish persistent access to compromised systems,
steal credentials, and maintain command and control channels.
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
    technique_id="T1176",
    technique_name="Software Extensions",
    tactic_ids=["TA0003"],  # Persistence
    mitre_url="https://attack.mitre.org/techniques/T1176/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse internet browser extensions to establish persistent access "
            "to victim systems. Malicious browser extensions can harvest credentials, steal "
            "user data, browse websites in background, and serve as remote access trojan "
            "(RAT) installers. In cloud environments, this includes browser extensions on "
            "developer workstations, administrative jump boxes, cloud shell environments, "
            "and virtual desktops that access cloud consoles and sensitive resources."
        ),
        attacker_goal="Maintain persistent access and steal credentials via malicious browser extensions",
        why_technique=[
            "Browser extensions have broad access to browsing data including credentials",
            "Extensions can silently browse websites and steal form input",
            "Persist across reboots and system updates",
            "Difficult for users to detect malicious behaviour",
            "Extensions can serve as command and control channels",
            "Access to cloud console credentials and session tokens",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Browser extensions represent a significant persistence mechanism with direct "
            "access to credentials and session tokens. In cloud environments, compromised "
            "extensions on administrator workstations can capture cloud console credentials, "
            "API keys, and session tokens, enabling broader cloud infrastructure compromise. "
            "The technique is particularly dangerous due to its stealth and broad permissions."
        ),
        business_impact=[
            "Theft of cloud console credentials and session tokens",
            "Unauthorised access to cloud resources via stolen credentials",
            "Exfiltration of sensitive data entered in browsers",
            "Persistent backdoor access to corporate systems",
            "Compliance violations from credential theft",
            "Lateral movement using harvested credentials",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1078", "T1552", "T1539"],
        often_follows=["T1078.004", "T1566", "T1204"],
    ),
    detection_strategies=[
        # Strategy 1: AWS WorkSpaces Browser Extension Monitoring
        DetectionStrategy(
            strategy_id="t1176-aws-workspaces",
            name="AWS WorkSpaces Browser Extension Installation Monitoring",
            description=(
                "Monitor AWS WorkSpaces and Windows EC2 instances for browser extension "
                "installations followed by unusual network activity or file access patterns."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, instanceId, processName, commandLine, networkDestination
| filter @message like /chrome.exe|firefox.exe|msedge.exe/
| filter @message like /extensions|add-ons|[.]crx|[.]xpi/
| filter networkDestination not like /(chrome.google.com|addons.mozilla.org|microsoftedge.microsoft.com)/
| stats count() as suspiciousActivity by instanceId, processName, bin(10m)
| filter suspiciousActivity > 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect browser extension installations on WorkSpaces and EC2

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group for WorkSpaces/EC2 instance logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  ExtensionAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: browser-extension-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for extension installations
  BrowserExtensionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process="*chrome.exe*" || process="*firefox.exe*", activity="*extensions*" || activity="*.crx*" || activity="*.xpi*"]'
      MetricTransformations:
        - MetricName: BrowserExtensionActivity
          MetricNamespace: Security/T1176
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for suspicious extension activity
  ExtensionActivityAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1176-BrowserExtensionInstallation
      AlarmDescription: Suspicious browser extension activity detected
      MetricName: BrowserExtensionActivity
      Namespace: Security/T1176
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref ExtensionAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref ExtensionAlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref ExtensionAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId

Outputs:
  SNSTopicArn:
    Description: SNS topic for browser extension alerts
    Value: !Ref ExtensionAlertTopic""",
                terraform_template="""# AWS: Monitor browser extension installations

variable "cloudwatch_log_group" {
  description = "Log group for WorkSpaces/EC2 instance logs"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "extension_alerts" {
  name = "browser-extension-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.extension_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for extension installations
resource "aws_cloudwatch_log_metric_filter" "browser_extensions" {
  name           = "browser-extension-activity"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process=\"*chrome.exe*\" || process=\"*firefox.exe*\", activity=\"*extensions*\" || activity=\"*.crx*\" || activity=\"*.xpi*\"]"

  metric_transformation {
    name          = "BrowserExtensionActivity"
    namespace     = "Security/T1176"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious extension activity
resource "aws_cloudwatch_metric_alarm" "extension_activity" {
  alarm_name          = "T1176-BrowserExtensionInstallation"
  alarm_description   = "Suspicious browser extension activity detected"
  metric_name         = "BrowserExtensionActivity"
  namespace           = "Security/T1176"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.extension_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.extension_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.extension_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Suspicious Browser Extension Activity Detected",
                alert_description_template=(
                    "Browser extension installation detected on instance {instance_id}. "
                    "Process: {process_name}. Multiple suspicious extension activities observed. "
                    "This may indicate malicious extension installation."
                ),
                investigation_steps=[
                    "Review the WorkSpaces or EC2 instance logs for full extension installation details",
                    "Identify which browser and extension was installed",
                    "Check the extension source and publisher",
                    "Review user activity during the installation timeframe",
                    "Examine network connections made by the browser after installation",
                    "Check for credential access or data exfiltration patterns",
                    "Verify if extension is from official store or sideloaded",
                ],
                containment_actions=[
                    "Disable or remove the suspicious browser extension",
                    "Terminate user session on affected WorkSpace/instance",
                    "Rotate credentials for any accounts accessed from the browser",
                    "Block extension installation via Group Policy",
                    "Isolate the affected instance from network",
                    "Review browser sync settings to prevent propagation",
                    "Implement browser extension allowlist policy",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist approved corporate extensions; establish extension approval process",
            detection_coverage="65% - detects extension installation patterns on monitored instances",
            evasion_considerations="Silent installations via registry manipulation may bypass logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20 depending on log volume",
            prerequisites=[
                "CloudWatch Logs Agent on instances",
                "Process and file system logging enabled",
            ],
        ),
        # Strategy 2: AWS GuardDuty Malware Detection
        DetectionStrategy(
            strategy_id="t1176-aws-guardduty",
            name="AWS GuardDuty Malicious File Detection for Extensions",
            description=(
                "Use AWS GuardDuty Runtime Monitoring and Malware Protection to detect "
                "malicious browser extension files and suspicious execution patterns."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:EC2/MaliciousFile",
                    "Execution:Runtime/NewBinaryExecuted",
                    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                    "Execution:Runtime/MaliciousFileExecuted",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty detection for malicious browser extensions

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Ensure GuardDuty has Malware Protection enabled
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: RUNTIME_MONITORING
          Status: ENABLED
        - Name: EBS_MALWARE_PROTECTION
          Status: ENABLED

  # Step 2: Create SNS topic for alerts
  MalwareAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: guardduty-malware-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create DLQ for reliability
  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: guardduty-malware-alerts-dlq
      MessageRetentionPeriod: 1209600

  MalwareDetectionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1176-MaliciousExtensionDetection
      Description: Alert on malicious browser extension files
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Execution:EC2"
            - prefix: "Trojan:Runtime"
            - "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom"
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref MalwareAlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAgeInSeconds: 3600
          DeadLetterConfig:
            Arn: !GetAtt DLQ.Arn

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref MalwareAlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublish
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref MalwareAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt MalwareDetectionRule.Arn""",
                terraform_template="""# AWS: GuardDuty malicious browser extension detection

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Enable GuardDuty with Malware Protection
resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "malware_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "malware_alerts" {
  name = "guardduty-malware-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.malware_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route malicious file findings to email
resource "aws_cloudwatch_event_rule" "malware_detection" {
  name        = "guardduty-malware-detection"
  description = "Alert on malicious browser extension files"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Execution:EC2" },
        { prefix = "Trojan:Runtime" },
        "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom"
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-malware-alerts-dlq"
  message_retention_seconds = 1209600
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
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
      values   = [aws_cloudwatch_event_rule.malware_detection.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.malware_detection.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.malware_alerts.arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
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

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.malware_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.malware_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.malware_detection.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Malicious Browser Extension Detected",
                alert_description_template=(
                    "GuardDuty detected malicious file activity on instance {instance_id}. "
                    "Finding: {finding_type}. This may indicate malicious browser extension installation. "
                    "Immediate investigation required."
                ),
                investigation_steps=[
                    "Review GuardDuty finding details and malware scan results",
                    "Identify the suspicious file path and hash",
                    "Check which browser or process accessed the file",
                    "Review user sessions and authentication logs",
                    "Examine network connections to identify C2 communication",
                    "Check for lateral movement or privilege escalation attempts",
                    "Review CloudTrail for API calls from the instance",
                ],
                containment_actions=[
                    "Isolate the instance immediately",
                    "Terminate malicious processes",
                    "Remove malicious extension files",
                    "Rotate all credentials accessed from the browser",
                    "Block malicious IPs and domains at network level",
                    "Create forensic snapshot before remediation",
                    "Consider instance termination if fully compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review suppression rules for known development tools; whitelist approved software",
            detection_coverage="80% - detects known malicious extension signatures",
            evasion_considerations="Zero-day or custom extensions may evade signature detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per instance per month for Runtime Monitoring",
            prerequisites=[
                "GuardDuty enabled",
                "Malware Protection enabled",
                "SSM Agent on instances",
            ],
        ),
        # Strategy 3: CloudTrail Browser Configuration Changes
        DetectionStrategy(
            strategy_id="t1176-cloudtrail-configs",
            name="Detect Browser Configuration Modifications",
            description=(
                "Monitor for suspicious modifications to browser configuration files, "
                "preference files, or registry keys that could enable silent extension installation."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, sourceIPAddress, requestParameters
| filter eventSource = "ssm.amazonaws.com"
| filter eventName in ["SendCommand", "StartSession"]
| filter requestParameters.parameters.commands like /Preferences|Secure Preferences|extensions_to_install|ExtensionInstallForcelist|mobileconfig/
| stats count() as modifications by userIdentity.principalId, sourceIPAddress, bin(1h)
| sort @timestamp desc""",
                terraform_template="""# AWS: Detect browser configuration modifications

variable "cloudtrail_log_group" {
  description = "CloudTrail log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "browser-config-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for browser config changes
resource "aws_cloudwatch_log_metric_filter" "browser_config_changes" {
  name           = "browser-config-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"ssm.amazonaws.com\") && ($.eventName = \"SendCommand\" || $.eventName = \"StartSession\") && ($.requestParameters.parameters.commands = \"*Preferences*\" || $.requestParameters.parameters.commands = \"*extensions_to_install*\") }"

  metric_transformation {
    name          = "BrowserConfigChanges"
    namespace     = "Security/T1176"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm
resource "aws_cloudwatch_metric_alarm" "config_changes" {
  alarm_name          = "T1176-BrowserConfigModification"
  alarm_description   = "Suspicious browser configuration modification detected"
  metric_name         = "BrowserConfigChanges"
  namespace           = "Security/T1176"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

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
}""",
                alert_severity="high",
                alert_title="Browser Configuration Modification Detected",
                alert_description_template=(
                    "Suspicious browser configuration modification detected. Principal: {principal_id}. "
                    "Source IP: {source_ip}. Command: {command}. This may indicate silent extension installation."
                ),
                investigation_steps=[
                    "Review the SSM command or session details",
                    "Identify which browser configuration was modified",
                    "Check the user or role that executed the command",
                    "Verify if the modification was authorised",
                    "Review resulting browser extension installations",
                    "Check for other suspicious SSM commands from same principal",
                    "Examine affected instances for compromise indicators",
                ],
                containment_actions=[
                    "Revert unauthorised browser configuration changes",
                    "Remove any silently installed extensions",
                    "Revoke credentials of the principal that made changes",
                    "Review and restrict SSM access permissions",
                    "Enable SCPs to prevent unauthorised configuration changes",
                    "Implement browser configuration management via Group Policy",
                    "Monitor for reinfection attempts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist approved configuration management activities; establish change approval workflow",
            detection_coverage="70% - detects configuration-based extension installations",
            evasion_considerations="Manual file modifications outside SSM may bypass detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail enabled with SSM logging",
                "Systems Manager in use",
            ],
        ),
        # Strategy 4: GCP VM Browser Extension Detection
        DetectionStrategy(
            strategy_id="t1176-gcp-vm-extensions",
            name="GCP: Browser Extension Installation Detection",
            description=(
                "Monitor GCP VM instances and virtual desktops for browser extension "
                "installations and suspicious browser behaviour."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(jsonPayload.message=~"chrome.exe|firefox|edge" AND
 jsonPayload.message=~"\\.crx|\\.xpi|extensions|add-ons")
OR protoPayload.request.command=~"Preferences|extensions_to_install"
severity>="INFO"''',
                gcp_terraform_template="""# GCP: Detect browser extension installations on VMs

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Browser Extension Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for extension installations
resource "google_logging_metric" "browser_extensions" {
  project = var.project_id
  name    = "browser-extension-installations"
  filter  = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.message=~"chrome.exe|firefox|edge" AND
     jsonPayload.message=~"\\.crx|\\.xpi|extensions|add-ons")
    OR protoPayload.request.command=~"Preferences|extensions_to_install"
    severity>="INFO"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where extension was installed"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "extension_alert" {
  project      = var.project_id
  display_name = "T1176: Browser Extension Installation Detected"
  combiner     = "OR"
  conditions {
    display_name = "Browser extension installation activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.browser_extensions.name}\" resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
  documentation {
    content   = "Browser extension installation detected on GCE instance. Investigate for malicious extensions."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Browser Extension Installation Detected",
                alert_description_template=(
                    "Browser extension installation detected on GCE instance {instance_id}. "
                    "Multiple extension-related activities observed. Investigate for malicious extensions."
                ),
                investigation_steps=[
                    "Review Cloud Logging for extension installation details",
                    "Identify which browser and extension was installed",
                    "Check the extension source and publisher",
                    "Verify service account permissions on the instance",
                    "Review network connections after installation",
                    "Check for credential access or data exfiltration",
                    "Examine VPC Flow Logs for suspicious traffic",
                ],
                containment_actions=[
                    "Stop the GCE instance to prevent further activity",
                    "Create disk snapshot for forensic analysis",
                    "Remove malicious browser extensions",
                    "Rotate service account credentials",
                    "Update firewall rules to isolate the instance",
                    "Implement browser extension policies via OS Config",
                    "Review all instances for similar extension patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal extension installations; whitelist approved corporate extensions",
            detection_coverage="65% - detects extension installation patterns on monitored VMs",
            evasion_considerations="Silent registry-based installations may produce minimal logs",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=[
                "Cloud Logging enabled for GCE",
                "Ops Agent installed on instances",
            ],
        ),
        # Strategy 5: GCP Workspace Browser Extension Policy
        DetectionStrategy(
            strategy_id="t1176-gcp-workspace-extensions",
            name="GCP: Workspace Browser Extension Policy Violations",
            description=(
                "Monitor for browser extension installations that violate organisational "
                "policies in Google Workspace environments."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="workspace_admin",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="workspace_admin"
protoPayload.methodName="google.admin.AdminService.modifyAppSettings"
(protoPayload.request.setting.name="CHROME_EXTENSION_REQUEST" OR
 protoPayload.request.setting.name="CHROME_BLOCKED_APPS")
protoPayload.request.setting.value="BLOCKED"''',
                gcp_terraform_template="""# GCP: Workspace browser extension policy monitoring

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Workspace Extension Policy Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for policy violations
resource "google_logging_metric" "extension_policy_violations" {
  project = var.project_id
  name    = "workspace-extension-policy-violations"
  filter  = <<-EOT
    resource.type="workspace_admin"
    protoPayload.methodName="google.admin.AdminService.modifyAppSettings"
    (protoPayload.request.setting.name="CHROME_EXTENSION_REQUEST" OR
     protoPayload.request.setting.name="CHROME_BLOCKED_APPS")
    protoPayload.request.setting.value="BLOCKED"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user_email"
      value_type  = "STRING"
      description = "User who modified the policy"
    }
  }

  label_extractors = {
    user_email = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert for policy modifications
resource "google_monitoring_alert_policy" "policy_alert" {
  project      = var.project_id
  display_name = "Workspace Extension Policy Violation"
  combiner     = "OR"
  conditions {
    display_name = "Extension policy modification detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.extension_policy_violations.name}\""
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
    auto_close = "3600s"
    notification_rate_limit {
      period = "300s"
    }
  }
  documentation {
    content   = "Browser extension policy modification detected in Workspace. Review for unauthorised changes."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Workspace Extension Policy Modified",
                alert_description_template=(
                    "Browser extension policy modification detected in Google Workspace. "
                    "User: {user_email}. Policy: {policy_name}. Review for unauthorised changes."
                ),
                investigation_steps=[
                    "Review Workspace Admin logs for policy change details",
                    "Identify which administrator made the change",
                    "Verify if the policy change was authorised",
                    "Check which extensions were blocked or allowed",
                    "Review if any users installed blocked extensions before the change",
                    "Examine administrator account for compromise",
                    "Check for other unauthorised Workspace configuration changes",
                ],
                containment_actions=[
                    "Revert unauthorised policy changes immediately",
                    "Review and remove any extensions installed during policy gap",
                    "Suspend administrator account if compromised",
                    "Enable 2FA for all Workspace administrators",
                    "Implement extension allowlist policy",
                    "Review Workspace admin permissions",
                    "Enable admin activity alerts for critical changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist approved admin changes; implement change management workflow",
            detection_coverage="85% - detects Workspace extension policy changes",
            evasion_considerations="Direct browser-level installations may bypass Workspace policies",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "Google Workspace Admin SDK enabled",
                "Cloud Logging for Workspace configured",
            ],
        ),
    ],
    recommended_order=[
        "t1176-aws-guardduty",
        "t1176-gcp-vm-extensions",
        "t1176-aws-workspaces",
        "t1176-cloudtrail-configs",
        "t1176-gcp-workspace-extensions",
    ],
    total_effort_hours=7.25,
    coverage_improvement="+25% improvement for Persistence tactic",
)
