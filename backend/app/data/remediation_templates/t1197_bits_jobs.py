"""
T1197 - BITS Jobs

Adversaries abuse Windows Background Intelligent Transfer Service (BITS) to download
malicious payloads, establish persistence, and execute commands covertly. BITS jobs
can be configured with notification commands that execute upon transfer completion.
Used by APT39, APT41, Leviathan, Patchwork, Wizard Spider, and in malware like
Bazar, Cobalt Strike, Egregor, and ProLock.
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
    technique_id="T1197",
    technique_name="BITS Jobs",
    tactic_ids=["TA0005", "TA0003"],  # Defense Evasion, Persistence
    mitre_url="https://attack.mitre.org/techniques/T1197/",

    threat_context=ThreatContext(
        description=(
            "Adversaries abuse Windows Background Intelligent Transfer Service (BITS) to download "
            "malicious payloads, establish persistence, and execute commands covertly. BITS is a "
            "low-bandwidth asynchronous file transfer mechanism built into Windows, exposed through "
            "COM interfaces and command-line tools like bitsadmin.exe and PowerShell. In cloud "
            "environments, this affects Windows EC2 instances, Windows containers, and Windows-based "
            "workloads on GCE. BITS jobs can run for up to 90 days by default, can survive reboots, "
            "and execute notification commands upon completion, making them ideal for persistence."
        ),
        attacker_goal="Download malicious tools and establish persistent command execution on Windows systems",
        why_technique=[
            "Blends in with legitimate Windows update traffic",
            "Survives system reboots and shutdowns",
            "Can execute commands via SetNotifyCmdLine parameter",
            "Operates within firewall-permitted HTTP/HTTPS/SMB protocols",
            "Difficult to distinguish from legitimate BITS activity",
            "Long-running jobs (90-day default lifespan) enable persistence",
            "Supports authenticated downloads using stored credentials",
            "Executes under svchost.exe context, appearing legitimate"
        ],
        known_threat_actors=[
            "APT39", "APT41", "Leviathan", "Patchwork", "Wizard Spider"
        ],
        recent_campaigns=[
            Campaign(
                name="Egregor Ransomware BITS Persistence",
                year=2024,
                description="Egregor ransomware used BITS jobs to download additional payloads and maintain persistence on compromised networks",
                reference_url="https://attack.mitre.org/software/S0554/"
            ),
            Campaign(
                name="Bazar Backdoor BITS Downloads",
                year=2024,
                description="Bazar malware extensively used BITS for downloading second-stage payloads while evading detection",
                reference_url="https://attack.mitre.org/software/S0534/"
            ),
            Campaign(
                name="APT41 BITS Job Abuse",
                year=2023,
                description="APT41 created BITS jobs on Windows instances to download tools and establish persistence mechanisms",
                reference_url="https://attack.mitre.org/groups/G0096/"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "BITS abuse is a common technique for establishing persistence and downloading "
            "malicious payloads on Windows systems. In cloud environments with Windows workloads, "
            "BITS jobs can download cryptominers, ransomware, or credential theft tools. The "
            "technique's ability to survive reboots and execute commands makes it particularly "
            "dangerous for maintaining long-term access to cloud infrastructure."
        ),
        business_impact=[
            "Persistent malware execution on Windows instances",
            "Covert download of ransomware and cryptominers",
            "Command execution via notification callbacks",
            "Data exfiltration using BITS upload capabilities",
            "Difficult to detect among legitimate update traffic",
            "Long-term compromise due to job persistence"
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1486", "T1496.001", "T1105", "T1059.001"],
        often_follows=["T1190", "T1078.004", "T1566"]
    ),

    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1197-aws-windows-bits",
            name="AWS Windows Instance BITS Job Detection",
            description="Detect BITS job creation and modification on Windows EC2 instances using CloudWatch Logs and SSM command logging.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, @message, instanceId, commandLine
| filter @message like /bitsadmin|Start-BitsTransfer|Add-BitsFile|Set-BitsTransfer|SetNotifyCmdLine/i
| filter @message like /create|addfile|setnotifycmdline|transfer|complete/i
| stats count(*) as bits_commands by instanceId, bin(10m)
| filter bits_commands > 2
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect BITS job abuse on Windows EC2 instances

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
      TopicName: bits-job-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for BITS commands
  BitsCommandFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "ssm.amazonaws.com") && ($.eventName = "SendCommand") && (($.requestParameters.documentName = "AWS-RunPowerShellScript") || ($.requestParameters.documentName = "AWS-RunShellScript")) && (($.requestParameters.parameters.commands[*] = "*bitsadmin*") || ($.requestParameters.parameters.commands[*] = "*Start-BitsTransfer*") || ($.requestParameters.parameters.commands[*] = "*SetNotifyCmdLine*")) }'
      MetricTransformations:
        - MetricName: BitsJobCommands
          MetricNamespace: Security/T1197
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for BITS job activity
  BitsJobAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1197-BitsJobDetected
      AlarmDescription: Detects BITS job creation on Windows instances
      MetricName: BitsJobCommands
      Namespace: Security/T1197
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 2
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching''',
                terraform_template='''# AWS: Detect BITS job abuse on Windows EC2 instances

variable "cloudtrail_log_group" {
  description = "CloudTrail log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "bits_alerts" {
  name = "bits-job-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.bits_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for BITS commands
resource "aws_cloudwatch_log_metric_filter" "bits_commands" {
  name           = "bits-job-commands"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"ssm.amazonaws.com\") && ($.eventName = \"SendCommand\") && (($.requestParameters.documentName = \"AWS-RunPowerShellScript\") || ($.requestParameters.documentName = \"AWS-RunShellScript\")) && (($.requestParameters.parameters.commands[*] = \"*bitsadmin*\") || ($.requestParameters.parameters.commands[*] = \"*Start-BitsTransfer*\") || ($.requestParameters.parameters.commands[*] = \"*SetNotifyCmdLine*\")) }"

  metric_transformation {
    name          = "BitsJobCommands"
    namespace     = "Security/T1197"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for BITS job activity
resource "aws_cloudwatch_metric_alarm" "bits_jobs" {
  alarm_name          = "T1197-BitsJobDetected"
  alarm_description   = "Detects BITS job creation on Windows instances"
  metric_name         = "BitsJobCommands"
  namespace           = "Security/T1197"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 2
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.bits_alerts.arn]
  treat_missing_data  = "notBreaching"
}''',
                alert_severity="high",
                alert_title="BITS Job Activity Detected on Windows Instance",
                alert_description_template="BITS job commands detected on instance {instanceId}. Command: {commandLine}.",
                investigation_steps=[
                    "Review the specific bitsadmin or PowerShell BITS command executed",
                    "Check for SetNotifyCmdLine parameter which indicates persistence",
                    "Enumerate all active BITS jobs on the instance using 'bitsadmin /list /allusers /verbose'",
                    "Identify download URLs and destination paths",
                    "Verify legitimacy of downloaded files via hash analysis",
                    "Review Windows Event Log ID 4688 for process creation",
                    "Check BITS-Client operational logs for job details",
                    "Analyse network connections to download sources"
                ],
                containment_actions=[
                    "Cancel malicious BITS jobs using 'bitsadmin /cancel' or 'Remove-BitsTransfer'",
                    "Isolate the instance via security group modification",
                    "Delete downloaded malicious files",
                    "Review and remove any notification command persistence",
                    "Rotate instance credentials and IAM roles",
                    "Create snapshot for forensic analysis",
                    "Block malicious download URLs at network level"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised software deployment and Windows Update processes",
            detection_coverage="75% - catches BITS command execution via SSM",
            evasion_considerations="Direct COM interface usage or GUI-based BITS jobs may evade command-line detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled with SSM logging", "SSM Agent installed on Windows instances"]
        ),

        DetectionStrategy(
            strategy_id="t1197-aws-windows-events",
            name="AWS Windows Event Log Analysis for BITS",
            description="Monitor Windows Event Logs forwarded to CloudWatch for BITS-Client operational events and BITS job creation.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, event.eventID, event.data.jobId, event.data.url, event.data.fileDestination
| filter event.channel = "Microsoft-Windows-Bits-Client/Operational"
| filter event.eventID in [3, 59, 60, 61]
| stats count(*) as job_events by event.data.jobId, event.data.url, bin(30m)
| filter job_events > 1
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor Windows Event Logs for BITS activity

Parameters:
  WindowsEventLogGroup:
    Type: String
    Description: CloudWatch log group receiving Windows Event Logs
    Default: /aws/ec2/windows/events
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: bits-event-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for BITS-Client events
  BitsEventFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref WindowsEventLogGroup
      FilterPattern: '[timestamp, instance, channel="*Bits-Client*", event_id=3 || event_id=59 || event_id=60 || event_id=61, ...]'
      MetricTransformations:
        - MetricName: BitsClientEvents
          MetricNamespace: Security/T1197
          MetricValue: "1"

  # Step 3: Create alarm for BITS events
  BitsEventAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1197-BitsClientActivity
      AlarmDescription: Detects BITS job activity via Windows Event Logs
      MetricName: BitsClientEvents
      Namespace: Security/T1197
      Statistic: Sum
      Period: 1800
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching''',
                terraform_template='''# AWS: Monitor Windows Event Logs for BITS activity

variable "windows_event_log_group" {
  description = "CloudWatch log group receiving Windows Event Logs"
  type        = string
  default     = "/aws/ec2/windows/events"
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "bits_event_alerts" {
  name = "bits-event-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.bits_event_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for BITS-Client events
resource "aws_cloudwatch_log_metric_filter" "bits_events" {
  name           = "bits-client-events"
  log_group_name = var.windows_event_log_group
  pattern        = "[timestamp, instance, channel=\"*Bits-Client*\", event_id=3 || event_id=59 || event_id=60 || event_id=61, ...]"

  metric_transformation {
    name      = "BitsClientEvents"
    namespace = "Security/T1197"
    value     = "1"
  }
}

# Step 3: Create alarm for BITS events
resource "aws_cloudwatch_metric_alarm" "bits_events" {
  alarm_name          = "T1197-BitsClientActivity"
  alarm_description   = "Detects BITS job activity via Windows Event Logs"
  metric_name         = "BitsClientEvents"
  namespace           = "Security/T1197"
  statistic           = "Sum"
  period              = 1800
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.bits_event_alerts.arn]
  treat_missing_data  = "notBreaching"
}''',
                alert_severity="medium",
                alert_title="BITS Job Activity via Windows Event Logs",
                alert_description_template="BITS job activity detected. Job ID: {jobId}, URL: {url}",
                investigation_steps=[
                    "Review Event ID details (3=job created, 59/60/61=transfer events)",
                    "Identify job owner and creation timestamp",
                    "Check download URL reputation and category",
                    "Verify file destination path legitimacy",
                    "Look for SetNotifyCmdLine in job properties",
                    "Correlate with network connection logs",
                    "Check for other suspicious processes on the instance",
                    "Review user account associated with the job"
                ],
                containment_actions=[
                    "Cancel suspicious BITS jobs immediately",
                    "Block malicious URLs at firewall/proxy level",
                    "Quarantine downloaded files",
                    "Disable BITS service if not required for operations",
                    "Review scheduled tasks for persistence mechanisms",
                    "Rotate credentials for affected user accounts",
                    "Enable BITS job auditing via Group Policy"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal Windows Update and software deployment BITS activity",
            detection_coverage="85% - comprehensive event log coverage",
            evasion_considerations="Attackers may clear event logs or use low-volume transfers to avoid thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Windows Event Log forwarding to CloudWatch configured", "CloudWatch Agent installed"]
        ),

        DetectionStrategy(
            strategy_id="t1197-aws-svchost-network",
            name="AWS Network Traffic from BITS Service",
            description="Detect network connections initiated by svchost.exe running BITS service to identify download activity.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, srcAddr, dstAddr, dstPort, protocol, bytes
| filter srcProcess = "svchost.exe" and srcService = "BITS"
| filter dstPort in [80, 443, 445]
| stats sum(bytes) as total_bytes, count(*) as connections by srcAddr, dstAddr, dstPort, bin(15m)
| filter total_bytes > 10485760 or connections > 20
| sort total_bytes desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network activity from BITS service

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: VPC Flow Logs log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: bits-network-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for large BITS transfers
  BitsNetworkFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, srcaddr, dstaddr, srcport, dstport IN (80,443,445), protocol, packets, bytes > 10485760, ...]'
      MetricTransformations:
        - MetricName: LargeBitsTransfers
          MetricNamespace: Security/T1197
          MetricValue: "$bytes"
          DefaultValue: 0

  # Step 3: Create alarm for suspicious transfers
  BitsNetworkAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1197-BitsLargeTransfer
      AlarmDescription: Detects large file transfers potentially via BITS
      MetricName: LargeBitsTransfers
      Namespace: Security/T1197
      Statistic: Sum
      Period: 900
      EvaluationPeriods: 1
      Threshold: 52428800
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching''',
                terraform_template='''# AWS: Detect network activity from BITS service

variable "vpc_flow_log_group" {
  description = "VPC Flow Logs log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "bits_network_alerts" {
  name = "bits-network-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.bits_network_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for large BITS transfers
resource "aws_cloudwatch_log_metric_filter" "bits_network" {
  name           = "large-bits-transfers"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, srcaddr, dstaddr, srcport, dstport IN (80,443,445), protocol, packets, bytes > 10485760, ...]"

  metric_transformation {
    name          = "LargeBitsTransfers"
    namespace     = "Security/T1197"
    value         = "$bytes"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious transfers
resource "aws_cloudwatch_metric_alarm" "bits_network" {
  alarm_name          = "T1197-BitsLargeTransfer"
  alarm_description   = "Detects large file transfers potentially via BITS"
  metric_name         = "LargeBitsTransfers"
  namespace           = "Security/T1197"
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 52428800
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.bits_network_alerts.arn]
  treat_missing_data  = "notBreaching"
}''',
                alert_severity="medium",
                alert_title="Large File Transfer via BITS Detected",
                alert_description_template="Instance {srcAddr} transferred {total_bytes} bytes to {dstAddr} via BITS service",
                investigation_steps=[
                    "Identify the Windows instance initiating transfers",
                    "Verify destination IP/domain legitimacy",
                    "Check if destination is known malware C2 infrastructure",
                    "Review active BITS jobs on the instance",
                    "Correlate with process execution logs",
                    "Check for authorised software updates or deployments",
                    "Review user activity on the instance during transfer period"
                ],
                containment_actions=[
                    "Block destination IP/domain if malicious",
                    "Cancel active BITS jobs",
                    "Isolate instance if compromise confirmed",
                    "Enable VPC endpoint for Windows Update to restrict outbound",
                    "Implement security group rules restricting outbound traffic",
                    "Review and harden Windows firewall rules",
                    "Consider disabling BITS if not operationally required"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Exclude Windows Update servers and known CDNs used for legitimate software distribution",
            detection_coverage="60% - network-level pattern detection",
            evasion_considerations="Low and slow transfers or encrypted channels may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled", "Enhanced network monitoring for process attribution"]
        ),

        DetectionStrategy(
            strategy_id="t1197-gcp-windows-bits",
            name="GCP Windows Instance BITS Job Detection",
            description="Detect BITS job creation and modification on Windows GCE instances using Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(jsonPayload.message=~"bitsadmin|Start-BitsTransfer|Add-BitsFile|SetNotifyCmdLine"
OR protoPayload.request.commandLine=~"bitsadmin.*create|bitsadmin.*addfile|bitsadmin.*setnotifycmdline")''',
                gcp_terraform_template='''# GCP: Detect BITS job abuse on Windows GCE instances

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - BITS Jobs"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for BITS commands
resource "google_logging_metric" "bits_jobs" {
  name   = "windows-bits-job-creation"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.message=~"bitsadmin|Start-BitsTransfer|Add-BitsFile|SetNotifyCmdLine"
    OR protoPayload.request.commandLine=~"bitsadmin.*create|bitsadmin.*addfile|bitsadmin.*setnotifycmdline")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "GCE instance ID"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy for BITS job activity
resource "google_monitoring_alert_policy" "bits_jobs" {
  display_name = "T1197: BITS Job Detected on Windows Instance"
  combiner     = "OR"

  conditions {
    display_name = "BITS job commands detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.bits_jobs.name}\" AND resource.type=\"gce_instance\""
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
  }

  documentation {
    content   = "BITS job activity detected on Windows GCE instance. Review jobs for malicious download or persistence mechanisms."
    mime_type = "text/markdown"
  }
}''',
                alert_severity="high",
                alert_title="GCP: BITS Job Detected on Windows Instance",
                alert_description_template="BITS job commands detected on instance {instance_id}",
                investigation_steps=[
                    "Review Cloud Logging for full command details",
                    "Connect to instance and enumerate BITS jobs",
                    "Check for SetNotifyCmdLine indicating persistence",
                    "Verify download URLs and destination paths",
                    "Review Windows Event Viewer for BITS-Client logs",
                    "Check service account permissions",
                    "Analyse network traffic from the instance",
                    "Review recent user login activity"
                ],
                containment_actions=[
                    "Cancel malicious BITS jobs on the instance",
                    "Stop the GCE instance if compromise confirmed",
                    "Create disk snapshot for forensic analysis",
                    "Block malicious URLs via Cloud DNS or firewall rules",
                    "Revoke service account credentials",
                    "Review and remove persistence mechanisms",
                    "Implement VPC firewall rules restricting outbound traffic"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised Windows Update and software deployment activities",
            detection_coverage="75% - catches BITS command execution",
            evasion_considerations="COM-based BITS job creation may evade command-line detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled for GCE", "Windows logging configured on instances"]
        ),

        DetectionStrategy(
            strategy_id="t1197-gcp-windows-events",
            name="GCP Windows Event Log Analysis for BITS",
            description="Monitor Windows Event Logs from GCE instances for BITS-Client operational events.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
jsonPayload.EventLog.Channel="Microsoft-Windows-Bits-Client/Operational"
jsonPayload.EventLog.EventID IN (3, 59, 60, 61)''',
                gcp_terraform_template='''# GCP: Monitor Windows Event Logs for BITS activity

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
  display_name = "Security Alerts - BITS Events"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for BITS-Client events
resource "google_logging_metric" "bits_events" {
  name   = "windows-bits-client-events"
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.EventLog.Channel="Microsoft-Windows-Bits-Client/Operational"
    jsonPayload.EventLog.EventID IN (3, 59, 60, 61)
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "GCE instance ID"
    }
    labels {
      key         = "event_id"
      value_type  = "STRING"
      description = "Windows Event ID"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
    "event_id"    = "EXTRACT(jsonPayload.EventLog.EventID)"
  }
}

# Step 3: Create alert policy for BITS events
resource "google_monitoring_alert_policy" "bits_events" {
  display_name = "T1197: BITS Client Activity Detected"
  combiner     = "OR"

  conditions {
    display_name = "BITS-Client events detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.bits_events.name}\" AND resource.type=\"gce_instance\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "900s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = "Multiple BITS-Client operational events detected. Review Event IDs: 3 (job created), 59/60/61 (transfer events)."
    mime_type = "text/markdown"
  }
}''',
                alert_severity="medium",
                alert_title="GCP: BITS Client Activity via Windows Events",
                alert_description_template="BITS-Client events detected on instance {instance_id}. Event ID: {event_id}",
                investigation_steps=[
                    "Review specific Event ID details in Cloud Logging",
                    "Identify job owner and creation timestamp",
                    "Check download URLs for malicious indicators",
                    "Verify file destination paths",
                    "Look for notification command configuration",
                    "Review network connections from the instance",
                    "Check for lateral movement attempts",
                    "Correlate with other security events"
                ],
                containment_actions=[
                    "Cancel active malicious BITS jobs",
                    "Quarantine downloaded files",
                    "Block malicious URLs via Cloud Armor or firewall",
                    "Stop instance if compromise confirmed",
                    "Disable BITS service if not required",
                    "Review and remove persistence mechanisms",
                    "Rotate credentials and service account keys",
                    "Create snapshot for forensic investigation"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate Windows Update and patch management BITS activity",
            detection_coverage="85% - comprehensive event coverage",
            evasion_considerations="Attackers may clear event logs or use minimal transfer volumes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Cloud Logging API enabled", "Windows Event Log forwarding configured on instances"]
        )
    ],

    recommended_order=[
        "t1197-aws-windows-bits",
        "t1197-gcp-windows-bits",
        "t1197-aws-windows-events",
        "t1197-gcp-windows-events",
        "t1197-aws-svchost-network"
    ],
    total_effort_hours=8.5,
    coverage_improvement="+15% improvement for Defense Evasion and Persistence tactics"
)
