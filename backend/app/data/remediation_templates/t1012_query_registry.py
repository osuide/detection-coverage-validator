"""
T1012 - Query Registry

Adversaries query the Windows Registry to gather system information, installed software,
security configurations, and operational intelligence for reconnaissance and attack planning.
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
    technique_id="T1012",
    technique_name="Query Registry",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1012/",
    threat_context=ThreatContext(
        description=(
            "Adversaries query the Windows Registry to gather critical system information including "
            "OS configuration, installed software, security settings, and network configurations. "
            "The Registry contains extensive operational intelligence that shapes follow-on behaviours, "
            "including whether adversaries fully infect targets, which exploits to deploy, and how "
            "to evade detection. In cloud environments, this occurs on Windows EC2 instances, "
            "GCE VMs, and Azure virtual machines during reconnaissance phases."
        ),
        attacker_goal="Extract system configuration and software inventory from Windows Registry to inform attack strategy",
        why_technique=[
            "Identifies installed security software and monitoring tools",
            "Reveals remote access tools like PuTTY, VNC, or RDP clients",
            "Discovers cryptocurrency wallets and sensitive applications",
            "Enumerates Terminal Server Client Registry keys for lateral movement",
            "Checks proxy configurations and network settings",
            "Identifies vulnerable software versions for exploitation",
            "Obtains MachineGuid and unique system identifiers",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="stable",
        severity_score=5,
        severity_reasoning=(
            "Registry queries represent critical reconnaissance activity with moderate direct impact. "
            "While low-risk individually, systematic Registry enumeration indicates active adversary "
            "presence and typically precedes exploitation, lateral movement, or data theft. "
            "Particularly concerning when targeting security tool detection or Terminal Server configurations."
        ),
        business_impact=[
            "Reveals defensive capabilities to adversaries",
            "Enables targeted evasion of security tools",
            "Facilitates lateral movement planning",
            "Identifies high-value targets like cryptocurrency wallets",
            "Precedes ransomware deployment in many campaigns",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1562.001", "T1021.001", "T1552.001", "T1486"],
        often_follows=["T1078.004", "T1133", "T1190"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Windows Registry Query Detection via CloudWatch
        DetectionStrategy(
            strategy_id="t1012-aws-registry-queries",
            name="AWS: Windows Registry Query Detection",
            description=(
                "Monitor Windows Event Logs forwarded to CloudWatch for suspicious Registry queries "
                "including security software checks, Terminal Server enumeration, and bulk Registry access."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, Computer, ProcessName, CommandLine, RegistryKey
| filter EventID = 4656 or EventID = 4663  # Registry access events
| filter ObjectName like /SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall|Terminal Server Client|PuTTY|SecurityCenter|Windows Defender/
| stats count() as query_count by Computer, ProcessName, bin(10m)
| filter query_count > 20
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious Windows Registry queries on EC2 instances

Parameters:
  WindowsLogGroup:
    Type: String
    Description: CloudWatch log group containing Windows Event Logs
    Default: /aws/ec2/windows
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for Registry queries
  RegistryQueryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref WindowsLogGroup
      FilterPattern: '[time, computer, event_id="4656" || event_id="4663", object="*SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall*" || object="*Terminal Server Client*" || object="*PuTTY*"]'
      MetricTransformations:
        - MetricName: RegistryQueries
          MetricNamespace: Security/T1012
          MetricValue: "1"

  # Step 3: Alarm for excessive Registry queries
  RegistryQueryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1012-SuspiciousRegistryQueries
      AlarmDescription: Suspicious Windows Registry enumeration detected
      MetricName: RegistryQueries
      Namespace: Security/T1012
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 30
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect suspicious Windows Registry queries on EC2

variable "windows_log_group" {
  type        = string
  description = "CloudWatch log group containing Windows Event Logs"
  default     = "/aws/ec2/windows"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "registry-query-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for Registry queries
resource "aws_cloudwatch_log_metric_filter" "registry_queries" {
  name           = "suspicious-registry-queries"
  log_group_name = var.windows_log_group
  pattern        = "[time, computer, event_id=\"4656\" || event_id=\"4663\", object=\"*SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall*\" || object=\"*Terminal Server Client*\" || object=\"*PuTTY*\"]"

  metric_transformation {
    name      = "RegistryQueries"
    namespace = "Security/T1012"
    value     = "1"
  }
}

# Step 3: Alarm for excessive Registry queries
resource "aws_cloudwatch_metric_alarm" "registry_queries" {
  alarm_name          = "T1012-SuspiciousRegistryQueries"
  alarm_description   = "Suspicious Windows Registry enumeration detected"
  metric_name         = "RegistryQueries"
  namespace           = "Security/T1012"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 30
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious Windows Registry Queries Detected",
                alert_description_template=(
                    "High volume of Registry queries detected on {Computer}. "
                    "Process: {ProcessName}. Queried keys include security software, "
                    "installed applications, and remote access tools."
                ),
                investigation_steps=[
                    "Identify which process is querying the Registry",
                    "Review the specific Registry keys accessed",
                    "Check if the process is legitimate or suspicious",
                    "Examine command-line arguments and parent process",
                    "Look for subsequent suspicious activity (credential access, lateral movement)",
                    "Review recent logons to the affected instance",
                    "Check for known reconnaissance tools (reg.exe, PowerShell, wmic)",
                ],
                containment_actions=[
                    "Isolate the instance if compromise is confirmed",
                    "Terminate suspicious processes",
                    "Review and restrict Registry permissions if needed",
                    "Rotate credentials for accounts that logged into the instance",
                    "Check for persistence mechanisms (Run keys, services)",
                    "Enable Windows Defender if disabled",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised inventory tools, patch management systems, and monitoring agents",
            detection_coverage="75% - catches systematic Registry enumeration",
            evasion_considerations="Slow queries over time or use of undocumented APIs may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudWatch Agent with Windows Event Log forwarding",
                "Windows Event Auditing enabled",
            ],
        ),
        # Strategy 2: AWS - Command-Line Registry Tool Detection
        DetectionStrategy(
            strategy_id="t1012-aws-reg-command",
            name="AWS: Reg.exe and Registry Tool Execution Detection",
            description=(
                "Detect execution of Windows Registry query commands including reg.exe query, "
                "PowerShell Get-ItemProperty, and WMIC Registry operations on EC2 instances."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, Computer, ProcessName, CommandLine
| filter ProcessName like /reg.exe|powershell.exe|wmic.exe/
| filter CommandLine like /reg query|Get-ItemProperty|HKLM|HKCU|wmic.*path.*Registry/
| stats count() as command_count by Computer, ProcessName, CommandLine, bin(10m)
| filter command_count > 5
| sort command_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Registry query tool execution on Windows EC2

Parameters:
  ProcessLogGroup:
    Type: String
    Description: CloudWatch log group with process execution logs
    Default: /aws/ec2/windows/processes
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

  # Step 2: Metric filter for reg.exe queries
  RegToolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ProcessLogGroup
      FilterPattern: '[time, computer, process="reg.exe" || process="powershell.exe", command="*reg query*" || command="*Get-ItemProperty*" || command="*HKLM*" || command="*HKCU*"]'
      MetricTransformations:
        - MetricName: RegistryToolExecution
          MetricNamespace: Security/T1012
          MetricValue: "1"

  # Step 3: Alarm for Registry tool usage
  RegToolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1012-RegistryToolExecution
      AlarmDescription: Registry query tools detected
      MetricName: RegistryToolExecution
      Namespace: Security/T1012
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect Registry query tool execution on Windows EC2

variable "process_log_group" {
  type        = string
  description = "CloudWatch log group with process execution logs"
  default     = "/aws/ec2/windows/processes"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "registry-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for reg.exe queries
resource "aws_cloudwatch_log_metric_filter" "reg_tool" {
  name           = "registry-tool-execution"
  log_group_name = var.process_log_group
  pattern        = "[time, computer, process=\"reg.exe\" || process=\"powershell.exe\", command=\"*reg query*\" || command=\"*Get-ItemProperty*\" || command=\"*HKLM*\" || command=\"*HKCU*\"]"

  metric_transformation {
    name      = "RegistryToolExecution"
    namespace = "Security/T1012"
    value     = "1"
  }
}

# Step 3: Alarm for Registry tool usage
resource "aws_cloudwatch_metric_alarm" "reg_tool" {
  alarm_name          = "T1012-RegistryToolExecution"
  alarm_description   = "Registry query tools detected"
  metric_name         = "RegistryToolExecution"
  namespace           = "Security/T1012"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Registry Query Tool Execution Detected",
                alert_description_template=(
                    "Registry query tool executed on {Computer}. Command: {CommandLine}. "
                    "This may indicate reconnaissance activity."
                ),
                investigation_steps=[
                    "Review the full command-line arguments",
                    "Identify the user account that executed the command",
                    "Check the parent process (was it spawned by malware or a script?)",
                    "Review which Registry keys were targeted",
                    "Look for patterns indicating automated enumeration",
                    "Check for recently created scripts or executables",
                    "Review CloudTrail for any suspicious API calls from the instance role",
                ],
                containment_actions=[
                    "Investigate the process and parent process tree",
                    "Block execution of scripts if malicious",
                    "Review and restrict administrative access to instances",
                    "Enable PowerShell script block logging",
                    "Implement application allowlisting if not already enabled",
                    "Check for lateral movement indicators",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist system administrators, deployment scripts, and configuration management tools",
            detection_coverage="80% - catches command-line Registry tools",
            evasion_considerations="Attackers may use native Windows APIs or COM objects to bypass command-line detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Process execution logging via Sysmon or CloudWatch Agent",
                "Command-line auditing enabled",
            ],
        ),
        # Strategy 3: AWS - GuardDuty Runtime Monitoring
        DetectionStrategy(
            strategy_id="t1012-aws-guardduty",
            name="AWS: GuardDuty Runtime Monitoring for Registry Reconnaissance",
            description=(
                "Leverage AWS GuardDuty Runtime Monitoring to detect suspicious process behaviour "
                "and reconnaissance activity including Registry enumeration on EC2 instances."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/NewBinaryExecuted",
                    "Discovery:Runtime/SuspiciousCommand",
                    "Execution:Runtime/SuspiciousCommand",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for Registry reconnaissance

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty with Runtime Monitoring
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: RUNTIME_MONITORING
          Status: ENABLED

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for Registry discovery
  RegistryDiscoveryRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1012-RegistryDiscovery
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Discovery:Runtime"
            - prefix: "Execution:Runtime"
      Targets:
        - Id: AlertTopic
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
                aws:SourceArn: !GetAtt RegistryDiscoveryRule.Arn""",
                terraform_template="""# GuardDuty Runtime Monitoring for Registry reconnaissance

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty with Runtime Monitoring
resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "registry-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for Registry discovery
resource "aws_cloudwatch_event_rule" "registry_discovery" {
  name = "guardduty-registry-discovery"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Discovery:Runtime" },
        { prefix = "Execution:Runtime" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "registry-discovery-dlq"
  message_retention_seconds = 1209600
}

data "aws_caller_identity" "current" {}

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
      values   = [aws_cloudwatch_event_rule.registry_discovery.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.registry_discovery.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

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
            "aws:SourceArn" = aws_cloudwatch_event_rule.registry_discovery.arn
          }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="GuardDuty: Registry Reconnaissance Detected",
                alert_description_template=(
                    "GuardDuty detected Registry reconnaissance on instance {instance_id}. "
                    "Finding: {finding_type}. Process: {process_name}."
                ),
                investigation_steps=[
                    "Review GuardDuty finding details and severity",
                    "Check the process name and command-line arguments",
                    "Identify the user context of the suspicious process",
                    "Review CloudTrail for API calls from the instance role",
                    "Check for indicators of compromise (IOCs) on the instance",
                    "Look for lateral movement or privilege escalation attempts",
                ],
                containment_actions=[
                    "Isolate the instance using security group modifications",
                    "Create a forensic snapshot before remediation",
                    "Terminate suspicious processes via SSM Session Manager",
                    "Rotate instance IAM role credentials",
                    "Review and patch vulnerable software identified in Registry",
                    "Consider instance termination if fully compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty ML models reduce false positives; whitelist known administrative activity",
            detection_coverage="70% - behavioural detection of reconnaissance patterns",
            evasion_considerations="Novel techniques or living-off-the-land binaries may evade ML detection initially",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per instance per month",
            prerequisites=["GuardDuty enabled", "SSM Agent on EC2 instances"],
        ),
        # Strategy 4: GCP - Windows VM Registry Query Detection
        DetectionStrategy(
            strategy_id="t1012-gcp-registry-queries",
            name="GCP: Windows VM Registry Query Detection",
            description=(
                "Monitor Cloud Logging for Windows Event Logs from GCE instances showing "
                "suspicious Registry access patterns and reconnaissance activity."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.eventName=~"4656|4663"
(textPayload=~"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall"
OR textPayload=~"Terminal Server Client"
OR textPayload=~"PuTTY\\\\Sessions"
OR textPayload=~"Windows Defender"
OR textPayload=~"SecurityCenter")""",
                gcp_terraform_template="""# GCP: Detect Registry queries on Windows VMs

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for Registry queries
resource "google_logging_metric" "registry_queries" {
  name   = "registry-query-detection"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.eventName=~"4656|4663"
    (textPayload=~"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall"
    OR textPayload=~"Terminal Server Client"
    OR textPayload=~"PuTTY\\\\Sessions")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance performing Registry queries"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Alert policy for Registry reconnaissance
resource "google_monitoring_alert_policy" "registry_queries" {
  display_name = "T1012: Registry Reconnaissance Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious Registry queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.registry_queries.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 30
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
    content   = "Suspicious Registry enumeration detected. Investigate for reconnaissance activity."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Registry Reconnaissance Detected",
                alert_description_template=(
                    "Suspicious Registry queries detected on GCE instance {instance_id}. "
                    "High volume of Registry reads targeting security software and installed applications."
                ),
                investigation_steps=[
                    "Review Cloud Logging for full Registry access details",
                    "Identify the process and user performing queries",
                    "Check for reconnaissance tools or malware",
                    "Review instance service account permissions",
                    "Look for follow-on exploitation or lateral movement",
                    "Check VPC Flow Logs for suspicious network activity",
                ],
                containment_actions=[
                    "Stop the instance to prevent further compromise",
                    "Create a snapshot for forensic analysis",
                    "Review and rotate service account credentials",
                    "Update firewall rules to isolate the instance",
                    "Scan for malware and persistence mechanisms",
                    "Review IAM policies for overly permissive access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised system administrators and inventory management tools",
            detection_coverage="75% - detects systematic Registry enumeration",
            evasion_considerations="Direct Registry API access or slow enumeration may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=[
                "Cloud Logging API enabled",
                "Windows Event Log forwarding configured",
                "Ops Agent installed",
            ],
        ),
    ],
    recommended_order=[
        "t1012-aws-guardduty",
        "t1012-aws-reg-command",
        "t1012-aws-registry-queries",
        "t1012-gcp-registry-queries",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+10% improvement for Discovery tactic",
)
