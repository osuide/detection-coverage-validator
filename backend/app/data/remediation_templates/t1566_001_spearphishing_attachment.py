"""
T1566.001 - Phishing: Spearphishing Attachment

Adversaries send spearphishing emails with malicious attachments to gain initial access.
Attachments include Office documents, PDFs, executables, or archives that exploit
vulnerabilities or require user execution.
Used by APT28, APT29, Lazarus Group, Sandworm Team, FIN7.
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
    technique_id="T1566.001",
    technique_name="Phishing: Spearphishing Attachment",
    tactic_ids=["TA0001"],
    mitre_url="https://attack.mitre.org/techniques/T1566/001/",

    threat_context=ThreatContext(
        description=(
            "Adversaries employ spearphishing emails containing malicious attachments "
            "to compromise victim systems. Attachments include Microsoft Office documents, "
            "executables, PDFs, or compressed archives. Files exploit vulnerabilities or "
            "execute directly upon opening. Email text provides pretexts for file opening "
            "and may include instructions to bypass security warnings."
        ),
        attacker_goal="Gain initial access by delivering malicious attachments via targeted emails",
        why_technique=[
            "Bypasses perimeter defences with social engineering",
            "Password-protected archives evade email scanning",
            "Targets human vulnerability rather than technical",
            "Enables initial foothold for lateral movement",
            "Effective against both technical and non-technical users"
        ],
        known_threat_actors=[
            "APT28", "APT29", "APT32", "APT37", "APT39", "APT41",
            "Lazarus Group", "Sandworm Team", "Kimsuky",
            "FIN4", "FIN6", "FIN7", "FIN8",
            "TA505", "TA551", "Wizard Spider",
            "Transparent Tribe", "Gamaredon Group", "OilRig"
        ],
        recent_campaigns=[
            Campaign(
                name="2015 Ukraine Electric Power Attack",
                year=2015,
                description="Sandworm Team used Microsoft Office attachments via phishing to compromise IT systems",
                reference_url="https://attack.mitre.org/campaigns/C0028/"
            ),
            Campaign(
                name="Operation Dream Job",
                year=2020,
                description="Lazarus Group sent weaponised email attachments targeting job seekers",
                reference_url="https://attack.mitre.org/campaigns/C0022/"
            ),
            Campaign(
                name="Operation Dust Storm",
                year=2016,
                description="Threat actors distributed malicious Word documents via spearphishing emails",
                reference_url="https://attack.mitre.org/campaigns/C0016/"
            )
        ],
        prevalence="very_common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Primary initial access vector used by both nation-state and financially-motivated "
            "threat actors. High success rate due to social engineering. Commonly delivers "
            "ransomware, banking trojans, and espionage malware."
        ),
        business_impact=[
            "Initial network compromise",
            "Malware infection (ransomware, trojans)",
            "Data exfiltration risk",
            "Credential theft",
            "Lateral movement enabler"
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1204.002", "T1059", "T1053", "T1078"],
        often_follows=[]
    ),

    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1566-001-aws-ses-attachment",
            name="AWS SES Malicious Attachment Detection",
            description="Detect suspicious email attachments via AWS SES and WorkMail logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, mail.messageId, mail.source, mail.destination, mail.commonHeaders.subject
| filter mail.attachments.0.filename like /\\.exe$|\\.scr$|\\.bat$|\\.cmd$|\\.js$|\\.vbs$|\\.ps1$|\\.zip$|\\.rar$/
| filter mail.attachments.0.filename not like /\\.pdf$|\\.docx$|\\.xlsx$|\\.pptx$/
| stats count(*) as suspicious_emails by mail.source, bin(1h)
| filter suspicious_emails > 0
| sort suspicious_emails desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious email attachments via SES/WorkMail

Parameters:
  MailLogGroup:
    Type: String
    Description: CloudWatch log group for email logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # SNS topic for security alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for suspicious attachments
  SuspiciousAttachmentFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref MailLogGroup
      FilterPattern: '{ ($.mail.attachments[0].filename = "*.exe") || ($.mail.attachments[0].filename = "*.scr") || ($.mail.attachments[0].filename = "*.bat") || ($.mail.attachments[0].filename = "*.cmd") }'
      MetricTransformations:
        - MetricName: SuspiciousEmailAttachments
          MetricNamespace: Security/Email
          MetricValue: "1"

  # Alarm for suspicious attachments
  SuspiciousAttachmentAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousEmailAttachments
      MetricName: SuspiciousEmailAttachments
      Namespace: Security/Email
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]
      AlarmDescription: Executable or suspicious file extension detected in email attachment''',
                terraform_template='''# Detect suspicious email attachments via SES/WorkMail

variable "mail_log_group" {
  type        = string
  description = "CloudWatch log group for email logs"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for security alerts
resource "aws_sns_topic" "email_alerts" {
  name = "suspicious-email-attachment-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.email_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for suspicious attachments
resource "aws_cloudwatch_log_metric_filter" "suspicious_attachments" {
  name           = "suspicious-email-attachments"
  log_group_name = var.mail_log_group
  pattern        = "{ ($.mail.attachments[0].filename = \"*.exe\") || ($.mail.attachments[0].filename = \"*.scr\") || ($.mail.attachments[0].filename = \"*.bat\") || ($.mail.attachments[0].filename = \"*.cmd\") }"

  metric_transformation {
    name      = "SuspiciousEmailAttachments"
    namespace = "Security/Email"
    value     = "1"
  }
}

# Alarm for suspicious attachments
resource "aws_cloudwatch_metric_alarm" "suspicious_attachments" {
  alarm_name          = "SuspiciousEmailAttachments"
  alarm_description   = "Executable or suspicious file extension detected in email attachment"
  metric_name         = "SuspiciousEmailAttachments"
  namespace           = "Security/Email"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.email_alerts.arn]
}''',
                alert_severity="high",
                alert_title="Suspicious Email Attachment Detected",
                alert_description_template="Email from {source} contains suspicious attachment: {filename}",
                investigation_steps=[
                    "Review email sender and subject line",
                    "Examine attachment file name and extension",
                    "Check if email was delivered to users",
                    "Review recipient's recent file system and process activity",
                    "Search for similar emails from same sender"
                ],
                containment_actions=[
                    "Quarantine or delete suspicious emails",
                    "Block sender domain/address if malicious",
                    "Notify recipients not to open attachment",
                    "Scan endpoints that received the email",
                    "Update email filtering rules"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate business applications may send executables; whitelist known senders",
            detection_coverage="65% - catches obvious malicious extensions",
            evasion_considerations="Password-protected archives and Office documents with macros may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["AWS SES or WorkMail with CloudWatch logging enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1566-001-aws-guardduty-malware",
            name="AWS GuardDuty Malware Detection",
            description="Detect malware execution from email attachments via GuardDuty.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, type, severity, resource.instanceDetails.instanceId, service.additionalInfo.threatName
| filter type like /Execution:EC2\/MaliciousFile|UnauthorizedAccess:EC2\/MaliciousFile/
| stats count(*) as detections by resource.instanceDetails.instanceId, service.additionalInfo.threatName
| sort detections desc''',
                terraform_template='''# Detect malware execution via GuardDuty

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-malware-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for GuardDuty malware findings
resource "aws_cloudwatch_event_rule" "guardduty_malware" {
  name        = "guardduty-malware-detection"
  description = "Trigger on GuardDuty malware findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Execution:EC2/MaliciousFile" },
        { prefix = "UnauthorizedAccess:EC2/MaliciousFile" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_malware.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn
}

resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
    }]
  })
}''',
                alert_severity="critical",
                alert_title="Malware Execution Detected",
                alert_description_template="GuardDuty detected malware: {threatName} on {instanceId}",
                investigation_steps=[
                    "Identify malware file name and location",
                    "Review process execution timeline",
                    "Check user email access logs",
                    "Examine downloaded files and attachments",
                    "Review network connections from host"
                ],
                containment_actions=[
                    "Isolate infected instance",
                    "Terminate malicious processes",
                    "Delete malware files",
                    "Scan for persistence mechanisms",
                    "Review and block C2 domains"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty malware detection is highly accurate",
            detection_coverage="75% - detects known malware signatures",
            evasion_considerations="Zero-day malware and custom payloads may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-50",
            prerequisites=["AWS GuardDuty enabled with Malware Protection"]
        ),

        DetectionStrategy(
            strategy_id="t1566-001-aws-office-spawning",
            name="AWS CloudWatch - Office Apps Spawning Suspicious Processes",
            description="Detect Office applications spawning PowerShell, CMD, or scripting engines.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, eventName, userIdentity.principalId, requestParameters
| filter eventName = "RunInstances" or eventName = "CreateFunction"
| filter requestParameters like /powershell|cmd\.exe|wscript|cscript|mshta/
| stats count(*) as suspicious by userIdentity.principalId
| filter suspicious > 0''',
                terraform_template='''# Detect Office apps spawning suspicious processes (via endpoint logs)

variable "endpoint_log_group" {
  type        = string
  description = "CloudWatch log group for endpoint/EDR logs"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# SNS topic for alerts
resource "aws_sns_topic" "process_alerts" {
  name = "suspicious-process-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.process_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for Office apps spawning suspicious processes
resource "aws_cloudwatch_log_metric_filter" "office_suspicious_spawn" {
  name           = "office-suspicious-process-spawn"
  log_group_name = var.endpoint_log_group
  pattern        = "[parent=WINWORD.EXE||EXCEL.EXE||POWERPNT.EXE, child=powershell.exe||cmd.exe||wscript.exe||cscript.exe||mshta.exe]"

  metric_transformation {
    name      = "OfficeSuspiciousSpawn"
    namespace = "Security/Endpoint"
    value     = "1"
  }
}

# Alarm for suspicious process spawning
resource "aws_cloudwatch_metric_alarm" "office_spawn" {
  alarm_name          = "OfficeSuspiciousProcessSpawn"
  alarm_description   = "Office application spawned suspicious child process"
  metric_name         = "OfficeSuspiciousSpawn"
  namespace           = "Security/Endpoint"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.process_alerts.arn]
}''',
                alert_severity="high",
                alert_title="Office Application Spawned Suspicious Process",
                alert_description_template="Office app spawned {child_process} on {hostname}",
                investigation_steps=[
                    "Identify which Office document was opened",
                    "Review document source (email attachment, download)",
                    "Examine spawned process command line arguments",
                    "Check for additional malicious activity",
                    "Review user's recent email attachments"
                ],
                containment_actions=[
                    "Isolate affected endpoint",
                    "Terminate suspicious processes",
                    "Delete malicious document",
                    "Scan for additional malware",
                    "Block document hash organisation-wide"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Some legitimate macros may spawn processes; whitelist known business documents",
            detection_coverage="80% - catches common macro-based attacks",
            evasion_considerations="Attackers may use legitimate Office features or alternative execution methods",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Endpoint logs forwarded to CloudWatch (via CloudWatch Agent or EDR integration)"]
        ),

        DetectionStrategy(
            strategy_id="t1566-001-gcp-gmail-attachment",
            name="GCP Gmail/Workspace Malicious Attachment Detection",
            description="Detect suspicious email attachments via Google Workspace logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gmail_message"
protoPayload.methodName="gmail.messages.insert"
protoPayload.metadata.attachments.file_extension=~"(exe|scr|bat|cmd|js|vbs|ps1)"''',
                gcp_terraform_template='''# GCP: Detect suspicious email attachments in Workspace

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Email Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for suspicious attachments
resource "google_logging_metric" "suspicious_attachments" {
  name   = "suspicious-email-attachments"
  filter = <<-EOT
    resource.type="gmail_message"
    protoPayload.methodName="gmail.messages.insert"
    protoPayload.metadata.attachments.file_extension=~"(exe|scr|bat|cmd|js|vbs|ps1)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "sender"
      value_type  = "STRING"
      description = "Email sender address"
    }
  }

  label_extractors = {
    "sender" = "EXTRACT(protoPayload.metadata.sender)"
  }
}

# Alert policy for suspicious attachments
resource "google_monitoring_alert_policy" "suspicious_attachments" {
  display_name = "Suspicious Email Attachments"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious attachment detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_attachments.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "604800s"
  }
}''',
                alert_severity="high",
                alert_title="GCP: Suspicious Email Attachment Detected",
                alert_description_template="Suspicious attachment detected in email from {sender}",
                investigation_steps=[
                    "Review email sender and recipient",
                    "Examine attachment file name and extension",
                    "Check if email was delivered or quarantined",
                    "Review Google Workspace security centre alerts",
                    "Search for similar emails from same sender"
                ],
                containment_actions=[
                    "Quarantine suspicious emails via Workspace admin",
                    "Block sender domain if malicious",
                    "Update attachment filtering rules",
                    "Notify affected users",
                    "Review DLP policies"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known legitimate software distributors",
            detection_coverage="70% - catches obvious malicious extensions",
            evasion_considerations="Password-protected archives and Office documents may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Google Workspace with audit logging enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1566-001-gcp-chronicle",
            name="GCP Chronicle - File Creation from Email Client",
            description="Detect suspicious file creation following email client activity.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="chronicle",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="chronicle_rule_detection"
jsonPayload.detection.ruleName="Email_Attachment_Execution"
jsonPayload.detection.ruleType="MULTI_EVENT"''',
                gcp_terraform_template='''# GCP: Detect file creation from email clients (Chronicle/SIEM)

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Chronicle Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for Chronicle detections
resource "google_logging_metric" "email_attachment_exec" {
  name   = "email-attachment-execution"
  filter = <<-EOT
    resource.type="chronicle_rule_detection"
    jsonPayload.detection.ruleName="Email_Attachment_Execution"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert policy
resource "google_monitoring_alert_policy" "email_attachment_exec" {
  display_name = "Email Attachment Execution Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious attachment executed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.email_attachment_exec.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}''',
                alert_severity="high",
                alert_title="GCP: Email Attachment Executed",
                alert_description_template="Suspicious file executed following email client activity on {hostname}",
                investigation_steps=[
                    "Review email client logs for recent attachments",
                    "Identify executed file name and location",
                    "Examine process execution timeline",
                    "Check for additional malicious activity",
                    "Review user's inbox for malicious emails"
                ],
                containment_actions=[
                    "Isolate affected endpoint",
                    "Terminate malicious processes",
                    "Delete malicious files",
                    "Quarantine related emails",
                    "Update email filtering rules"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Correlates email activity with file execution; highly accurate",
            detection_coverage="85% - catches execution following email delivery",
            evasion_considerations="Delayed execution or manual file transfers may evade correlation",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$100-300",
            prerequisites=["Google Chronicle SIEM with endpoint telemetry"]
        )
    ],

    recommended_order=[
        "t1566-001-aws-guardduty-malware",
        "t1566-001-aws-office-spawning",
        "t1566-001-aws-ses-attachment",
        "t1566-001-gcp-chronicle",
        "t1566-001-gcp-gmail-attachment"
    ],
    total_effort_hours=8.5,
    coverage_improvement="+25% improvement for Initial Access tactic"
)
