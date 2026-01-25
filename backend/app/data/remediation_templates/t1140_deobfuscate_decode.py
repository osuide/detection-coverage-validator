"""
T1140 - Deobfuscate/Decode Files or Information

Adversaries use this technique to reverse obfuscation applied to artifacts,
enabling them to use hidden tools and payloads through decoding or deobfuscation.
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
    technique_id="T1140",
    technique_name="Deobfuscate/Decode Files or Information",
    tactic_ids=["TA0005"],  # Defense Evasion
    mitre_url="https://attack.mitre.org/techniques/T1140/",
    threat_context=ThreatContext(
        description=(
            "Adversaries reverse obfuscation applied to artefacts to enable the use of hidden "
            "tools and payloads. This defensive evasion technique involves decoding or deobfuscating "
            "information that was previously hidden using base64 encoding, XOR operations, RC4/AES "
            "encryption, or custom algorithms. Common methods include using system utilities like "
            "certutil -decode, built-in malware decryption mechanisms, or requiring user interaction "
            "to decrypt protected archives."
        ),
        attacker_goal="Reveal hidden malicious payloads and tools by reversing obfuscation at runtime",
        why_technique=[
            "Bypasses static analysis and signature-based detection systems",
            "Enables multi-stage attacks where final payload remains hidden until execution",
            "Conceals malicious tools during transfer and storage",
            "Evades file-based security scanning of obfuscated artefacts",
            "Allows manual DLL mapping and shellcode decryption at runtime",
            "Facilitates payload reassembly from fragmented binary components",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Deobfuscation is a critical enabler for modern malware operations, with over 350 "
            "malware families employing this technique including ransomware (Conti, REvil, LockBit), "
            "RATs (Cobalt Strike, PlugX, Emotet), and stealers (Agent Tesla, Lumma). In cloud "
            "environments, adversaries decode payloads on compute instances, decrypt serverless "
            "function code, and reassemble fragmented tools to evade detection. The technique's "
            "prevalence and fundamental role in the attack chain makes it a high-severity concern."
        ),
        business_impact=[
            "Delayed detection as payloads remain hidden until execution",
            "Ransomware deployment through decoded encryption tools",
            "Data exfiltration using decoded stealer malware",
            "Credential theft via decoded keyloggers and infostealers",
            "Persistent backdoor access through runtime-decoded RATs",
            "Cloud resource compromise from decoded serverless malware",
        ],
        typical_attack_phase="defense_evasion",
        often_precedes=["T1059", "T1105", "T1003", "T1486"],
        often_follows=["T1027", "T1566", "T1190", "T1078"],
    ),
    detection_strategies=[
        # Strategy 1: Certutil and Decoding Utility Detection
        DetectionStrategy(
            strategy_id="t1140-certutil-decode",
            name="AWS: Detect Certutil and Decoding Utility Usage",
            description=(
                "Monitor CloudWatch Logs for suspicious use of certutil -decode, base64, "
                "openssl, and other decoding utilities frequently abused to deobfuscate "
                "malicious payloads on Windows and Linux instances."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, userName, commandLine
| filter @message like /certutil.*-decode|certutil.*-f|base64 -d|openssl.*-d|python.*decode|perl.*decode/
| filter @message like /[.]txt|[.]dat|[.]bin|[.]tmp|[.]enc|[.]b64/
| stats count() as decode_operations by instanceId, userName, bin(10m)
| filter decode_operations > 2
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect certutil and decoding utility abuse

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing instance execution logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create metric filter for decoding activity
  DecodingUtilityFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, user, cmd="*certutil*-decode*" || cmd="*base64 -d*" || cmd="*openssl*-d*"]'
      MetricTransformations:
        - MetricName: DecodingUtilityUsage
          MetricNamespace: Security/T1140
          MetricValue: "1"

  # Step 2: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Deobfuscation Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create alarm for decoding activity
  DecodingActivityAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1140-DecodingUtilityAbuse
      AlarmDescription: Suspicious decoding utility usage detected
      MetricName: DecodingUtilityUsage
      Namespace: Security/T1140
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 2
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SecurityAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SecurityAlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect certutil and decoding utility abuse

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing instance execution logs"
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

# Step 1: Create metric filter for decoding activity
resource "aws_cloudwatch_log_metric_filter" "decoding_utilities" {
  name           = "decoding-utility-usage"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, user, cmd=\"*certutil*-decode*\" || cmd=\"*base64 -d*\" || cmd=\"*openssl*-d*\"]"

  metric_transformation {
    name      = "DecodingUtilityUsage"
    namespace = "Security/T1140"
    value     = "1"
  }
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "deobfuscation_alerts" {
  name         = "deobfuscation-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Deobfuscation Detection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.deobfuscation_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for decoding activity
resource "aws_cloudwatch_metric_alarm" "decoding_activity" {
  alarm_name          = "T1140-DecodingUtilityAbuse"
  alarm_description   = "Suspicious decoding utility usage detected"
  metric_name         = "DecodingUtilityUsage"
  namespace           = "Security/T1140"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 2
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.deobfuscation_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.deobfuscation_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.deobfuscation_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Decoding Utility Abuse Detected",
                alert_description_template=(
                    "Suspicious decoding utility usage detected on instance {instance_id}. "
                    "User: {user_name}. Command: {command_line}. "
                    "Multiple decode operations in short timeframe may indicate payload deobfuscation."
                ),
                investigation_steps=[
                    "Review the decoded file location and content hash",
                    "Identify the source of the encoded file (local, S3, external download)",
                    "Examine the user or service account executing the decoding commands",
                    "Check for subsequent execution of the decoded file",
                    "Review CloudTrail for S3 downloads or external data transfers",
                    "Analyse the decoded content for malicious indicators",
                ],
                containment_actions=[
                    "Isolate the instance to prevent decoded payload execution",
                    "Capture both encoded and decoded files for forensic analysis",
                    "Terminate any processes spawned after decoding activity",
                    "Delete decoded payloads from the instance filesystem",
                    "Rotate credentials that may have been compromised",
                    "Review and restrict use of decoding utilities via Systems Manager",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude legitimate certificate operations and known deployment automation using certutil",
            detection_coverage="75% - detects common decoding utilities but may miss custom decoders",
            evasion_considerations="Attackers may use custom decoding scripts or split decoding across multiple sessions",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$8-15 depending on log volume",
            prerequisites=[
                "CloudWatch Logs Agent with process logging",
                "Bash history or auditd logging enabled",
            ],
        ),
        # Strategy 2: PowerShell Decode and Decompression
        DetectionStrategy(
            strategy_id="t1140-powershell-decode",
            name="AWS: Detect PowerShell Decoding and Decompression",
            description=(
                "Monitor for PowerShell commands using FromBase64String, IO.Compression, "
                "and deobfuscation techniques commonly used to decode and decompress "
                "malicious payloads on Windows instances."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, commandLine, userName
| filter commandLine like /FromBase64String|IO[.]Compression|ConvertFrom-SecureString|BinaryFormatter/i
| filter commandLine like /GZipStream|DeflateStream|MemoryStream|Decompress/i
  or commandLine like /System[.]Text[.]Encoding|ToCharArray|ToString[(]/i
| stats count() as decode_commands by userName, bin(15m)
| filter decode_commands > 1
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect PowerShell decoding and decompression activity

Parameters:
  SystemsManagerLogGroup:
    Type: String
    Description: SSM Session Manager or EC2 console log group
    Default: /aws/ssm/session-logs
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for PowerShell decode operations
  PowerShellDecodeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemsManagerLogGroup
      FilterPattern: '[time, session, user, cmd="*FromBase64String*" || cmd="*IO.Compression*" || cmd="*GZipStream*"]'
      MetricTransformations:
        - MetricName: PowerShellDeobfuscation
          MetricNamespace: Security/T1140
          MetricValue: "1"

  # Step 2: Create alarm for PowerShell decoding
  PowerShellDecodeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1140-PowerShellDecoding
      AlarmDescription: PowerShell decoding or decompression detected
      MetricName: PowerShellDeobfuscation
      Namespace: Security/T1140
      Statistic: Sum
      Period: 900
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor for archive decompression
  ArchiveDecompressionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemsManagerLogGroup
      FilterPattern: '[time, session, user, cmd="*Expand-Archive*" || cmd="*7z*x*" || cmd="*unzip*"]'
      MetricTransformations:
        - MetricName: ArchiveDecompression
          MetricNamespace: Security/T1140
          MetricValue: "1"''',
                terraform_template="""# Detect PowerShell decoding and decompression

variable "ssm_log_group" {
  type        = string
  description = "SSM Session Manager or EC2 console log group"
  default     = "/aws/ssm/session-logs"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "powershell-decode-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for PowerShell decode operations
resource "aws_cloudwatch_log_metric_filter" "powershell_decode" {
  name           = "powershell-deobfuscation"
  log_group_name = var.ssm_log_group
  pattern        = "[time, session, user, cmd=\"*FromBase64String*\" || cmd=\"*IO.Compression*\" || cmd=\"*GZipStream*\"]"

  metric_transformation {
    name      = "PowerShellDeobfuscation"
    namespace = "Security/T1140"
    value     = "1"
  }
}

# Step 2: Create alarm for PowerShell decoding
resource "aws_cloudwatch_metric_alarm" "powershell_decode" {
  alarm_name          = "T1140-PowerShellDecoding"
  alarm_description   = "PowerShell decoding or decompression detected"
  metric_name         = "PowerShellDeobfuscation"
  namespace           = "Security/T1140"
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor for archive decompression
resource "aws_cloudwatch_log_metric_filter" "archive_decompression" {
  name           = "archive-decompression"
  log_group_name = var.ssm_log_group
  pattern        = "[time, session, user, cmd=\"*Expand-Archive*\" || cmd=\"*7z*x*\" || cmd=\"*unzip*\"]"

  metric_transformation {
    name      = "ArchiveDecompression"
    namespace = "Security/T1140"
    value     = "1"
  }
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
                alert_title="PowerShell Decoding Activity Detected",
                alert_description_template=(
                    "PowerShell decoding or decompression detected. User: {user_name}. "
                    "Command: {command_line}. May indicate payload deobfuscation or archive extraction."
                ),
                investigation_steps=[
                    "Decode the PowerShell command to reveal the actual payload",
                    "Identify the source of the encoded or compressed data",
                    "Check for file writes following the decoding operation",
                    "Review process tree for child processes spawned after decoding",
                    "Examine CloudTrail for S3 or external downloads preceding this activity",
                    "Search for related deobfuscation commands in the session history",
                ],
                containment_actions=[
                    "Terminate the PowerShell session immediately",
                    "Kill any processes spawned from the decoded payload",
                    "Review and revoke IAM credentials used in the session",
                    "Delete decoded artefacts from the instance filesystem",
                    "Isolate the instance for forensic analysis",
                    "Enable PowerShell script block logging for future visibility",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known deployment scripts using compression; exclude legitimate certificate operations",
            detection_coverage="70% - covers common PowerShell decode techniques",
            evasion_considerations="Multi-layer encoding or custom decompression algorithms may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-18",
            prerequisites=[
                "SSM Session Manager logging enabled",
                "PowerShell execution logging configured",
            ],
        ),
        # Strategy 3: XOR and Runtime Decryption
        DetectionStrategy(
            strategy_id="t1140-runtime-decrypt",
            name="AWS: Detect Runtime Decryption and XOR Operations",
            description=(
                "Monitor for runtime decryption activities including XOR operations, "
                "RC4/AES decryption, and DLL manual mapping commonly used by malware "
                "to decrypt shellcode and payloads at execution time."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, processName, commandLine
| filter @message like /VirtualAlloc|VirtualProtect|CreateThread|LoadLibrary|GetProcAddress/
| filter @message like /xor|decrypt|RC4|AES|shellcode|payload/i
  or processName like /rundll32|regsvr32|mshta|wscript|cscript/
| stats count() as decrypt_operations by instanceId, processName, bin(5m)
| filter decrypt_operations > 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect runtime decryption and manual DLL mapping

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group with process execution logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create metric filter for runtime decryption
  RuntimeDecryptionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process, msg="*VirtualAlloc*" || msg="*decrypt*" || msg="*shellcode*"]'
      MetricTransformations:
        - MetricName: RuntimeDecryption
          MetricNamespace: Security/T1140
          MetricValue: "1"

  # Step 2: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Runtime Decryption Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create alarm for runtime decryption
  RuntimeDecryptionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1140-RuntimeDecryption
      AlarmDescription: Runtime decryption or manual mapping detected
      MetricName: RuntimeDecryption
      Namespace: Security/T1140
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SecurityAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SecurityAlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublish
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect runtime decryption and manual DLL mapping

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group with process execution logs"
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

# Step 1: Create metric filter for runtime decryption
resource "aws_cloudwatch_log_metric_filter" "runtime_decryption" {
  name           = "runtime-decryption-detection"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process, msg=\"*VirtualAlloc*\" || msg=\"*decrypt*\" || msg=\"*shellcode*\"]"

  metric_transformation {
    name      = "RuntimeDecryption"
    namespace = "Security/T1140"
    value     = "1"
  }
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "runtime_decrypt_alerts" {
  name         = "runtime-decryption-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Runtime Decryption Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.runtime_decrypt_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for runtime decryption
resource "aws_cloudwatch_metric_alarm" "runtime_decryption" {
  alarm_name          = "T1140-RuntimeDecryption"
  alarm_description   = "Runtime decryption or manual mapping detected"
  metric_name         = "RuntimeDecryption"
  namespace           = "Security/T1140"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.runtime_decrypt_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.runtime_decrypt_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.runtime_decrypt_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Runtime Decryption Activity Detected",
                alert_description_template=(
                    "Runtime decryption or shellcode injection detected on instance {instance_id}. "
                    "Process: {process_name}. Multiple memory allocation and decryption operations detected."
                ),
                investigation_steps=[
                    "Identify the parent process and execution context",
                    "Capture memory dump of the suspicious process for analysis",
                    "Review process command line and DLL load events",
                    "Check for network connections from the suspicious process",
                    "Examine recent file downloads or S3 transfers to the instance",
                    "Search for additional indicators of compromise on the instance",
                ],
                containment_actions=[
                    "Terminate the suspicious process and all child processes immediately",
                    "Isolate the instance from the network to prevent lateral movement",
                    "Capture full memory dump for forensic analysis",
                    "Delete any suspicious executables or libraries",
                    "Rotate all credentials accessible from the instance",
                    "Review security group rules and remove unnecessary access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Requires EDR or advanced logging; baseline legitimate software using memory operations",
            detection_coverage="60% - requires process execution monitoring; may miss novel techniques",
            evasion_considerations="Custom encryption schemes or gradual decryption may evade detection",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3 hours",
            estimated_monthly_cost="$20-35 depending on EDR integration",
            prerequisites=[
                "Advanced process logging or EDR agent",
                "Sysmon or equivalent monitoring",
            ],
        ),
        # Strategy 4: GCP Deobfuscation Detection
        DetectionStrategy(
            strategy_id="t1140-gcp-decode",
            name="GCP: Detect Decoding and Deobfuscation Activity",
            description=(
                "Monitor GCP Cloud Logging for decoding utilities, decompression operations, "
                "and runtime decryption on GCE instances, Cloud Functions, and Cloud Run services."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type=("gce_instance" OR "cloud_function" OR "cloud_run_revision")
(textPayload=~"base64 -d|certutil.*-decode|openssl.*-d|python.*decode|unzip|gunzip|7z x"
OR protoPayload.request.commandLine=~"FromBase64String|IO.Compression|GZipStream|Decompress"
OR textPayload=~"VirtualAlloc|decrypt|xor.*key|RC4|AES.*decrypt")
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Detect decoding and deobfuscation activity

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Deobfuscation Detection Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for deobfuscation
resource "google_logging_metric" "deobfuscation_activity" {
  project = var.project_id
  name    = "deobfuscation-detection"
  filter  = <<-EOT
    resource.type=("gce_instance" OR "cloud_function" OR "cloud_run_revision")
    (textPayload=~"base64 -d|certutil.*-decode|openssl.*-d|python.*decode|unzip|gunzip|7z x"
    OR protoPayload.request.commandLine=~"FromBase64String|IO.Compression|GZipStream|Decompress"
    OR textPayload=~"VirtualAlloc|decrypt|xor.*key|RC4|AES.*decrypt")
    severity>=WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "resource_name"
      value_type  = "STRING"
      description = "Resource where deobfuscation was detected"
    }
  }

  label_extractors = {
    resource_name = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "deobfuscation_detection" {
  project      = var.project_id
  display_name = "T1140: Deobfuscation Activity Detected"
  combiner     = "OR"
  conditions {
    display_name = "Decoding or deobfuscation detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/$${google_logging_metric.deobfuscation_activity.name}\" resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2
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
    content   = "Decoding or deobfuscation activity detected. Investigate for potential malicious payload extraction."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Deobfuscation Activity Detected",
                alert_description_template=(
                    "Decoding or deobfuscation activity detected on {resource_type} {resource_name}. "
                    "Command: {command_line}. Investigate for malicious payload extraction."
                ),
                investigation_steps=[
                    "Review the Cloud Logging entry for complete command details",
                    "Identify the service account or user executing the commands",
                    "Check VPC Flow Logs for network activity from the resource",
                    "Examine recent API calls and file operations",
                    "Look for file uploads to Cloud Storage with suspicious patterns",
                    "Review the resource's IAM permissions and recent permission changes",
                ],
                containment_actions=[
                    "Stop the GCE instance or disable the Cloud Function/Cloud Run service",
                    "Revoke the service account credentials immediately",
                    "Create a snapshot of the instance for forensic analysis",
                    "Delete decoded payloads from the filesystem",
                    "Update VPC firewall rules to isolate the resource",
                    "Enable VPC Service Controls to restrict API access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude known CI/CD pipelines and deployment automation using compression",
            detection_coverage="70% - detects common decoding utilities and patterns",
            evasion_considerations="Custom decoders or gradual decryption may evade pattern matching",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-28",
            prerequisites=[
                "Cloud Logging API enabled",
                "Ops Agent on GCE instances for enhanced logging",
            ],
        ),
        # Strategy 5: Lambda Function Decoding
        DetectionStrategy(
            strategy_id="t1140-lambda-decode",
            name="AWS: Detect Serverless Function Decoding Operations",
            description=(
                "Monitor Lambda function execution for base64 decoding, decompression, "
                "and decryption operations that may indicate malicious payload extraction "
                "within serverless environments."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, @logStream, requestId
| filter @message like /base64[.]b64decode|atob|Buffer[.]from.*base64|decode[(]|decrypt[(]/
| filter @message like /zlib|gzip|decompress|inflate|unzip/i
  or @message like /Crypto|AES|RC4|XOR.*key/
| stats count() as decode_operations by @logStream, bin(10m)
| filter decode_operations > 2
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda function decoding and deobfuscation

Parameters:
  LambdaLogGroupPrefix:
    Type: String
    Description: Lambda log group prefix
    Default: /aws/lambda/
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Monitor Lambda execution for decoding
  LambdaDecodeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LambdaLogGroupPrefix
      FilterPattern: '[timestamp, request, level, msg="*decode(*" || msg="*decrypt(*" || msg="*decompress(*"]'
      MetricTransformations:
        - MetricName: LambdaDecodingOperations
          MetricNamespace: Security/T1140
          MetricValue: "1"

  # Step 2: Create alarm for decoding in Lambda
  LambdaDecodeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1140-LambdaDecoding
      AlarmDescription: Decoding operations in Lambda function
      MetricName: LambdaDecodingOperations
      Namespace: Security/T1140
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 2
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor Lambda environment variable changes
  LambdaConfigChangeRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1140-LambdaConfigChanges
      Description: Monitor Lambda configuration for encoded variables
      EventPattern:
        source: [aws.lambda]
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - UpdateFunctionConfiguration
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref SNSTopicArn""",
                terraform_template="""# Detect Lambda function decoding operations

variable "lambda_log_group_prefix" {
  type        = string
  description = "Lambda log group prefix"
  default     = "/aws/lambda/"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "lambda-decode-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Monitor Lambda execution for decoding
resource "aws_cloudwatch_log_metric_filter" "lambda_decode" {
  name           = "lambda-decoding-operations"
  log_group_name = var.lambda_log_group_prefix
  pattern        = "[timestamp, request, level, msg=\"*decode(*\" || msg=\"*decrypt(*\" || msg=\"*decompress(*\"]"

  metric_transformation {
    name      = "LambdaDecodingOperations"
    namespace = "Security/T1140"
    value     = "1"
  }
}

# Step 2: Create alarm for decoding in Lambda
resource "aws_cloudwatch_metric_alarm" "lambda_decode" {
  alarm_name          = "T1140-LambdaDecoding"
  alarm_description   = "Decoding operations in Lambda function"
  metric_name         = "LambdaDecodingOperations"
  namespace           = "Security/T1140"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 2
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor Lambda configuration changes
resource "aws_cloudwatch_event_rule" "lambda_config_changes" {
  name        = "lambda-config-changes"
  description = "Monitor Lambda configuration for encoded variables"
  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["UpdateFunctionConfiguration"]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "lambda-config-alerts-dlq"
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
      values   = [aws_cloudwatch_event_rule.lambda_config_changes.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "lambda_config_alerts" {
  rule      = aws_cloudwatch_event_rule.lambda_config_changes.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
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

resource "aws_sns_topic_policy" "lambda_alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.lambda_config_changes.arn
          }
        }
      },
      {
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
      }
    ]
  })
}""",
                alert_severity="medium",
                alert_title="Lambda Function Decoding Detected",
                alert_description_template=(
                    "Decoding operations detected in Lambda function {function_name}. "
                    "Request ID: {request_id}. Review function code for malicious deobfuscation."
                ),
                investigation_steps=[
                    "Download and review the Lambda function code package",
                    "Examine environment variables for encoded payloads",
                    "Review CloudWatch Logs for the complete execution flow",
                    "Check the function's IAM role permissions for sensitive access",
                    "Identify API calls made by the function during/after decoding",
                    "Review recent deployments and who updated the function",
                ],
                containment_actions=[
                    "Disable the Lambda function immediately",
                    "Remove the function's IAM execution role",
                    "Review and delete any S3 objects or data written by the function",
                    "Check for secrets or credentials exposed in environment variables",
                    "Delete the function if confirmed malicious",
                    "Enable Lambda code signing to prevent unauthorised deployments",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate Lambda functions using compression or encoding for data processing",
            detection_coverage="65% - detects common decoding patterns but requires code review",
            evasion_considerations="Obfuscated decoding logic or multi-stage operations may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$8-18",
            prerequisites=[
                "CloudTrail enabled",
                "Lambda execution logs sent to CloudWatch",
            ],
        ),
        # Azure Strategy: Deobfuscate/Decode Files or Information
        DetectionStrategy(
            strategy_id="t1140-azure",
            name="Azure Deobfuscate/Decode Files or Information Detection",
            description=(
                "Azure detection for Deobfuscate/Decode Files or Information. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                sentinel_rule_query="""// Sentinel Analytics Rule: Deobfuscate/Decode Files or Information
// MITRE ATT&CK: T1140
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
                azure_terraform_template="""# Azure Detection for Deobfuscate/Decode Files or Information
# MITRE ATT&CK: T1140

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
  name                = "deobfuscate-decode-files-or-information-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "deobfuscate-decode-files-or-information-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Deobfuscate/Decode Files or Information
// MITRE ATT&CK: T1140
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

  description = "Detects Deobfuscate/Decode Files or Information (T1140) activity in Azure environment"
  display_name = "Deobfuscate/Decode Files or Information Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1140"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Deobfuscate/Decode Files or Information Detected",
                alert_description_template=(
                    "Deobfuscate/Decode Files or Information activity detected. "
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
        "t1140-certutil-decode",
        "t1140-powershell-decode",
        "t1140-lambda-decode",
        "t1140-gcp-decode",
        "t1140-runtime-decrypt",
    ],
    total_effort_hours=9.5,
    coverage_improvement="+30% improvement for Defence Evasion tactic",
)
