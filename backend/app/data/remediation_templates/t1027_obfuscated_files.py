"""
T1027 - Obfuscated Files or Information

Adversaries attempt to conceal executable files or data through encryption,
encoding, or obfuscation on systems or during transit to evade detection.
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
    technique_id="T1027",
    technique_name="Obfuscated Files or Information",
    tactic_ids=["TA0005"],  # Defense Evasion
    mitre_url="https://attack.mitre.org/techniques/T1027/",
    threat_context=ThreatContext(
        description=(
            "Adversaries conceal executable files or data through encryption, encoding, "
            "or obfuscation to circumvent security controls. This defensive evasion technique "
            "operates across platforms using compression, encryption, string encoding, payload "
            "fragmentation, and command obfuscation to avoid detection during initial access, "
            "lateral movement, and execution phases."
        ),
        attacker_goal="Evade detection systems by hiding malicious payloads and commands",
        why_technique=[
            "Bypasses signature-based antivirus and EDR solutions",
            "Conceals malicious strings and indicators from security scanning",
            "Enables payload staging without triggering security alerts",
            "Obfuscates command-line activity to avoid logging detection",
            "Prevents analysis of malicious tools and scripts",
            "Facilitates multi-stage attacks by hiding subsequent payloads",
        ],
        known_threat_actors=[
            "Sandworm Team",
            "APT37",
            "APT41",
            "Kimsuky",
            "Cobalt Strike operators",
            "Conti ransomware",
            "Emotet operators",
            "TrickBot operators",
        ],
        recent_campaigns=[
            Campaign(
                name="Sandworm Industroyer Attacks",
                year=2016,
                description="Deployed heavily obfuscated code in Windows Notepad backdoor during Ukrainian infrastructure attacks",
                reference_url="https://attack.mitre.org/groups/G0034/",
            ),
            Campaign(
                name="APT41 VMProtected Binaries",
                year=2023,
                description="Used VMProtected binaries and fragmented executables (DEADEYE, KEYPLUG) to evade detection systems",
                reference_url="https://attack.mitre.org/groups/G0096/",
            ),
            Campaign(
                name="Conti Ransomware Operations",
                year=2021,
                description="Applied compiler-based obfuscation, encrypted DLL files, and concealed Windows API calls",
                reference_url="https://attack.mitre.org/software/S0575/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Obfuscation is a foundational evasion technique used across the attack lifecycle. "
            "In cloud environments, obfuscated scripts and encoded payloads can bypass security "
            "monitoring, enabling lateral movement, privilege escalation, and data exfiltration. "
            "The proliferation of obfuscation frameworks and increasing sophistication of encoding "
            "techniques makes this a persistent challenge for defenders."
        ),
        business_impact=[
            "Delayed detection of malicious activity",
            "Increased dwell time for attackers in cloud environments",
            "Failed security control effectiveness",
            "Compromised instances executing undetected malicious code",
            "Data exfiltration using obfuscated channels",
            "Ransomware deployment through encoded payloads",
        ],
        typical_attack_phase="defense_evasion",
        often_precedes=["T1059", "T1204", "T1105", "T1071"],
        often_follows=["T1190", "T1566", "T1078"],
    ),
    detection_strategies=[
        # Strategy 1: High-Entropy File Detection
        DetectionStrategy(
            strategy_id="t1027-high-entropy",
            name="AWS: Detect High-Entropy Files and Encoded Content",
            description=(
                "Monitor CloudWatch Logs for creation or transfer of high-entropy files "
                "(base64, compressed, encrypted) that may indicate obfuscated payloads. "
                "Detects unusual file operations with encoding utilities."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, processName, commandLine
| filter @message like /base64|gzip|openssl enc|uuencode|certutil.*encode|xxd|\\.7z|\\.enc|\\.zip/
| filter @message like /curl|wget|aws s3|scp/ or processName like /python|perl|ruby/
| stats count() as encoding_operations by instanceId, processName, bin(10m)
| filter encoding_operations > 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect obfuscated files and encoded content creation

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing instance execution logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create metric filter for encoding activity
  EncodedFileFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process, command="*base64*" || command="*openssl enc*" || command="*gzip*" || command="*certutil*encode*"]'
      MetricTransformations:
        - MetricName: EncodedFileCreation
          MetricNamespace: Security/T1027
          MetricValue: "1"

  # Step 2: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Obfuscation Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create alarm for encoding activity
  EncodingActivityAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1027-EncodedFileActivity
      AlarmDescription: High-entropy file or encoding activity detected
      MetricName: EncodedFileCreation
      Namespace: Security/T1027
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref SecurityAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SecurityAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic""",
                terraform_template="""# Detect obfuscated files and encoded content

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing instance execution logs"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create metric filter for encoding activity
resource "aws_cloudwatch_log_metric_filter" "encoded_files" {
  name           = "encoded-file-creation"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process, command=\"*base64*\" || command=\"*openssl enc*\" || command=\"*gzip*\" || command=\"*certutil*encode*\"]"

  metric_transformation {
    name      = "EncodedFileCreation"
    namespace = "Security/T1027"
    value     = "1"
  }
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "obfuscation_alerts" {
  name         = "obfuscation-detection-alerts"
  display_name = "Obfuscation Detection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.obfuscation_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for encoding activity
resource "aws_cloudwatch_metric_alarm" "encoding_activity" {
  alarm_name          = "T1027-EncodedFileActivity"
  alarm_description   = "High-entropy file or encoding activity detected"
  metric_name         = "EncodedFileCreation"
  namespace           = "Security/T1027"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.obfuscation_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Obfuscated File Creation Detected",
                alert_description_template=(
                    "Encoding or obfuscation activity detected on instance {instance_id}. "
                    "Process: {process_name}. Command: {command_line}. "
                    "Multiple encoding operations in short timeframe."
                ),
                investigation_steps=[
                    "Review the command-line arguments and identify the encoded content",
                    "Check the source and destination of encoded files",
                    "Examine the user or service account executing the encoding commands",
                    "Look for network transfers of encoded files",
                    "Check CloudTrail for S3 uploads of suspicious files",
                    "Decode sample content to determine if malicious",
                ],
                containment_actions=[
                    "Isolate the instance to prevent payload execution",
                    "Capture the encoded files for forensic analysis",
                    "Review and delete any uploaded obfuscated files from S3",
                    "Terminate suspicious processes",
                    "Rotate credentials that may have been compromised",
                    "Apply S3 bucket policies to prevent anonymous or external uploads",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate backup operations, software updates, and known deployment scripts",
            detection_coverage="60% - detects common encoding patterns but may miss novel obfuscation",
            evasion_considerations="Attackers may use custom encoding schemes or split operations across time",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20 depending on log volume",
            prerequisites=[
                "CloudWatch Logs Agent with process logging",
                "Bash history or auditd logging enabled",
            ],
        ),
        # Strategy 2: Obfuscated PowerShell/Script Detection
        DetectionStrategy(
            strategy_id="t1027-script-obfuscation",
            name="AWS: Detect Obfuscated Scripts and Command Execution",
            description=(
                "Monitor for obfuscated PowerShell, Python, and shell scripts with "
                "suspicious encoding patterns, environment variable substitution, "
                "and string concatenation often used to hide malicious intent."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, commandLine, userName
| filter commandLine like /powershell.*-enc|python.*-c.*eval|bash.*-c.*eval|\\$\\{.*\\}|\\`.*\\`/
| filter commandLine like /IEX|Invoke-Expression|exec|char.*join|frombase64/i
| stats count() as obfuscated_commands by userName, bin(15m)
| filter obfuscated_commands > 2
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect obfuscated script execution

Parameters:
  SystemsManagerLogGroup:
    Type: String
    Description: SSM Session Manager or EC2 console log group
    Default: /aws/ssm/session-logs
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for obfuscated scripts
  ObfuscatedScriptFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemsManagerLogGroup
      FilterPattern: '[time, session, user, cmd="*-enc*" || cmd="*IEX*" || cmd="*eval(*" || cmd="*frombase64*"]'
      MetricTransformations:
        - MetricName: ObfuscatedScriptExecution
          MetricNamespace: Security/T1027
          MetricValue: "1"

  # Step 2: Create alarm for obfuscated execution
  ObfuscatedScriptAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1027-ObfuscatedScriptExecution
      AlarmDescription: Obfuscated script or command detected
      MetricName: ObfuscatedScriptExecution
      Namespace: Security/T1027
      Statistic: Sum
      Period: 900
      EvaluationPeriods: 1
      Threshold: 2
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor for environment variable obfuscation
  EnvVarObfuscationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemsManagerLogGroup
      FilterPattern: '[time, session, user, cmd="*${*}*${*}*" || cmd="*`*`*`*"]'
      MetricTransformations:
        - MetricName: EnvironmentVariableObfuscation
          MetricNamespace: Security/T1027
          MetricValue: "1"''',
                terraform_template="""# Detect obfuscated script execution

variable "ssm_log_group" {
  type        = string
  description = "SSM Session Manager or EC2 console log group"
  default     = "/aws/ssm/session-logs"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "obfuscated-script-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for obfuscated scripts
resource "aws_cloudwatch_log_metric_filter" "obfuscated_scripts" {
  name           = "obfuscated-script-execution"
  log_group_name = var.ssm_log_group
  pattern        = "[time, session, user, cmd=\"*-enc*\" || cmd=\"*IEX*\" || cmd=\"*eval(*\" || cmd=\"*frombase64*\"]"

  metric_transformation {
    name      = "ObfuscatedScriptExecution"
    namespace = "Security/T1027"
    value     = "1"
  }
}

# Step 2: Create alarm for obfuscated execution
resource "aws_cloudwatch_metric_alarm" "obfuscated_scripts" {
  alarm_name          = "T1027-ObfuscatedScriptExecution"
  alarm_description   = "Obfuscated script or command detected"
  metric_name         = "ObfuscatedScriptExecution"
  namespace           = "Security/T1027"
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 2
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor for environment variable obfuscation
resource "aws_cloudwatch_log_metric_filter" "env_var_obfuscation" {
  name           = "environment-variable-obfuscation"
  log_group_name = var.ssm_log_group
  pattern        = "[time, session, user, cmd=\"*$${*}*$${*}*\" || cmd=\"*`*`*`*\"]"

  metric_transformation {
    name      = "EnvironmentVariableObfuscation"
    namespace = "Security/T1027"
    value     = "1"
  }
}""",
                alert_severity="high",
                alert_title="Obfuscated Script Execution Detected",
                alert_description_template=(
                    "Obfuscated script execution detected. User: {user_name}. "
                    "Command: {command_line}. Multiple obfuscated commands in short timeframe."
                ),
                investigation_steps=[
                    "Decode the obfuscated command to reveal actual intent",
                    "Identify the user session and source IP address",
                    "Check for additional suspicious commands in the session",
                    "Review CloudTrail for API calls made during or after execution",
                    "Examine parent process and execution context",
                    "Search for related obfuscated files on the instance",
                ],
                containment_actions=[
                    "Terminate the suspicious user session immediately",
                    "Kill any processes spawned by the obfuscated command",
                    "Review and revoke IAM credentials used",
                    "Check for persistence mechanisms installed",
                    "Isolate the instance for forensic analysis",
                    "Enable CloudTrail Insights to detect anomalous API patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known automation frameworks and deployment scripts using encoding",
            detection_coverage="70% - covers common script obfuscation techniques",
            evasion_considerations="Novel obfuscation techniques or multi-layer encoding may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$8-15",
            prerequisites=[
                "SSM Session Manager logging enabled",
                "CloudWatch Logs Agent configured",
            ],
        ),
        # Strategy 3: GuardDuty Malware Detection
        DetectionStrategy(
            strategy_id="t1027-guardduty-malware",
            name="AWS: GuardDuty Malware Protection for S3",
            description=(
                "AWS GuardDuty Malware Protection scans objects uploaded to S3 buckets "
                "for malicious content, including obfuscated or encrypted malware payloads."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:S3/MaliciousFile",
                    "Execution:S3/SuspiciousFile",
                    "Backdoor:S3/MalwareFile",
                    "Trojan:S3/MalwareFile",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Malware Protection for obfuscated files

Parameters:
  S3BucketName:
    Type: String
    Description: S3 bucket to protect with malware scanning
  AlertEmail:
    Type: String
    Description: Email for malware alerts

Resources:
  # Step 1: Enable GuardDuty with Malware Protection
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: S3_DATA_EVENTS
          Status: ENABLED

  # Step 2: Create SNS topic for malware alerts
  MalwareAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: S3 Malware Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route malware findings to alerts
  MalwareDetectionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1027-S3MalwareDetection
      Description: Alert on malicious files in S3
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "Execution:S3"
            - prefix: "Backdoor:S3"
            - prefix: "Trojan:S3"
      State: ENABLED
      Targets:
        - Id: MalwareAlertTopic
          Arn: !Ref MalwareAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref MalwareAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref MalwareAlertTopic""",
                terraform_template="""# GuardDuty Malware Protection for obfuscated files

variable "s3_bucket_name" {
  type        = string
  description = "S3 bucket to protect with malware scanning"
}

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty with S3 Protection
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
  }
}

resource "aws_guardduty_detector_feature" "s3_protection" {
  detector_id = aws_guardduty_detector.main.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# Step 2: Create SNS topic for malware alerts
resource "aws_sns_topic" "malware_alerts" {
  name         = "s3-malware-detection-alerts"
  display_name = "S3 Malware Detection Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.malware_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route malware findings to alerts
resource "aws_cloudwatch_event_rule" "malware_detection" {
  name        = "guardduty-s3-malware"
  description = "Alert on malicious files in S3"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "Execution:S3" },
        { prefix = "Backdoor:S3" },
        { prefix = "Trojan:S3" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.malware_detection.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.malware_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.malware_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.malware_alerts.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Malicious File Detected in S3",
                alert_description_template=(
                    "GuardDuty detected malicious or suspicious file in S3 bucket {bucket_name}. "
                    "Object key: {object_key}. Finding: {finding_type}. "
                    "File may contain obfuscated malware."
                ),
                investigation_steps=[
                    "Review the GuardDuty finding for threat classification",
                    "Check CloudTrail for who uploaded the file and from where",
                    "Examine the file metadata and upload timestamp",
                    "Review S3 bucket policies and access controls",
                    "Check if the file was accessed or downloaded",
                    "Search for related files uploaded by the same principal",
                ],
                containment_actions=[
                    "Delete the malicious file from S3 immediately",
                    "Enable S3 Object Lock on critical buckets to prevent deletion",
                    "Review and restrict S3 bucket IAM policies",
                    "Rotate credentials used to upload the file",
                    "Enable S3 versioning and MFA delete",
                    "Implement S3 bucket policies to block public uploads",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review findings for legitimate compressed or encrypted files; whitelist known safe sources",
            detection_coverage="75% - effective at detecting known malware signatures and heuristics",
            evasion_considerations="Zero-day malware or heavily obfuscated custom tools may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$0.40 per GB scanned (first 150GB/month free per account)",
            prerequisites=["GuardDuty enabled", "S3 buckets with data events enabled"],
        ),
        # Strategy 4: GCP Detection
        DetectionStrategy(
            strategy_id="t1027-gcp-obfuscation",
            name="GCP: Detect Obfuscated Files and Script Execution",
            description=(
                "Monitor GCP Cloud Logging for creation and execution of obfuscated "
                "content on GCE instances, Cloud Functions, and Cloud Run services."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type=("gce_instance" OR "cloud_function" OR "cloud_run_revision")
(textPayload=~"base64|gzip|openssl enc|python.*eval|bash.*-c"
OR protoPayload.request.commandLine=~"-enc|-e .*base64|IEX|Invoke-Expression"
OR textPayload=~"certutil.*encode|xxd|uuencode")
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Detect obfuscated files and script execution

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Obfuscation Detection Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for obfuscation
resource "google_logging_metric" "obfuscated_content" {
  project = var.project_id
  name    = "obfuscated-content-detection"
  filter  = <<-EOT
    resource.type=("gce_instance" OR "cloud_function" OR "cloud_run_revision")
    (textPayload=~"base64|gzip|openssl enc|python.*eval|bash.*-c"
    OR protoPayload.request.commandLine=~"-enc|-e .*base64|IEX|Invoke-Expression"
    OR textPayload=~"certutil.*encode|xxd|uuencode")
    severity>=WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "resource_name"
      value_type  = "STRING"
      description = "Resource where obfuscation was detected"
    }
  }

  label_extractors = {
    resource_name = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "obfuscation_detection" {
  project      = var.project_id
  display_name = "T1027: Obfuscated Content Detected"
  combiner     = "OR"
  conditions {
    display_name = "Obfuscation activity detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/$${google_logging_metric.obfuscated_content.name}\" resource.type=\"gce_instance\""
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
    content   = "Obfuscated file or script execution detected. Investigate for potential malicious activity."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Obfuscated Content Detected",
                alert_description_template=(
                    "Obfuscation activity detected on {resource_type} {resource_name}. "
                    "Command: {command_line}. Investigate for malicious intent."
                ),
                investigation_steps=[
                    "Review the Cloud Logging entry for full command details",
                    "Identify the service account or user executing the command",
                    "Check VPC Flow Logs for network activity from the resource",
                    "Examine recent API calls from the resource's service account",
                    "Look for file uploads to Cloud Storage with suspicious patterns",
                    "Review the resource's IAM permissions and recent changes",
                ],
                containment_actions=[
                    "Stop the GCE instance or disable the Cloud Function/Cloud Run service",
                    "Revoke the service account credentials",
                    "Create a snapshot for forensic analysis",
                    "Review and delete suspicious files from Cloud Storage",
                    "Update VPC firewall rules to isolate the resource",
                    "Enable VPC Service Controls to restrict API access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known CI/CD pipelines and deployment automation that legitimately uses encoding",
            detection_coverage="65% - detects common obfuscation patterns",
            evasion_considerations="Custom encoding schemes or multi-stage obfuscation may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$12-25",
            prerequisites=[
                "Cloud Logging API enabled",
                "Ops Agent on GCE instances for enhanced logging",
            ],
        ),
        # Strategy 5: Lambda Function Obfuscation
        DetectionStrategy(
            strategy_id="t1027-lambda-obfuscation",
            name="AWS: Detect Obfuscated Lambda Function Code",
            description=(
                "Monitor Lambda function deployments for obfuscated code patterns, "
                "suspicious dependencies, and encoded environment variables that may "
                "indicate malicious serverless functions."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.functionName, eventName
| filter eventSource = "lambda.amazonaws.com"
| filter eventName in ["CreateFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration"]
| filter requestParameters.environment.variables like /base64|eval|exec/
  or requestParameters.code.zipFile like /obfuscated|encrypted/
| stats count() as suspicious_updates by requestParameters.functionName, userIdentity.principalId
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect obfuscated Lambda function deployments

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String

Resources:
  # Step 1: Monitor Lambda function creation with suspicious patterns
  SuspiciousLambdaFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "lambda.amazonaws.com") && ($.eventName = "CreateFunction" || $.eventName = "UpdateFunctionCode") }'
      MetricTransformations:
        - MetricName: LambdaFunctionDeployment
          MetricNamespace: Security/T1027
          MetricValue: "1"

  # Step 2: Create EventBridge rule for Lambda updates
  LambdaUpdateRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1027-LambdaObfuscation
      Description: Detect suspicious Lambda deployments
      EventPattern:
        source: [aws.lambda]
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - CreateFunction
            - UpdateFunctionCode
            - UpdateFunctionConfiguration
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref SNSTopicArn

  # Step 3: Monitor Lambda execution with eval/exec patterns
  LambdaExecutionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Sub /aws/lambda/*
      FilterPattern: '[time, request, level, msg="*eval(*" || msg="*exec(*" || msg="*base64*decode*"]'
      MetricTransformations:
        - MetricName: ObfuscatedLambdaExecution
          MetricNamespace: Security/T1027
          MetricValue: "1"''',
                terraform_template="""# Detect obfuscated Lambda function deployments

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "lambda-obfuscation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Monitor Lambda function creation
resource "aws_cloudwatch_log_metric_filter" "suspicious_lambda" {
  name           = "suspicious-lambda-deployment"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"lambda.amazonaws.com\") && ($.eventName = \"CreateFunction\" || $.eventName = \"UpdateFunctionCode\") }"

  metric_transformation {
    name      = "LambdaFunctionDeployment"
    namespace = "Security/T1027"
    value     = "1"
  }
}

# Step 2: Create EventBridge rule for Lambda updates
resource "aws_cloudwatch_event_rule" "lambda_updates" {
  name        = "lambda-suspicious-deployments"
  description = "Detect suspicious Lambda deployments"
  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateFunction",
        "UpdateFunctionCode",
        "UpdateFunctionConfiguration"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_alerts" {
  rule      = aws_cloudwatch_event_rule.lambda_updates.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn
}

# Step 3: Allow EventBridge to publish to SNS
resource "aws_sns_topic_policy" "lambda_alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Suspicious Lambda Function Deployment",
                alert_description_template=(
                    "Lambda function {function_name} created or updated with suspicious patterns. "
                    "Principal: {principal_id}. Review function code for obfuscation."
                ),
                investigation_steps=[
                    "Download and review the Lambda function code package",
                    "Examine environment variables for encoded secrets or commands",
                    "Check function dependencies and layers for malicious libraries",
                    "Review the function's IAM role and permissions",
                    "Check CloudWatch Logs for function execution patterns",
                    "Identify who deployed the function and from which source IP",
                ],
                containment_actions=[
                    "Disable the Lambda function immediately",
                    "Remove the function's IAM role to prevent execution",
                    "Review and revoke any credentials or API keys in the function",
                    "Check for S3 buckets, databases, or APIs accessed by the function",
                    "Delete the function if confirmed malicious",
                    "Enable Lambda code signing to prevent unauthorised deployments",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal Lambda deployment patterns; exclude known CI/CD automation",
            detection_coverage="55% - detects suspicious deployments but requires code analysis",
            evasion_considerations="Attackers may use legitimate-looking function names and gradual deployment",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-12",
            prerequisites=[
                "CloudTrail enabled",
                "Lambda execution logs sent to CloudWatch",
            ],
        ),
    ],
    recommended_order=[
        "t1027-guardduty-malware",
        "t1027-high-entropy",
        "t1027-script-obfuscation",
        "t1027-lambda-obfuscation",
        "t1027-gcp-obfuscation",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+25% improvement for Defence Evasion tactic",
)
