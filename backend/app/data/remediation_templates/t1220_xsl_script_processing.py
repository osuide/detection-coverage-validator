"""
T1220 - XSL Script Processing

Adversaries abuse XSL files to execute malicious scripts embedded within them,
bypassing application controls through trusted XML transformation utilities.
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
    technique_id="T1220",
    technique_name="XSL Script Processing",
    tactic_ids=["TA0005"],  # Defense Evasion
    mitre_url="https://attack.mitre.org/techniques/T1220/",
    threat_context=ThreatContext(
        description=(
            "Adversaries embed malicious scripts within XSL (Extensible Stylesheet Language) "
            "files to bypass application controls and execute code. XSL files normally describe "
            "XML data processing, but their scripting capabilities can be weaponised using "
            "msxsl.exe or the 'Squiblytwo' technique with wmic.exe. In cloud environments, "
            "attackers may upload XSL files to S3/Cloud Storage and execute them on compromised "
            "Windows instances to evade detection and maintain persistence."
        ),
        attacker_goal="Execute malicious scripts using trusted XML transformation utilities to bypass security controls",
        why_technique=[
            "Abuses legitimate Windows utilities to evade application control policies",
            "Bypasses AppLocker and other execution prevention mechanisms",
            "Uses trusted signed binaries (msxsl.exe, wmic.exe) to avoid detection",
            "Can execute scripts from remote locations including cloud storage",
            "Allows arbitrary file extensions to disguise malicious XSL files",
            "Enables fileless execution through WMI-based script processing",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="uncommon",
        trend="stable",
        severity_score=6,
        severity_reasoning=(
            "XSL Script Processing is a sophisticated evasion technique that abuses trusted "
            "Windows utilities to execute malicious code. While less common than other techniques, "
            "it is highly effective at bypassing application controls. In cloud environments, "
            "the ability to execute remote XSL files from S3 or Cloud Storage increases the risk, "
            "as attackers can update payloads without touching disk. The technique requires Windows "
            "platforms and specific utilities, limiting its applicability but increasing its value "
            "when targeting Windows-based cloud workloads."
        ),
        business_impact=[
            "Bypass of application control and security policies",
            "Unauthorised code execution on Windows instances",
            "Persistence through scheduled XSL script execution",
            "Data exfiltration via embedded script payloads",
            "Credential theft from compromised Windows workloads",
            "Lateral movement to other Windows systems in cloud environment",
        ],
        typical_attack_phase="defense_evasion",
        often_precedes=["T1059", "T1003", "T1055", "T1021"],
        often_follows=["T1190", "T1078", "T1566", "T1105"],
    ),
    detection_strategies=[
        # Strategy 1: msxsl.exe Execution Detection
        DetectionStrategy(
            strategy_id="t1220-msxsl-execution",
            name="AWS: Detect msxsl.exe Execution via CloudWatch Logs",
            description=(
                "Monitor CloudWatch Logs for execution of msxsl.exe, a non-standard Windows "
                "utility used to transform XML documents with XSL stylesheets. Detects both "
                "local and remote XSL file processing that may contain malicious scripts."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, processName, commandLine, parentProcess
| filter processName like /(?i)msxsl[.]exe/
| filter commandLine like /[.]xsl|[.]xml|http/
| stats count() as executions by instanceId, commandLine, parentProcess, bin(5m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect msxsl.exe execution for XSL script processing

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing Windows instance process logs
    Default: /aws/ec2/windows/security
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create metric filter for msxsl.exe execution
  MsxslExecutionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process="*msxsl.exe*", command]'
      MetricTransformations:
        - MetricName: MsxslExecution
          MetricNamespace: Security/T1220
          MetricValue: "1"

  # Step 2: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: XSL Script Processing Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create alarm for msxsl.exe execution
  MsxslExecutionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1220-MsxslExecution
      AlarmDescription: msxsl.exe execution detected - potential XSL script processing attack
      MetricName: MsxslExecution
      Namespace: Security/T1220
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

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
                terraform_template="""# Detect msxsl.exe execution for XSL script processing

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing Windows instance process logs"
  default     = "/aws/ec2/windows/security"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create metric filter for msxsl.exe execution
resource "aws_cloudwatch_log_metric_filter" "msxsl_execution" {
  name           = "msxsl-execution"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process=\"*msxsl.exe*\", command]"

  metric_transformation {
    name      = "MsxslExecution"
    namespace = "Security/T1220"
    value     = "1"
  }
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "xsl_script_alerts" {
  name         = "xsl-script-processing-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "XSL Script Processing Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.xsl_script_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Create alarm for msxsl.exe execution
resource "aws_cloudwatch_metric_alarm" "msxsl_execution" {
  alarm_name          = "T1220-MsxslExecution"
  alarm_description   = "msxsl.exe execution detected - potential XSL script processing attack"
  metric_name         = "MsxslExecution"
  namespace           = "Security/T1220"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.xsl_script_alerts.arn]
}""",
                alert_severity="high",
                alert_title="msxsl.exe Execution Detected",
                alert_description_template=(
                    "msxsl.exe execution detected on instance {instance_id}. "
                    "Command: {command_line}. Parent process: {parent_process}. "
                    "This may indicate XSL script processing attack to bypass security controls."
                ),
                investigation_steps=[
                    "Review the complete command line to identify XSL and XML file paths",
                    "Check if XSL files are local or downloaded from remote URLs (including S3)",
                    "Examine the parent process that spawned msxsl.exe",
                    "Retrieve and analyse the XSL file content for embedded scripts",
                    "Check CloudTrail for S3 GetObject calls to retrieve XSL files",
                    "Review process tree to identify post-execution activity",
                    "Search for additional msxsl.exe executions across the environment",
                ],
                containment_actions=[
                    "Terminate the msxsl.exe process immediately",
                    "Isolate the instance to prevent lateral movement",
                    "Retrieve the XSL file for forensic analysis before deletion",
                    "Delete any malicious XSL files from local disk and S3 buckets",
                    "Block msxsl.exe execution via AppLocker or application control policies",
                    "Review and rotate credentials accessible to the compromised instance",
                    "Check for persistence mechanisms installed by the script",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="msxsl.exe is not a standard Windows utility; any execution should be investigated",
            detection_coverage="90% - detects all msxsl.exe executions",
            evasion_considerations="Attackers may rename msxsl.exe or use alternative XSL processors",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$8-15 depending on log volume",
            prerequisites=[
                "CloudWatch Logs Agent with Windows process logging",
                "Process creation logging enabled via Sysmon or Windows Events",
            ],
        ),
        # Strategy 2: WMIC Squiblytwo Detection
        DetectionStrategy(
            strategy_id="t1220-wmic-format",
            name="AWS: Detect WMIC /FORMAT Squiblytwo Technique",
            description=(
                "Monitor for wmic.exe execution with the /FORMAT switch, which can execute "
                "JScript or VBScript embedded in XSL files. This 'Squiblytwo' technique "
                "bypasses application controls using a signed Windows binary."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, processName, commandLine, userName
| filter processName like /(?i)wmic[.]exe/
| filter commandLine like /(?i)[/]format|[/]f/
| filter commandLine like /[.]xsl|http|s3[.]|amazonaws[.]com/
| stats count() as wmic_format_executions by instanceId, userName, commandLine, bin(5m)
| sort @timestamp desc""",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect WMIC /FORMAT XSL script execution (Squiblytwo)

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing Windows process execution logs
  SNSTopicArn:
    Type: String
    Description: SNS topic ARN for alerts

Resources:
  # Step 1: Create metric filter for WMIC /FORMAT execution
  WmicFormatFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process="*wmic.exe*", command="*/format*" || command="*/f *"]'
      MetricTransformations:
        - MetricName: WmicFormatExecution
          MetricNamespace: Security/T1220
          MetricValue: "1"

  # Step 2: Create alarm for WMIC /FORMAT usage
  WmicFormatAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1220-WmicSquiblytwo
      AlarmDescription: WMIC /FORMAT execution detected - Squiblytwo technique
      MetricName: WmicFormatExecution
      Namespace: Security/T1220
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Monitor for remote XSL file downloads
  RemoteXslFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process, command="*wmic*" && (command="*http*" || command="*s3*")]'
      MetricTransformations:
        - MetricName: RemoteXslDownload
          MetricNamespace: Security/T1220
          MetricValue: "1"''',
                terraform_template="""# Detect WMIC /FORMAT XSL script execution (Squiblytwo)

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing Windows process execution logs"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "wmic-squiblytwo-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for WMIC /FORMAT execution
resource "aws_cloudwatch_log_metric_filter" "wmic_format" {
  name           = "wmic-format-execution"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process=\"*wmic.exe*\", command=\"*/format*\" || command=\"*/f *\"]"

  metric_transformation {
    name      = "WmicFormatExecution"
    namespace = "Security/T1220"
    value     = "1"
  }
}

# Step 2: Create alarm for WMIC /FORMAT usage
resource "aws_cloudwatch_metric_alarm" "wmic_squiblytwo" {
  alarm_name          = "T1220-WmicSquiblytwo"
  alarm_description   = "WMIC /FORMAT execution detected - Squiblytwo technique"
  metric_name         = "WmicFormatExecution"
  namespace           = "Security/T1220"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Monitor for remote XSL file downloads
resource "aws_cloudwatch_log_metric_filter" "remote_xsl" {
  name           = "remote-xsl-download"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process, command=\"*wmic*\" && (command=\"*http*\" || command=\"*s3*\")]"

  metric_transformation {
    name      = "RemoteXslDownload"
    namespace = "Security/T1220"
    value     = "1"
  }
}""",
                alert_severity="high",
                alert_title="WMIC /FORMAT Squiblytwo Technique Detected",
                alert_description_template=(
                    "WMIC execution with /FORMAT switch detected on instance {instance_id}. "
                    "User: {user_name}. Command: {command_line}. "
                    "This Squiblytwo technique may execute malicious XSL scripts."
                ),
                investigation_steps=[
                    "Extract the complete WMIC command including the XSL file path/URL",
                    "Check if the XSL file was retrieved from a remote location (HTTP/S3)",
                    "Review S3 access logs if the XSL file was hosted in S3",
                    "Identify the user account or process that executed the WMIC command",
                    "Retrieve the XSL file content and analyse for embedded JScript/VBScript",
                    "Check for network connections to external IPs following execution",
                    "Review child processes spawned by the XSL script execution",
                ],
                containment_actions=[
                    "Terminate the WMIC process and any child processes",
                    "Isolate the instance from the network",
                    "Delete malicious XSL files from S3 buckets and local storage",
                    "Block WMIC /FORMAT execution via GPO or AppLocker rules",
                    "Rotate credentials for the user account that executed the command",
                    "Review and restrict S3 bucket policies to prevent public XSL hosting",
                    "Implement application control policies to prevent WMIC script execution",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate use of WMIC /FORMAT is rare; investigate all occurrences",
            detection_coverage="85% - detects WMIC /FORMAT patterns, may miss obfuscated switches",
            evasion_considerations="Attackers may use alternative switch syntax or load XSL from SMB shares",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$8-15",
            prerequisites=[
                "Process execution logging enabled",
                "CloudWatch Logs Agent installed",
            ],
        ),
        # Strategy 3: S3 XSL File Upload Detection
        DetectionStrategy(
            strategy_id="t1220-s3-xsl-upload",
            name="AWS: Detect Suspicious XSL File Uploads to S3",
            description=(
                "Monitor CloudTrail for uploads of XSL files to S3 buckets, particularly "
                "from unusual principals or containing script elements. Detects staging "
                "of XSL scripts for remote execution on compromised instances."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.bucketName, requestParameters.key, sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
| filter eventName in ["PutObject", "CopyObject"]
| filter requestParameters.key like /[.]xsl$/i
| stats count() as xsl_uploads by userIdentity.principalId, requestParameters.bucketName, sourceIPAddress, bin(10m)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious XSL file uploads to S3

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for XSL file uploads
  XslUploadFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "s3.amazonaws.com") && ($.eventName = "PutObject") && ($.requestParameters.key = "*.xsl") }'
      MetricTransformations:
        - MetricName: XslFileUploads
          MetricNamespace: Security/T1220
          MetricValue: "1"

  # Step 2: Create alarm for XSL uploads
  XslUploadAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1220-S3XslUpload
      AlarmDescription: XSL file uploaded to S3 - potential staging for XSL script processing
      MetricName: XslFileUploads
      Namespace: Security/T1220
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Create EventBridge rule for real-time XSL upload detection
  XslUploadRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1220-XslUploadDetection
      Description: Detect XSL file uploads to S3 buckets
      EventPattern:
        source: [aws.s3]
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName: [PutObject, CopyObject]
          requestParameters:
            key:
              - suffix: .xsl
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref SNSTopicArn""",
                terraform_template="""# Detect suspicious XSL file uploads to S3

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type = string
}

resource "aws_sns_topic" "alerts" {
  name = "s3-xsl-upload-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 1: Create metric filter for XSL file uploads
resource "aws_cloudwatch_log_metric_filter" "xsl_uploads" {
  name           = "s3-xsl-file-uploads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.eventName = \"PutObject\") && ($.requestParameters.key = \"*.xsl\") }"

  metric_transformation {
    name      = "XslFileUploads"
    namespace = "Security/T1220"
    value     = "1"
  }
}

# Step 2: Create alarm for XSL uploads
resource "aws_cloudwatch_metric_alarm" "xsl_uploads" {
  alarm_name          = "T1220-S3XslUpload"
  alarm_description   = "XSL file uploaded to S3 - potential staging for XSL script processing"
  metric_name         = "XslFileUploads"
  namespace           = "Security/T1220"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Create EventBridge rule for real-time XSL upload detection
resource "aws_cloudwatch_event_rule" "xsl_upload" {
  name        = "s3-xsl-upload-detection"
  description = "Detect XSL file uploads to S3 buckets"
  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutObject", "CopyObject"]
      requestParameters = {
        key = [{ suffix = ".xsl" }]
      }
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "s3-xsl-upload-dlq"
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
      values   = [aws_cloudwatch_event_rule.xsl_upload.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "xsl_upload_alert" {
  rule      = aws_cloudwatch_event_rule.xsl_upload.name
  target_id = "SendToSNS"
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

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.xsl_upload.arn
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="XSL File Uploaded to S3",
                alert_description_template=(
                    "XSL file uploaded to S3 bucket {bucket_name}. "
                    "Key: {object_key}. Principal: {principal_id}. "
                    "Source IP: {source_ip}. May indicate staging for XSL script processing attack."
                ),
                investigation_steps=[
                    "Download and analyse the XSL file content for embedded scripts",
                    "Review the principal that uploaded the file and their recent activities",
                    "Check if the source IP is expected or from a known threat source",
                    "Review S3 bucket policies and public access settings",
                    "Search for GetObject calls to retrieve this XSL file",
                    "Check if any EC2 instances accessed this XSL file",
                    "Look for other XSL files uploaded by the same principal",
                ],
                containment_actions=[
                    "Delete the malicious XSL file from S3 immediately",
                    "Enable S3 versioning and review previous versions",
                    "Block public access to the S3 bucket",
                    "Review and restrict bucket IAM policies",
                    "Rotate credentials for the principal that uploaded the file",
                    "Enable S3 Object Lock on sensitive buckets",
                    "Implement S3 bucket policies requiring VPC endpoint access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate XSL files used for data transformation; review file content",
            detection_coverage="70% - detects S3-hosted XSL files, may miss files in other storage",
            evasion_considerations="Attackers may use alternative file extensions or store XSL in non-S3 locations",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail S3 data events enabled",
                "S3 bucket logging enabled",
            ],
        ),
        # Strategy 4: GuardDuty Runtime Monitoring
        DetectionStrategy(
            strategy_id="t1220-guardduty-runtime",
            name="AWS: GuardDuty Runtime Monitoring for XSL Script Execution",
            description=(
                "AWS GuardDuty Runtime Monitoring detects suspicious process execution "
                "on EC2 instances, including msxsl.exe and wmic.exe with XSL parameters. "
                "Provides behavioural detection for XSL script processing attacks."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/ReverseShell",
                    "DefenseEvasion:Runtime/ProcessInjection.Proc",
                    "PrivilegeEscalation:Runtime/SuspiciousCommand",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for XSL script processing detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Enable GuardDuty with Runtime Monitoring
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: RUNTIME_MONITORING
          Status: ENABLED

  # Step 2: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: XSL Script Processing Runtime Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route runtime findings to email
  RuntimeDetectionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1220-RuntimeDetection
      Description: Alert on suspicious runtime activity from XSL processing
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Execution:Runtime"
            - prefix: "DefenseEvasion:Runtime"
            - prefix: "PrivilegeEscalation:Runtime"
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref SecurityAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref SecurityAlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt RuntimeDetectionRule.Arn""",
                terraform_template="""# GuardDuty Runtime Monitoring for XSL script processing

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Enable GuardDuty with Runtime Monitoring
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "runtime_alerts" {
  name         = "xsl-script-runtime-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "XSL Script Processing Runtime Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.runtime_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route runtime findings to email
resource "aws_cloudwatch_event_rule" "runtime_detection" {
  name        = "guardduty-xsl-runtime"
  description = "Alert on suspicious runtime activity from XSL processing"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Execution:Runtime" },
        { prefix = "DefenseEvasion:Runtime" },
        { prefix = "PrivilegeEscalation:Runtime" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.runtime_detection.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.runtime_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.runtime_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.runtime_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.runtime_detection.arn
          }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Suspicious Runtime Activity Detected",
                alert_description_template=(
                    "GuardDuty Runtime Monitoring detected suspicious activity on instance {instance_id}. "
                    "Finding: {finding_type}. Process: {process_name}. "
                    "May indicate XSL script processing or related post-exploitation activity."
                ),
                investigation_steps=[
                    "Review the GuardDuty finding details and threat indicators",
                    "Examine the process execution chain on the affected instance",
                    "Check for msxsl.exe or wmic.exe execution in process history",
                    "Review CloudTrail for API calls from the instance role",
                    "Inspect network connections for command-and-control activity",
                    "Search for XSL files on the instance file system",
                    "Check for lateral movement attempts to other instances",
                ],
                containment_actions=[
                    "Isolate the instance by modifying security group rules",
                    "Create a forensic snapshot before remediation",
                    "Terminate suspicious processes identified by GuardDuty",
                    "Revoke the instance IAM role session credentials",
                    "Rotate all credentials accessible from the instance",
                    "Review and patch the instance or rebuild from known-good AMI",
                    "Enable application control policies to prevent future XSL execution",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML models; baseline normal instance behaviour to reduce false positives",
            detection_coverage="75% - detects behavioural patterns associated with XSL script execution",
            evasion_considerations="Sophisticated attackers may use delayed execution or living-off-the-land techniques",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per instance per month for Runtime Monitoring",
            prerequisites=[
                "GuardDuty enabled",
                "SSM Agent on EC2 instances for Runtime Monitoring",
            ],
        ),
        # Strategy 5: GCP Detection
        DetectionStrategy(
            strategy_id="t1220-gcp-xsl-detection",
            name="GCP: Detect XSL Script Processing on Windows Instances",
            description=(
                "Monitor GCP Cloud Logging for msxsl.exe and wmic.exe /FORMAT execution "
                "on Windows Compute Engine instances. Detects XSL script processing attacks "
                "in GCP environments."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(protoPayload.request.commandLine=~"msxsl[.]exe|wmic.*/format|wmic.*/f"
OR textPayload=~"msxsl[.]exe.*[.]xsl|wmic.*format.*[.]xsl"
OR protoPayload.methodName="storage.objects.get"
AND protoPayload.resourceName=~".*[.]xsl$")""",
                gcp_terraform_template="""# GCP: Detect XSL script processing on Windows instances

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
  display_name = "XSL Script Processing Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for XSL script processing
resource "google_logging_metric" "xsl_script_processing" {
  project = var.project_id
  name    = "xsl-script-processing-attempts"
  filter  = <<-EOT
    resource.type="gce_instance"
    (protoPayload.request.commandLine=~"msxsl\\.exe|wmic.*\\/format|wmic.*\\/f"
    OR textPayload=~"msxsl\\.exe.*\\.xsl|wmic.*format.*\\.xsl"
    OR (protoPayload.methodName="storage.objects.get"
        AND protoPayload.resourceName=~".*\\.xsl$"))
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance where XSL processing was detected"
    }
    labels {
      key         = "command"
      value_type  = "STRING"
      description = "Command executed"
    }
  }

  label_extractors = {
    instance_id = "EXTRACT(resource.labels.instance_id)"
    command     = "EXTRACT(protoPayload.request.commandLine)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "xsl_processing" {
  project      = var.project_id
  display_name = "T1220: XSL Script Processing Detected"
  combiner     = "OR"
  conditions {
    display_name = "XSL script processing activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/$${google_logging_metric.xsl_script_processing.name}\" resource.type=\"gce_instance\""
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
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
  documentation {
    content   = <<-EOT
      XSL Script Processing (T1220) detected on GCE instance.

      **Immediate Actions:**
      1. Review the command line and XSL file source
      2. Stop the instance to prevent further compromise
      3. Analyse the XSL file for malicious content
      4. Check for lateral movement or data exfiltration

      **Investigation:** Review Cloud Logging for complete process execution history.
    EOT
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: XSL Script Processing Detected",
                alert_description_template=(
                    "XSL script processing detected on GCE instance {instance_id}. "
                    "Command: {command_line}. Investigate immediately for potential compromise."
                ),
                investigation_steps=[
                    "Review Cloud Logging for complete command execution details",
                    "Check if XSL files were downloaded from Cloud Storage",
                    "Examine the instance's service account permissions",
                    "Review VPC Flow Logs for network connections",
                    "Check for API calls made by the instance service account",
                    "Search for other instances with similar suspicious activity",
                    "Retrieve and analyse the XSL file content",
                ],
                containment_actions=[
                    "Stop the GCE instance immediately",
                    "Create a snapshot for forensic investigation",
                    "Revoke the instance's service account credentials",
                    "Delete malicious XSL files from Cloud Storage buckets",
                    "Update VPC firewall rules to isolate the instance",
                    "Review and restrict Cloud Storage bucket IAM policies",
                    "Implement OS Login for better process auditing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="msxsl.exe and WMIC /FORMAT are rarely used legitimately; investigate all detections",
            detection_coverage="80% - detects known XSL processing patterns on Windows instances",
            evasion_considerations="Attackers may use renamed binaries or alternative XSL processors",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$12-20",
            prerequisites=[
                "Cloud Logging API enabled",
                "Ops Agent on GCE instances",
                "Process execution logging enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1220-guardduty-runtime",
        "t1220-wmic-format",
        "t1220-msxsl-execution",
        "t1220-s3-xsl-upload",
        "t1220-gcp-xsl-detection",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+15% improvement for Defence Evasion tactic",
)
