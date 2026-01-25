"""
T1059 - Command and Scripting Interpreter

Adversaries exploit command and script interpreters to execute commands, scripts, or binaries.
Used by APT19, APT32, APT37, APT39, FIN5, FIN6, FIN7, OilRig, Mustang Panda.
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
    technique_id="T1059",
    technique_name="Command and Scripting Interpreter",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1059/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse command and script interpreters to execute commands, scripts, or binaries. "
            "These interpreters are standard across most platforms (PowerShell, bash, Python, JavaScript) "
            "and provide direct system interaction capabilities. In cloud environments, this includes "
            "CLI tools, cloud shells, SDKs, and container command interfaces that enable adversaries "
            "to execute arbitrary commands and manipulate cloud resources."
        ),
        attacker_goal="Execute malicious commands using legitimate system interpreters to evade detection",
        why_technique=[
            "Interpreters are present on virtually all systems by default",
            "Commands blend with legitimate administrative activity",
            "Provides broad control over system and cloud resources",
            "Can execute encoded or obfuscated payloads",
            "Enables automation of multi-stage attacks",
            "Hard to distinguish from normal scripting usage",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Command and scripting interpreters are fundamental attack vectors across all platforms. "
            "Their ubiquity and legitimate use makes detection challenging whilst providing adversaries "
            "with extensive control over systems and cloud infrastructure. Cloud environments add "
            "additional attack surface through CLI tools, cloud shells, and API-driven execution."
        ),
        business_impact=[
            "Arbitrary code execution on systems and cloud infrastructure",
            "Data exfiltration via scripted commands",
            "Privilege escalation through automated enumeration",
            "Persistence via scheduled scripts",
            "Resource manipulation and security control bypass",
            "Lateral movement automation",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1087", "T1083", "T1069", "T1530", "T1562"],
        often_follows=["T1078", "T1190", "T1566", "T1055"],
    ),
    detection_strategies=[
        # AWS Strategy 1: CloudWatch Process Execution Monitoring
        DetectionStrategy(
            strategy_id="t1059-aws-process-exec",
            name="AWS EC2 Process Execution Monitoring",
            description=(
                "Monitor EC2 instances for suspicious interpreter execution patterns including "
                "encoded commands, unusual parent processes, and unexpected scripting activity."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""# Requires CloudWatch Agent with process monitoring enabled
fields @timestamp, processName, commandLine, parentProcessName, username
| filter processName in ["powershell.exe", "cmd.exe", "bash", "sh", "python", "python3", "perl", "ruby", "node"]
| filter commandLine like /(-enc|-e |base64|wget|curl|Invoke-|IEX|DownloadString)/
| stats count(*) as exec_count by processName, username, commandLine, bin(5m)
| filter exec_count > 5
| sort exec_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious interpreter execution on EC2 instances

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Interpreter Execution Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create CloudWatch Log Metric Filter
  InterpreterMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      FilterPattern: '[time, process=powershell.exe||bash||python, ...]'
      LogGroupName: /aws/ec2/processes
      MetricTransformations:
        - MetricName: SuspiciousInterpreterExecution
          MetricNamespace: Security/T1059
          MetricValue: '1'
          DefaultValue: 0

  # Step 3: Create alarm for suspicious activity
  InterpreterAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1059-SuspiciousInterpreterExecution
      AlarmDescription: Detects unusual interpreter execution patterns
      MetricName: SuspiciousInterpreterExecution
      Namespace: Security/T1059
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchPublishScoped
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect suspicious interpreter execution on EC2 instances

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "interpreter_alerts" {
  name         = "interpreter-execution-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Interpreter Execution Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.interpreter_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create CloudWatch Log Metric Filter
resource "aws_cloudwatch_log_metric_filter" "interpreter_exec" {
  name           = "suspicious-interpreter-execution"
  log_group_name = "/aws/ec2/processes"
  pattern        = "[time, process=powershell.exe||bash||python, ...]"

  metric_transformation {
    name      = "SuspiciousInterpreterExecution"
    namespace = "Security/T1059"
    value     = "1"
  }
}

# Step 3: Create alarm for suspicious activity
resource "aws_cloudwatch_metric_alarm" "interpreter_alert" {
  alarm_name          = "T1059-SuspiciousInterpreterExecution"
  alarm_description   = "Detects unusual interpreter execution patterns"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SuspiciousInterpreterExecution"
  namespace           = "Security/T1059"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.interpreter_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "interpreter_policy" {
  arn = aws_sns_topic.interpreter_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.interpreter_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Suspicious Interpreter Execution Detected",
                alert_description_template=(
                    "Detected suspicious execution of {processName} with potentially malicious command line: {commandLine}. "
                    "User: {username}. This may indicate command and scripting interpreter abuse (T1059)."
                ),
                investigation_steps=[
                    "Review the full command line executed and parent process",
                    "Check if the executing user typically runs such commands",
                    "Examine the process tree to understand execution context",
                    "Look for encoded or obfuscated content in the command",
                    "Review network connections established by the process",
                    "Check for subsequent file modifications or downloads",
                ],
                containment_actions=[
                    "Isolate the affected EC2 instance if compromise confirmed",
                    "Terminate suspicious processes",
                    "Review and rotate credentials that may have been exposed",
                    "Collect memory dumps for forensic analysis",
                    "Block identified malicious scripts at the network level",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Baseline legitimate automation and administrative scripting patterns. "
                "Whitelist known deployment and configuration management tools. "
                "Tune thresholds based on normal command execution frequency."
            ),
            detection_coverage="60% - catches common interpreter abuse patterns",
            evasion_considerations=(
                "Adversaries may use alternative interpreters, binary execution, or "
                "living-off-the-land binaries (LOLBins) to evade detection"
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="£15-40 depending on instance count and log volume",
            prerequisites=[
                "CloudWatch Agent installed on EC2 instances",
                "Process monitoring enabled in CloudWatch Agent configuration",
                "CloudWatch Logs configured to receive process logs",
            ],
        ),
        # AWS Strategy 2: GuardDuty Runtime Monitoring
        DetectionStrategy(
            strategy_id="t1059-aws-guardduty",
            name="GuardDuty Runtime Monitoring for Scripting Abuse",
            description=(
                "Leverage GuardDuty Runtime Monitoring to detect malicious script execution, "
                "reverse shells, and suspicious interpreter activity on EC2 and ECS."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/ReverseShell",
                    "Execution:Runtime/SuspiciousCommand",
                    "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
                    "DefenseEvasion:Runtime/FilelessExecution",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty Runtime Monitoring for T1059 detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email for GuardDuty alerts

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
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: GuardDuty Runtime Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Dead Letter Queue for failed deliveries
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: guardduty-execution-alerts-dlq
      MessageRetentionPeriod: 1209600

  # Step 4: Route execution findings to email
  ExecutionFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1059-ExecutionFindings
      Description: Alert on execution-related GuardDuty findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Execution:Runtime"
            - prefix: "DefenseEvasion:Runtime"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          DeadLetterConfig:
            Arn: !GetAtt DeadLetterQueue.Arn
          InputTransformer:
            InputPathsMap:
              account: $.account
              region: $.region
              time: $.time
              type: $.detail.type
              severity: $.detail.severity
              description: $.detail.description
            InputTemplate: |
              "GuardDuty Runtime Execution Alert (T1059)"
              "Time: <time>"
              "Account: <account> | Region: <region>"
              "Finding Type: <type>"
              "Severity: <severity>"
              "Description: <description>"
              "Action: Investigate runtime execution immediately"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ExecutionFindingsRule.Arn

  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref DeadLetterQueue
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt DeadLetterQueue.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ExecutionFindingsRule.Arn""",
                terraform_template="""# GuardDuty Runtime Monitoring for T1059 detection

variable "alert_email" {
  type = string
}

data "aws_caller_identity" "current" {}

# Step 1: Enable GuardDuty with Runtime Monitoring
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

# Note: Runtime Monitoring requires EKS/ECS agent deployment
# See: https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name              = "guardduty-runtime-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name      = "GuardDuty Runtime Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Dead Letter Queue for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-execution-alerts-dlq"
  message_retention_seconds = 1209600
}

# Step 4: Route execution findings to email
resource "aws_cloudwatch_event_rule" "execution_findings" {
  name        = "T1059-ExecutionFindings"
  description = "Alert on execution-related GuardDuty findings"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Execution:Runtime" },
        { prefix = "DefenseEvasion:Runtime" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.execution_findings.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      account     = "$.account"
      region      = "$.region"
      time        = "$.time"
      type        = "$.detail.type"
      severity    = "$.detail.severity"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Runtime Execution Alert (T1059)
Time: <time>
Account: <account> | Region: <region>
Finding Type: <type>
Severity: <severity>
Description: <description>
Action: Investigate runtime execution immediately"
EOT
  }
}

resource "aws_sns_topic_policy" "guardduty_policy" {
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.execution_findings.arn
        }
      }
    }]
  })
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Malicious Script Execution Detected",
                alert_description_template=(
                    "GuardDuty detected suspicious runtime activity: {finding_type}. "
                    "Resource: {resource}. This may indicate command interpreter abuse (T1059)."
                ),
                investigation_steps=[
                    "Review the GuardDuty finding details and severity",
                    "Examine the affected EC2 instance or container",
                    "Check process lineage and command line arguments",
                    "Review network activity from the affected resource",
                    "Look for lateral movement indicators",
                    "Check for persistence mechanisms",
                ],
                containment_actions=[
                    "Isolate the affected instance or container",
                    "Snapshot the instance for forensic analysis",
                    "Terminate malicious processes",
                    "Revoke temporary credentials if container-based",
                    "Update security groups to prevent further access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty's ML models are pre-tuned. Add trusted processes to suppression rules. "
                "Exclude known CI/CD and automation workflows."
            ),
            detection_coverage="75% - comprehensive runtime behaviour analysis",
            evasion_considerations=(
                "May not detect very subtle or low-frequency command execution. "
                "Requires agent deployment for full coverage."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="£25-50 for Runtime Monitoring feature",
            prerequisites=[
                "GuardDuty enabled in AWS account",
                "ECS or EKS agent deployed for Runtime Monitoring",
                "IAM permissions for GuardDuty to monitor resources",
            ],
        ),
        # AWS Strategy 3: Lambda Execution Monitoring
        DetectionStrategy(
            strategy_id="t1059-aws-lambda",
            name="AWS Lambda Suspicious Execution Detection",
            description=(
                "Monitor Lambda function executions for suspicious runtime behaviour including "
                "unexpected interpreter usage, reverse shells, and malicious code execution."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, @logStream
| filter @message like /(?i)(sh|bash|cmd|powershell|eval|exec|system|subprocess)/
| filter @message like /(?i)(curl|wget|nc|netcat|reverse|shell|download|invoke)/
| stats count(*) as suspicious_calls by @logStream, bin(5m)
| filter suspicious_calls > 3
| sort suspicious_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious Lambda function execution patterns

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for Lambda security alerts
  LambdaAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Lambda Security Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for suspicious Lambda activity
  SuspiciousLambdaFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      FilterPattern: '[time, request_id, level, msg="*bash*" || msg="*curl*" || msg="*wget*" || msg="*nc*"]'
      LogGroupName: /aws/lambda/*
      MetricTransformations:
        - MetricName: SuspiciousLambdaExecution
          MetricNamespace: Security/T1059
          MetricValue: '1'

  # Step 3: Create alarm for Lambda abuse
  LambdaExecutionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1059-SuspiciousLambdaExecution
      AlarmDescription: Detects suspicious command execution in Lambda functions
      MetricName: SuspiciousLambdaExecution
      Namespace: Security/T1059
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref LambdaAlertTopic""",
                terraform_template="""# Detect suspicious Lambda function execution patterns

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic for Lambda security alerts
resource "aws_sns_topic" "lambda_alerts" {
  name         = "lambda-security-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Lambda Security Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.lambda_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious Lambda activity
resource "aws_cloudwatch_log_metric_filter" "suspicious_lambda" {
  name           = "suspicious-lambda-execution"
  log_group_name = "/aws/lambda/*"  # Adjust to specific functions if needed
  pattern        = "[time, request_id, level, msg=\"*bash*\" || msg=\"*curl*\" || msg=\"*wget*\" || msg=\"*nc*\"]"

  metric_transformation {
    name      = "SuspiciousLambdaExecution"
    namespace = "Security/T1059"
    value     = "1"
  }
}

# Step 3: Create alarm for Lambda abuse
resource "aws_cloudwatch_metric_alarm" "lambda_execution_alert" {
  alarm_name          = "T1059-SuspiciousLambdaExecution"
  alarm_description   = "Detects suspicious command execution in Lambda functions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SuspiciousLambdaExecution"
  namespace           = "Security/T1059"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.lambda_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious Lambda Function Execution",
                alert_description_template=(
                    "Lambda function exhibited suspicious behaviour with {suspicious_calls} "
                    "potentially malicious command executions. Function: {logStream}."
                ),
                investigation_steps=[
                    "Review Lambda function code for malicious modifications",
                    "Check function environment variables for injected commands",
                    "Examine function invocation source (trigger, API call)",
                    "Review IAM role permissions for the Lambda function",
                    "Check for lateral movement or data access attempts",
                    "Analyse CloudTrail for function updates or modifications",
                ],
                containment_actions=[
                    "Remove or update the compromised Lambda function",
                    "Revoke IAM role credentials associated with the function",
                    "Review and restrict Lambda execution role permissions",
                    "Enable Lambda function code signing",
                    "Block trigger sources if malicious",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Exclude legitimate system administration Lambda functions. "
                "Adjust patterns to ignore approved deployment and automation tools."
            ),
            detection_coverage="65% - catches common serverless execution abuse",
            evasion_considerations=(
                "Sophisticated attackers may use language-native functions instead of "
                "shell commands to evade string-based detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="£8-25 depending on Lambda usage",
            prerequisites=[
                "Lambda functions with CloudWatch Logs enabled",
                "CloudWatch Logs retention configured",
            ],
        ),
        # GCP Strategy 1: Cloud Logging Process Monitoring
        DetectionStrategy(
            strategy_id="t1059-gcp-process",
            name="GCP Compute Engine Process Execution Monitoring",
            description=(
                "Monitor GCP Compute Engine instances for suspicious interpreter and script "
                "execution using Cloud Logging and OS Config management."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
logName="projects/PROJECT_ID/logs/syslog"
jsonPayload.message=~"(bash|sh|python|perl|ruby|node).*(-c|eval|exec|system)"
OR jsonPayload.message=~"(curl|wget).*http"
OR jsonPayload.message=~"nc.*-e|/bin/sh"''',
                gcp_terraform_template="""# GCP: Monitor suspicious interpreter execution

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  display_name = "Security Alerts Email"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for interpreter execution
resource "google_logging_metric" "interpreter_exec" {
  name    = "suspicious-interpreter-execution"
  project = var.project_id

  filter = <<-EOT
    resource.type="gce_instance"
    logName="projects/${var.project_id}/logs/syslog"
    (jsonPayload.message=~"(bash|sh|python|perl|ruby|node).*(-c|eval|exec|system)"
    OR jsonPayload.message=~"(curl|wget).*http"
    OR jsonPayload.message=~"nc.*-e|/bin/sh")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    display_name = "Suspicious Interpreter Execution Count"
  }
}

# Step 3: Create alert policy for detection
resource "google_monitoring_alert_policy" "interpreter_alert" {
  project      = var.project_id
  display_name = "T1059 - Suspicious Interpreter Execution"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious interpreter activity detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.interpreter_exec.name}\" AND resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "604800s"  # 7 days
  }

  documentation {
    content = <<-EOT
      Suspicious interpreter execution detected on GCP Compute Engine instance.
      This may indicate T1059 (Command and Scripting Interpreter) abuse.

      Investigation steps:
      1. Review the instance logs for executed commands
      2. Check instance metadata and SSH access logs
      3. Verify the user accounts that executed commands
      4. Look for lateral movement or data exfiltration
    EOT
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious Interpreter Execution",
                alert_description_template=(
                    "Detected suspicious command interpreter execution on GCP instance. "
                    "This may indicate malicious scripting activity (T1059)."
                ),
                investigation_steps=[
                    "Review Cloud Logging for full command execution details",
                    "Check instance OS inventory and running processes",
                    "Verify SSH access logs and service account usage",
                    "Examine VPC flow logs for network connections",
                    "Review IAM audit logs for permission escalation",
                    "Check for persistence mechanisms (startup scripts, cron)",
                ],
                containment_actions=[
                    "Stop the affected Compute Engine instance",
                    "Create snapshot for forensic analysis",
                    "Revoke service account keys if compromised",
                    "Update firewall rules to isolate the instance",
                    "Review and remove malicious startup scripts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Exclude known automation and deployment workflows. "
                "Baseline normal administrative script execution patterns. "
                "Adjust thresholds based on environment size."
            ),
            detection_coverage="65% - catches common interpreter abuse patterns",
            evasion_considerations=(
                "May not detect binary execution or living-off-the-land techniques. "
                "Advanced adversaries may use compiled languages."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="£10-30 depending on instance count",
            prerequisites=[
                "Cloud Logging enabled on Compute Engine instances",
                "OS Config or logging agent installed",
                "Appropriate IAM permissions for monitoring",
            ],
        ),
        # GCP Strategy 2: Cloud Functions Execution Monitoring
        DetectionStrategy(
            strategy_id="t1059-gcp-functions",
            name="GCP Cloud Functions Suspicious Execution Detection",
            description=(
                "Detect suspicious command execution and interpreter abuse in Cloud Functions "
                "through log analysis and behaviour monitoring."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
severity>=WARNING
textPayload=~"(subprocess|os.system|exec|eval|shell|bash|sh)"
OR textPayload=~"(requests.get|urllib|curl|wget)"
OR jsonPayload.message=~"command.*execution"''',
                gcp_terraform_template="""# GCP: Detect suspicious Cloud Functions execution

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "functions_email" {
  display_name = "Cloud Functions Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for suspicious function execution
resource "google_logging_metric" "function_exec" {
  name    = "suspicious-function-execution"
  project = var.project_id

  filter = <<-EOT
    resource.type="cloud_function"
    severity>=WARNING
    (textPayload=~"(subprocess|os.system|exec|eval|shell|bash|sh)"
    OR textPayload=~"(requests.get|urllib|curl|wget)"
    OR jsonPayload.message=~"command.*execution")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    display_name = "Suspicious Function Execution"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "function_alert" {
  project      = var.project_id
  display_name = "T1059 - Suspicious Cloud Function Execution"
  combiner     = "OR"

  conditions {
    display_name = "Malicious Cloud Function behaviour"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_exec.name}\""
      duration        = "180s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5

      aggregations {
        alignment_period   = "180s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.functions_email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = <<-EOT
      Suspicious execution detected in Cloud Functions.
      May indicate T1059 (Command and Scripting Interpreter) abuse.

      Investigate immediately:
      - Review function source code for modifications
      - Check function environment variables
      - Audit deployment history
      - Review service account permissions
    EOT
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious Cloud Function Execution",
                alert_description_template=(
                    "Cloud Function exhibited suspicious command execution behaviour. "
                    "This may indicate malicious code injection or function compromise (T1059)."
                ),
                investigation_steps=[
                    "Review Cloud Function source code and recent deployments",
                    "Check function environment variables for injection",
                    "Examine invocation source and triggers",
                    "Review service account permissions and access logs",
                    "Check for data exfiltration or lateral movement",
                    "Analyse Cloud Build history for unauthorised deployments",
                ],
                containment_actions=[
                    "Disable or delete the compromised Cloud Function",
                    "Revoke service account credentials",
                    "Review and restrict function IAM bindings",
                    "Enable VPC Service Controls to limit access",
                    "Audit and remove malicious environment variables",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Exclude legitimate system integration functions. "
                "Baseline normal HTTP request patterns for external API calls. "
                "Adjust severity thresholds."
            ),
            detection_coverage="70% - detects common serverless execution abuse",
            evasion_considerations=(
                "Language-native functions may evade string-based detection. "
                "Low-frequency execution may avoid threshold triggers."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="£5-20 depending on function usage",
            prerequisites=[
                "Cloud Functions deployed with Cloud Logging enabled",
                "Monitoring API enabled in GCP project",
            ],
        ),
        # GCP Strategy 3: Cloud Shell Abuse Detection
        DetectionStrategy(
            strategy_id="t1059-gcp-shell",
            name="GCP Cloud Shell Abuse Detection",
            description=(
                "Monitor Cloud Shell usage for suspicious activity including unusual command "
                "patterns, enumeration, and unauthorised resource manipulation."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="cloudshell.googleapis.com/Environment"
protoPayload.methodName="google.cloudshell.v1.CloudShellService.StartSession"
OR (resource.type="audited_resource"
    protoPayload.serviceName="cloudshell.googleapis.com"
    protoPayload.methodName!="google.cloudshell.v1.CloudShellService.GetEnvironment")""",
                gcp_terraform_template="""# GCP: Detect Cloud Shell abuse

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "shell_email" {
  display_name = "Cloud Shell Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for Cloud Shell usage
resource "google_logging_metric" "shell_usage" {
  name    = "cloud-shell-activity"
  project = var.project_id

  filter = <<-EOT
    resource.type="cloudshell.googleapis.com/Environment"
    protoPayload.methodName="google.cloudshell.v1.CloudShellService.StartSession"
    OR (resource.type="audited_resource"
        protoPayload.serviceName="cloudshell.googleapis.com")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    display_name = "Cloud Shell Activity"
  }
}

# Step 3: Create alert for unusual Cloud Shell usage
resource "google_monitoring_alert_policy" "shell_alert" {
  project      = var.project_id
  display_name = "T1059 - Unusual Cloud Shell Activity"
  combiner     = "OR"

  conditions {
    display_name = "High Cloud Shell usage detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.shell_usage.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.labels.user_email"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.shell_email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = <<-EOT
      Unusual Cloud Shell activity detected.
      May indicate T1059 (Command and Scripting Interpreter) via Cloud Shell.

      Actions:
      - Review user's Cloud Shell command history if available
      - Check for enumeration or privilege escalation attempts
      - Verify user identity and access patterns
      - Review IAM audit logs for suspicious actions
    EOT
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Unusual Cloud Shell Activity",
                alert_description_template=(
                    "Detected unusual Cloud Shell usage patterns. User may be leveraging "
                    "Cloud Shell for reconnaissance or command execution (T1059)."
                ),
                investigation_steps=[
                    "Review Cloud Audit Logs for user's Cloud Shell sessions",
                    "Check user's IAM permissions and recent grants",
                    "Examine API calls made during Cloud Shell sessions",
                    "Look for resource enumeration patterns",
                    "Review data access and exfiltration indicators",
                    "Verify user's typical Cloud Shell usage patterns",
                ],
                containment_actions=[
                    "Suspend user's Cloud Shell access if unauthorised",
                    "Review and revoke excessive IAM permissions",
                    "Rotate user credentials if compromise suspected",
                    "Enable additional monitoring for the user account",
                    "Implement organisation policy to restrict Cloud Shell access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Baseline normal Cloud Shell usage per user. "
                "Exclude known power users and administrators. "
                "Adjust thresholds based on organisation size and development practices."
            ),
            detection_coverage="60% - catches anomalous Cloud Shell behaviour",
            evasion_considerations=(
                "Legitimate-looking commands may blend with normal usage. "
                "Low-frequency attacks may evade rate-based detection."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="1-2 hours",
            estimated_monthly_cost="£3-15",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Cloud Shell service enabled in organisation",
            ],
        ),
        # AWS Strategy 4: SSM Run Command/Session Manager Detection (T1059.009)
        DetectionStrategy(
            strategy_id="t1059-aws-ssm",
            name="AWS SSM Run Command and Session Manager Detection",
            description=(
                "Detect AWS Systems Manager Run Command and Session Manager usage for "
                "command execution on EC2 instances. Attackers use SSM to execute commands "
                "without requiring direct SSH/RDP access (T1059.009 - Cloud API)."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "SendCommand",
                            "StartSession",
                            "StartAutomationExecution",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect AWS SSM Run Command and Session Manager usage (T1059.009)

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: SSM Command Execution Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Dead Letter Queue for failed deliveries
  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: ssm-command-alerts-dlq
      MessageRetentionPeriod: 1209600

  # Step 3: EventBridge rule for SSM command execution
  SSMCommandRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1059-SSMCommandExecution
      Description: Detect SSM Run Command and Session Manager usage
      EventPattern:
        source:
          - aws.ssm
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - SendCommand
            - StartSession
            - StartAutomationExecution
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          DeadLetterConfig:
            Arn: !GetAtt DeadLetterQueue.Arn
          InputTransformer:
            InputPathsMap:
              account: $.account
              region: $.region
              time: $.time
              eventName: $.detail.eventName
              userArn: $.detail.userIdentity.arn
              sourceIp: $.detail.sourceIPAddress
              documentName: $.detail.requestParameters.documentName
              instanceId: $.detail.requestParameters.target
            InputTemplate: |
              "SSM Command Execution Alert (T1059.009)"
              "Time: <time>"
              "Account: <account> | Region: <region>"
              "Event: <eventName>"
              "User: <userArn>"
              "Source IP: <sourceIp>"
              "Document: <documentName>"
              "Target: <instanceId>"
              "Action: Verify this SSM command execution is authorised"

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt SSMCommandRule.Arn

  DLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref DeadLetterQueue
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt DeadLetterQueue.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt SSMCommandRule.Arn""",
                terraform_template="""# Detect AWS SSM Run Command and Session Manager usage (T1059.009)

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

data "aws_caller_identity" "current" {}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "ssm_alerts" {
  name              = "ssm-command-execution-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name      = "SSM Command Execution Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Dead Letter Queue for failed deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "ssm-command-alerts-dlq"
  message_retention_seconds = 1209600
}

# Step 3: EventBridge rule for SSM command execution
resource "aws_cloudwatch_event_rule" "ssm_commands" {
  name        = "T1059-SSMCommandExecution"
  description = "Detect SSM Run Command and Session Manager usage"

  event_pattern = jsonencode({
    source        = ["aws.ssm"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand", "StartSession", "StartAutomationExecution"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ssm_commands.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.ssm_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      account      = "$.account"
      region       = "$.region"
      time         = "$.time"
      eventName    = "$.detail.eventName"
      userArn      = "$.detail.userIdentity.arn"
      sourceIp     = "$.detail.sourceIPAddress"
      documentName = "$.detail.requestParameters.documentName"
      instanceId   = "$.detail.requestParameters.target"
    }

    input_template = <<-EOT
"SSM Command Execution Alert (T1059.009)
Time: <time>
Account: <account> | Region: <region>
Event: <eventName>
User: <userArn>
Source IP: <sourceIp>
Document: <documentName>
Target: <instanceId>
Action: Verify this SSM command execution is authorised"
EOT
  }
}

resource "aws_sns_topic_policy" "ssm_policy" {
  arn = aws_sns_topic.ssm_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssm_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ssm_commands.arn
        }
      }
    }]
  })
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="AWS SSM Command Execution",
                alert_description_template=(
                    "AWS Systems Manager command execution detected. User {userArn} executed "
                    "{eventName} targeting {instanceId} from {sourceIp}. "
                    "Verify this SSM activity is authorised (T1059.009)."
                ),
                investigation_steps=[
                    "Verify the user identity and whether they normally use SSM",
                    "Check the source IP address for anomalies",
                    "Review the SSM document and commands executed",
                    "Examine the target instances for suspicious activity",
                    "Check CloudTrail for other SSM activity from the same user",
                    "Review session logs if Session Manager was used",
                ],
                containment_actions=[
                    "Terminate active SSM sessions if unauthorised",
                    "Revoke IAM permissions for SSM access",
                    "Isolate affected EC2 instances",
                    "Review and rotate credentials if compromise suspected",
                    "Enable SSM session logging to S3/CloudWatch",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist known automation users and CI/CD pipelines. "
                "Exclude scheduled maintenance windows. "
                "Filter by specific SSM documents used legitimately."
            ),
            detection_coverage="85% - catches all SSM command executions via CloudTrail",
            evasion_considerations=(
                "Attackers with IAM access could use other methods. "
                "SSM Session Manager provides interactive access without network exposure."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="£2-5",
            prerequisites=[
                "CloudTrail enabled with management events",
                "SSM service enabled in the account",
            ],
        ),
        # Azure Strategy: Command and Scripting Interpreter
        DetectionStrategy(
            strategy_id="t1059-azure",
            name="Azure Command and Scripting Interpreter Detection",
            description=(
                "Azure detection for Command and Scripting Interpreter. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Azure Log Analytics KQL Query: Command and Scripting Interpreter
// MITRE ATT&CK: T1059
// Detects Azure VM Run Command, Azure Automation, Cloud Shell, and script execution
let lookback = 24h;
// VM Run Command execution
let vmRunCommand = AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue has_any (
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/WRITE",
    "Microsoft.Compute/virtualMachines/runCommand/action"
)
| where ActivityStatusValue in ("Success", "Succeeded", "Started")
| extend TechniqueDetail = "VM Run Command execution"
| project TimeGenerated, Caller, CallerIpAddress, SubscriptionId, ResourceGroup,
    Resource, OperationNameValue, TechniqueDetail, ActivityStatusValue;
// Azure Automation Runbook execution
let automationRunbook = AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue has_any (
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/PUBLISH/ACTION",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/JOBS/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE",
    "Microsoft.Automation/automationAccounts/jobs/write"
)
| where ActivityStatusValue in ("Success", "Succeeded", "Started")
| extend TechniqueDetail = "Automation Runbook execution"
| project TimeGenerated, Caller, CallerIpAddress, SubscriptionId, ResourceGroup,
    Resource, OperationNameValue, TechniqueDetail, ActivityStatusValue;
// Cloud Shell usage
let cloudShell = AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue has_any (
    "MICROSOFT.PORTAL/CONSOLES/WRITE",
    "Microsoft.Portal/consoles/write"
)
| where ActivityStatusValue in ("Success", "Succeeded")
| extend TechniqueDetail = "Cloud Shell session"
| project TimeGenerated, Caller, CallerIpAddress, SubscriptionId, ResourceGroup,
    Resource, OperationNameValue, TechniqueDetail, ActivityStatusValue;
// Azure Functions execution (potential script execution)
let functionExecution = AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue has_any (
    "MICROSOFT.WEB/SITES/FUNCTIONS/WRITE",
    "MICROSOFT.WEB/SITES/HOST/SYNC/ACTION"
)
| where ActivityStatusValue in ("Success", "Succeeded")
| extend TechniqueDetail = "Azure Functions execution"
| project TimeGenerated, Caller, CallerIpAddress, SubscriptionId, ResourceGroup,
    Resource, OperationNameValue, TechniqueDetail, ActivityStatusValue;
// Union all results
union vmRunCommand, automationRunbook, cloudShell, functionExecution
| summarize
    EventCount = count(),
    TechniquesUsed = make_set(TechniqueDetail),
    Operations = make_set(OperationNameValue, 10),
    Resources = make_set(Resource, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Caller, CallerIpAddress, SubscriptionId
| extend
    AccountName = tostring(split(Caller, "@")[0]),
    AccountDomain = tostring(split(Caller, "@")[1])
| project
    TimeGenerated = LastSeen,
    AccountName, AccountDomain, Caller, CallerIpAddress,
    SubscriptionId, EventCount, TechniquesUsed, Operations, Resources""",
                sentinel_rule_query="""// Sentinel Analytics Rule: Command and Scripting Interpreter
// MITRE ATT&CK: T1059
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
                azure_terraform_template="""# Azure Detection for Command and Scripting Interpreter
# MITRE ATT&CK: T1059

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
  name                = "command-and-scripting-interpreter-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "command-and-scripting-interpreter-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Sentinel Analytics Rule: Command and Scripting Interpreter
// MITRE ATT&CK: T1059
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

  description = "Detects Command and Scripting Interpreter (T1059) activity in Azure environment"
  display_name = "Command and Scripting Interpreter Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1059"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Command and Scripting Interpreter Detected",
                alert_description_template=(
                    "Command and Scripting Interpreter activity detected. "
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
        "t1059-aws-guardduty",
        "t1059-aws-ssm",
        "t1059-gcp-functions",
        "t1059-gcp-shell",
        "t1059-aws-lambda",
        "t1059-aws-process-exec",
        "t1059-gcp-process",
    ],
    total_effort_hours=15.0,
    coverage_improvement="+20% improvement for Execution tactic across AWS and GCP",
)
