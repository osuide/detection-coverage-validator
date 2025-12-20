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
    Campaign,
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
        known_threat_actors=[
            "APT19",
            "APT32",
            "APT37",
            "APT39",
            "FIN5",
            "FIN6",
            "FIN7",
            "OilRig",
            "Dragonfly",
            "Fox Kitten",
            "Mustang Panda",
            "Winter Vivern",
            "Stealth Falcon",
            "Whitefly",
        ],
        recent_campaigns=[
            Campaign(
                name="APT32 PowerShell Backdoors",
                year=2024,
                description="Leveraged PowerShell and JavaScript to deploy backdoors across compromised networks",
                reference_url="https://attack.mitre.org/groups/G0050/",
            ),
            Campaign(
                name="FIN7 JSSLoader",
                year=2023,
                description="Used JavaScript-based loader to execute commands and deploy additional payloads",
                reference_url="https://attack.mitre.org/groups/G0046/",
            ),
            Campaign(
                name="Mustang Panda PlugX",
                year=2024,
                description="Employed scripting interpreters for initial execution and persistence mechanisms",
                reference_url="https://attack.mitre.org/groups/G0129/",
            ),
        ],
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
      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect suspicious interpreter execution on EC2 instances

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "interpreter_alerts" {
  name         = "interpreter-execution-alerts"
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
  alarm_actions       = [aws_sns_topic.interpreter_alerts.arn]
}

resource "aws_sns_topic_policy" "interpreter_policy" {
  arn = aws_sns_topic.interpreter_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.interpreter_alerts.arn
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
                    "Execution:Runtime/SuspiciousCommandExecuted",
                    "PrivilegeEscalation:Runtime/ContainerMountsWithShadowFile",
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
      DisplayName: GuardDuty Runtime Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route execution findings to email
  ExecutionFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1059-ExecutionFindings
      Description: Alert on execution-related GuardDuty findings
      EventPattern:
        source:
          - aws.guardduty
        detail:
          type:
            - prefix: "Execution:Runtime"
            - prefix: "DefenseEvasion:Runtime"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# GuardDuty Runtime Monitoring for T1059 detection

variable "alert_email" {
  type = string
}

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
  name         = "guardduty-runtime-alerts"
  display_name = "GuardDuty Runtime Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route execution findings to email
resource "aws_cloudwatch_event_rule" "execution_findings" {
  name        = "T1059-ExecutionFindings"
  description = "Alert on execution-related GuardDuty findings"

  event_pattern = jsonencode({
    source = ["aws.guardduty"]
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
}

resource "aws_sns_topic_policy" "guardduty_policy" {
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
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
      AlarmActions:
        - !Ref LambdaAlertTopic""",
                terraform_template="""# Detect suspicious Lambda function execution patterns

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic for Lambda security alerts
resource "aws_sns_topic" "lambda_alerts" {
  name         = "lambda-security-alerts"
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
resource "google_monitoring_notification_channel" "email" {
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
  display_name = "T1059 - Suspicious Interpreter Execution"
  project      = var.project_id
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

  notification_channels = [google_monitoring_notification_channel.email.id]

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
  display_name = "T1059 - Suspicious Cloud Function Execution"
  project      = var.project_id
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
  display_name = "T1059 - Unusual Cloud Shell Activity"
  project      = var.project_id
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
    ],
    recommended_order=[
        "t1059-aws-guardduty",
        "t1059-gcp-functions",
        "t1059-gcp-shell",
        "t1059-aws-lambda",
        "t1059-aws-process-exec",
        "t1059-gcp-process",
    ],
    total_effort_hours=15.0,
    coverage_improvement="+20% improvement for Execution tactic across AWS and GCP",
)
