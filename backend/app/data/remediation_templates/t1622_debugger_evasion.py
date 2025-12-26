"""
T1622 - Debugger Evasion

Adversaries employ debugger detection techniques to avoid reverse engineering analysis.
When malware detects a debugger, it may alter behaviour, disengage, or hide core functionality.
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
    technique_id="T1622",
    technique_name="Debugger Evasion",
    tactic_ids=["TA0005", "TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1622/",
    threat_context=ThreatContext(
        description=(
            "Adversaries employ debugger detection techniques to avoid reverse engineering analysis. "
            "When malware detects a debugger, it may alter its behaviour, disengage from the victim, "
            "or hide its core functionality. Common techniques include API calls like IsDebuggerPresent() "
            "on Windows, ptrace() checks on Linux, and inspecting process status flags to detect analysis environments."
        ),
        attacker_goal="Evade security analysis and debugging by detecting reverse engineering tools",
        why_technique=[
            "Prevents security researchers from analysing malware behaviour",
            "Hides malicious payloads from automated analysis systems",
            "Enables selective execution of malicious code only when not being debugged",
            "Reduces likelihood of detection signatures being created",
            "Protects malware intellectual property from analysis",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Whilst debugger evasion doesn't directly cause damage, it's a critical defence evasion "
            "technique that prevents security analysis and enables subsequent malicious activities to "
            "proceed undetected. The presence of anti-debugging checks strongly indicates malicious "
            "intent and sophisticated threat actor behaviour, particularly in cloud workloads."
        ),
        business_impact=[
            "Reduced efficacy of security analysis and incident response",
            "Delayed threat detection and malware characterisation",
            "Incomplete forensic evidence and behavioural telemetry",
            "Potential for undetected malware execution in production",
            "Increased complexity in threat hunting operations",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1059", "T1105", "T1486"],
        often_follows=["T1204", "T1566", "T1190"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Lambda Anti-Debugging Behaviour
        DetectionStrategy(
            strategy_id="t1622-aws-lambda-debug-checks",
            name="AWS Lambda Anti-Debugging Detection",
            description=(
                "Detect Lambda functions performing debugger detection checks typical of malware, "
                "such as checking for debugging flags, exception handling patterns, or process inspection APIs."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, @logStream
| filter @message like /(?i)(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|BeingDebugged|DebuggerPresent)/
  or @message like /(?i)(ptrace|PTRACE_TRACEME|PTRACE_DENY_ATTACH|TracerPid)/
  or @message like /(?i)(OutputDebugString|UnhandledExceptionFilter|SEH|exception.*debug)/
| stats count(*) as debug_checks by @logStream, bin(5m) as time_window
| filter debug_checks >= 2
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Lambda anti-debugging behaviour detection for T1622

Parameters:
  LambdaLogGroup:
    Type: String
    Description: CloudWatch log group for Lambda functions
  SNSTopicArn:
    Type: String
    Description: SNS topic for security alerts

Resources:
  # Step 1: Metric filter for debugger detection checks
  DebuggerEvasionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LambdaLogGroup
      FilterPattern: '[msg="*IsDebuggerPresent*" || msg="*ptrace*" || msg="*PTRACE_DENY_ATTACH*" || msg="*BeingDebugged*" || msg="*TracerPid*" || msg="*CheckRemoteDebuggerPresent*"]'
      MetricTransformations:
        - MetricName: DebuggerEvasionChecks
          MetricNamespace: Security/T1622
          MetricValue: "1"

  # Step 2: Alarm for suspicious debugger checks
  DebuggerEvasionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1622-LambdaDebuggerEvasion
      AlarmDescription: Lambda function performing debugger detection checks
      MetricName: DebuggerEvasionChecks
      Namespace: Security/T1622
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 2
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Query definition for investigation
  DebuggerEvasionQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: T1622-LambdaDebuggerEvasion
      LogGroupNames:
        - !Ref LambdaLogGroup
      QueryString: |
        fields @timestamp, @message, @logStream
        | filter @message like /(?i)(IsDebuggerPresent|ptrace|BeingDebugged|TracerPid)/
        | stats count(*) as debug_checks by @logStream, bin(5m)
        | sort @timestamp desc""",
                terraform_template="""# Lambda anti-debugging behaviour detection for T1622

variable "lambda_log_group" {
  type        = string
  description = "CloudWatch log group for Lambda functions"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic for security alerts"
}

# Step 1: Metric filter for debugger detection checks
resource "aws_cloudwatch_log_metric_filter" "debugger_evasion" {
  name           = "T1622-DebuggerEvasion"
  log_group_name = var.lambda_log_group
  pattern        = "[msg=\"*IsDebuggerPresent*\" || msg=\"*ptrace*\" || msg=\"*PTRACE_DENY_ATTACH*\" || msg=\"*BeingDebugged*\" || msg=\"*TracerPid*\" || msg=\"*CheckRemoteDebuggerPresent*\"]"

  metric_transformation {
    name      = "DebuggerEvasionChecks"
    namespace = "Security/T1622"
    value     = "1"
  }
}

# Step 2: Alarm for suspicious debugger checks
resource "aws_cloudwatch_metric_alarm" "debugger_evasion" {
  alarm_name          = "T1622-LambdaDebuggerEvasion"
  alarm_description   = "Lambda function performing debugger detection checks"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "DebuggerEvasionChecks"
  namespace           = "Security/T1622"
  period              = 300
  statistic           = "Sum"
  threshold           = 2
  treat_missing_data  = "notBreaching"

  alarm_actions       = [var.sns_topic_arn]
}

# Step 3: Query definition for investigation
resource "aws_cloudwatch_query_definition" "debugger_evasion" {
  name = "T1622-LambdaDebuggerEvasion"

  log_group_names = [var.lambda_log_group]

  query_string = <<-EOT
    fields @timestamp, @message, @logStream
    | filter @message like /(?i)(IsDebuggerPresent|ptrace|BeingDebugged|TracerPid)/
    | stats count(*) as debug_checks by @logStream, bin(5m)
    | sort @timestamp desc
  EOT
}""",
                alert_severity="high",
                alert_title="Lambda Anti-Debugging Behaviour Detected",
                alert_description_template=(
                    "Lambda function {logStream} performed {debug_checks} debugger detection checks "
                    "consistent with anti-debugging techniques. This strongly indicates malicious code "
                    "attempting to evade security analysis."
                ),
                investigation_steps=[
                    "Review the Lambda function's code for anti-debugging API calls",
                    "Identify who deployed or last modified the function",
                    "Check function's execution history and invocation patterns",
                    "Analyse what the function does when debugger is not detected",
                    "Review IAM permissions granted to the function",
                    "Check for code obfuscation or packing techniques",
                    "Examine function dependencies and imported libraries",
                ],
                containment_actions=[
                    "Immediately disable or quarantine the suspicious Lambda function",
                    "Review and revoke excessive IAM permissions",
                    "Extract and analyse function code in isolated environment",
                    "Check for similar functions deployed by the same principal",
                    "Review CloudTrail for function deployment and update events",
                    "Enable AWS Lambda Insights for enhanced monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate debugging tools rare in Lambda; validate any whitelisted functions",
            detection_coverage="70% - catches functions with common anti-debugging checks",
            evasion_considerations="Sophisticated malware may use obfuscated or dynamically loaded anti-debugging code",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Lambda function logs sent to CloudWatch"],
        ),
        # Strategy 2: AWS - ECS Container Anti-Debugging
        DetectionStrategy(
            strategy_id="t1622-aws-ecs-debug-detection",
            name="AWS ECS Container Debugger Detection",
            description=(
                "Monitor ECS container logs for process inspection patterns indicative of debugger "
                "detection, such as checking /proc/self/status for TracerPid or using ptrace system calls."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, @logStream, @log
| filter @message like /(?i)(proc.self.status|TracerPid|proc.*status)/
  or @message like /(?i)(ptrace|PTRACE_TRACEME|PTRACE_DENY_ATTACH|anti.*debug)/
  or @message like /(?i)(sysctl.*debug|kern[.]proc|process.*tracer)/
| stats count(*) as proc_checks by @logStream, bin(10m) as time_window
| filter proc_checks >= 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: ECS container debugger detection for T1622

Parameters:
  ECSLogGroup:
    Type: String
    Description: CloudWatch log group for ECS containers
  SNSTopicArn:
    Type: String
    Description: SNS topic for security alerts

Resources:
  # Step 1: Metric filter for process inspection patterns
  ContainerDebugCheckFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ECSLogGroup
      FilterPattern: '[msg="*/proc/self/status*" || msg="*TracerPid*" || msg="*ptrace*" || msg="*PTRACE_DENY_ATTACH*"]'
      MetricTransformations:
        - MetricName: ContainerDebuggerChecks
          MetricNamespace: Security/T1622
          MetricValue: "1"

  # Step 2: Alarm for anti-debugging activity
  ContainerDebugCheckAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1622-ECSDebuggerDetection
      AlarmDescription: ECS container performing debugger detection checks
      MetricName: ContainerDebuggerChecks
      Namespace: Security/T1622
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Investigation query
  ContainerDebugCheckQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: T1622-ECSDebuggerDetection
      LogGroupNames:
        - !Ref ECSLogGroup
      QueryString: |
        fields @timestamp, @message, @logStream
        | filter @message like /(?i)(proc.self.status|TracerPid|ptrace)/
        | stats count(*) as proc_checks by @logStream, bin(10m)
        | sort @timestamp desc""",
                terraform_template="""# ECS container debugger detection for T1622

variable "ecs_log_group" {
  type        = string
  description = "CloudWatch log group for ECS containers"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic for security alerts"
}

# Step 1: Metric filter for process inspection patterns
resource "aws_cloudwatch_log_metric_filter" "container_debug_checks" {
  name           = "T1622-ContainerDebugChecks"
  log_group_name = var.ecs_log_group
  pattern        = "[msg=\"*/proc/self/status*\" || msg=\"*TracerPid*\" || msg=\"*ptrace*\" || msg=\"*PTRACE_DENY_ATTACH*\"]"

  metric_transformation {
    name      = "ContainerDebuggerChecks"
    namespace = "Security/T1622"
    value     = "1"
  }
}

# Step 2: Alarm for anti-debugging activity
resource "aws_cloudwatch_metric_alarm" "container_debug_checks" {
  alarm_name          = "T1622-ECSDebuggerDetection"
  alarm_description   = "ECS container performing debugger detection checks"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ContainerDebuggerChecks"
  namespace           = "Security/T1622"
  period              = 600
  statistic           = "Sum"
  threshold           = 3
  treat_missing_data  = "notBreaching"

  alarm_actions       = [var.sns_topic_arn]
}

# Step 3: Investigation query
resource "aws_cloudwatch_query_definition" "container_debug_checks" {
  name            = "T1622-ECSDebuggerDetection"
  log_group_names = [var.ecs_log_group]

  query_string = <<-EOT
    fields @timestamp, @message, @logStream
    | filter @message like /(?i)(proc.self.status|TracerPid|ptrace)/
    | stats count(*) as proc_checks by @logStream, bin(10m)
    | sort @timestamp desc
  EOT
}""",
                alert_severity="high",
                alert_title="ECS Container Debugger Detection Activity",
                alert_description_template=(
                    "ECS container {logStream} performed {proc_checks} process inspection checks "
                    "consistent with debugger detection techniques. This indicates potential malicious "
                    "code attempting to evade analysis."
                ),
                investigation_steps=[
                    "Identify the ECS task and container image performing checks",
                    "Review container image layers and build history",
                    "Check what processes are running in the container",
                    "Analyse container's subsequent behaviour after checks",
                    "Review task IAM role permissions",
                    "Examine network connections from the container",
                    "Check if container image is from trusted registry",
                ],
                containment_actions=[
                    "Stop the suspicious ECS task immediately",
                    "Quarantine the container image for analysis",
                    "Review and update ECS task definitions",
                    "Check for similar tasks using the same image",
                    "Enable ECS Container Insights for enhanced monitoring",
                    "Scan container image with security tools",
                    "Review ECR repository access and push events",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude legitimate monitoring or diagnostic containers; validate security tools",
            detection_coverage="75% - catches containers with Linux anti-debugging techniques",
            evasion_considerations="Attackers may use indirect methods or external binaries to check debugger presence",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["ECS container logs sent to CloudWatch"],
        ),
        # Strategy 3: AWS - EC2 Process Debugging Checks
        DetectionStrategy(
            strategy_id="t1622-aws-ec2-debug-api",
            name="EC2 Instance Debugging API Detection",
            description=(
                "Detect EC2 instances making unusual debugging-related API calls or exhibiting "
                "patterns consistent with malware checking for analysis environments."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, sourceIPAddress, errorCode,
       eventName, requestParameters
| filter eventSource = "ssm.amazonaws.com" or eventSource = "ec2.amazonaws.com"
| filter eventName like /(?i)(DescribeInstanceAttribute|GetParameter|DescribeInstances)/
  and requestParameters.attributeName like /(?i)(kernel|platform|instanceType)/
| stats count(*) as api_checks by sourceIPAddress, user, bin(10m) as time_window
| filter api_checks >= 5
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: EC2 debugging API pattern detection for T1622

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudWatch log group for CloudTrail
  SNSTopicArn:
    Type: String
    Description: SNS topic for security alerts

Resources:
  # Step 1: Detect environment reconnaissance patterns
  DebugAPICheckFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "DescribeInstanceAttribute") || ($.eventName = "DescribeInstances" && $.requestParameters.attributeName = "kernel") }'
      MetricTransformations:
        - MetricName: EC2DebugAPIChecks
          MetricNamespace: Security/T1622
          MetricValue: "1"

  # Step 2: Alert on suspicious API patterns
  DebugAPICheckAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1622-EC2DebugAPIPattern
      AlarmDescription: Unusual EC2 debugging-related API calls detected
      MetricName: EC2DebugAPIChecks
      Namespace: Security/T1622
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Investigation query
  DebugAPICheckQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: T1622-EC2DebugAPIPattern
      LogGroupNames:
        - !Ref CloudTrailLogGroup
      QueryString: |
        fields @timestamp, userIdentity.arn, sourceIPAddress, eventName, requestParameters.attributeName
        | filter eventName = "DescribeInstanceAttribute" or eventName = "DescribeInstances"
        | stats count(*) as api_checks by sourceIPAddress, userIdentity.arn, bin(10m)
        | sort @timestamp desc""",
                terraform_template="""# EC2 debugging API pattern detection for T1622

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudWatch log group for CloudTrail"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic for security alerts"
}

# Step 1: Detect environment reconnaissance patterns
resource "aws_cloudwatch_log_metric_filter" "debug_api_checks" {
  name           = "T1622-EC2DebugAPI"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"DescribeInstanceAttribute\") || ($.eventName = \"DescribeInstances\" && $.requestParameters.attributeName = \"kernel\") }"

  metric_transformation {
    name      = "EC2DebugAPIChecks"
    namespace = "Security/T1622"
    value     = "1"
  }
}

# Step 2: Alert on suspicious API patterns
resource "aws_cloudwatch_metric_alarm" "debug_api_checks" {
  alarm_name          = "T1622-EC2DebugAPIPattern"
  alarm_description   = "Unusual EC2 debugging-related API calls detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "EC2DebugAPIChecks"
  namespace           = "Security/T1622"
  period              = 600
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  alarm_actions       = [var.sns_topic_arn]
}

# Step 3: Investigation query
resource "aws_cloudwatch_query_definition" "debug_api_checks" {
  name            = "T1622-EC2DebugAPIPattern"
  log_group_names = [var.cloudtrail_log_group]

  query_string = <<-EOT
    fields @timestamp, userIdentity.arn, sourceIPAddress, eventName, requestParameters.attributeName
    | filter eventName = "DescribeInstanceAttribute" or eventName = "DescribeInstances"
    | stats count(*) as api_checks by sourceIPAddress, userIdentity.arn, bin(10m)
    | sort @timestamp desc
  EOT
}""",
                alert_severity="medium",
                alert_title="EC2 Debugging API Pattern Detected",
                alert_description_template=(
                    "Source {sourceIPAddress} performed {api_checks} EC2 environment API calls in 10 minutes. "
                    "This pattern may indicate debugger detection reconnaissance. Principal: {user}"
                ),
                investigation_steps=[
                    "Identify the source instance or IAM principal making API calls",
                    "Review what specific EC2 attributes were being queried",
                    "Check if the source matches known legitimate workloads",
                    "Look for subsequent suspicious activity from the same source",
                    "Review the principal's other recent API calls in CloudTrail",
                    "Check for any new instances or functions deployed recently",
                ],
                containment_actions=[
                    "Investigate the source instance or principal for compromise",
                    "Review security group rules for the source instance",
                    "Check for signs of malware on the querying instance",
                    "Consider isolating the instance for forensic analysis",
                    "Enable VPC Flow Logs for network traffic analysis",
                    "Review and restrict IAM permissions if over-permissive",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal infrastructure automation; exclude monitoring and management tools",
            detection_coverage="60% - catches API-based environment reconnaissance",
            evasion_considerations="Attackers may use time delays between API calls or alternative methods",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Strategy 4: GCP - Cloud Functions Debugger Detection
        DetectionStrategy(
            strategy_id="t1622-gcp-function-debug",
            name="GCP Cloud Functions Anti-Debugging Detection",
            description=(
                "Detect Cloud Functions performing debugger detection checks typical of malware, "
                "such as process inspection or exception handling patterns used for anti-debugging."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
textPayload=~"(?i)(ptrace|PTRACE_DENY_ATTACH|TracerPid|proc/self/status|anti.*debug|debugger.*detect|IsDebuggerPresent)"
severity>="WARNING"''',
                gcp_terraform_template="""# GCP: Cloud Functions anti-debugging behaviour detection

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "T1622 Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for debugger detection
resource "google_logging_metric" "function_debug_checks" {
  name   = "t1622-function-debugger-detection"
  filter = <<-EOT
    resource.type="cloud_function"
    textPayload=~"(?i)(ptrace|PTRACE_DENY_ATTACH|TracerPid|proc/self/status|anti.*debug|debugger.*detect)"
    severity>="WARNING"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "function_name"
      value_type  = "STRING"
      description = "Cloud Function name"
    }
  }

  label_extractors = {
    "function_name" = "EXTRACT(resource.labels.function_name)"
  }
}

# Step 3: Alert policy for anti-debugging behaviour
resource "google_monitoring_alert_policy" "function_debug_checks" {
  display_name = "T1622 - Cloud Functions Debugger Detection"
  combiner     = "OR"

  conditions {
    display_name = "Debugger detection pattern detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_debug_checks.name}\" AND resource.type=\"cloud_function\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 2
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.labels.function_name"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = <<-EOT
      Cloud Function exhibiting debugger detection behaviour detected.

      Investigation steps:
      1. Review function source code for anti-debugging checks
      2. Identify who deployed or updated the function
      3. Check function execution history and patterns
      4. Analyse what occurs after debugger checks
      5. Review IAM bindings and permissions
    EOT
  }
}""",
                alert_severity="high",
                alert_title="GCP: Cloud Function Debugger Detection",
                alert_description_template=(
                    "Cloud Function {function_name} performed debugger detection checks. "
                    "This strongly indicates malicious code attempting to evade security analysis."
                ),
                investigation_steps=[
                    "Review the function's source code for anti-debugging API calls",
                    "Identify who deployed or last modified the function",
                    "Check function invocation logs and execution patterns",
                    "Analyse what the function does when debugger is not detected",
                    "Review IAM bindings and service account permissions",
                    "Check for code obfuscation or unusual dependencies",
                    "Examine Cloud Build history if applicable",
                ],
                containment_actions=[
                    "Immediately disable or delete the suspicious Cloud Function",
                    "Review and revoke excessive IAM permissions",
                    "Analyse function code in isolated environment",
                    "Check for similar functions deployed by the same principal",
                    "Review Cloud Audit Logs for function deployment events",
                    "Enable Cloud Functions detailed monitoring",
                    "Scan function deployment package with security tools",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate debugging rare in production functions; validate any whitelisted functions",
            detection_coverage="70% - catches functions with common anti-debugging checks",
            evasion_considerations="Sophisticated malware may use obfuscated or dynamically loaded anti-debugging code",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Logging enabled for Cloud Functions"],
        ),
        # Strategy 5: GCP - Compute Engine Process Inspection
        DetectionStrategy(
            strategy_id="t1622-gcp-compute-debug",
            name="GCP Compute Engine Debugger Detection",
            description=(
                "Monitor GCE instance logs for process inspection patterns indicative of debugger "
                "detection, such as checking process status or using ptrace system calls."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(textPayload=~"(?i)(/proc/self/status|TracerPid|proc.*status)" OR
 textPayload=~"(?i)(ptrace|PTRACE_TRACEME|PTRACE_DENY_ATTACH|anti.*debug)" OR
 textPayload=~"(?i)(sysctl.*debug|kern\\.proc|process.*tracer)")""",
                gcp_terraform_template="""# GCP: Compute Engine debugger detection

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "T1622 GCE Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for process inspection
resource "google_logging_metric" "instance_debug_checks" {
  name   = "t1622-gce-debugger-detection"
  filter = <<-EOT
    resource.type="gce_instance"
    (textPayload=~"(?i)(/proc/self/status|TracerPid|proc.*status)" OR
     textPayload=~"(?i)(ptrace|PTRACE_TRACEME|PTRACE_DENY_ATTACH|anti.*debug)")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance performing checks"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Alert policy for debugger detection
resource "google_monitoring_alert_policy" "instance_debug_checks" {
  display_name = "T1622 - GCE Debugger Detection"
  combiner     = "OR"

  conditions {
    display_name = "Process inspection pattern detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.instance_debug_checks.name}\" AND resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = <<-EOT
      GCE instance performing debugger detection checks detected.

      Investigation steps:
      1. Identify the instance performing process inspection
      2. Review running processes on the instance
      3. Check what occurs after debugger checks
      4. Analyse instance startup scripts
      5. Review service account permissions
      6. Check for signs of compromise
    EOT
  }
}""",
                alert_severity="high",
                alert_title="GCP: Compute Engine Debugger Detection",
                alert_description_template=(
                    "GCE instance {instance_id} performed process inspection checks consistent with "
                    "debugger detection techniques. This indicates potential malicious code attempting "
                    "to evade analysis."
                ),
                investigation_steps=[
                    "Identify the GCE instance performing debugger checks",
                    "Review running processes and scheduled tasks",
                    "Check instance startup scripts and metadata",
                    "Analyse what processes execute after checks",
                    "Review service account IAM bindings",
                    "Examine network connections and firewall rules",
                    "Check instance creation and configuration history",
                ],
                containment_actions=[
                    "Stop the suspicious GCE instance immediately",
                    "Create disk snapshot for forensic analysis",
                    "Review and restrict service account permissions",
                    "Check for similar instances in the project",
                    "Enable VPC Flow Logs for network analysis",
                    "Review Cloud Audit Logs for instance operations",
                    "Scan instance disk with security tools if safe to do so",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude legitimate monitoring or diagnostic workloads; validate security tools",
            detection_coverage="75% - catches instances with Linux anti-debugging techniques",
            evasion_considerations="Attackers may use indirect methods or external binaries for debugger detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Cloud Logging enabled for Compute Engine",
                "Instance logging configured",
            ],
        ),
    ],
    recommended_order=[
        "t1622-aws-lambda-debug-checks",
        "t1622-gcp-function-debug",
        "t1622-aws-ecs-debug-detection",
        "t1622-gcp-compute-debug",
        "t1622-aws-ec2-debug-api",
    ],
    total_effort_hours=10.0,
    coverage_improvement="+12% improvement for Defence Evasion tactic",
)
