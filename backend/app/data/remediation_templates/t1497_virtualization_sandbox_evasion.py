"""
T1497 - Virtualization/Sandbox Evasion

Adversaries may employ methods to detect and avoid virtualization and analysis environments.
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
    technique_id="T1497",
    technique_name="Virtualization/Sandbox Evasion",
    tactic_ids=["TA0005", "TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1497/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may employ methods to detect and avoid virtualization and analysis environments. "
            "By changing behaviour based on checks for virtual machine environments (VME) or sandbox "
            "indicators, attackers can evade detection systems, alter malware behaviour, or conceal "
            "implant functions when analysis is suspected."
        ),
        attacker_goal="Evade detection and analysis by security tools through environment detection",
        why_technique=[
            "Allows malware to evade automated sandbox analysis",
            "Enables selective payload delivery to real targets only",
            "Prevents security tools from observing malicious behaviour",
            "Reduces likelihood of malware samples being analysed",
            "Enables attackers to avoid triggering alerts in test environments",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Contagious Interview",
                year=2024,
                description="Social engineering campaign that requested victims disable Docker containers to evade detection",
                reference_url="https://attack.mitre.org/groups/G1052/",
            ),
            Campaign(
                name="Raspberry Robin Worm",
                year=2022,
                description="USB worm that checks for virtualised environments and only delivers real payload outside VMs",
                reference_url="https://www.microsoft.com/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem/",
            ),
            Campaign(
                name="Darkhotel APT",
                year=2020,
                description="APT group using anti-VM checks to avoid sandbox detection in targeted hotel Wi-Fi attacks",
                reference_url="https://attack.mitre.org/groups/G0012/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Whilst virtualization/sandbox evasion doesn't directly cause damage, it's a critical "
            "defence evasion technique that enables subsequent malicious activities to proceed undetected. "
            "The presence of anti-VM or anti-sandbox checks strongly indicates malicious intent and "
            "sophisticated threat actor behaviour."
        ),
        business_impact=[
            "Reduced efficacy of automated malware analysis systems",
            "Delayed threat detection and response",
            "Incomplete security telemetry and forensic evidence",
            "Potential for undetected malware execution in production",
            "Increased incident response complexity",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1059", "T1053", "T1105"],
        often_follows=["T1204", "T1566"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Lambda Anti-Sandbox Behaviour
        DetectionStrategy(
            strategy_id="t1497-aws-lambda-evasion",
            name="AWS Lambda Anti-Sandbox Detection",
            description=(
                "Detect Lambda functions performing environment checks typical of sandbox evasion, "
                "such as checking CPU count, available memory, execution environment, or unusual timing delays."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, @logStream
| filter @message like /(?i)(cpu|processor|vmware|virtualbox|sandbox|hypervisor|xen|kvm)/
  or @message like /(?i)(sleep|delay|wait|timer)/
  or @message like /(?i)(docker|container|virtualization)/
| filter @message not like /normal-application-pattern/
| stats count(*) as evasion_checks by @logStream, bin(5m) as time_window
| filter evasion_checks >= 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Lambda anti-sandbox behaviour detection for T1497

Parameters:
  LambdaLogGroup:
    Type: String
    Description: CloudWatch log group for Lambda functions
  SNSTopicArn:
    Type: String
    Description: SNS topic for security alerts

Resources:
  # Step 1: Metric filter for environment checks
  SandboxEvasionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LambdaLogGroup
      FilterPattern: '[msg="*cpu*" || msg="*vmware*" || msg="*virtualbox*" || msg="*sandbox*" || msg="*hypervisor*" || msg="*docker*"]'
      MetricTransformations:
        - MetricName: SandboxEvasionChecks
          MetricNamespace: Security/T1497
          MetricValue: "1"

  # Step 2: Alarm for suspicious checks
  SandboxEvasionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1497-LambdaSandboxEvasion
      AlarmDescription: Lambda function performing sandbox evasion checks
      MetricName: SandboxEvasionChecks
      Namespace: Security/T1497
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Query for investigation
  SandboxEvasionQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: T1497-LambdaSandboxEvasion
      LogGroupNames:
        - !Ref LambdaLogGroup
      QueryString: |
        fields @timestamp, @message, @logStream
        | filter @message like /(?i)(cpu|vmware|virtualbox|sandbox|hypervisor|docker)/
        | stats count(*) by @logStream, bin(5m)
        | sort @timestamp desc""",
                terraform_template="""# Lambda anti-sandbox behaviour detection for T1497

variable "lambda_log_group" {
  type        = string
  description = "CloudWatch log group for Lambda functions"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic for security alerts"
}

# Step 1: Metric filter for environment checks
resource "aws_cloudwatch_log_metric_filter" "sandbox_evasion" {
  name           = "T1497-SandboxEvasion"
  log_group_name = var.lambda_log_group
  pattern        = "[msg=\"*cpu*\" || msg=\"*vmware*\" || msg=\"*virtualbox*\" || msg=\"*sandbox*\" || msg=\"*hypervisor*\" || msg=\"*docker*\"]"

  metric_transformation {
    name      = "SandboxEvasionChecks"
    namespace = "Security/T1497"
    value     = "1"
  }
}

# Step 2: Alarm for suspicious checks
resource "aws_cloudwatch_metric_alarm" "sandbox_evasion" {
  alarm_name          = "T1497-LambdaSandboxEvasion"
  alarm_description   = "Lambda function performing sandbox evasion checks"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SandboxEvasionChecks"
  namespace           = "Security/T1497"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_actions       = [var.sns_topic_arn]
}

# Step 3: Query for investigation
resource "aws_cloudwatch_query_definition" "sandbox_evasion" {
  name = "T1497-LambdaSandboxEvasion"

  log_group_names = [var.lambda_log_group]

  query_string = <<-EOT
    fields @timestamp, @message, @logStream
    | filter @message like /(?i)(cpu|vmware|virtualbox|sandbox|hypervisor|docker)/
    | stats count(*) by @logStream, bin(5m)
    | sort @timestamp desc
  EOT
}""",
                alert_severity="medium",
                alert_title="Lambda Anti-Sandbox Behaviour Detected",
                alert_description_template=(
                    "Lambda function {logStream} performed {evasion_checks} environment checks "
                    "consistent with sandbox evasion techniques. This may indicate malicious code "
                    "attempting to evade detection systems."
                ),
                investigation_steps=[
                    "Review the Lambda function's code for anti-VM/sandbox checks",
                    "Identify who deployed or updated the function",
                    "Check function's execution history and invocation patterns",
                    "Analyse what the function does after environment checks",
                    "Review IAM permissions granted to the function",
                    "Check for unusual network connections or API calls",
                ],
                containment_actions=[
                    "Disable or quarantine the suspicious Lambda function",
                    "Review and revoke excessive IAM permissions",
                    "Analyse function code for malicious payloads",
                    "Check for similar functions deployed by the same principal",
                    "Enable AWS Lambda Insights for enhanced monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate infrastructure monitoring functions; tune keyword patterns",
            detection_coverage="50% - catches functions with obvious environment checks",
            evasion_considerations="Sophisticated malware may use obfuscated checks or time-based delays",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Lambda function logs sent to CloudWatch"],
        ),
        # Strategy 2: AWS - EC2 Instance Metadata Queries
        DetectionStrategy(
            strategy_id="t1497-aws-metadata-checks",
            name="EC2 Instance Metadata Environment Checks",
            description=(
                "Monitor for unusual patterns of EC2 instance metadata queries that may indicate "
                "malware checking execution environment characteristics to determine if it's in a sandbox."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, sourceIPAddress,
       requestParameters.attribute as metadata_attribute
| filter eventName = "DescribeInstanceAttribute"
  or eventName = "DescribeInstances"
  or (eventSource = "ec2.amazonaws.com" and requestParameters.attribute like /(?i)(instanceType|hypervisor|platform)/)
| stats count(*) as check_count by sourceIPAddress, user, bin(5m) as time_window
| filter check_count >= 10
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: EC2 metadata environment check detection for T1497

Parameters:
  CloudTrailLogGroup:
    Type: String
  SNSTopicArn:
    Type: String

Resources:
  # Step 1: Detect rapid EC2 environment queries
  MetadataCheckFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "DescribeInstanceAttribute") || ($.eventName = "DescribeInstances") }'
      MetricTransformations:
        - MetricName: EC2EnvironmentChecks
          MetricNamespace: Security/T1497
          MetricValue: "1"

  # Step 2: Alert on unusual query volume
  MetadataCheckAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1497-EC2MetadataChecks
      AlarmDescription: Unusual EC2 environment metadata queries detected
      MetricName: EC2EnvironmentChecks
      Namespace: Security/T1497
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Investigation query
  MetadataCheckQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: T1497-EC2EnvironmentChecks
      LogGroupNames:
        - !Ref CloudTrailLogGroup
      QueryString: |
        fields @timestamp, userIdentity.arn, sourceIPAddress, requestParameters.attribute
        | filter eventName = "DescribeInstanceAttribute" or eventName = "DescribeInstances"
        | stats count(*) by sourceIPAddress, userIdentity.arn, bin(5m)
        | sort @timestamp desc""",
                terraform_template="""# EC2 metadata environment check detection for T1497

variable "cloudtrail_log_group" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

# Step 1: Detect rapid EC2 environment queries
resource "aws_cloudwatch_log_metric_filter" "metadata_checks" {
  name           = "T1497-EC2MetadataChecks"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"DescribeInstanceAttribute\") || ($.eventName = \"DescribeInstances\") }"

  metric_transformation {
    name      = "EC2EnvironmentChecks"
    namespace = "Security/T1497"
    value     = "1"
  }
}

# Step 2: Alert on unusual query volume
resource "aws_cloudwatch_metric_alarm" "metadata_checks" {
  alarm_name          = "T1497-EC2MetadataChecks"
  alarm_description   = "Unusual EC2 environment metadata queries detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "EC2EnvironmentChecks"
  namespace           = "Security/T1497"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_actions       = [var.sns_topic_arn]
}

# Step 3: Investigation query
resource "aws_cloudwatch_query_definition" "metadata_checks" {
  name            = "T1497-EC2EnvironmentChecks"
  log_group_names = [var.cloudtrail_log_group]

  query_string = <<-EOT
    fields @timestamp, userIdentity.arn, sourceIPAddress, requestParameters.attribute
    | filter eventName = "DescribeInstanceAttribute" or eventName = "DescribeInstances"
    | stats count(*) by sourceIPAddress, userIdentity.arn, bin(5m)
    | sort @timestamp desc
  EOT
}""",
                alert_severity="medium",
                alert_title="EC2 Environment Check Pattern Detected",
                alert_description_template=(
                    "Source {sourceIPAddress} performed {check_count} EC2 environment queries in 5 minutes. "
                    "This pattern may indicate sandbox evasion reconnaissance. Principal: {user}"
                ),
                investigation_steps=[
                    "Identify the source of the metadata queries",
                    "Review what EC2 attributes were being queried",
                    "Check if the source IP matches known workloads",
                    "Look for subsequent suspicious activity from the same source",
                    "Review the IAM principal's other recent API calls",
                    "Check for any new instances launched around the same time",
                ],
                containment_actions=[
                    "Investigate the source instance or principal",
                    "Review security group rules for the source",
                    "Check for signs of compromise on the querying instance",
                    "Consider isolating the instance for forensic analysis",
                    "Enable VPC Flow Logs for network analysis",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal infrastructure automation; exclude monitoring tools",
            detection_coverage="60% - catches API-based environment reconnaissance",
            evasion_considerations="Attackers may use time delays between queries or IMDS v1/v2 directly",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Strategy 3: AWS - Unusual Timing Delays
        DetectionStrategy(
            strategy_id="t1497-aws-timing-delays",
            name="Time-Based Evasion Detection",
            description=(
                "Detect functions or workloads exhibiting unusual timing delays or sleep patterns "
                "that may indicate time-based sandbox evasion techniques."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @duration, @billedDuration, @message, @logStream
| filter @type = "REPORT"
| filter @duration > 60000 and @message not like /normal-long-running/
| stats avg(@duration) as avg_duration, max(@duration) as max_duration,
  count(*) as invocation_count by @logStream, bin(1h) as time_window
| filter max_duration > 120000 or (invocation_count > 5 and avg_duration > 60000)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Time-based evasion detection for Lambda functions

Parameters:
  LambdaLogGroup:
    Type: String
  SNSTopicArn:
    Type: String

Resources:
  # Step 1: CloudWatch Insights scheduled query
  TimingAnomalyQuery:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: T1497-TimingDelayDetection
      LogGroupNames:
        - !Ref LambdaLogGroup
      QueryString: |
        fields @timestamp, @duration, @billedDuration, @logStream
        | filter @type = "REPORT"
        | filter @duration > 60000
        | stats avg(@duration) as avg_duration, max(@duration) as max_duration,
          count(*) as invocation_count by @logStream, bin(1h)
        | filter max_duration > 120000
        | sort @timestamp desc

  # Step 2: Metric for long-running executions
  LongExecutionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LambdaLogGroup
      FilterPattern: '[report_type="REPORT", ...., duration_label="Duration:", duration>60000, ...]'
      MetricTransformations:
        - MetricName: LongRunningExecutions
          MetricNamespace: Security/T1497
          MetricValue: "1"

  # Step 3: Alert on suspicious patterns
  LongExecutionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1497-TimingDelayEvasion
      AlarmDescription: Detect potential time-based sandbox evasion
      MetricName: LongRunningExecutions
      Namespace: Security/T1497
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn""",
                terraform_template="""# Time-based evasion detection for Lambda functions

variable "lambda_log_group" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

# Step 1: CloudWatch Insights query
resource "aws_cloudwatch_query_definition" "timing_anomaly" {
  name            = "T1497-TimingDelayDetection"
  log_group_names = [var.lambda_log_group]

  query_string = <<-EOT
    fields @timestamp, @duration, @billedDuration, @logStream
    | filter @type = "REPORT"
    | filter @duration > 60000
    | stats avg(@duration) as avg_duration, max(@duration) as max_duration,
      count(*) as invocation_count by @logStream, bin(1h)
    | filter max_duration > 120000
    | sort @timestamp desc
  EOT
}

# Step 2: Metric for long-running executions
resource "aws_cloudwatch_log_metric_filter" "long_execution" {
  name           = "T1497-LongExecutions"
  log_group_name = var.lambda_log_group
  pattern        = "[report_type=\"REPORT\", ...., duration_label=\"Duration:\", duration>60000, ...]"

  metric_transformation {
    name      = "LongRunningExecutions"
    namespace = "Security/T1497"
    value     = "1"
  }
}

# Step 3: Alert on suspicious patterns
resource "aws_cloudwatch_metric_alarm" "long_execution" {
  alarm_name          = "T1497-TimingDelayEvasion"
  alarm_description   = "Detect potential time-based sandbox evasion"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "LongRunningExecutions"
  namespace           = "Security/T1497"
  period              = 3600
  statistic           = "Sum"
  threshold           = 5
  alarm_actions       = [var.sns_topic_arn]
}""",
                alert_severity="low",
                alert_title="Time-Based Evasion Pattern Detected",
                alert_description_template=(
                    "Lambda function {logStream} exhibited unusual timing patterns: "
                    "average duration {avg_duration}ms, maximum {max_duration}ms over {invocation_count} invocations. "
                    "This may indicate time-based sandbox evasion."
                ),
                investigation_steps=[
                    "Review the function code for sleep/delay calls",
                    "Check if timing delays correlate with environment checks",
                    "Analyse what the function does after delays",
                    "Compare timing patterns with known-good behaviour",
                    "Review function deployment history",
                    "Check for code obfuscation or unusual logic",
                ],
                containment_actions=[
                    "Review and analyse the function's code",
                    "Monitor for subsequent malicious activity",
                    "Consider disabling the function pending investigation",
                    "Review IAM permissions and execution role",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Baseline normal function durations; whitelist legitimate long-running workloads",
            detection_coverage="40% - catches obvious timing-based evasion",
            evasion_considerations="Sophisticated malware may use variable delays or distributed timing",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["Lambda execution logs in CloudWatch"],
        ),
        # Strategy 4: GCP - Compute Engine Metadata Checks
        DetectionStrategy(
            strategy_id="t1497-gcp-metadata-checks",
            name="GCP Compute Engine Metadata Environment Checks",
            description=(
                "Monitor for unusual patterns of GCE instance metadata queries that may indicate "
                "malware performing environment reconnaissance to detect virtualisation or sandbox environments."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName=~".*instances.get.*|.*instances.describe.*"
protoPayload.metadata.@type="type.googleapis.com/google.cloud.audit.AuditLog"''',
                gcp_terraform_template="""# GCP: Compute Engine metadata environment check detection

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "T1497 Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for metadata checks
resource "google_logging_metric" "metadata_checks" {
  name   = "t1497-gce-metadata-checks"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~".*instances.get.*|.*instances.describe.*"
    protoPayload.metadata.@type="type.googleapis.com/google.cloud.audit.AuditLog"
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

# Step 3: Alert policy for unusual query patterns
resource "google_monitoring_alert_policy" "metadata_checks" {
  display_name = "T1497 - GCE Environment Checks"
  combiner     = "OR"

  conditions {
    display_name = "High volume metadata queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.metadata_checks.name}\" AND resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = <<-EOT
      Unusual pattern of GCE metadata queries detected, which may indicate sandbox evasion reconnaissance.

      Investigation steps:
      1. Review the instance performing metadata queries
      2. Check what metadata attributes were queried
      3. Look for subsequent suspicious activity
      4. Analyse running processes on the instance
    EOT
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Compute Engine Environment Check Pattern",
                alert_description_template=(
                    "GCE instance {instance_id} performed unusual metadata queries. "
                    "This pattern may indicate virtualisation detection or sandbox evasion attempts."
                ),
                investigation_steps=[
                    "Identify the GCE instance performing metadata queries",
                    "Review what metadata attributes were being accessed",
                    "Check instance startup scripts and running processes",
                    "Look for subsequent API calls or network activity",
                    "Review service account permissions",
                    "Analyse instance creation and configuration history",
                ],
                containment_actions=[
                    "Investigate the instance for signs of compromise",
                    "Review instance IAM bindings and service account",
                    "Consider isolating the instance for forensic analysis",
                    "Enable VPC Flow Logs for network analysis",
                    "Review and restrict metadata server access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal infrastructure automation; exclude monitoring workloads",
            detection_coverage="60% - catches API-based metadata reconnaissance",
            evasion_considerations="Attackers may query metadata server directly via HTTP rather than API",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"],
        ),
        # Strategy 5: GCP - Cloud Functions Environment Checks
        DetectionStrategy(
            strategy_id="t1497-gcp-function-evasion",
            name="GCP Cloud Functions Anti-Sandbox Detection",
            description=(
                "Detect Cloud Functions performing environment checks typical of sandbox evasion, "
                "such as checking execution environment characteristics, CPU information, or timing delays."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
textPayload=~"(?i)(cpu|processor|vmware|virtualbox|sandbox|hypervisor|xen|kvm|docker|container|virtualization)"
severity>="WARNING"''',
                gcp_terraform_template="""# GCP: Cloud Functions anti-sandbox behaviour detection

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "T1497 Function Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for environment checks
resource "google_logging_metric" "function_evasion" {
  name   = "t1497-function-sandbox-evasion"
  filter = <<-EOT
    resource.type="cloud_function"
    textPayload=~"(?i)(cpu|processor|vmware|virtualbox|sandbox|hypervisor|xen|kvm|docker|container)"
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

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "function_evasion" {
  display_name = "T1497 - Cloud Functions Sandbox Evasion"
  combiner     = "OR"

  conditions {
    display_name = "Environment check pattern detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_evasion.name}\" AND resource.type=\"cloud_function\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
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
      Cloud Function exhibiting sandbox evasion behaviour detected.

      Investigation:
      1. Review function source code for anti-VM checks
      2. Identify who deployed the function
      3. Check function's execution history
      4. Analyse what occurs after environment checks
    EOT
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Function Anti-Sandbox Behaviour",
                alert_description_template=(
                    "Cloud Function {function_name} performed environment checks consistent with "
                    "sandbox evasion techniques. This may indicate malicious code attempting to "
                    "evade detection systems."
                ),
                investigation_steps=[
                    "Review the function's source code for anti-VM/sandbox checks",
                    "Identify who deployed or updated the function",
                    "Check function invocation logs and patterns",
                    "Analyse what the function does after environment checks",
                    "Review IAM bindings and service account permissions",
                    "Check for unusual network connections or API calls",
                ],
                containment_actions=[
                    "Disable or delete the suspicious Cloud Function",
                    "Review and revoke excessive IAM permissions",
                    "Analyse function code for malicious payloads",
                    "Check for similar functions deployed by the same principal",
                    "Review Cloud Build history if applicable",
                    "Enable Cloud Functions detailed monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate system monitoring functions; adjust keyword patterns",
            detection_coverage="50% - catches functions with obvious environment checks",
            evasion_considerations="Sophisticated malware may use obfuscated checks or indirect detection methods",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Logging enabled for Cloud Functions"],
        ),
    ],
    recommended_order=[
        "t1497-aws-lambda-evasion",
        "t1497-gcp-function-evasion",
        "t1497-aws-metadata-checks",
        "t1497-gcp-metadata-checks",
        "t1497-aws-timing-delays",
    ],
    total_effort_hours=9.0,
    coverage_improvement="+15% improvement for Defence Evasion tactic",
)
