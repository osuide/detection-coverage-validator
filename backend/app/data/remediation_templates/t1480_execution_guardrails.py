"""
T1480 - Execution Guardrails

Adversaries employ execution guardrails to restrict malware activation based on
environment-specific conditions expected on target systems.
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
    technique_id="T1480",
    technique_name="Execution Guardrails",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1480/",
    threat_context=ThreatContext(
        description=(
            "Adversaries employ execution guardrails to restrict malware activation based on "
            "environment-specific conditions expected on target systems. These mechanisms ensure "
            "payloads execute only against intended targets, minimising collateral damage. Target-specific "
            "values may include network share names, physical devices, files, Active Directory domains, "
            "IP addresses, and geolocation. Guardrails validate for expected target values rather than "
            "excluding known sandbox indicators."
        ),
        attacker_goal="Ensure malware executes only on intended target systems whilst avoiding detection",
        why_technique=[
            "Prevents malware execution on unintended systems",
            "Minimises collateral damage and reduces visibility",
            "Ensures payload delivery only to specific targets",
            "Validates environment before executing malicious actions",
            "Protects malware from analysis in security sandboxes",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Execution guardrails indicate sophisticated threat actor behaviour and targeted attacks. "
            "Whilst guardrails themselves don't cause damage, they enable subsequent malicious activities "
            "to proceed undetected by security systems. The presence of environment validation logic "
            "strongly suggests intentional, targeted malicious intent."
        ),
        business_impact=[
            "Delayed threat detection due to selective execution",
            "Reduced efficacy of sandbox analysis systems",
            "Incomplete security telemetry and forensic evidence",
            "Increased complexity of incident response",
            "Potential for undetected compromise in production environments",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1059", "T1053", "T1486"],
        often_follows=["T1204", "T1566", "T1105"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Lambda Environmental Validation
        DetectionStrategy(
            strategy_id="t1480-aws-lambda-guardrails",
            name="AWS Lambda Environmental Guardrail Detection",
            description=(
                "Detect Lambda functions performing environmental validation typical of execution guardrails, "
                "such as checking system properties, IP addresses, domain membership, or specific file existence "
                "before executing payload logic."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, @logStream
| filter @message like /(?i)(hostname|domain|ip.*address|network.*share|registry.*key|file.*exists)/
  or @message like /(?i)(environment.*check|validation|guardrail|target.*system)/
  or @message like /(?i)(geolocation|region.*check|language.*setting)/
| filter @message not like /normal-application-pattern/
| stats count(*) as validation_checks by @logStream, bin(5m) as time_window
| filter validation_checks >= 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Lambda execution guardrail detection for T1480

Parameters:
  LambdaLogGroup:
    Type: String
    Description: CloudWatch log group for Lambda functions
  SNSTopicArn:
    Type: String
    Description: SNS topic for security alerts

Resources:
  # Step 1: Metric filter for environmental validation checks
  ExecutionGuardrailFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LambdaLogGroup
      FilterPattern: '[msg="*hostname*" || msg="*domain*" || msg="*ip*address*" || msg="*network*share*" || msg="*registry*" || msg="*geolocation*" || msg="*language*setting*"]'
      MetricTransformations:
        - MetricName: ExecutionGuardrailChecks
          MetricNamespace: Security/T1480
          MetricValue: "1"

  # Step 2: Alarm for suspicious environmental validation
  ExecutionGuardrailAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1480-LambdaExecutionGuardrails
      AlarmDescription: Lambda function performing execution guardrail validation
      MetricName: ExecutionGuardrailChecks
      Namespace: Security/T1480
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Query definition for investigation
  ExecutionGuardrailQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: T1480-LambdaExecutionGuardrails
      LogGroupNames:
        - !Ref LambdaLogGroup
      QueryString: |
        fields @timestamp, @message, @logStream
        | filter @message like /(?i)(hostname|domain|ip.*address|network|registry|geolocation)/
        | stats count(*) as validation_checks by @logStream, bin(5m)
        | sort @timestamp desc""",
                terraform_template="""# Lambda execution guardrail detection for T1480

variable "lambda_log_group" {
  type        = string
  description = "CloudWatch log group for Lambda functions"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic for security alerts"
}

# Step 1: Metric filter for environmental validation checks
resource "aws_cloudwatch_log_metric_filter" "execution_guardrails" {
  name           = "T1480-ExecutionGuardrails"
  log_group_name = var.lambda_log_group
  pattern        = "[msg=\"*hostname*\" || msg=\"*domain*\" || msg=\"*ip*address*\" || msg=\"*network*share*\" || msg=\"*registry*\" || msg=\"*geolocation*\" || msg=\"*language*setting*\"]"

  metric_transformation {
    name      = "ExecutionGuardrailChecks"
    namespace = "Security/T1480"
    value     = "1"
  }
}

# Step 2: Alarm for suspicious environmental validation
resource "aws_cloudwatch_metric_alarm" "execution_guardrails" {
  alarm_name          = "T1480-LambdaExecutionGuardrails"
  alarm_description   = "Lambda function performing execution guardrail validation"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ExecutionGuardrailChecks"
  namespace           = "Security/T1480"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_actions       = [var.sns_topic_arn]
}

# Step 3: Query definition for investigation
resource "aws_cloudwatch_query_definition" "execution_guardrails" {
  name = "T1480-LambdaExecutionGuardrails"

  log_group_names = [var.lambda_log_group]

  query_string = <<-EOT
    fields @timestamp, @message, @logStream
    | filter @message like /(?i)(hostname|domain|ip.*address|network|registry|geolocation)/
    | stats count(*) as validation_checks by @logStream, bin(5m)
    | sort @timestamp desc
  EOT
}""",
                alert_severity="high",
                alert_title="Lambda Execution Guardrail Pattern Detected",
                alert_description_template=(
                    "Lambda function {logStream} performed {validation_checks} environmental validation checks "
                    "consistent with execution guardrail techniques. This may indicate targeted malware that "
                    "validates the execution environment before activating payload."
                ),
                investigation_steps=[
                    "Review the Lambda function's code for environmental validation logic",
                    "Identify what conditions are being checked (hostname, IP, domain, etc.)",
                    "Determine what actions occur after validation succeeds/fails",
                    "Check who deployed or last updated the function",
                    "Review function's execution history and invocation patterns",
                    "Analyse IAM permissions granted to the function",
                    "Check for conditional logic that gates payload execution",
                ],
                containment_actions=[
                    "Disable or quarantine the suspicious Lambda function",
                    "Review and revoke excessive IAM permissions",
                    "Analyse function code for malicious conditional payloads",
                    "Check for similar functions deployed by the same principal",
                    "Enable AWS Lambda Insights for enhanced monitoring",
                    "Review function's network connections and external communications",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate environment-aware applications; baseline normal validation patterns",
            detection_coverage="55% - catches functions with obvious environmental checks",
            evasion_considerations="Sophisticated malware may obfuscate validation logic or use encrypted configuration",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Lambda function logs sent to CloudWatch"],
        ),
        # Strategy 2: AWS - EC2 Geolocation Validation
        DetectionStrategy(
            strategy_id="t1480-aws-geolocation",
            name="EC2 Geolocation-Based Guardrail Detection",
            description=(
                "Monitor for API calls that retrieve geolocation information or perform IP-based "
                "validation, which may indicate malware performing geographic filtering before execution."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, sourceIPAddress,
       requestParameters.filterSet.items.0.name as filter_name
| filter eventSource = "ec2.amazonaws.com"
  and (requestParameters.filterSet.items.0.name like /(?i)(availability-zone|region|placement)/
       or eventName = "DescribeRegions"
       or eventName = "DescribeAvailabilityZones")
| stats count(*) as geo_checks by sourceIPAddress, user, bin(5m) as time_window
| filter geo_checks >= 5
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Geolocation-based execution guardrail detection for T1480

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String
    Description: SNS topic for security alerts

Resources:
  # Step 1: Detect geolocation validation API calls
  GeolocationCheckFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "DescribeRegions") || ($.eventName = "DescribeAvailabilityZones") }'
      MetricTransformations:
        - MetricName: GeolocationValidationCalls
          MetricNamespace: Security/T1480
          MetricValue: "1"

  # Step 2: Alert on unusual geolocation query patterns
  GeolocationCheckAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1480-GeolocationGuardrails
      AlarmDescription: Unusual geolocation validation API calls detected
      MetricName: GeolocationValidationCalls
      Namespace: Security/T1480
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Investigation query definition
  GeolocationCheckQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: T1480-GeolocationValidation
      LogGroupNames:
        - !Ref CloudTrailLogGroup
      QueryString: |
        fields @timestamp, userIdentity.arn, sourceIPAddress, eventName
        | filter eventName = "DescribeRegions" or eventName = "DescribeAvailabilityZones"
        | stats count(*) as geo_checks by sourceIPAddress, userIdentity.arn, bin(5m)
        | sort @timestamp desc""",
                terraform_template="""# Geolocation-based execution guardrail detection for T1480

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic for security alerts"
}

# Step 1: Detect geolocation validation API calls
resource "aws_cloudwatch_log_metric_filter" "geolocation_checks" {
  name           = "T1480-GeolocationValidation"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"DescribeRegions\") || ($.eventName = \"DescribeAvailabilityZones\") }"

  metric_transformation {
    name      = "GeolocationValidationCalls"
    namespace = "Security/T1480"
    value     = "1"
  }
}

# Step 2: Alert on unusual geolocation query patterns
resource "aws_cloudwatch_metric_alarm" "geolocation_checks" {
  alarm_name          = "T1480-GeolocationGuardrails"
  alarm_description   = "Unusual geolocation validation API calls detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "GeolocationValidationCalls"
  namespace           = "Security/T1480"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_actions       = [var.sns_topic_arn]
}

# Step 3: Investigation query definition
resource "aws_cloudwatch_query_definition" "geolocation_checks" {
  name            = "T1480-GeolocationValidation"
  log_group_names = [var.cloudtrail_log_group]

  query_string = <<-EOT
    fields @timestamp, userIdentity.arn, sourceIPAddress, eventName
    | filter eventName = "DescribeRegions" or eventName = "DescribeAvailabilityZones"
    | stats count(*) as geo_checks by sourceIPAddress, userIdentity.arn, bin(5m)
    | sort @timestamp desc
  EOT
}""",
                alert_severity="medium",
                alert_title="Geolocation Validation Pattern Detected",
                alert_description_template=(
                    "Source {sourceIPAddress} performed {geo_checks} geolocation validation API calls in 5 minutes. "
                    "This pattern may indicate execution guardrails based on geographic location. Principal: {user}"
                ),
                investigation_steps=[
                    "Identify the source of the geolocation queries",
                    "Determine if the queries correlate with other suspicious activity",
                    "Check if the source IP matches known legitimate workloads",
                    "Review what actions occurred after geolocation validation",
                    "Analyse the IAM principal's other recent API calls",
                    "Look for patterns of conditional execution based on location",
                ],
                containment_actions=[
                    "Investigate the source instance or principal",
                    "Review IAM permissions for the querying principal",
                    "Check for signs of compromise on the source system",
                    "Monitor for subsequent malicious activity",
                    "Enable VPC Flow Logs for network analysis",
                    "Consider SCPs to restrict regional operations if appropriate",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal infrastructure automation; exclude multi-region management tools",
            detection_coverage="50% - catches API-based geographic validation",
            evasion_considerations="Attackers may use external geolocation APIs or hardcoded region values",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Strategy 3: AWS - S3 Bucket Regional Validation
        DetectionStrategy(
            strategy_id="t1480-aws-s3-region",
            name="S3 Bucket Regional Validation Detection",
            description=(
                "Detect patterns of S3 bucket location queries that may indicate malware validating "
                "bucket regions before executing data exfiltration or encryption operations."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, requestParameters.bucketName,
       sourceIPAddress
| filter eventSource = "s3.amazonaws.com"
  and eventName = "GetBucketLocation"
| stats count(*) as location_checks by sourceIPAddress, user, bin(5m) as time_window
| filter location_checks >= 10
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: S3 bucket regional validation detection for T1480

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String
    Description: SNS topic for security alerts

Resources:
  # Step 1: Detect S3 bucket location validation
  S3LocationCheckFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "s3.amazonaws.com" && $.eventName = "GetBucketLocation" }'
      MetricTransformations:
        - MetricName: S3BucketLocationChecks
          MetricNamespace: Security/T1480
          MetricValue: "1"

  # Step 2: Alert on high volume of location checks
  S3LocationCheckAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1480-S3RegionalValidation
      AlarmDescription: High volume of S3 bucket location validation detected
      MetricName: S3BucketLocationChecks
      Namespace: Security/T1480
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn

  # Step 3: Investigation query definition
  S3LocationQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: T1480-S3RegionalValidation
      LogGroupNames:
        - !Ref CloudTrailLogGroup
      QueryString: |
        fields @timestamp, userIdentity.arn, sourceIPAddress, requestParameters.bucketName
        | filter eventSource = "s3.amazonaws.com" and eventName = "GetBucketLocation"
        | stats count(*) as location_checks by sourceIPAddress, userIdentity.arn, bin(5m)
        | sort @timestamp desc""",
                terraform_template="""# S3 bucket regional validation detection for T1480

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic for security alerts"
}

# Step 1: Detect S3 bucket location validation
resource "aws_cloudwatch_log_metric_filter" "s3_location_checks" {
  name           = "T1480-S3LocationChecks"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"s3.amazonaws.com\" && $.eventName = \"GetBucketLocation\" }"

  metric_transformation {
    name      = "S3BucketLocationChecks"
    namespace = "Security/T1480"
    value     = "1"
  }
}

# Step 2: Alert on high volume of location checks
resource "aws_cloudwatch_metric_alarm" "s3_location_checks" {
  alarm_name          = "T1480-S3RegionalValidation"
  alarm_description   = "High volume of S3 bucket location validation detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "S3BucketLocationChecks"
  namespace           = "Security/T1480"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_actions       = [var.sns_topic_arn]
}

# Step 3: Investigation query definition
resource "aws_cloudwatch_query_definition" "s3_location_checks" {
  name            = "T1480-S3RegionalValidation"
  log_group_names = [var.cloudtrail_log_group]

  query_string = <<-EOT
    fields @timestamp, userIdentity.arn, sourceIPAddress, requestParameters.bucketName
    | filter eventSource = "s3.amazonaws.com" and eventName = "GetBucketLocation"
    | stats count(*) as location_checks by sourceIPAddress, userIdentity.arn, bin(5m)
    | sort @timestamp desc
  EOT
}""",
                alert_severity="medium",
                alert_title="S3 Regional Validation Pattern Detected",
                alert_description_template=(
                    "Source {sourceIPAddress} performed {location_checks} S3 bucket location checks in 5 minutes. "
                    "This pattern may indicate execution guardrails validating bucket regions before operations. "
                    "Principal: {user}"
                ),
                investigation_steps=[
                    "Identify which buckets were checked for location",
                    "Review subsequent operations on the validated buckets",
                    "Check if the pattern correlates with data exfiltration or encryption",
                    "Verify if the source IP matches known legitimate automation",
                    "Analyse the IAM principal's other recent S3 operations",
                    "Look for conditional logic based on bucket location",
                ],
                containment_actions=[
                    "Investigate the source principal for signs of compromise",
                    "Review S3 bucket access patterns and data transfers",
                    "Check for unauthorised data modifications or deletions",
                    "Enable S3 Object Lock if not already configured",
                    "Review and restrict S3 permissions",
                    "Monitor for subsequent suspicious S3 activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Baseline normal S3 management tools; whitelist legitimate multi-region operations",
            detection_coverage="65% - catches S3-based regional validation",
            evasion_considerations="Attackers may cache location information or use hardcoded region values",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail S3 data events enabled"],
        ),
        # Strategy 4: GCP - Compute Engine Instance Validation
        DetectionStrategy(
            strategy_id="t1480-gcp-instance-validation",
            name="GCP Compute Engine Instance Validation Detection",
            description=(
                "Monitor for patterns of GCE instance queries that validate environment characteristics, "
                "such as instance metadata, zone, region, or labels, which may indicate execution guardrails."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName=~".*instances.get.*|.*zones.get.*|.*regions.get.*"
protoPayload.metadata.@type="type.googleapis.com/google.cloud.audit.AuditLog"''',
                gcp_terraform_template="""# GCP: Compute Engine instance validation detection for T1480

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "T1480 Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for instance validation checks
resource "google_logging_metric" "instance_validation" {
  name   = "t1480-gce-instance-validation"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~".*instances.get.*|.*zones.get.*|.*regions.get.*"
    protoPayload.metadata.@type="type.googleapis.com/google.cloud.audit.AuditLog"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "Principal performing validation"
    }
  }

  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for unusual validation patterns
resource "google_monitoring_alert_policy" "instance_validation" {
  display_name = "T1480 - GCE Instance Validation Guardrails"
  combiner     = "OR"

  conditions {
    display_name = "High volume instance validation queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.instance_validation.name}\" AND resource.type=\"gce_instance\""
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
      Unusual pattern of GCE instance validation queries detected, which may indicate execution guardrails.

      Investigation steps:
      1. Review the principal performing validation queries
      2. Check what instance attributes were queried
      3. Look for subsequent conditional operations
      4. Analyse correlation with other suspicious activity
      5. Review service account permissions
    EOT
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Compute Engine Validation Guardrail Pattern",
                alert_description_template=(
                    "Principal {principal_email} performed unusual instance validation queries. "
                    "This pattern may indicate execution guardrails validating environment before payload execution."
                ),
                investigation_steps=[
                    "Identify the principal performing validation queries",
                    "Review what instance attributes were being checked",
                    "Check for conditional logic following validation",
                    "Analyse subsequent API calls or operations",
                    "Review service account permissions and bindings",
                    "Look for patterns of environment-based execution",
                ],
                containment_actions=[
                    "Investigate the principal for signs of compromise",
                    "Review instance access patterns and operations",
                    "Check for unauthorised instance modifications",
                    "Revoke or restrict service account permissions if needed",
                    "Enable VPC Flow Logs for network analysis",
                    "Monitor for subsequent suspicious activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal infrastructure management tools; exclude monitoring workloads",
            detection_coverage="60% - catches API-based instance validation",
            evasion_considerations="Attackers may query metadata server directly or use cached environment data",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"],
        ),
        # Strategy 5: GCP - Cloud Functions Language and Region Checks
        DetectionStrategy(
            strategy_id="t1480-gcp-function-guardrails",
            name="GCP Cloud Functions Environmental Guardrail Detection",
            description=(
                "Detect Cloud Functions performing environmental validation checks such as language settings, "
                "region validation, or project-specific characteristics before executing payload logic."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
textPayload=~"(?i)(language.*setting|locale|region.*check|project.*id|environment.*validation|target.*system|guardrail)"
severity>="INFO"''',
                gcp_terraform_template="""# GCP: Cloud Functions environmental guardrail detection for T1480

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "T1480 Function Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for environmental validation
resource "google_logging_metric" "function_guardrails" {
  name   = "t1480-function-execution-guardrails"
  filter = <<-EOT
    resource.type="cloud_function"
    textPayload=~"(?i)(language.*setting|locale|region.*check|project.*id|environment.*validation|target.*system)"
    severity>="INFO"
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

# Step 3: Alert policy for execution guardrails
resource "google_monitoring_alert_policy" "function_guardrails" {
  display_name = "T1480 - Cloud Functions Execution Guardrails"
  combiner     = "OR"

  conditions {
    display_name = "Environmental validation pattern detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_guardrails.name}\" AND resource.type=\"cloud_function\""
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
      Cloud Function exhibiting execution guardrail behaviour detected.

      Investigation:
      1. Review function source code for environmental checks
      2. Identify what conditions are being validated
      3. Determine what actions follow successful validation
      4. Check who deployed the function
      5. Review function execution patterns
      6. Analyse IAM permissions and service account
    EOT
  }
}""",
                alert_severity="high",
                alert_title="GCP: Cloud Function Execution Guardrail Detected",
                alert_description_template=(
                    "Cloud Function {function_name} performed environmental validation checks consistent with "
                    "execution guardrail techniques. This may indicate targeted malware validating execution "
                    "environment before payload activation."
                ),
                investigation_steps=[
                    "Review the function's source code for validation logic",
                    "Identify what environmental conditions are being checked",
                    "Determine what actions occur after validation succeeds",
                    "Check who deployed or last updated the function",
                    "Review function invocation logs and patterns",
                    "Analyse IAM bindings and service account permissions",
                    "Look for conditional execution based on environment",
                ],
                containment_actions=[
                    "Disable or delete the suspicious Cloud Function",
                    "Review and revoke excessive IAM permissions",
                    "Analyse function code for malicious conditional payloads",
                    "Check for similar functions deployed by same principal",
                    "Review Cloud Build or deployment history",
                    "Enable Cloud Functions detailed monitoring and logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate multi-region or internationalised applications; adjust patterns",
            detection_coverage="55% - catches functions with obvious guardrail checks",
            evasion_considerations="Sophisticated malware may obfuscate validation logic or use encrypted configuration",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Logging enabled for Cloud Functions"],
        ),
    ],
    recommended_order=[
        "t1480-aws-lambda-guardrails",
        "t1480-gcp-function-guardrails",
        "t1480-aws-geolocation",
        "t1480-gcp-instance-validation",
        "t1480-aws-s3-region",
    ],
    total_effort_hours=9.5,
    coverage_improvement="+18% improvement for Defence Evasion tactic",
)
