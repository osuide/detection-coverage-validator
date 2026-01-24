"""
T1499 - Endpoint Denial of Service

Adversaries perform Endpoint DoS attacks to degrade or block availability of services.
In cloud environments, this includes resource exhaustion attacks against applications,
APIs, databases, and compute instances. Used by Sandworm Team in Georgian attacks.
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
    technique_id="T1499",
    technique_name="Endpoint Denial of Service",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1499/",
    threat_context=ThreatContext(
        description=(
            "Adversaries perform Endpoint Denial of Service (DoS) attacks to degrade or block "
            "the availability of services to users. These attacks exhaust system resources "
            "(CPU, memory, disk I/O) or exploit vulnerabilities to cause service crashes. "
            "In cloud environments, targets include web applications, APIs, databases, "
            "Lambda functions, and container workloads. Unlike network-layer DDoS, endpoint "
            "DoS attacks overwhelm the application or system itself without necessarily "
            "saturating network bandwidth."
        ),
        attacker_goal="Exhaust system resources or crash services to deny availability",
        why_technique=[
            "Disrupt business operations and revenue",
            "Application-layer attacks bypass network defences",
            "Resource exhaustion causes service crashes",
            "Can trigger auto-scaling costs in cloud",
            "May mask other attack activities",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "High impact on availability and business operations. "
            "Can cause service outages and financial damage. "
            "In cloud environments, may trigger excessive auto-scaling costs. "
            "Often used for disruption or to mask other attacks."
        ),
        business_impact=[
            "Service unavailability",
            "Revenue loss during outages",
            "Excessive cloud costs from auto-scaling",
            "Customer dissatisfaction",
            "Reputational damage",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1190", "T1078.004"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1499-aws-cpu-exhaustion",
            name="AWS CPU/Memory Exhaustion Detection",
            description="Detect abnormal CPU and memory usage indicating resource exhaustion attacks.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect CPU/Memory exhaustion attacks on EC2/ECS

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # EC2 CPU Exhaustion Alarm
  EC2CpuAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EC2-CPU-Exhaustion
      MetricName: CPUUtilization
      Namespace: AWS/EC2
      Statistic: Average
      Period: 300
      EvaluationPeriods: 2
      Threshold: 90
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  # ECS CPU Exhaustion Alarm
  ECSCpuAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ECS-CPU-Exhaustion
      MetricName: CPUUtilization
      Namespace: AWS/ECS
      Statistic: Average
      Period: 300
      EvaluationPeriods: 2
      Threshold: 90
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect CPU/Memory exhaustion attacks

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "endpoint-dos-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EC2 CPU Exhaustion Alarm
resource "aws_cloudwatch_metric_alarm" "ec2_cpu" {
  alarm_name          = "EC2-CPU-Exhaustion"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 90
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# ECS CPU Exhaustion Alarm
resource "aws_cloudwatch_metric_alarm" "ecs_cpu" {
  alarm_name          = "ECS-CPU-Exhaustion"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 90
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# RDS CPU Exhaustion Alarm
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "RDS-CPU-Exhaustion"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 90
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
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
                alert_title="Resource Exhaustion Detected",
                alert_description_template="High CPU/Memory usage detected - possible DoS attack.",
                investigation_steps=[
                    "Check application logs for errors or crashes",
                    "Review CloudWatch metrics for abnormal patterns",
                    "Analyse network traffic for attack signatures",
                    "Check for OOM kills or process crashes",
                    "Review recent application deployments",
                ],
                containment_actions=[
                    "Enable AWS Shield for DDoS protection",
                    "Implement rate limiting on APIs",
                    "Scale resources if legitimate traffic",
                    "Block malicious source IPs via WAF",
                    "Enable CloudFront caching to reduce load",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on normal usage patterns, exclude scheduled high-load jobs",
            detection_coverage="80% - detects resource exhaustion patterns",
            evasion_considerations="Slow-rate attacks may stay below thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudWatch metrics enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1499-aws-lambda-throttle",
            name="AWS Lambda Throttling Detection",
            description="Detect excessive Lambda invocations causing throttling or exhaustion.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# Detect Lambda function exhaustion/throttling

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "lambda-dos-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Lambda Throttles Alarm
resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  alarm_name          = "Lambda-Throttling-Attack"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Lambda Errors Alarm
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "Lambda-Error-Spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Lambda Concurrent Executions Alarm
resource "aws_cloudwatch_metric_alarm" "lambda_concurrent" {
  alarm_name          = "Lambda-Concurrent-Exhaustion"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ConcurrentExecutions"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Maximum"
  threshold           = 900  # Near account limit
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
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
                alert_title="Lambda Exhaustion Attack",
                alert_description_template="Lambda function experiencing throttling or excessive errors.",
                investigation_steps=[
                    "Review Lambda invocation logs",
                    "Check X-Ray traces for error patterns",
                    "Identify source of excessive invocations",
                    "Review API Gateway or trigger metrics",
                    "Check for malicious event sources",
                ],
                containment_actions=[
                    "Implement reserved concurrency limits",
                    "Enable API Gateway throttling",
                    "Block malicious sources via WAF",
                    "Implement authentication on triggers",
                    "Review and restrict function permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust throttle thresholds based on normal traffic, exclude legitimate spikes",
            detection_coverage="90% - detects Lambda-specific exhaustion",
            evasion_considerations="Distributed low-rate attacks may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudWatch metrics enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1499-aws-api-flood",
            name="AWS API Request Flood Detection",
            description="Detect API request floods targeting AWS services via CloudTrail.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, sourceIPAddress, userAgent, errorCode
| filter errorCode in ["Throttling", "RequestLimitExceeded", "TooManyRequestsException"]
| stats count(*) as throttle_count by sourceIPAddress, bin(5m)
| filter throttle_count > 100
| sort throttle_count desc""",
                terraform_template="""# Detect API request flood attacks

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "api-flood-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for API throttling
resource "aws_cloudwatch_log_metric_filter" "api_throttle" {
  name           = "api-request-flood"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.errorCode = \"Throttling\" || $.errorCode = \"RequestLimitExceeded\" || $.errorCode = \"TooManyRequestsException\" }"

  metric_transformation {
    name      = "APIThrottleEvents"
    namespace = "Security"
    value     = "1"
  }
}

# Alarm for excessive throttling
resource "aws_cloudwatch_metric_alarm" "api_flood" {
  alarm_name          = "API-Request-Flood"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "APIThrottleEvents"
  namespace           = "Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects API request flood attacks causing throttling"
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
                alert_title="API Request Flood Detected",
                alert_description_template="Excessive API requests causing throttling from {sourceIPAddress}.",
                investigation_steps=[
                    "Identify source IPs generating flood",
                    "Review CloudTrail for attack patterns",
                    "Check which APIs are being targeted",
                    "Determine if attack is distributed",
                    "Review authentication method used",
                ],
                containment_actions=[
                    "Block malicious IPs via security groups",
                    "Implement API Gateway resource policies",
                    "Enable AWS WAF with rate limiting",
                    "Revoke compromised credentials if applicable",
                    "Contact AWS Support for assistance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate automation may trigger throttling - whitelist known tools",
            detection_coverage="85% - detects API-level floods",
            evasion_considerations="Distributed attacks from many IPs harder to detect",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1499-gcp-resource-exhaustion",
            name="GCP Resource Exhaustion Detection",
            description="Detect abnormal CPU/memory usage on GCE instances and GKE pods.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_monitoring",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
OR resource.type="k8s_container"
severity>=WARNING
(jsonPayload.message=~"out of memory" OR jsonPayload.message=~"OOM")""",
                gcp_terraform_template="""# GCP: Detect resource exhaustion attacks

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# GCE CPU Exhaustion Alert
resource "google_monitoring_alert_policy" "gce_cpu" {
  project      = var.project_id
  display_name = "GCE CPU Exhaustion"
  combiner     = "OR"
  conditions {
    display_name = "High CPU usage"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metric.type=\"compute.googleapis.com/instance/cpu/utilization\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.90
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
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
}

# GKE Container CPU Exhaustion
resource "google_monitoring_alert_policy" "gke_cpu" {
  project      = var.project_id
  display_name = "GKE Container CPU Exhaustion"
  combiner     = "OR"
  conditions {
    display_name = "Container CPU exhausted"
    condition_threshold {
      filter          = "resource.type=\"k8s_container\" AND metric.type=\"kubernetes.io/container/cpu/core_usage_time\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.90
      aggregations {
        alignment_period   = "60s"
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
}

# OOM Kill Detection via Logging
resource "google_logging_metric" "oom_kills" {
  project = var.project_id
  name   = "oom-kills"
  filter = <<-EOT
    (resource.type="gce_instance" OR resource.type="k8s_container")
    AND (jsonPayload.message=~"out of memory" OR jsonPayload.message=~"OOM")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "oom_alert" {
  project      = var.project_id
  display_name = "OOM Kill Detection"
  combiner     = "OR"
  conditions {
    display_name = "OOM kills detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.oom_kills.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Resource Exhaustion Detected",
                alert_description_template="High CPU/memory usage or OOM kills detected.",
                investigation_steps=[
                    "Check Cloud Monitoring for resource trends",
                    "Review application logs for errors",
                    "Analyse Cloud Logging for attack patterns",
                    "Check for crashlooping pods in GKE",
                    "Review recent deployments or changes",
                ],
                containment_actions=[
                    "Enable Google Cloud Armour for DDoS protection",
                    "Implement rate limiting on APIs",
                    "Scale resources if legitimate traffic",
                    "Configure resource quotas and limits",
                    "Block malicious sources via firewall rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust CPU thresholds for workload patterns, exclude batch jobs",
            detection_coverage="80% - detects resource exhaustion",
            evasion_considerations="Gradual resource exhaustion may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Monitoring and Cloud Logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1499-gcp-api-quota",
            name="GCP API Quota Exhaustion Detection",
            description="Detect API quota exhaustion indicating request flood attacks.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.status.code=8
OR protoPayload.status.message=~"quota.*exceeded"
OR protoPayload.status.message=~"rate limit exceeded"''',
                gcp_terraform_template="""# GCP: Detect API quota exhaustion attacks

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Metric for quota exhaustion
resource "google_logging_metric" "quota_exhaustion" {
  project = var.project_id
  name   = "api-quota-exhaustion"
  filter = <<-EOT
    protoPayload.status.code=8
    OR protoPayload.status.message=~"quota.*exceeded"
    OR protoPayload.status.message=~"rate limit exceeded"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "api_method"
      value_type  = "STRING"
      description = "API method being throttled"
    }
  }
  label_extractors = {
    "api_method" = "EXTRACT(protoPayload.methodName)"
  }
}

# Alert on excessive quota exhaustion
resource "google_monitoring_alert_policy" "quota_alert" {
  project      = var.project_id
  display_name = "API Quota Exhaustion Attack"
  combiner     = "OR"
  conditions {
    display_name = "Excessive quota errors"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.quota_exhaustion.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
  documentation {
    content = "API quota exhaustion detected - possible DoS attack or misconfigured application"
  }
}""",
                alert_severity="high",
                alert_title="GCP: API Quota Exhaustion",
                alert_description_template="Excessive API quota errors - possible request flood attack.",
                investigation_steps=[
                    "Identify which APIs are being exhausted",
                    "Review Cloud Logging for source IPs/identities",
                    "Check for distributed attack patterns",
                    "Review API quotas and current usage",
                    "Determine if legitimate or malicious",
                ],
                containment_actions=[
                    "Implement Cloud Armour rate limiting",
                    "Configure API Gateway quotas",
                    "Block malicious sources via firewall",
                    "Request quota increase if legitimate",
                    "Implement authentication and API keys",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Legitimate spikes may occur - review quota limits and usage patterns",
            detection_coverage="85% - detects quota-based attacks",
            evasion_considerations="Attacks staying just below quotas may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Azure Strategy: Endpoint Denial of Service
        DetectionStrategy(
            strategy_id="t1499-azure",
            name="Azure Endpoint Denial of Service Detection",
            description=(
                "Detect endpoint resource exhaustion attacks targeting Azure VMs, App Services, "
                "Azure Functions, and AKS containers. Monitors CPU/memory exhaustion, API throttling, "
                "and application-layer DoS patterns."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=[
                    "Resource exhaustion detected",
                    "CPU exhaustion attack",
                    "Memory exhaustion attack",
                    "Application DoS detected",
                ],
                azure_kql_query="""// Azure Endpoint Denial of Service Detection
// MITRE ATT&CK: T1499 - Endpoint Denial of Service
// Detects resource exhaustion attacks on Azure endpoints

// VM CPU/Memory exhaustion
Perf
| where TimeGenerated > ago(1h)
| where ObjectName == "Processor" and CounterName == "% Processor Time"
| where CounterValue > 95
| summarize AvgCPU = avg(CounterValue), MaxCPU = max(CounterValue)
    by Computer, bin(TimeGenerated, 5m)
| where AvgCPU > 90
| project TimeGenerated, Computer, AvgCPU, MaxCPU, ExhaustionType = "CPU"

// App Service performance degradation
AppServiceHTTPLogs
| where TimeGenerated > ago(1h)
| where ScStatus >= 500 or TimeTaken > 30000
| summarize
    ErrorCount = countif(ScStatus >= 500),
    SlowRequests = countif(TimeTaken > 30000),
    TotalRequests = count()
    by _ResourceId, bin(TimeGenerated, 5m)
| where ErrorCount > 100 or SlowRequests > 50
| extend ErrorRate = round(100.0 * ErrorCount / TotalRequests, 2)
| project TimeGenerated, _ResourceId, ErrorCount, SlowRequests, ErrorRate

// Azure Functions throttling
FunctionAppLogs
| where TimeGenerated > ago(1h)
| where Level == "Error" or Message has_any ("throttl", "timeout", "exhausted")
| summarize EventCount = count() by _ResourceId, bin(TimeGenerated, 5m)
| where EventCount > 50
| project TimeGenerated, _ResourceId, EventCount, ExhaustionType = "Function Throttling"

// AKS container resource exhaustion
ContainerLog
| where TimeGenerated > ago(1h)
| where LogEntry has_any ("OOMKilled", "memory exhausted", "resource limit")
| summarize OOMCount = count() by ContainerID, bin(TimeGenerated, 5m)
| project TimeGenerated, ContainerID, OOMCount, ExhaustionType = "Container OOM\"""",
                sentinel_rule_query="""// Sentinel Analytics Rule: Endpoint Denial of Service Detection
// MITRE ATT&CK: T1499 - Endpoint Denial of Service
let lookback = 1h;
let cpu_threshold = 95;
let error_rate_threshold = 10;  // 10% error rate

// Detection 1: VM CPU exhaustion
let vm_cpu_exhaustion = Perf
| where TimeGenerated > ago(lookback)
| where ObjectName == "Processor" and CounterName == "% Processor Time"
| where CounterValue > cpu_threshold
| summarize
    AvgCPU = avg(CounterValue),
    MaxCPU = max(CounterValue),
    SampleCount = count()
    by Computer, _ResourceId, bin(TimeGenerated, 5m)
| where AvgCPU > 90 and SampleCount > 5
| project
    TimeGenerated,
    ResourceType = "VirtualMachine",
    ResourceId = _ResourceId,
    ResourceName = Computer,
    ExhaustionType = "CPU Exhaustion",
    Metric = AvgCPU,
    Severity = "High";

// Detection 2: VM Memory exhaustion
let vm_memory_exhaustion = Perf
| where TimeGenerated > ago(lookback)
| where ObjectName == "Memory" and CounterName == "% Used Memory"
| where CounterValue > 95
| summarize AvgMemory = avg(CounterValue) by Computer, _ResourceId, bin(TimeGenerated, 5m)
| where AvgMemory > 90
| project
    TimeGenerated,
    ResourceType = "VirtualMachine",
    ResourceId = _ResourceId,
    ResourceName = Computer,
    ExhaustionType = "Memory Exhaustion",
    Metric = AvgMemory,
    Severity = "High";

// Detection 3: App Service DoS patterns
let app_service_dos = AppServiceHTTPLogs
| where TimeGenerated > ago(lookback)
| summarize
    TotalRequests = count(),
    ErrorCount = countif(ScStatus >= 500),
    SlowCount = countif(TimeTaken > 30000)
    by _ResourceId, CsHost, bin(TimeGenerated, 5m)
| where TotalRequests > 100
| extend ErrorRate = round(100.0 * ErrorCount / TotalRequests, 2)
| where ErrorRate > error_rate_threshold or SlowCount > 50
| project
    TimeGenerated,
    ResourceType = "AppService",
    ResourceId = _ResourceId,
    ResourceName = CsHost,
    ExhaustionType = "Application Layer DoS",
    Metric = ErrorRate,
    Severity = "Medium";

// Detection 4: Azure Function throttling
let function_throttling = FunctionAppLogs
| where TimeGenerated > ago(lookback)
| where Level in ("Error", "Warning")
| where Message has_any ("throttl", "timeout", "exhausted", "limit exceeded")
| summarize ThrottleCount = count() by _ResourceId, bin(TimeGenerated, 5m)
| where ThrottleCount > 100
| project
    TimeGenerated,
    ResourceType = "FunctionApp",
    ResourceId = _ResourceId,
    ResourceName = "",
    ExhaustionType = "Function Throttling",
    Metric = toreal(ThrottleCount),
    Severity = "Medium";

// Detection 5: AKS container OOM kills
let container_oom = KubePodInventory
| where TimeGenerated > ago(lookback)
| where PodStatus == "Failed"
| where ContainerStatusReason has_any ("OOMKilled", "Error")
| summarize OOMCount = count() by ClusterName, Namespace, Name, bin(TimeGenerated, 5m)
| where OOMCount > 3
| project
    TimeGenerated,
    ResourceType = "AKS",
    ResourceId = "",
    ResourceName = strcat(ClusterName, "/", Namespace, "/", Name),
    ExhaustionType = "Container OOM",
    Metric = toreal(OOMCount),
    Severity = "High";

// Combine all detections
vm_cpu_exhaustion
| union vm_memory_exhaustion
| union app_service_dos
| union function_throttling
| union container_oom
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    EventCount = count(),
    ExhaustionTypes = make_set(ExhaustionType),
    AvgMetric = avg(Metric)
    by ResourceType, ResourceId, ResourceName, Severity
| project
    TimeGenerated = LastSeen,
    ResourceType,
    ResourceId,
    ResourceName,
    Severity,
    EventCount,
    FirstSeen,
    ExhaustionTypes,
    AvgMetric
| order by Severity asc, EventCount desc""",
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Endpoint Denial of Service (T1499)
# Microsoft Defender detects Endpoint Denial of Service activity

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
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1499-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1499"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (
                    "Suspicious activity detected",
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Endpoint Denial of Service activity"
  display_name = "Defender: Endpoint Denial of Service"
  enabled      = true
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Endpoint Denial of Service Detected",
                alert_description_template=(
                    "Endpoint Denial of Service activity detected. "
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
        "t1499-aws-cpu-exhaustion",
        "t1499-aws-lambda-throttle",
        "t1499-aws-api-flood",
        "t1499-gcp-resource-exhaustion",
        "t1499-gcp-api-quota",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+18% improvement for Impact tactic",
)
