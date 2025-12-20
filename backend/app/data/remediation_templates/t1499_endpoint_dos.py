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
    Campaign,
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
        known_threat_actors=["Sandworm Team"],
        recent_campaigns=[
            Campaign(
                name="Sandworm Georgian Website Attacks",
                year=2019,
                description="Disrupted over 2,000 Georgian government and private sector websites through DoS attacks",
                reference_url="https://attack.mitre.org/groups/G0034/",
            )
        ],
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
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

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
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# Detect CPU/Memory exhaustion attacks

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "endpoint-dos-alerts"
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
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
  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects API request flood attacks causing throttling"
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

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# GCE CPU Exhaustion Alert
resource "google_monitoring_alert_policy" "gce_cpu" {
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
  notification_channels = [google_monitoring_notification_channel.email.id]
}

# GKE Container CPU Exhaustion
resource "google_monitoring_alert_policy" "gke_cpu" {
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
  notification_channels = [google_monitoring_notification_channel.email.id]
}

# OOM Kill Detection via Logging
resource "google_logging_metric" "oom_kills" {
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
  notification_channels = [google_monitoring_notification_channel.email.id]
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

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Metric for quota exhaustion
resource "google_logging_metric" "quota_exhaustion" {
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
  notification_channels = [google_monitoring_notification_channel.email.id]
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
