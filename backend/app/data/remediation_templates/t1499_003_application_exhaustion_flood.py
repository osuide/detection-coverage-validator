"""
T1499.003 - Endpoint Denial of Service: Application Exhaustion Flood

Adversaries exploit resource-intensive application features through repeated requests
to exhaust system resources and deny access to the application or server.
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
    technique_id="T1499.003",
    technique_name="Endpoint Denial of Service: Application Exhaustion Flood",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1499/003/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit resource-intensive application features through repeated "
            "requests that exhaust system resources and deny access to the application or "
            "server. This includes targeting endpoints with expensive computations, database "
            "queries, file operations, or workflows that cause prolonged resource locks."
        ),
        attacker_goal="Deny service availability by exhausting application resources through targeted requests",
        why_technique=[
            "Bypasses network-level DDoS protections",
            "Requires fewer requests than network floods",
            "Targets application logic vulnerabilities",
            "Difficult to distinguish from legitimate traffic",
            "No infrastructure required beyond basic HTTP clients",
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Application exhaustion attacks can severely impact availability with relatively "
            "few requests. They exploit application logic flaws, making them harder to detect "
            "and mitigate than traditional network-level DDoS attacks."
        ),
        business_impact=[
            "Service unavailability and downtime",
            "Revenue loss during outages",
            "Customer dissatisfaction and churn",
            "Resource costs from auto-scaling responses",
            "Reputational damage",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1595", "T1592"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1499003-aws-alb-resource",
            name="AWS ALB Resource-Intensive Endpoint Detection",
            description="Detect repeated requests to resource-heavy endpoints with elevated response times.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, client_ip, request_url, target_processing_time, elb_status_code
| filter target_processing_time > 5
| stats count(*) as slow_requests, avg(target_processing_time) as avg_time by client_ip, request_url, bin(5m)
| filter slow_requests > 20
| sort slow_requests desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect application exhaustion via ALB metrics

Parameters:
  ALBLogGroup:
    Type: String
    Description: ALB access log group name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Monitor slow response times indicating resource exhaustion
  SlowRequestFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ALBLogGroup
      FilterPattern: '[..., target_processing_time > 5, ...]'
      MetricTransformations:
        - MetricName: SlowRequests
          MetricNamespace: Security/AppExhaustion
          MetricValue: "1"

  SlowRequestAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighSlowRequestRate
      AlarmDescription: Elevated slow requests indicating app exhaustion
      MetricName: SlowRequests
      Namespace: Security/AppExhaustion
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 2
      AlarmActions: [!Ref AlertTopic]

  # Monitor 5xx errors indicating resource exhaustion
  ServerErrorFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ALBLogGroup
      FilterPattern: '[..., status_code=5*, ...]'
      MetricTransformations:
        - MetricName: ServerErrors
          MetricNamespace: Security/AppExhaustion
          MetricValue: "1"

  ServerErrorAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighServerErrorRate
      AlarmDescription: High 5xx rate indicating exhaustion
      MetricName: ServerErrors
      Namespace: Security/AppExhaustion
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 2
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect application exhaustion via ALB metrics

variable "alb_log_group" {
  type        = string
  description = "ALB access log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "app-exhaustion-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Monitor slow response times indicating resource exhaustion
resource "aws_cloudwatch_log_metric_filter" "slow_requests" {
  name           = "slow-requests"
  log_group_name = var.alb_log_group
  pattern        = "[..., target_processing_time > 5, ...]"

  metric_transformation {
    name      = "SlowRequests"
    namespace = "Security/AppExhaustion"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "slow_request_rate" {
  alarm_name          = "HighSlowRequestRate"
  alarm_description   = "Elevated slow requests indicating app exhaustion"
  metric_name         = "SlowRequests"
  namespace           = "Security/AppExhaustion"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Monitor 5xx errors indicating resource exhaustion
resource "aws_cloudwatch_log_metric_filter" "server_errors" {
  name           = "server-errors"
  log_group_name = var.alb_log_group
  pattern        = "[..., status_code=5*, ...]"

  metric_transformation {
    name      = "ServerErrors"
    namespace = "Security/AppExhaustion"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "server_error_rate" {
  alarm_name          = "HighServerErrorRate"
  alarm_description   = "High 5xx rate indicating exhaustion"
  metric_name         = "ServerErrors"
  namespace           = "Security/AppExhaustion"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Application Exhaustion Attack Detected",
                alert_description_template="Elevated slow requests or errors from {client_ip} to {request_url}.",
                investigation_steps=[
                    "Review target endpoints and response times",
                    "Identify source IPs and request patterns",
                    "Check application server CPU/memory metrics",
                    "Review database query performance",
                    "Examine application logs for errors",
                ],
                containment_actions=[
                    "Rate-limit suspicious source IPs",
                    "Enable WAF rate-based rules",
                    "Scale application resources temporarily",
                    "Implement endpoint-specific rate limits",
                    "Add caching for expensive operations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on normal application behaviour and legitimate traffic spikes",
            detection_coverage="60% - catches patterns of resource exhaustion",
            evasion_considerations="Distributed attacks from many IPs or slow-rate attacks may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["ALB access logging enabled", "CloudWatch Logs configured"],
        ),
        DetectionStrategy(
            strategy_id="t1499003-aws-ecs-resource",
            name="AWS ECS/EC2 Resource Exhaustion Detection",
            description="Detect resource exhaustion via elevated CPU/memory usage and autoscaling events.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect resource exhaustion via ECS metrics

Parameters:
  ECSClusterName:
    Type: String
    Description: ECS cluster name to monitor
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Monitor sustained high CPU usage
  HighCPUAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ECSHighCPUExhaustion
      AlarmDescription: Sustained high CPU indicating exhaustion attack
      MetricName: CPUUtilization
      Namespace: AWS/ECS
      Statistic: Average
      Period: 300
      Threshold: 85
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 3
      Dimensions:
        - Name: ClusterName
          Value: !Ref ECSClusterName
      AlarmActions: [!Ref AlertTopic]

  # Monitor sustained high memory usage
  HighMemoryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ECSHighMemoryExhaustion
      AlarmDescription: Sustained high memory indicating exhaustion attack
      MetricName: MemoryUtilization
      Namespace: AWS/ECS
      Statistic: Average
      Period: 300
      Threshold: 85
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 3
      Dimensions:
        - Name: ClusterName
          Value: !Ref ECSClusterName
      AlarmActions: [!Ref AlertTopic]

  # Monitor rapid autoscaling events
  RapidScalingCompositeAlarm:
    Type: AWS::CloudWatch::CompositeAlarm
    Properties:
      AlarmName: RapidAutoscalingExhaustion
      AlarmDescription: Rapid autoscaling suggesting DoS attack
      AlarmRule: !Sub "ALARM(${HighCPUAlarm}) AND ALARM(${HighMemoryAlarm})"
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect resource exhaustion via ECS metrics

variable "ecs_cluster_name" {
  type        = string
  description = "ECS cluster name to monitor"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

resource "aws_sns_topic" "alerts" {
  name = "ecs-exhaustion-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Monitor sustained high CPU usage
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "ECSHighCPUExhaustion"
  alarm_description   = "Sustained high CPU indicating exhaustion attack"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  statistic           = "Average"
  period              = 300
  threshold           = 85
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3

  dimensions = {
    ClusterName = var.ecs_cluster_name
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}

# Monitor sustained high memory usage
resource "aws_cloudwatch_metric_alarm" "high_memory" {
  alarm_name          = "ECSHighMemoryExhaustion"
  alarm_description   = "Sustained high memory indicating exhaustion attack"
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  statistic           = "Average"
  period              = 300
  threshold           = 85
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3

  dimensions = {
    ClusterName = var.ecs_cluster_name
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}

# Monitor rapid autoscaling events (composite alarm)
resource "aws_cloudwatch_composite_alarm" "rapid_scaling" {
  alarm_name          = "RapidAutoscalingExhaustion"
  alarm_description   = "Rapid autoscaling suggesting DoS attack"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  alarm_rule = join(" AND ", [
    "ALARM(${aws_cloudwatch_metric_alarm.high_cpu.alarm_name})",
    "ALARM(${aws_cloudwatch_metric_alarm.high_memory.alarm_name})"
  ])
}""",
                alert_severity="high",
                alert_title="Resource Exhaustion Attack on Application Infrastructure",
                alert_description_template="Sustained high resource usage on {cluster_name} indicating potential DoS attack.",
                investigation_steps=[
                    "Review CloudWatch Container Insights metrics",
                    "Check ALB access logs for request patterns",
                    "Identify tasks/containers with highest resource usage",
                    "Review application logs for error patterns",
                    "Check for scaling events and triggers",
                ],
                containment_actions=[
                    "Enable AWS WAF rate limiting",
                    "Implement AWS Shield if not enabled",
                    "Scale out application capacity",
                    "Add endpoint-specific rate limits",
                    "Block attacking source IPs",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal traffic patterns and adjust thresholds for legitimate load spikes",
            detection_coverage="65% - catches infrastructure-level exhaustion",
            evasion_considerations="Slow-rate attacks or attacks targeting specific endpoints may not trigger alarms",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "ECS cluster with CloudWatch monitoring",
                "Container Insights enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1499003-gcp-lb-resource",
            name="GCP Load Balancer Resource Exhaustion Detection",
            description="Detect application exhaustion via Cloud Load Balancer metrics and logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="http_load_balancer"
httpRequest.latency > "5s"
httpRequest.status >= 500""",
                gcp_terraform_template="""# GCP: Detect application exhaustion via load balancer

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "App Exhaustion Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Monitor slow requests indicating resource exhaustion
resource "google_logging_metric" "slow_requests" {
  name   = "slow-requests-exhaustion"
  filter = <<-EOT
    resource.type="http_load_balancer"
    httpRequest.latency > "5s"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "slow_request_rate" {
  display_name = "High Slow Request Rate"
  combiner     = "OR"

  conditions {
    display_name = "Elevated slow requests"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.slow_requests.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
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
}

# Monitor 5xx errors indicating exhaustion
resource "google_logging_metric" "server_errors" {
  name   = "server-errors-exhaustion"
  filter = <<-EOT
    resource.type="http_load_balancer"
    httpRequest.status >= 500
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "server_error_rate" {
  display_name = "High Server Error Rate"
  combiner     = "OR"

  conditions {
    display_name = "Elevated 5xx errors"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.server_errors.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
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
}""",
                alert_severity="high",
                alert_title="GCP: Application Exhaustion Attack Detected",
                alert_description_template="High rate of slow requests or server errors indicating resource exhaustion.",
                investigation_steps=[
                    "Review Cloud Load Balancer logs for request patterns",
                    "Check backend service metrics (CPU, memory)",
                    "Identify source IPs and geographical distribution",
                    "Review Cloud Trace for slow transactions",
                    "Check Cloud Logging for application errors",
                ],
                containment_actions=[
                    "Enable Cloud Armor with rate limiting",
                    "Scale backend services",
                    "Implement backend service circuit breakers",
                    "Add request throttling policies",
                    "Block malicious IPs via Cloud Armor",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust latency thresholds based on application baseline behaviour",
            detection_coverage="65% - catches exhaustion patterns",
            evasion_considerations="Distributed low-rate attacks may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "Cloud Load Balancer with logging enabled",
                "Cloud Monitoring configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1499003-gcp-gce-resource",
            name="GCP Compute Engine Resource Exhaustion Detection",
            description="Detect resource exhaustion via GCE instance metrics and autoscaling events.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_monitoring",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_terraform_template="""# GCP: Detect resource exhaustion via GCE metrics

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "instance_group" {
  type        = string
  description = "Instance group name to monitor"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "GCE Exhaustion Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Monitor sustained high CPU usage
resource "google_monitoring_alert_policy" "high_cpu" {
  display_name = "GCE High CPU Exhaustion"
  combiner     = "OR"

  conditions {
    display_name = "Sustained high CPU usage"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metric.type=\"compute.googleapis.com/instance/cpu/utilization\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.85
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields      = ["resource.instance_id"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content = "Sustained high CPU usage may indicate application exhaustion attack"
  }
}

# Monitor memory usage patterns
resource "google_monitoring_alert_policy" "high_memory" {
  display_name = "GCE High Memory Exhaustion"
  combiner     = "OR"

  conditions {
    display_name = "Sustained high memory usage"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metric.type=\"agent.googleapis.com/memory/percent_used\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 85
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields      = ["resource.instance_id"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content = "Sustained high memory usage may indicate application exhaustion attack"
  }
}

# Monitor autoscaling events
resource "google_logging_metric" "autoscaling_events" {
  name   = "autoscaling-exhaustion-events"
  filter = <<-EOT
    resource.type="gce_autoscaler"
    protoPayload.methodName="compute.autoscalers.scalingEvent"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "rapid_autoscaling" {
  display_name = "Rapid Autoscaling Activity"
  combiner     = "OR"

  conditions {
    display_name = "Frequent autoscaling events"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.autoscaling_events.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "600s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content = "Rapid autoscaling may indicate DoS attack causing resource exhaustion"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Compute Resource Exhaustion Attack",
                alert_description_template="Sustained high resource usage and rapid autoscaling on {instance_group}.",
                investigation_steps=[
                    "Review instance metrics in Cloud Monitoring",
                    "Check load balancer logs for traffic patterns",
                    "Identify instances with highest resource usage",
                    "Review application logs via Cloud Logging",
                    "Check autoscaling history and triggers",
                ],
                containment_actions=[
                    "Enable Cloud Armor rate limiting",
                    "Manually scale instance group",
                    "Implement connection draining",
                    "Add backend service timeouts",
                    "Configure request throttling",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baseline metrics during normal traffic and adjust thresholds accordingly",
            detection_coverage="60% - catches infrastructure exhaustion",
            evasion_considerations="Gradual exhaustion attacks may appear as normal load increases",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Monitoring enabled",
                "Cloud Monitoring Agent installed",
                "Managed Instance Groups configured",
            ],
        ),
    ],
    recommended_order=[
        "t1499003-aws-alb-resource",
        "t1499003-gcp-lb-resource",
        "t1499003-aws-ecs-resource",
        "t1499003-gcp-gce-resource",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+25% improvement for Impact tactic",
)
