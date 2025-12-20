"""
T1499.002 - Endpoint Denial of Service: Service Exhaustion Flood

Adversaries exhaust network service resources through high-volume request floods.
Includes HTTP floods and SSL/TLS renegotiation attacks targeting web services,
DNS, and other network-facing applications. Note: No documented threat actor examples.
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
    technique_id="T1499.002",
    technique_name="Endpoint Denial of Service: Service Exhaustion Flood",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1499/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries overwhelm network services by exhausting their resources through "
            "high-volume request floods. Unlike bandwidth saturation attacks, service exhaustion "
            "floods target application resources (worker threads, connection pools, CPU for "
            "cryptographic operations). Common variants include HTTP floods that send massive "
            "quantities of HTTP requests, and SSL/TLS renegotiation attacks that exploit the "
            "computational cost of cryptographic handshakes. In cloud environments, these attacks "
            "target web applications, APIs, DNS services, and load balancers. The technique "
            "relies on raw volume to exhaust resources rather than exploiting specific vulnerabilities."
        ),
        attacker_goal="Exhaust network service resources to deny availability through request flooding",
        why_technique=[
            "HTTP floods overwhelm web server worker threads",
            "SSL/TLS renegotiation consumes CPU cycles",
            "Simple to execute with basic scripting tools",
            "Can trigger excessive cloud auto-scaling costs",
            "Bypasses network-layer DDoS protections",
            "Effective against poorly configured services",
        ],
        known_threat_actors=[],  # No documented threat actors per MITRE
        recent_campaigns=[],  # No documented campaigns per MITRE
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "High impact on service availability. HTTP floods and SSL/TLS renegotiation "
            "attacks can completely deny access to critical services. In cloud environments, "
            "can trigger significant financial costs through auto-scaling. Relatively easy to "
            "execute with automated tools. Targets DNS, web services, and other critical infrastructure."
        ),
        business_impact=[
            "Service unavailability and customer impact",
            "Revenue loss during outages",
            "Excessive cloud costs from auto-scaling",
            "Degraded performance affecting user experience",
            "Reputational damage from service disruption",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1190", "T1078.004", "T1078"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1499-002-aws-alb-flood",
            name="AWS ALB HTTP Flood Detection",
            description="Detect HTTP request floods via Application Load Balancer metrics and logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, client_ip, request_url, target_status_code, request_processing_time
| filter target_status_code like /5[0-9][0-9]/
| stats count(*) as request_count, avg(request_processing_time) as avg_time by client_ip, bin(1m)
| filter request_count > 1000
| sort request_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect HTTP flood attacks via ALB metrics

Parameters:
  LoadBalancerName:
    Type: String
    Description: Name of the Application Load Balancer
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

  # High request count alarm
  HighRequestCountAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ALB-HTTP-Flood
      MetricName: RequestCount
      Namespace: AWS/ApplicationELB
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 3
      Threshold: 10000
      ComparisonOperator: GreaterThanThreshold
      Dimensions:
        - Name: LoadBalancer
          Value: !Ref LoadBalancerName
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

  # High 5xx error rate alarm
  High5xxAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ALB-High-5xx-Errors
      MetricName: HTTPCode_Target_5XX_Count
      Namespace: AWS/ApplicationELB
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 2
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      Dimensions:
        - Name: LoadBalancer
          Value: !Ref LoadBalancerName
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching

  # Target response time alarm
  HighResponseTimeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ALB-High-Response-Time
      MetricName: TargetResponseTime
      Namespace: AWS/ApplicationELB
      Statistic: Average
      Period: 300
      EvaluationPeriods: 2
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      Dimensions:
        - Name: LoadBalancer
          Value: !Ref LoadBalancerName
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# Detect HTTP flood attacks via ALB metrics

variable "load_balancer_name" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "alb-http-flood-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# High request count alarm
resource "aws_cloudwatch_metric_alarm" "http_flood" {
  alarm_name          = "ALB-HTTP-Flood"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "RequestCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10000
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.load_balancer_name
  }
}

# High 5xx error rate alarm
resource "aws_cloudwatch_metric_alarm" "high_5xx" {
  alarm_name          = "ALB-High-5xx-Errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.load_balancer_name
  }
}

# Target response time alarm
resource "aws_cloudwatch_metric_alarm" "high_response_time" {
  alarm_name          = "ALB-High-Response-Time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Average"
  threshold           = 5
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.load_balancer_name
  }
}""",
                alert_severity="high",
                alert_title="HTTP Flood Attack Detected",
                alert_description_template="High volume HTTP requests detected on ALB {LoadBalancerName}.",
                investigation_steps=[
                    "Review ALB access logs for request patterns",
                    "Identify source IPs with abnormally high request rates",
                    "Check CloudWatch metrics for request count spikes",
                    "Analyse target group health and response times",
                    "Review application logs for errors or resource exhaustion",
                    "Check for geographic distribution of requests",
                ],
                containment_actions=[
                    "Enable AWS WAF with rate limiting rules",
                    "Block attacking source IPs via WAF IP sets",
                    "Configure CloudFront with caching to absorb traffic",
                    "Enable AWS Shield Advanced for DDoS protection",
                    "Implement CAPTCHA challenges for suspicious sources",
                    "Scale target group capacity if legitimate traffic",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on normal traffic patterns, exclude legitimate high-traffic events like sales or launches",
            detection_coverage="85% - detects volumetric HTTP floods",
            evasion_considerations="Distributed attacks from many IPs may evade simple rate limits, slow HTTP attacks may stay below thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["ALB access logging enabled", "CloudWatch metrics enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1499-002-aws-cloudfront-flood",
            name="AWS CloudFront Request Flood Detection",
            description="Detect request floods targeting CloudFront distributions.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# Detect request floods via CloudFront metrics

variable "distribution_id" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "cloudfront-flood-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# High request rate alarm
resource "aws_cloudwatch_metric_alarm" "request_flood" {
  alarm_name          = "CloudFront-Request-Flood"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "Requests"
  namespace           = "AWS/CloudFront"
  period              = 60
  statistic           = "Sum"
  threshold           = 50000
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    DistributionId = var.distribution_id
  }
}

# High 5xx error rate alarm
resource "aws_cloudwatch_metric_alarm" "high_errors" {
  alarm_name          = "CloudFront-High-5xx-Errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "5xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = 300
  statistic           = "Average"
  threshold           = 5
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    DistributionId = var.distribution_id
  }
}

# Origin latency alarm
resource "aws_cloudwatch_metric_alarm" "origin_latency" {
  alarm_name          = "CloudFront-High-Origin-Latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "OriginLatency"
  namespace           = "AWS/CloudFront"
  period              = 300
  statistic           = "Average"
  threshold           = 3000
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    DistributionId = var.distribution_id
  }
}""",
                alert_severity="high",
                alert_title="CloudFront Request Flood",
                alert_description_template="High request volume or errors on CloudFront distribution {DistributionId}.",
                investigation_steps=[
                    "Review CloudFront access logs for patterns",
                    "Identify geographic distribution of requests",
                    "Check cache hit ratio to assess effectiveness",
                    "Analyse user-agent strings for bot patterns",
                    "Review origin server metrics and health",
                    "Check for sudden traffic spikes or anomalies",
                ],
                containment_actions=[
                    "Enable AWS WAF on CloudFront distribution",
                    "Configure rate-based rules to throttle requests",
                    "Implement geographic restrictions if applicable",
                    "Enable AWS Shield Advanced for Layer 7 protection",
                    "Optimise caching to reduce origin load",
                    "Configure custom error pages to reduce load",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust request thresholds for your traffic baseline, account for legitimate viral events",
            detection_coverage="80% - detects CloudFront-level floods",
            evasion_considerations="Cache-bypassing attacks may evade detection, distributed slow floods may stay below thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudFront distribution with metrics enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1499-002-aws-connection-flood",
            name="AWS Connection Exhaustion Detection",
            description="Detect connection floods exhausting target group connections.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# Detect connection exhaustion attacks

variable "target_group_name" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "connection-flood-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Active connection count alarm
resource "aws_cloudwatch_metric_alarm" "connection_flood" {
  alarm_name          = "Target-Connection-Flood"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ActiveConnectionCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 5000
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    TargetGroup = var.target_group_name
  }
}

# New connection rate alarm
resource "aws_cloudwatch_metric_alarm" "new_connections" {
  alarm_name          = "High-New-Connection-Rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "NewConnectionCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 2000
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    TargetGroup = var.target_group_name
  }
}

# Rejected connection alarm
resource "aws_cloudwatch_metric_alarm" "rejected_connections" {
  alarm_name          = "Rejected-Connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RejectedConnectionCount"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    TargetGroup = var.target_group_name
  }
}""",
                alert_severity="high",
                alert_title="Connection Exhaustion Attack",
                alert_description_template="High connection count exhausting target group {TargetGroup}.",
                investigation_steps=[
                    "Review active and new connection metrics",
                    "Check for rejected connections indicating exhaustion",
                    "Analyse ALB access logs for connection patterns",
                    "Identify source IPs with excessive connections",
                    "Review target health and capacity",
                    "Check application connection pool settings",
                ],
                containment_actions=[
                    "Implement connection limits via WAF",
                    "Configure idle timeout settings on ALB",
                    "Block attacking IPs via security groups",
                    "Scale target group to handle connections",
                    "Implement connection rate limiting",
                    "Enable keep-alive timeout optimisation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust connection thresholds based on application architecture and normal patterns",
            detection_coverage="90% - detects connection exhaustion",
            evasion_considerations="Slow connection attacks may evade detection by staying just below thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["ALB with target group metrics enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1499-002-gcp-http-flood",
            name="GCP HTTP Load Balancer Flood Detection",
            description="Detect HTTP request floods via Google Cloud Load Balancer metrics.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_monitoring",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="http_load_balancer"
httpRequest.status>=500
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Detect HTTP flood attacks via Load Balancer

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# High request rate alert
resource "google_monitoring_alert_policy" "http_flood" {
  display_name = "HTTP Request Flood"
  combiner     = "OR"
  conditions {
    display_name = "High request rate"
    condition_threshold {
      filter          = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/request_count\""
      duration        = "180s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10000
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content = "HTTP request flood detected - possible DoS attack"
  }
}

# High 5xx error rate alert
resource "google_monitoring_alert_policy" "high_5xx" {
  display_name = "High 5xx Error Rate"
  combiner     = "OR"
  conditions {
    display_name = "Elevated 5xx errors"
    condition_threshold {
      filter          = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/request_count\" AND metric.label.response_code_class=\"500\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}

# Backend latency alert
resource "google_monitoring_alert_policy" "backend_latency" {
  display_name = "High Backend Latency"
  combiner     = "OR"
  conditions {
    display_name = "Backend latency spike"
    condition_threshold {
      filter          = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/backend_latencies\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3000
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}

# Log-based metric for flood detection
resource "google_logging_metric" "http_errors" {
  name   = "http-load-balancer-errors"
  filter = <<-EOT
    resource.type="http_load_balancer"
    AND httpRequest.status>=500
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "status_code"
      value_type  = "STRING"
      description = "HTTP status code"
    }
  }
  label_extractors = {
    "status_code" = "EXTRACT(httpRequest.status)"
  }
}""",
                alert_severity="high",
                alert_title="GCP: HTTP Flood Attack Detected",
                alert_description_template="High volume HTTP requests or errors on Cloud Load Balancer.",
                investigation_steps=[
                    "Review Cloud Load Balancing logs in Cloud Logging",
                    "Check request rate and error rate metrics",
                    "Identify source IPs and geographic distribution",
                    "Analyse backend service health and latency",
                    "Review Cloud Armour logs if enabled",
                    "Check for bot or automated traffic patterns",
                ],
                containment_actions=[
                    "Enable Google Cloud Armour with rate limiting",
                    "Configure security policies to block malicious IPs",
                    "Implement CAPTCHA or challenge mechanisms",
                    "Enable Cloud CDN to absorb traffic",
                    "Configure backend service auto-scaling",
                    "Implement geographic access restrictions if applicable",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds for your baseline traffic, account for legitimate spikes during events",
            detection_coverage="85% - detects volumetric HTTP floods",
            evasion_considerations="Distributed attacks from many sources may evade simple rate limits",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=[
                "Cloud Load Balancer with logging enabled",
                "Cloud Monitoring configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1499-002-gcp-armor-flood",
            name="GCP Cloud Armour Rate Limit Detection",
            description="Detect request floods via Cloud Armour rate limiting and blocking.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
jsonPayload.enforcedSecurityPolicy.outcome="DENY"
jsonPayload.enforcedSecurityPolicy.configuredAction="RATE_BASED_BAN"''',
                gcp_terraform_template="""# GCP: Detect floods via Cloud Armour rate limiting

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log-based metric for rate limit blocks
resource "google_logging_metric" "rate_limit_blocks" {
  name   = "cloud-armor-rate-limit-blocks"
  filter = <<-EOT
    resource.type="http_load_balancer"
    AND jsonPayload.enforcedSecurityPolicy.outcome="DENY"
    AND jsonPayload.enforcedSecurityPolicy.configuredAction="RATE_BASED_BAN"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "client_ip"
      value_type  = "STRING"
      description = "Client IP being rate limited"
    }
  }
  label_extractors = {
    "client_ip" = "EXTRACT(httpRequest.remoteIp)"
  }
}

# Alert on excessive rate limiting
resource "google_monitoring_alert_policy" "rate_limit_alert" {
  display_name = "Cloud Armour Rate Limit Flood"
  combiner     = "OR"
  conditions {
    display_name = "High rate limit blocks"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.rate_limit_blocks.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 1000
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content = "High volume of rate-limited requests detected - possible HTTP flood attack"
  }
}

# Alert on throttled requests
resource "google_monitoring_alert_policy" "throttle_alert" {
  display_name = "Cloud Armour Throttling Active"
  combiner     = "OR"
  conditions {
    display_name = "Excessive throttling"
    condition_threshold {
      filter          = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/request_count\" AND metric.label.response_code=\"429\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 500
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Request Flood Rate Limited",
                alert_description_template="Cloud Armour actively rate limiting flood attack.",
                investigation_steps=[
                    "Review Cloud Armour security policy logs",
                    "Identify IPs being rate limited or banned",
                    "Check for distributed attack patterns",
                    "Analyse geographic source of attacks",
                    "Review rate limit rule effectiveness",
                    "Check for legitimate traffic being blocked",
                ],
                containment_actions=[
                    "Adjust Cloud Armour rate limit thresholds",
                    "Configure adaptive protection for automatic mitigation",
                    "Add IP blocklists for persistent attackers",
                    "Enable preview mode to test new rules",
                    "Configure custom error pages for rate limited requests",
                    "Implement CAPTCHA challenges for borderline traffic",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Cloud Armour rate limiting is generally accurate, review thresholds for legitimate high-volume users",
            detection_coverage="90% - detects rate-limited floods",
            evasion_considerations="Attackers may rotate IPs to evade rate limits",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Armour security policy configured with rate limiting"
            ],
        ),
        DetectionStrategy(
            strategy_id="t1499-002-gcp-connection-flood",
            name="GCP Connection Exhaustion Detection",
            description="Detect connection floods exhausting backend services.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_monitoring",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
severity>=ERROR
jsonPayload.statusDetails=~"backend_connection.*"''',
                gcp_terraform_template="""# GCP: Detect connection exhaustion attacks

variable "project_id" { type = string }
variable "alert_email" { type = string }
variable "backend_service_name" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Backend connection errors metric
resource "google_logging_metric" "connection_errors" {
  name   = "backend-connection-errors"
  filter = <<-EOT
    resource.type="http_load_balancer"
    AND severity>=ERROR
    AND jsonPayload.statusDetails=~"backend_connection.*"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert on connection errors
resource "google_monitoring_alert_policy" "connection_errors" {
  display_name = "Backend Connection Errors"
  combiner     = "OR"
  conditions {
    display_name = "High connection errors"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.connection_errors.name}\""
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
}

# Backend request count alert
resource "google_monitoring_alert_policy" "backend_requests" {
  display_name = "High Backend Request Rate"
  combiner     = "OR"
  conditions {
    display_name = "Request flood to backend"
    condition_threshold {
      filter          = "resource.type=\"https_lb_rule\" AND metric.type=\"loadbalancing.googleapis.com/https/backend_request_count\""
      duration        = "180s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5000
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Connection Exhaustion Attack",
                alert_description_template="Backend service experiencing connection exhaustion.",
                investigation_steps=[
                    "Review backend service health check status",
                    "Check connection error logs and patterns",
                    "Analyse request rate to backend services",
                    "Review instance group capacity and scaling",
                    "Check for connection timeout settings",
                    "Identify source of excessive connections",
                ],
                containment_actions=[
                    "Scale backend instance groups to handle load",
                    "Configure connection draining settings",
                    "Implement Cloud Armour rate limiting",
                    "Adjust load balancer timeout settings",
                    "Enable connection pooling on backends",
                    "Block attacking sources via firewall rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust thresholds based on backend capacity and normal connection patterns",
            detection_coverage="85% - detects connection exhaustion",
            evasion_considerations="Slow connection attacks may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Load Balancer with backend services",
                "Cloud Logging enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1499-002-aws-alb-flood",
        "t1499-002-aws-connection-flood",
        "t1499-002-aws-cloudfront-flood",
        "t1499-002-gcp-http-flood",
        "t1499-002-gcp-armor-flood",
        "t1499-002-gcp-connection-flood",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+15% improvement for Impact tactic (service exhaustion floods)",
)
