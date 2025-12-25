"""
T1594 - Search Victim-Owned Websites

Adversaries search websites owned by the victim organisation for information
that can be used during targeting. This includes identifying departmental
structures, physical locations, employee names, and contact information.
Used by APT41, Kimsuky, Leviathan, Sandworm Team, Silent Librarian.
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
    technique_id="T1594",
    technique_name="Search Victim-Owned Websites",
    tactic_ids=["TA0043"],
    mitre_url="https://attack.mitre.org/techniques/T1594/",
    threat_context=ThreatContext(
        description=(
            "Adversaries conduct reconnaissance by searching websites owned by the "
            "victim organisation to gather actionable intelligence. This includes "
            "identifying departmental structures, physical locations, employee names, "
            "roles, and contact information. Both manual browsing and automated methods "
            "like wordlist scanning are used, plus exploitation of sitemap.xml and "
            "robots.txt to discover hidden directories or sensitive functionality."
        ),
        attacker_goal="Gather intelligence from victim-owned websites for targeting and social engineering",
        why_technique=[
            "Public websites contain valuable targeting information",
            "Automated web crawling tools are readily available",
            "Activity occurs outside defender's network",
            "Reveals organisational structure and personnel",
            "Enables tailored phishing campaigns",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=5,
        severity_reasoning=(
            "Pre-compromise reconnaissance technique that occurs outside enterprise "
            "defenses. While not directly harmful, it enables more sophisticated "
            "attacks including targeted phishing and social engineering."
        ),
        business_impact=[
            "Enables targeted phishing campaigns",
            "Reveals organisational structure",
            "Exposes employee information",
            "Identifies potential attack surfaces",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1589", "T1598", "T1566"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1594-aws-cloudfront",
            name="AWS CloudFront Reconnaissance Detection",
            description="Detect web crawling and reconnaissance activity via CloudFront logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, c-ip, cs-uri-stem, cs-user-agent
| filter cs-uri-stem like /robots\\.txt|sitemap\\.xml/
| stats count(*) as requests by c-ip, bin(1h)
| filter requests > 5
| sort requests desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect web reconnaissance via CloudFront

Parameters:
  CloudFrontLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  ReconFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudFrontLogGroup
      FilterPattern: '[timestamp, x-edge-location, sc-bytes, c-ip, cs-method, cs-host, cs-uri-stem=*robots.txt* || cs-uri-stem=*sitemap.xml*, ...]'
      MetricTransformations:
        - MetricName: ReconRequests
          MetricNamespace: Security
          MetricValue: "1"

  ReconAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: WebsiteReconnaissance
      MetricName: ReconRequests
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect web reconnaissance via CloudFront

variable "cloudfront_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "cloudfront-recon-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "recon_activity" {
  name           = "website-reconnaissance"
  log_group_name = var.cloudfront_log_group
  pattern        = "[timestamp, x-edge-location, sc-bytes, c-ip, cs-method, cs-host, cs-uri-stem=*robots.txt* || cs-uri-stem=*sitemap.xml*, ...]"

  metric_transformation {
    name      = "ReconRequests"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "recon_detection" {
  alarm_name          = "WebsiteReconnaissance"
  metric_name         = "ReconRequests"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Website Reconnaissance Detected",
                alert_description_template="Suspicious reconnaissance activity from {c-ip} accessing sensitive site files.",
                investigation_steps=[
                    "Review source IP geolocation and reputation",
                    "Check user-agent strings for automated tools",
                    "Analyse request patterns and frequency",
                    "Review accessed URIs for sensitive paths",
                ],
                containment_actions=[
                    "Rate-limit suspicious IPs via WAF",
                    "Review exposed information in robots.txt/sitemap",
                    "Monitor for follow-on phishing attempts",
                    "Consider implementing CAPTCHA for high-volume sources",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate search engines and SEO tools may trigger alerts. Whitelist known crawlers.",
            detection_coverage="40% - detects automated reconnaissance",
            evasion_considerations="Manual browsing and distributed crawling may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudFront with logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1594-aws-alb-crawl",
            name="ALB Web Crawling Detection",
            description="Detect automated web crawling via Application Load Balancer logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, client_ip, user_agent, request_url
| filter request_url like /robots\\.txt|sitemap|\\.xml|admin|login|api/
| stats count(*) as requests, count_distinct(request_url) as unique_paths by client_ip, user_agent, bin(10m)
| filter requests > 20 or unique_paths > 15
| sort requests desc""",
                terraform_template="""# Detect web crawling via ALB logs

variable "alb_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "alb-crawl-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "crawl_activity" {
  name           = "web-crawling"
  log_group_name = var.alb_log_group
  pattern        = "[type, timestamp, elb, client_port, target_port, request_processing_time, target_processing_time, response_processing_time, elb_status_code, target_status_code, received_bytes, sent_bytes, request=*robots.txt* || request=*sitemap*, ...]"

  metric_transformation {
    name      = "CrawlRequests"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "crawl_detection" {
  alarm_name          = "WebCrawlingActivity"
  metric_name         = "CrawlRequests"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 600
  threshold           = 30
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Web Crawling Activity Detected",
                alert_description_template="Automated crawling detected from {client_ip} with user-agent {user_agent}.",
                investigation_steps=[
                    "Identify user-agent and compare to known crawlers",
                    "Review request rate and patterns",
                    "Check for access to sensitive endpoints",
                    "Correlate with other reconnaissance indicators",
                ],
                containment_actions=[
                    "Implement rate limiting for suspicious sources",
                    "Update robots.txt to restrict sensitive paths",
                    "Enable WAF rules for bot management",
                    "Monitor for subsequent attack attempts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate search engine crawlers (Googlebot, Bingbot). Adjust thresholds based on normal traffic patterns.",
            detection_coverage="50% - catches automated reconnaissance",
            evasion_considerations="Slow, distributed crawling with legitimate user-agents may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["ALB access logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1594-gcp-lb-recon",
            name="GCP Load Balancer Reconnaissance Detection",
            description="Detect reconnaissance activity via HTTP(S) Load Balancer logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
(httpRequest.requestUrl=~"robots.txt" OR httpRequest.requestUrl=~"sitemap")
NOT httpRequest.userAgent=~"Googlebot|Bingbot|compatible"''',
                gcp_terraform_template="""# GCP: Detect website reconnaissance via Load Balancer

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "recon_requests" {
  name   = "website-reconnaissance"
  filter = <<-EOT
    resource.type="http_load_balancer"
    (httpRequest.requestUrl=~"robots.txt" OR httpRequest.requestUrl=~"sitemap")
    NOT httpRequest.userAgent=~"Googlebot|Bingbot|compatible"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "recon_activity" {
  display_name = "Website Reconnaissance"
  combiner     = "OR"
  conditions {
    display_name = "High reconnaissance activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.recon_requests.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Website Reconnaissance Detected",
                alert_description_template="Reconnaissance activity detected accessing sensitive site files.",
                investigation_steps=[
                    "Review source IP addresses",
                    "Analyse user-agent patterns",
                    "Check request frequency and timing",
                    "Review accessed resources",
                ],
                containment_actions=[
                    "Apply Cloud Armor rate limiting",
                    "Restrict access to sensitive paths",
                    "Enable bot management features",
                    "Monitor for follow-on attacks",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known legitimate crawlers. Adjust thresholds based on site traffic.",
            detection_coverage="45% - detects automated reconnaissance",
            evasion_considerations="Manual browsing and sophisticated bot evasion techniques may bypass",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["HTTP(S) Load Balancer logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1594-aws-contact-form",
            name="AWS Contact Form Abuse Detection",
            description="Detect abuse of contact forms for reconnaissance and phishing delivery.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, client_ip, request_url, user_agent
| filter request_url like /contact|form|submit/
| filter elb_status_code = 200
| stats count(*) as submissions by client_ip, bin(1h)
| filter submissions > 5
| sort submissions desc""",
                terraform_template="""# Detect contact form abuse

variable "application_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "contact-form-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "form_abuse" {
  name           = "contact-form-abuse"
  log_group_name = var.application_log_group
  pattern        = "[..., request=*contact* || request=*form*, status_code=200, ...]"

  metric_transformation {
    name      = "ContactFormSubmissions"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "form_abuse_detection" {
  alarm_name          = "ContactFormAbuse"
  metric_name         = "ContactFormSubmissions"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Contact Form Abuse Detected",
                alert_description_template="Multiple contact form submissions from {client_ip}.",
                investigation_steps=[
                    "Review form submission content",
                    "Check for automated submission patterns",
                    "Identify source IP reputation",
                    "Look for phishing URLs in submissions",
                ],
                containment_actions=[
                    "Implement CAPTCHA on contact forms",
                    "Rate-limit form submissions per IP",
                    "Add honeypot fields to detect bots",
                    "Review and sanitise form data handling",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Adjust threshold based on legitimate form traffic. Consider implementing CAPTCHA before alerting.",
            detection_coverage="30% - detects high-volume abuse",
            evasion_considerations="Low-volume manual submissions will evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["Application logging with form submission tracking"],
        ),
    ],
    recommended_order=[
        "t1594-aws-cloudfront",
        "t1594-gcp-lb-recon",
        "t1594-aws-alb-crawl",
        "t1594-aws-contact-form",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+15% improvement for Reconnaissance tactic",
)
