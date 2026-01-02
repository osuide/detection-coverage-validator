"""
T1071.001 - Application Layer Protocol: Web Protocols

Adversaries use HTTP/HTTPS and WebSocket protocols to blend C2 communications with normal web traffic.
Commands are concealed within HTTP headers, cookies, POST bodies, and other protocol fields.
Used by APT28, APT32, APT33, Lazarus Group, Sandworm Team, and 70+ tracked threat groups.
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
    technique_id="T1071.001",
    technique_name="Application Layer Protocol: Web Protocols",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1071/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage web protocols (HTTP/HTTPS and WebSocket) to blend command and "
            "control communications with normal network traffic, evading detection. Commands and "
            "results are concealed within protocol headers, cookies, POST bodies, and request "
            "parameters. Attackers exploit legitimate web traffic characteristics, using standard "
            "ports (80, 443) to avoid filtering whilst encoding data in various HTTP fields. "
            "SSL/TLS encryption further obscures the malicious nature of communications."
        ),
        attacker_goal="Establish covert C2 channels using HTTP/HTTPS protocols that blend with legitimate web traffic",
        why_technique=[
            "Blends seamlessly with normal web browsing and API traffic",
            "Uses standard ports (80, 443) allowed by most firewalls",
            "SSL/TLS encryption conceals command content",
            "HTTP headers and cookies provide numerous concealment options",
            "WebSocket enables persistent bidirectional communication",
            "Difficult to distinguish from legitimate application behaviour",
            "Wide availability of tools supporting HTTP-based C2",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "HTTP/HTTPS C2 is one of the most prevalent command and control techniques, used by "
            "over 70 tracked threat groups and 500+ malware families. Its widespread adoption stems "
            "from effectiveness in evading traditional network defences. High severity due to enabling "
            "persistent unauthorised access, data exfiltration, and difficulty in detection. The "
            "technique's use of encryption and legitimate protocols makes it a cornerstone of modern "
            "adversary operations."
        ),
        business_impact=[
            "Unauthorised persistent command and control access",
            "Data exfiltration disguised as legitimate web traffic",
            "Difficulty in detection leading to extended dwell time",
            "Potential for lateral movement and privilege escalation",
            "Compliance violations from undetected malicious communications",
            "Compromise of SSL/TLS trust model",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1567", "T1048"],  # Exfiltration techniques
        often_follows=[
            "T1078.004",
            "T1190",
            "T1566",
            "T1203",
        ],  # Initial Access techniques
    ),
    detection_strategies=[
        # Strategy 1: AWS - WAF HTTP Anomaly Detection
        DetectionStrategy(
            strategy_id="t1071-001-aws-waf",
            name="AWS WAF HTTP Anomaly Detection",
            description="Detect suspicious HTTP patterns including unusual headers, high-entropy payloads, and known C2 signatures via AWS WAF.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, httpRequest.clientIp, httpRequest.uri, httpRequest.headers, action
| filter httpRequest.headers like /User-Agent.*python|curl|wget|powershell/
  or httpRequest.uri like /\\/api\\/.*[a-zA-Z0-9]{50,}/
  or httpRequest.headers like /Cookie:.*[a-zA-Z0-9+\\/=]{100,}/
| stats count(*) as suspicious_requests by httpRequest.clientIp, bin(5m)
| filter suspicious_requests > 10
| sort suspicious_requests desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious HTTP patterns for C2 activity

Parameters:
  WAFLogGroup:
    Type: String
    Description: CloudWatch Log Group for WAF logs
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for suspicious HTTP patterns
  SuspiciousHttpMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref WAFLogGroup
      FilterPattern: '{ ($.httpRequest.headers[*].value = "*python*" || $.httpRequest.headers[*].value = "*curl*" || $.httpRequest.headers[*].value = "*wget*") }'
      MetricTransformations:
        - MetricName: SuspiciousHttpRequests
          MetricNamespace: Security/C2Detection
          MetricValue: "1"

  # Step 3: CloudWatch alarm for C2 patterns
  HttpC2Alarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousHttpC2Pattern
      AlarmDescription: Alert on suspicious HTTP patterns indicative of C2
      MetricName: SuspiciousHttpRequests
      Namespace: Security/C2Detection
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect suspicious HTTP patterns for C2 activity

variable "waf_log_group" {
  type        = string
  description = "CloudWatch Log Group for WAF logs"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "http_c2_alerts" {
  name = "http-c2-pattern-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.http_c2_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter for suspicious HTTP patterns
resource "aws_cloudwatch_log_metric_filter" "suspicious_http" {
  name           = "suspicious-http-c2-patterns"
  log_group_name = var.waf_log_group

  pattern = "{ ($.httpRequest.headers[*].value = \"*python*\" || $.httpRequest.headers[*].value = \"*curl*\" || $.httpRequest.headers[*].value = \"*wget*\") }"

  metric_transformation {
    name      = "SuspiciousHttpRequests"
    namespace = "Security/C2Detection"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "http_c2" {
  alarm_name          = "SuspiciousHttpC2Pattern"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SuspiciousHttpRequests"
  namespace           = "Security/C2Detection"
  period              = 300
  statistic           = "Sum"
  threshold           = 20
  alarm_description   = "Alert on suspicious HTTP patterns indicative of C2"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.http_c2_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious HTTP C2 Pattern Detected",
                alert_description_template="Suspicious HTTP patterns detected from {clientIp}. Unusual user agents or high-entropy data in headers may indicate C2 activity.",
                investigation_steps=[
                    "Review HTTP request headers and user agents",
                    "Analyse URI patterns for encoded data",
                    "Check cookie contents for unusual Base64 or hex-encoded strings",
                    "Identify the source IP and associated AWS resources",
                    "Review application logs for the timeframe",
                    "Check destination domain reputation and ownership",
                    "Analyse request frequency and timing patterns",
                ],
                containment_actions=[
                    "Block suspicious client IPs via WAF",
                    "Add custom WAF rules for detected patterns",
                    "Isolate affected instances from network",
                    "Review and restrict security group egress rules",
                    "Enable enhanced WAF logging",
                    "Deploy endpoint detection on affected resources",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate automation tools, monitoring agents, and CI/CD pipelines using non-browser user agents",
            detection_coverage="70% - detects known C2 patterns but may miss custom implementations",
            evasion_considerations="Attackers may use legitimate user agents and standard HTTP patterns to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-40",
            prerequisites=["AWS WAF enabled", "WAF logging to CloudWatch"],
        ),
        # Strategy 2: AWS - ALB Access Log Analysis
        DetectionStrategy(
            strategy_id="t1071-001-aws-alb",
            name="AWS ALB HTTP Beaconing Detection",
            description="Detect HTTP beaconing patterns in ALB access logs that indicate regular C2 check-ins.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, client_ip, request_url, user_agent, elb_status_code, sent_bytes
| filter user_agent not like /Mozilla|Chrome|Safari|Edge/
| stats count(*) as request_count, avg(sent_bytes) as avg_response by client_ip, user_agent, bin(5m)
| filter request_count > 30 and avg_response < 5000
| sort request_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect HTTP beaconing behaviour via ALB logs

Parameters:
  ALBLogGroup:
    Type: String
    Description: CloudWatch Log Group for ALB access logs
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for beaconing patterns
  BeaconingMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ALBLogGroup
      FilterPattern: '[..., user_agent!="*Mozilla*" && user_agent!="*Chrome*", ...]'
      MetricTransformations:
        - MetricName: HttpBeaconingRequests
          MetricNamespace: Security/C2Detection
          MetricValue: "1"

  # Step 3: CloudWatch alarm
  BeaconingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HttpBeaconingDetected
      AlarmDescription: Alert on HTTP beaconing behaviour
      MetricName: HttpBeaconingRequests
      Namespace: Security/C2Detection
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect HTTP beaconing behaviour via ALB logs

variable "alb_log_group" {
  type        = string
  description = "CloudWatch Log Group for ALB access logs"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "beaconing_alerts" {
  name = "http-beaconing-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.beaconing_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter for beaconing patterns
resource "aws_cloudwatch_log_metric_filter" "beaconing" {
  name           = "http-beaconing-detection"
  log_group_name = var.alb_log_group

  pattern = "[..., user_agent!=\"*Mozilla*\" && user_agent!=\"*Chrome*\", ...]"

  metric_transformation {
    name      = "HttpBeaconingRequests"
    namespace = "Security/C2Detection"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "beaconing" {
  alarm_name          = "HttpBeaconingDetected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HttpBeaconingRequests"
  namespace           = "Security/C2Detection"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_description   = "Alert on HTTP beaconing behaviour"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.beaconing_alerts.arn]
}""",
                alert_severity="high",
                alert_title="HTTP Beaconing Pattern Detected",
                alert_description_template="HTTP beaconing behaviour detected from {client_ip}. Regular small requests may indicate C2 check-ins.",
                investigation_steps=[
                    "Identify source instance making the requests",
                    "Analyse request timing and frequency patterns",
                    "Review user agent strings for anomalies",
                    "Check response sizes and status codes",
                    "Examine request URIs for encoded data",
                    "Review instance processes and scheduled tasks",
                    "Correlate with other suspicious activities",
                ],
                containment_actions=[
                    "Block suspicious client IPs at security group level",
                    "Isolate affected instances for investigation",
                    "Review and terminate suspicious processes",
                    "Enable enhanced monitoring and logging",
                    "Deploy EDR solution on affected instances",
                    "Review IAM roles and permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate health checks, monitoring tools, and API clients. Establish baseline for normal request patterns.",
            detection_coverage="75% - detects regular beaconing but may miss irregular patterns",
            evasion_considerations="Attackers may randomise timing, use legitimate user agents, or vary request sizes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=[
                "ALB access logging enabled",
                "Logs delivered to CloudWatch",
            ],
        ),
        # Strategy 3: AWS - VPC Flow Logs HTTPS Analysis
        DetectionStrategy(
            strategy_id="t1071-001-aws-vpc",
            name="AWS VPC Flow Logs HTTPS Connection Analysis",
            description="Detect unusual HTTPS connection patterns including long-duration connections and high-frequency connections to suspicious destinations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes
| filter dstPort = 443 and protocol = 6
| stats count() as connection_count, sum(bytes) as total_bytes by srcAddr, dstAddr, bin(5m)
| filter connection_count > 100
| sort connection_count desc
| limit 50""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual HTTPS connection patterns for C2 detection

Parameters:
  VpcFlowLogGroup:
    Type: String
    Description: CloudWatch Log Group for VPC Flow Logs
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for unusual HTTPS connections
  HttpsAnomalyMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VpcFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport="443", protocol="6", ...]'
      MetricTransformations:
        - MetricName: HighFrequencyHttps
          MetricNamespace: Security/C2Detection
          MetricValue: "1"

  # Step 3: CloudWatch alarm
  HttpsAnomalyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualHttpsConnections
      AlarmDescription: Alert on unusual HTTPS connection patterns
      MetricName: HighFrequencyHttps
      Namespace: Security/C2Detection
      Statistic: Sum
      Period: 300
      Threshold: 200
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect unusual HTTPS connection patterns

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "https_anomaly_alerts" {
  name = "https-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.https_anomaly_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter
resource "aws_cloudwatch_log_metric_filter" "https_anomaly" {
  name           = "unusual-https-connections"
  log_group_name = var.vpc_flow_log_group

  pattern = "[version, account, eni, source, destination, srcport, dstport=\"443\", protocol=\"6\", ...]"

  metric_transformation {
    name      = "HighFrequencyHttps"
    namespace = "Security/C2Detection"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "https_anomaly" {
  alarm_name          = "UnusualHttpsConnections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HighFrequencyHttps"
  namespace           = "Security/C2Detection"
  period              = 300
  statistic           = "Sum"
  threshold           = 200
  alarm_description   = "Alert on unusual HTTPS connection patterns"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.https_anomaly_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Unusual HTTPS Connection Pattern Detected",
                alert_description_template="High-frequency HTTPS connections detected from {srcAddr} to {dstAddr}. May indicate C2 activity.",
                investigation_steps=[
                    "Identify the source instance and its function",
                    "Review destination IP and domain ownership",
                    "Check destination IP reputation via threat intelligence",
                    "Analyse connection timing and duration patterns",
                    "Review application logs for context",
                    "Check for certificate anomalies or pinning",
                    "Examine instance for malware or backdoors",
                ],
                containment_actions=[
                    "Block suspicious destination IPs via security groups",
                    "Enable SSL/TLS inspection where possible",
                    "Isolate affected instances for investigation",
                    "Review and restrict outbound internet access",
                    "Deploy network-based IDS/IPS",
                    "Review and update security group rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist legitimate high-traffic HTTPS destinations (CDNs, APIs, SaaS platforms). Establish baseline for each application.",
            detection_coverage="60% - detects high-volume patterns but encrypted payload prevents deep inspection",
            evasion_considerations="Attackers may use low-frequency connections or blend with legitimate HTTPS traffic",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-15",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 4: GCP - Cloud Armor HTTP Anomaly Detection
        DetectionStrategy(
            strategy_id="t1071-001-gcp-armor",
            name="GCP Cloud Armor HTTP Anomaly Detection",
            description="Detect suspicious HTTP patterns and known C2 signatures using Cloud Armor security policies.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="http_load_balancer"
jsonPayload.enforcedSecurityPolicy.outcome="DENY"
OR (
  httpRequest.userAgent!~"Mozilla|Chrome|Safari|Edge"
  AND httpRequest.requestUrl=~".*[a-zA-Z0-9]{50,}.*"
)""",
                gcp_terraform_template="""# GCP: Detect HTTP anomalies via Cloud Armor

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
  project      = var.project_id
  display_name = "Security Alerts - HTTP C2 Detection"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for suspicious HTTP patterns
resource "google_logging_metric" "http_c2_patterns" {
  project = var.project_id
  name   = "http-c2-suspicious-patterns"
  filter = <<-EOT
    resource.type="http_load_balancer"
    (jsonPayload.enforcedSecurityPolicy.outcome="DENY"
    OR (
      httpRequest.userAgent!~"Mozilla|Chrome|Safari|Edge"
      AND httpRequest.requestUrl=~".*[a-zA-Z0-9]{50,}.*"
    ))
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "http_c2_detection" {
  project      = var.project_id
  display_name = "HTTP C2 Pattern Detection"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious HTTP patterns detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.http_c2_patterns.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious HTTP C2 Pattern Detected",
                alert_description_template="Suspicious HTTP patterns detected in Cloud Armor logs. Unusual user agents or high-entropy URIs may indicate C2 activity.",
                investigation_steps=[
                    "Review Cloud Armor security policy logs",
                    "Analyse HTTP request headers and user agents",
                    "Check source IP addresses and geolocation",
                    "Review Load Balancer backend logs",
                    "Identify affected GCP resources",
                    "Check for other suspicious activities from same source",
                    "Analyse request frequency and timing",
                ],
                containment_actions=[
                    "Add Cloud Armor rules to block suspicious patterns",
                    "Block malicious source IPs",
                    "Enable additional Cloud Armor security policies",
                    "Isolate affected backend instances",
                    "Review and restrict VPC firewall rules",
                    "Deploy additional security monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate automation, API clients, and monitoring tools. Review and tune Cloud Armor rules regularly.",
            detection_coverage="75% - detects known patterns but may miss novel C2 implementations",
            evasion_considerations="Attackers may use legitimate user agents and standard HTTP patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$20-50",
            prerequisites=[
                "Cloud Armor enabled",
                "HTTP(S) Load Balancer",
                "Cloud Logging",
            ],
        ),
        # Strategy 5: GCP - VPC Flow Logs HTTPS Analysis
        DetectionStrategy(
            strategy_id="t1071-001-gcp-vpc",
            name="GCP VPC Flow Logs HTTP/HTTPS Beaconing Detection",
            description="Detect HTTP/HTTPS beaconing patterns in VPC Flow Logs indicating regular C2 check-ins.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port:(443 OR 80 OR 8080 OR 8443)
jsonPayload.connection.protocol=6
jsonPayload.bytes_sent<5000""",
                gcp_terraform_template="""# GCP: Detect HTTP/HTTPS beaconing in VPC Flow Logs

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
  project      = var.project_id
  display_name = "Security Alerts - HTTP Beaconing"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for beaconing patterns
resource "google_logging_metric" "http_beaconing" {
  project = var.project_id
  name   = "http-beaconing-pattern"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port:(443 OR 80 OR 8080 OR 8443)
    jsonPayload.connection.protocol=6
    jsonPayload.bytes_sent<5000
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "beaconing_detection" {
  project      = var.project_id
  display_name = "HTTP/HTTPS Beaconing Detection"
  combiner     = "OR"

  conditions {
    display_name = "Beaconing pattern detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.http_beaconing.name}\""
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

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: HTTP/HTTPS Beaconing Pattern Detected",
                alert_description_template="HTTP/HTTPS beaconing behaviour detected in VPC Flow Logs. Regular small connections may indicate C2 activity.",
                investigation_steps=[
                    "Identify source VM instances",
                    "Review connection timing and frequency",
                    "Check destination IP reputation",
                    "Analyse VPC Flow Logs for patterns",
                    "Review VM instance metadata and startup scripts",
                    "Check running processes on affected VMs",
                    "Correlate with other security findings",
                ],
                containment_actions=[
                    "Isolate affected VMs using VPC firewall rules",
                    "Create snapshots for forensic analysis",
                    "Block suspicious destination IPs",
                    "Revoke service account credentials",
                    "Review and restrict egress firewall rules",
                    "Deploy security agents on affected instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate health checks, monitoring, and API polling. Establish per-application baselines.",
            detection_coverage="75% - detects regular beaconing but may miss irregular patterns",
            evasion_considerations="Attackers may randomise timing and payload sizes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$15-35",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging"],
        ),
        # Strategy 6: AWS - GuardDuty C2 Detection
        DetectionStrategy(
            strategy_id="t1071-001-aws-guardduty",
            name="AWS GuardDuty HTTP C2 Detection",
            description="Leverage GuardDuty to detect known HTTP/HTTPS C2 activity using threat intelligence.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B",
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "Trojan:EC2/BlackholeTraffic",
                    "Trojan:EC2/DropPoint",
                    "UnauthorizedAccess:EC2/TorClient",
                    "UnauthorizedAccess:EC2/TorRelay",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Configure GuardDuty for HTTP C2 detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable GuardDuty
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for HTTP C2 findings
  C2FindingRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Alert on GuardDuty HTTP C2 findings
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          type:
            - prefix: Backdoor:EC2/C&CActivity
            - prefix: Trojan:EC2/BlackholeTraffic
            - prefix: Trojan:EC2/DropPoint
            - prefix: UnauthorizedAccess:EC2/Tor
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt C2FindingRule.Arn""",
                terraform_template="""# Configure GuardDuty for HTTP C2 detection

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "c2_alerts" {
  name = "guardduty-http-c2-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.c2_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for C2 findings
resource "aws_cloudwatch_event_rule" "guardduty_c2" {
  name        = "guardduty-http-c2-detection"
  description = "Alert on GuardDuty HTTP C2 findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2/C&CActivity.B" },
        { prefix = "Trojan:EC2/BlackholeTraffic" },
        { prefix = "Trojan:EC2/DropPoint" },
        { prefix = "UnauthorizedAccess:EC2/TorClient" }
      ]
    }
  })
}

# SQS DLQ for failed EventBridge deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-c2-eventbridge-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.dlq.arn
    }]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_c2.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.c2_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account    = "$.account"
      region     = "$.region"
      time       = "$.time"
      type       = "$.detail.type"
      severity   = "$.detail.severity"
      title      = "$.detail.title"
      description = "$.detail.description"
    }

    input_template = <<-EOT
"GuardDuty Finding Alert
Time: <time>
Account: <account>
Region: <region>
Finding: <type>
Severity: <severity>
Title: <title>
Description: <description>
Action: Review finding in GuardDuty console and investigate"
EOT
  }

}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.c2_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.c2_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_c2.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty HTTP C2 Activity Detected",
                alert_description_template="GuardDuty detected {type} on instance {resource.instanceDetails.instanceId}. This indicates HTTP-based command and control activity.",
                investigation_steps=[
                    "Review GuardDuty finding details and evidence",
                    "Identify affected EC2 instances and their roles",
                    "Check destination IPs in threat intelligence feeds",
                    "Review CloudTrail logs for suspicious API activity",
                    "Analyse VPC Flow Logs for connection patterns",
                    "Examine instance for malware or backdoors",
                    "Check for lateral movement indicators",
                ],
                containment_actions=[
                    "Isolate affected instances immediately",
                    "Create forensic snapshots before remediation",
                    "Revoke instance IAM role credentials",
                    "Block malicious IPs via security groups",
                    "Review and rotate any exposed credentials",
                    "Deploy replacement instances from clean AMIs",
                    "Update security group rules to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review and suppress findings for known security tools and monitoring systems. Maintain updated threat intelligence feeds.",
            detection_coverage="85% - high accuracy using threat intelligence and ML",
            evasion_considerations="Zero-day C2 infrastructure not in threat feeds may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$30-100 depending on data volume",
            prerequisites=["GuardDuty enabled", "VPC Flow Logs", "DNS Logs"],
        ),
    ],
    recommended_order=[
        "t1071-001-aws-guardduty",
        "t1071-001-aws-waf",
        "t1071-001-gcp-armor",
        "t1071-001-aws-alb",
        "t1071-001-aws-vpc",
        "t1071-001-gcp-vpc",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+30% improvement for Command and Control tactic detection",
)
