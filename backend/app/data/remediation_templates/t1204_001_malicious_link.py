"""
T1204.001 - User Execution: Malicious Link

Adversaries rely upon users clicking malicious links to gain execution.
Users manipulated through social engineering, often via spearphishing links.
Used by APT28, APT29, APT32, Lazarus Group, FIN7, and many others.
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
    technique_id="T1204.001",
    technique_name="User Execution: Malicious Link",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1204/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage user clicks on malicious links to achieve code execution. "
            "Users are typically manipulated through social engineering in spearphishing campaigns. "
            "Clicked links may lead to browser exploitations, application vulnerabilities, or "
            "downloads requiring subsequent execution."
        ),
        attacker_goal="Gain code execution by tricking users into clicking malicious links",
        why_technique=[
            "Bypasses perimeter security controls",
            "Exploits human trust and curiosity",
            "Common in spearphishing campaigns",
            "Enables delivery of malware payloads",
            "Difficult to prevent with technical controls alone",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Extremely common initial access vector used by over 80 threat groups. "
            "Combines technical exploitation with social engineering to bypass security controls."
        ),
        business_impact=[
            "Initial compromise enabler",
            "Malware delivery vector",
            "Credential theft risk",
            "Data exfiltration pathway",
            "Ransomware deployment",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1204.002", "T1566.002", "T1059", "T1105"],
        often_follows=["T1566.002"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1204-001-aws-guardduty",
            name="AWS GuardDuty Malicious Domain Detection",
            description="Detect connections to known malicious domains from EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, service.action.networkConnectionAction.remoteIpDetails.ipAddressV4,
       service.action.networkConnectionAction.remotePortDetails.portName,
       severity, title
| filter type like /Backdoor|Trojan|CryptoMining/
| filter service.action.networkConnectionAction.connectionDirection = "OUTBOUND"
| stats count(*) as malicious_connections by service.action.networkConnectionAction.remoteIpDetails.ipAddressV4, bin(1h)
| sort malicious_connections desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect malicious domain connections via GuardDuty

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  SecurityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Malicious Link Detection Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for GuardDuty findings
  GuardDutyMaliciousLinkRule:
    Type: AWS::Events::Rule
    Properties:
      Name: GuardDutyMaliciousDomainDetection
      Description: Trigger on malicious domain connections
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: Backdoor
            - prefix: Trojan
            - prefix: UnauthorizedAccess
      State: ENABLED
      Targets:
        - Arn: !Ref SecurityAlertTopic
          Id: SecurityAlertTarget

  # Step 3: Grant EventBridge permission to publish to SNS
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref SecurityAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref SecurityAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt GuardDutyMaliciousLinkRule.Arn""",
                terraform_template="""# Detect malicious domain connections via GuardDuty

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "security_alerts" {
  name         = "malicious-link-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Malicious Link Detection Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_malicious_links" {
  name        = "guardduty-malicious-domain-detection"
  description = "Trigger on malicious domain connections"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor" },
        { prefix = "Trojan" },
        { prefix = "UnauthorizedAccess" }
      ]
    }
  })
}

# DLQ for failed EventBridge deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "malicious-link-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "dlq_policy" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_malicious_links.arn
        }
      }
    }]
  })
}

# Step 3: Connect EventBridge to SNS
resource "aws_cloudwatch_event_target" "sns_target" {
  rule      = aws_cloudwatch_event_rule.guardduty_malicious_links.name
  target_id = "SecurityAlertTarget"
  arn       = aws_sns_topic.security_alerts.arn

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

resource "aws_sns_topic_policy" "eventbridge_publish" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.security_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty_malicious_links.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Malicious Domain Connection Detected",
                alert_description_template="EC2 instance {instanceId} connected to known malicious domain {remoteDomain}.",
                investigation_steps=[
                    "Review GuardDuty finding details and threat intelligence",
                    "Identify affected EC2 instance and user activity",
                    "Check browser history and email logs for malicious links",
                    "Review process execution logs for suspicious activity",
                    "Examine network traffic for data exfiltration",
                ],
                containment_actions=[
                    "Isolate affected EC2 instance from network",
                    "Block malicious domain at security group/WAF",
                    "Terminate suspicious processes",
                    "Revoke potentially compromised credentials",
                    "Review and apply security patches",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses threat intelligence; false positives are rare",
            detection_coverage="65% - catches known malicious domains",
            evasion_considerations="New/unknown malicious domains may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-20",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1204-001-aws-cloudtrail",
            name="AWS CloudTrail Suspicious Browser Activity",
            description="Detect suspicious URL handling and downloads via CloudTrail and VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudtrail",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress,
       requestParameters.instancesSet.items.0.instanceId
| filter eventName = "RunInstances" OR eventName = "StartInstances"
| filter sourceIPAddress not like /^10\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\.|^192\\.168\\./
| stats count(*) as suspicious_starts by sourceIPAddress, bin(1h)
| filter suspicious_starts > 3
| sort suspicious_starts desc""",
                terraform_template="""# Detect suspicious browser/download activity patterns

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "malicious-link-activity-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious activity
resource "aws_cloudwatch_log_metric_filter" "suspicious_downloads" {
  name           = "suspicious-download-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"RunInstances\" || $.eventName = \"StartInstances\") && $.sourceIPAddress != \"10.*\" && $.sourceIPAddress != \"172.16.*\" && $.sourceIPAddress != \"192.168.*\" }"

  metric_transformation {
    name      = "SuspiciousInstanceActivity"
    namespace = "Security/MaliciousLinks"
    value     = "1"
  }
}

# Step 3: Create alarm for high activity
resource "aws_cloudwatch_metric_alarm" "suspicious_activity" {
  alarm_name          = "SuspiciousBrowserActivity"
  metric_name         = "SuspiciousInstanceActivity"
  namespace           = "Security/MaliciousLinks"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_description   = "Detect suspicious instance launch patterns"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious Browser/Download Activity",
                alert_description_template="Unusual instance activity from external IP {sourceIPAddress}.",
                investigation_steps=[
                    "Review user activity and recent emails",
                    "Check browser history for suspicious links",
                    "Examine downloaded files in user directories",
                    "Review process execution logs",
                    "Check for lateral movement indicators",
                ],
                containment_actions=[
                    "Disable compromised user account",
                    "Isolate affected systems",
                    "Remove malicious files",
                    "Reset user credentials",
                    "Review email security settings",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust thresholds based on normal user activity patterns",
            detection_coverage="50% - behavioral detection of suspicious patterns",
            evasion_considerations="Attackers using legitimate cloud services may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1204-001-aws-proxy",
            name="AWS Web Proxy URL Analysis",
            description="Analyse web proxy logs for suspicious URL patterns and downloads.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, client_ip, url, http_status, bytes_sent
| filter url like /\\.exe|\\.scr|\\.pif|\\.cpl|\\.zip|\\.rar/
| filter http_status = 200
| stats count(*) as downloads, sum(bytes_sent) as total_bytes by client_ip, url
| filter downloads > 0
| sort downloads desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious file downloads via web proxy logs

Parameters:
  ProxyLogGroup:
    Type: String
    Description: Web proxy CloudWatch log group
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Suspicious Download Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for suspicious downloads
  SuspiciousDownloadFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ProxyLogGroup
      FilterPattern: '[time, client_ip, url="*.exe" || url="*.scr" || url="*.pif" || url="*.cpl", status=200, ...]'
      MetricTransformations:
        - MetricName: SuspiciousFileDownloads
          MetricNamespace: Security/MaliciousLinks
          MetricValue: "1"

  # Step 3: Create alarm for suspicious downloads
  DownloadAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousFileDownloadDetected
      MetricName: SuspiciousFileDownloads
      Namespace: Security/MaliciousLinks
      Statistic: Sum
      Period: 300
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmDescription: Detect suspicious file types downloaded
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect suspicious file downloads via web proxy

variable "proxy_log_group" {
  type        = string
  description = "Web proxy CloudWatch log group"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "download_alerts" {
  name         = "suspicious-download-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Suspicious Download Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.download_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious file types
resource "aws_cloudwatch_log_metric_filter" "suspicious_downloads" {
  name           = "suspicious-file-downloads"
  log_group_name = var.proxy_log_group
  pattern        = "[time, client_ip, url=\"*.exe\" || url=\"*.scr\" || url=\"*.pif\" || url=\"*.cpl\", status=200, ...]"

  metric_transformation {
    name      = "SuspiciousFileDownloads"
    namespace = "Security/MaliciousLinks"
    value     = "1"
  }
}

# Step 3: Create alarm for download activity
resource "aws_cloudwatch_metric_alarm" "download_alert" {
  alarm_name          = "SuspiciousFileDownloadDetected"
  metric_name         = "SuspiciousFileDownloads"
  namespace           = "Security/MaliciousLinks"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_description   = "Detect suspicious file types downloaded"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.download_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious File Download Detected",
                alert_description_template="User {client_ip} downloaded suspicious file: {url}.",
                investigation_steps=[
                    "Identify user associated with client IP",
                    "Review full browsing history and email",
                    "Analyse downloaded file for malware",
                    "Check if file was executed",
                    "Review endpoint security logs",
                ],
                containment_actions=[
                    "Quarantine downloaded file",
                    "Block malicious URL at proxy/firewall",
                    "Scan endpoint for malware",
                    "Disable user account if compromised",
                    "Review and strengthen email filtering",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate software distribution domains",
            detection_coverage="60% - catches common malicious file types",
            evasion_considerations="Attackers may use archives or obfuscated file extensions",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Web proxy with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1204-001-gcp-chronicle",
            name="GCP Chronicle SIEM Detection",
            description="Detect malicious link clicks via Chronicle SIEM analysis.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="chronicle",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
log_name="projects/YOUR_PROJECT/logs/syslog"
jsonPayload.message=~"(wget|curl|browser).*http"
severity>="WARNING"''',
                gcp_terraform_template="""# GCP: Detect malicious link activity via Cloud Logging

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Malicious Link Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for suspicious URL access
resource "google_logging_metric" "malicious_link_activity" {
  project = var.project_id
  name   = "malicious-link-activity"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.message=~"wget.*http" OR
     jsonPayload.message=~"curl.*http" OR
     jsonPayload.message=~"browser.*http")
    severity>="WARNING"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance ID"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy for suspicious activity
resource "google_monitoring_alert_policy" "malicious_link_alert" {
  project      = var.project_id
  display_name = "Malicious Link Activity Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious URL access detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.malicious_link_activity.name}\" AND resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Suspicious URL access or download activity detected on GCE instance. Investigate for potential malicious link execution."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Malicious Link Activity Detected",
                alert_description_template="Suspicious URL access detected on instance {instance_id}.",
                investigation_steps=[
                    "Review GCE instance logs for user activity",
                    "Check browser history and downloaded files",
                    "Analyse network traffic for C2 communication",
                    "Review recent authentication events",
                    "Examine process execution logs",
                ],
                containment_actions=[
                    "Isolate affected GCE instance",
                    "Block malicious domains at VPC firewall",
                    "Scan instance for malware",
                    "Revoke potentially compromised credentials",
                    "Review and update security policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate automated update/download processes",
            detection_coverage="55% - detects suspicious URL patterns",
            evasion_considerations="HTTPS traffic and obfuscated commands may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-35",
            prerequisites=["GCP Cloud Logging enabled", "Chronicle SIEM recommended"],
        ),
        DetectionStrategy(
            strategy_id="t1204-001-gcp-safebrowsing",
            name="GCP Safe Browsing API Integration",
            description="Detect malicious URLs accessed by users via Safe Browsing API.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="safe_browsing",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
jsonPayload.safeBrowsingThreat!=""
severity="WARNING"''',
                gcp_terraform_template="""# GCP: Detect malicious URLs via Safe Browsing API

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Safe Browsing Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for Safe Browsing threats
resource "google_logging_metric" "safe_browsing_threats" {
  project = var.project_id
  name   = "safe-browsing-threats"
  filter = <<-EOT
    resource.type="cloud_function"
    jsonPayload.safeBrowsingThreat!=""
    severity>="WARNING"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "threat_type"
      value_type  = "STRING"
      description = "Type of threat detected"
    }
  }

  label_extractors = {
    "threat_type" = "EXTRACT(jsonPayload.safeBrowsingThreat)"
  }
}

# Step 3: Create alert for malicious URL detection
resource "google_monitoring_alert_policy" "safe_browsing_alert" {
  project      = var.project_id
  display_name = "Malicious URL Detected"
  combiner     = "OR"

  conditions {
    display_name = "Safe Browsing threat detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.safe_browsing_threats.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

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
    content   = "Malicious URL accessed by user. Safe Browsing API detected threat. Investigate immediately for potential compromise."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Malicious URL Accessed",
                alert_description_template="Safe Browsing detected threat type: {threat_type}.",
                investigation_steps=[
                    "Identify user who accessed malicious URL",
                    "Review user's recent browsing activity",
                    "Check for downloaded files or executables",
                    "Examine system logs for suspicious processes",
                    "Review authentication logs for compromise",
                ],
                containment_actions=[
                    "Block malicious URL at organisational level",
                    "Quarantine affected user system",
                    "Reset user credentials",
                    "Scan for malware/backdoors",
                    "Enhance security awareness training",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Safe Browsing API is highly accurate; false positives rare",
            detection_coverage="70% - catches known malicious URLs",
            evasion_considerations="New/unknown malicious sites may not be in database",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=[
                "Safe Browsing API enabled",
                "Cloud Functions for URL scanning",
            ],
        ),
    ],
    recommended_order=[
        "t1204-001-aws-guardduty",
        "t1204-001-gcp-safebrowsing",
        "t1204-001-aws-proxy",
        "t1204-001-gcp-chronicle",
        "t1204-001-aws-cloudtrail",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+25% improvement for Execution tactic",
)
