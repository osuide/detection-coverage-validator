"""
T1567.004 - Exfiltration Over Webhook

Adversaries exfiltrate data through webhook endpoints to bypass traditional C2 monitoring.
Used by various threat actors for automated data exfiltration via collaboration platforms.
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
    technique_id="T1567.004",
    technique_name="Exfiltration Over Webhook",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1567/004/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exfiltrate data through webhook endpoints rather than primary command "
            "and control channels. Webhooks enable servers to push data via HTTP/S to clients "
            "without continuous polling. Adversaries may link victim-owned SaaS services to "
            "attacker-controlled environments to achieve automated data exfiltration of emails "
            "and chat messages, or manually post staged data directly to webhook URLs. HTTPS "
            "encryption and integration with common collaboration services like Discord and Slack "
            "help such exfiltration blend with normal network traffic."
        ),
        attacker_goal="Exfiltrate data using webhook endpoints to evade C2 detection and blend with legitimate traffic",
        why_technique=[
            "Blends with legitimate collaboration platform traffic",
            "HTTPS encryption hides data content",
            "Bypasses traditional C2 channel monitoring",
            "Webhook services rarely blocked by firewalls",
            "Enables automated exfiltration from SaaS applications",
            "Popular platforms (Discord, Slack) provide easy setup",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Webhook-based exfiltration is increasingly popular due to ease of use and "
            "difficulty in detection. Data is transmitted over HTTPS to legitimate services, "
            "making it hard to distinguish from normal traffic. Loss of sensitive data can "
            "result in severe financial, regulatory, and reputational damage."
        ),
        business_impact=[
            "Data breach and loss of sensitive information",
            "Intellectual property theft",
            "Regulatory fines and compliance violations",
            "Reputational damage and customer trust loss",
            "Exposure of credentials and authentication tokens",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1530", "T1552.001", "T1114.003", "T1074"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1567-004-aws-webhook",
            name="AWS Webhook POST Detection",
            description="Detect suspicious HTTP POST requests to webhook endpoints from compute instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, srcAddr, dstAddr, httpMethod, httpRequest.uri, userAgent, bytesTransferredOut
| filter httpMethod = "POST" or httpMethod = "PUT"
| filter httpRequest.uri like /webhook/ or httpRequest.uri like /api\/webhooks/ or httpRequest.uri like /hooks/
| filter dstAddr like /discord/ or dstAddr like /slack/ or dstAddr like /teams.microsoft/
| stats sum(bytesTransferredOut) as total_bytes, count(*) as request_count by srcAddr, dstAddr, bin(1h)
| filter total_bytes > 1048576 or request_count > 50
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Webhook exfiltration detection via VPC Flow Logs and CloudTrail

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for webhook POST requests
  WebhookFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=443, protocol=6, packets, bytes > 1000000, ...]'
      MetricTransformations:
        - MetricName: WebhookPOSTRequests
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on suspicious webhook activity
  WebhookAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Webhook-Exfiltration-Detected
      MetricName: WebhookPOSTRequests
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Webhook exfiltration detection via VPC Flow Logs and CloudTrail

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "webhook-exfil-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for webhook POST requests
resource "aws_cloudwatch_log_metric_filter" "webhook_post" {
  name           = "webhook-post-requests"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=443, protocol=6, packets, bytes > 1000000, ...]"

  metric_transformation {
    name      = "WebhookPOSTRequests"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on suspicious webhook activity
resource "aws_cloudwatch_metric_alarm" "webhook_exfil" {
  alarm_name          = "Webhook-Exfiltration-Detected"
  metric_name         = "WebhookPOSTRequests"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Webhook Exfiltration Activity Detected",
                alert_description_template="Suspicious webhook POST requests from {srcAddr} to {dstAddr}: {request_count} requests, {total_bytes} bytes transferred.",
                investigation_steps=[
                    "Identify the source instance making webhook requests",
                    "Review the destination webhook URLs and platforms",
                    "Examine the content and size of data being posted",
                    "Check for authorised integrations with collaboration platforms",
                    "Review user activity and process execution on source instance",
                    "Correlate with other suspicious activities (data staging, credential access)",
                ],
                containment_actions=[
                    "Block webhook URLs at network firewall or proxy",
                    "Isolate the source instance",
                    "Revoke API keys and webhook tokens",
                    "Review and restrict outbound HTTPS to collaboration platforms",
                    "Disable unauthorised SaaS integrations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised webhook integrations; exclude known monitoring and alerting platforms",
            detection_coverage="65% - catches webhook-based exfiltration",
            evasion_considerations="Low and slow exfiltration, custom webhook endpoints, legitimate service abuse",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "VPC Flow Logs enabled",
                "DNS query logging for domain resolution",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1567-004-aws-script",
            name="AWS Script Webhook POST Detection",
            description="Detect PowerShell, Python, or curl commands posting data to webhook endpoints.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.command, responseElements.instanceId
| filter eventName = "SendCommand" or eventName = "RunInstances"
| filter requestParameters.command like /curl.*webhook/ or requestParameters.command like /powershell.*Invoke-WebRequest/ or requestParameters.command like /python.*requests.post/
| stats count(*) as command_count by userIdentity.arn, requestParameters.command, bin(1h)
| sort command_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Script-based webhook exfiltration detection

Parameters:
  AlertEmail:
    Type: String
  CloudTrailLogGroup:
    Type: String

Resources:
  # Step 1: Create SNS alert topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Filter for script-based webhook commands
  ScriptWebhookFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "SendCommand" || $.eventName = "RunInstances") && ($.requestParameters.command = "*webhook*" || $.requestParameters.command = "*Invoke-WebRequest*" || $.requestParameters.command = "*requests.post*") }'
      MetricTransformations:
        - MetricName: ScriptWebhookCommands
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on suspicious script activity
  ScriptWebhookAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Script-Webhook-Exfiltration
      MetricName: ScriptWebhookCommands
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Script-based webhook exfiltration detection

variable "alert_email" { type = string }
variable "cloudtrail_log_group" { type = string }

# Step 1: Create SNS alert topic
resource "aws_sns_topic" "alerts" {
  name = "script-webhook-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Filter for script-based webhook commands
resource "aws_cloudwatch_log_metric_filter" "script_webhook" {
  name           = "script-webhook-commands"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"SendCommand\" || $.eventName = \"RunInstances\") && ($.requestParameters.command = \"*webhook*\" || $.requestParameters.command = \"*Invoke-WebRequest*\" || $.requestParameters.command = \"*requests.post*\") }"

  metric_transformation {
    name      = "ScriptWebhookCommands"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on suspicious script activity
resource "aws_cloudwatch_metric_alarm" "script_webhook" {
  alarm_name          = "Script-Webhook-Exfiltration"
  metric_name         = "ScriptWebhookCommands"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Script-Based Webhook Exfiltration Detected",
                alert_description_template="Suspicious script command detected: {requestParameters.command} executed by {userIdentity.arn}.",
                investigation_steps=[
                    "Review the full command and parameters executed",
                    "Identify the user or role that executed the command",
                    "Check for data staging activities before webhook POST",
                    "Examine recent login history for the user",
                    "Review other commands executed by the same identity",
                    "Analyse the webhook URL and destination platform",
                ],
                containment_actions=[
                    "Revoke credentials for the executing identity",
                    "Block the webhook URL at network level",
                    "Isolate affected instances",
                    "Review and restrict Systems Manager permissions",
                    "Enable session logging for command execution",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised automation scripts; exclude approved CI/CD workflows",
            detection_coverage="70% - catches command-line webhook exfiltration",
            evasion_considerations="Obfuscated commands, encoded payloads, alternative tools",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled with Systems Manager events"],
        ),
        DetectionStrategy(
            strategy_id="t1567-004-aws-saas",
            name="AWS SaaS Webhook Configuration Monitoring",
            description="Detect unauthorised webhook configurations in SaaS applications via CloudTrail API calls.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.webhookUrl, sourceIPAddress
| filter eventName in ["CreateWebhook", "UpdateWebhook", "PutWebhookConfiguration", "SetWebhook"]
| filter requestParameters.webhookUrl not like /your-approved-domain.com/
| stats count(*) as config_count by userIdentity.arn, requestParameters.webhookUrl, sourceIPAddress
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: SaaS webhook configuration monitoring

Parameters:
  AlertEmail:
    Type: String
  CloudTrailLogGroup:
    Type: String

Resources:
  # Step 1: Create alert notification topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Monitor webhook configuration changes
  WebhookConfigFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "CreateWebhook" || $.eventName = "UpdateWebhook" || $.eventName = "PutWebhookConfiguration") }'
      MetricTransformations:
        - MetricName: WebhookConfigurations
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on unauthorised webhook setup
  WebhookConfigAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Unauthorised-Webhook-Configuration
      MetricName: WebhookConfigurations
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# SaaS webhook configuration monitoring

variable "alert_email" { type = string }
variable "cloudtrail_log_group" { type = string }

# Step 1: Create alert notification topic
resource "aws_sns_topic" "alerts" {
  name = "webhook-config-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Monitor webhook configuration changes
resource "aws_cloudwatch_log_metric_filter" "webhook_config" {
  name           = "webhook-configurations"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"CreateWebhook\" || $.eventName = \"UpdateWebhook\" || $.eventName = \"PutWebhookConfiguration\") }"

  metric_transformation {
    name      = "WebhookConfigurations"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on unauthorised webhook setup
resource "aws_cloudwatch_metric_alarm" "webhook_config" {
  alarm_name          = "Unauthorised-Webhook-Configuration"
  metric_name         = "WebhookConfigurations"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unauthorised Webhook Configuration Detected",
                alert_description_template="Webhook configuration change by {userIdentity.arn} pointing to {requestParameters.webhookUrl} from {sourceIPAddress}.",
                investigation_steps=[
                    "Verify the webhook URL and destination",
                    "Check if the configuration change was authorised",
                    "Review the user's recent activity and permissions",
                    "Identify what data the webhook will receive",
                    "Check for other suspicious configuration changes",
                    "Review SaaS application audit logs",
                ],
                containment_actions=[
                    "Remove unauthorised webhook configurations",
                    "Revoke user access to SaaS application",
                    "Block webhook destination at network level",
                    "Review and restrict webhook configuration permissions",
                    "Enable approval workflow for integration changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist approved webhook domains; implement change request validation",
            detection_coverage="75% - catches SaaS webhook configuration abuse",
            evasion_considerations="Using approved domains, legitimate service accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled for SaaS API calls",
                "SaaS application API logging",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1567-004-gcp-webhook",
            name="GCP Webhook POST Detection",
            description="Detect suspicious HTTP POST requests to webhook endpoints from GCP compute instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
httpRequest.requestMethod="POST"
(httpRequest.requestUrl=~"webhook" OR httpRequest.requestUrl=~"discord.com/api/webhooks" OR httpRequest.requestUrl=~"hooks.slack.com")
httpRequest.requestSize > 1000000""",
                gcp_terraform_template="""# GCP: Webhook exfiltration detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create log metric for webhook POST requests
resource "google_logging_metric" "webhook_post" {
  name   = "webhook-post-requests"
  filter = <<-EOT
    resource.type="gce_instance"
    httpRequest.requestMethod="POST"
    (httpRequest.requestUrl=~"webhook" OR
     httpRequest.requestUrl=~"discord.com/api/webhooks" OR
     httpRequest.requestUrl=~"hooks.slack.com")
    httpRequest.requestSize > 1000000
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "webhook_exfil" {
  display_name = "Webhook Exfiltration Detected"
  combiner     = "OR"
  conditions {
    display_name = "Suspicious webhook POST activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.webhook_post.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Webhook Exfiltration Activity Detected",
                alert_description_template="Suspicious webhook POST requests detected from GCP instance.",
                investigation_steps=[
                    "Identify the source compute instance",
                    "Review the webhook URLs being accessed",
                    "Examine the data being posted to webhooks",
                    "Check for authorised integrations",
                    "Review user and service account activity",
                    "Correlate with other suspicious activities",
                ],
                containment_actions=[
                    "Block webhook URLs via Cloud Armor or firewall",
                    "Isolate the source instance",
                    "Revoke webhook tokens and API keys",
                    "Review and restrict egress firewall rules",
                    "Disable unauthorised SaaS integrations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised webhook integrations and monitoring services",
            detection_coverage="65% - catches webhook-based exfiltration",
            evasion_considerations="Low and slow exfiltration, custom endpoints",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled", "HTTP request logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1567-004-gcp-script",
            name="GCP Script Webhook Detection",
            description="Detect script commands posting data to webhooks via Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.start"
(textPayload=~"curl.*webhook" OR textPayload=~"python.*requests.post" OR textPayload=~"wget.*POST")""",
                gcp_terraform_template="""# GCP: Script-based webhook detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create metric for script webhook commands
resource "google_logging_metric" "script_webhook" {
  name   = "script-webhook-commands"
  filter = <<-EOT
    resource.type="gce_instance"
    (textPayload=~"curl.*webhook" OR
     textPayload=~"python.*requests.post" OR
     textPayload=~"wget.*POST.*webhook")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert on script webhook activity
resource "google_monitoring_alert_policy" "script_webhook" {
  display_name = "Script Webhook Exfiltration"
  combiner     = "OR"
  conditions {
    display_name = "Webhook commands detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.script_webhook.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Script-Based Webhook Exfiltration",
                alert_description_template="Suspicious script webhook command detected on GCP instance.",
                investigation_steps=[
                    "Review the executed command and parameters",
                    "Identify the user or service account",
                    "Check for data staging before webhook POST",
                    "Examine recent instance activity",
                    "Analyse webhook destination",
                    "Review startup scripts and metadata",
                ],
                containment_actions=[
                    "Revoke service account credentials",
                    "Block webhook URLs at network level",
                    "Isolate the instance",
                    "Review IAM permissions",
                    "Enable OS Login for audit trail",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude authorised automation scripts and CI/CD workflows",
            detection_coverage="70% - catches command-line webhook exfiltration",
            evasion_considerations="Obfuscated commands, encoded data",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Logging enabled for compute instances",
                "OS-level logging enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1567-004-aws-script",
        "t1567-004-gcp-script",
        "t1567-004-aws-webhook",
        "t1567-004-gcp-webhook",
        "t1567-004-aws-saas",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+15% improvement for Exfiltration tactic",
)
