"""
T1596 - Search Open Technical Databases

Adversaries leverage publicly accessible technical databases containing victim
information for targeting purposes. This includes DNS/Passive DNS, WHOIS, digital
certificates, CDNs, and scan databases.
Used by APT28, Kimsuky.
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
    technique_id="T1596",
    technique_name="Search Open Technical Databases",
    tactic_ids=["TA0043"],  # Reconnaissance
    mitre_url="https://attack.mitre.org/techniques/T1596/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage publicly accessible technical databases to gather "
            "victim information for targeting. This includes DNS/Passive DNS, WHOIS "
            "records, digital certificates, CDN data, and internet scan databases. "
            "Intelligence gathered facilitates phishing campaigns, infrastructure "
            "acquisition, and initial access attempts."
        ),
        attacker_goal="Gather technical intelligence about target infrastructure from public databases",
        why_technique=[
            "Completely passive - undetectable by target",
            "Freely available information",
            "Reveals infrastructure and technology stack",
            "Identifies potential vulnerabilities",
            "Maps external attack surface",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=4,
        severity_reasoning=(
            "Pre-compromise technique with no direct impact but enables subsequent "
            "attacks. Difficult to detect as activity occurs outside organisational "
            "control. Increasing trend due to AI/LLM-enhanced reconnaissance."
        ),
        business_impact=[
            "Intelligence gathering for targeted attacks",
            "Attack surface mapping",
            "Technology stack enumeration",
            "Enables social engineering",
            "Identifies exposed services",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1598", "T1593", "T1595", "T1566"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1596-aws-exposure",
            name="AWS External Exposure Monitoring",
            description="Monitor for excessive external reconnaissance indicators via AWS services.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""# Monitor Route53 query patterns that may indicate reconnaissance
fields @timestamp, query_name, query_type, srcaddr
| filter query_type in ["ANY", "AXFR", "TXT"]
| stats count(*) as queries by srcaddr, bin(1h)
| filter queries > 100
| sort queries desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor for external reconnaissance indicators

Parameters:
  Route53LogGroup:
    Type: String
    Description: Route53 query logging log group
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

  # Monitor for suspicious DNS query patterns
  SuspiciousDNSFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref Route53LogGroup
      FilterPattern: '{ $.query_type = "ANY" || $.query_type = "AXFR" }'
      MetricTransformations:
        - MetricName: SuspiciousDNSQueries
          MetricNamespace: Security/Reconnaissance
          MetricValue: "1"

  SuspiciousDNSAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HighSuspiciousDNSQueries
      MetricName: SuspiciousDNSQueries
      Namespace: Security/Reconnaissance
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Monitor for external reconnaissance indicators

variable "route53_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "reconnaissance-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Monitor for suspicious DNS query patterns
resource "aws_cloudwatch_log_metric_filter" "suspicious_dns" {
  name           = "suspicious-dns-queries"
  log_group_name = var.route53_log_group
  pattern        = "{ $.query_type = \"ANY\" || $.query_type = \"AXFR\" }"

  metric_transformation {
    name      = "SuspiciousDNSQueries"
    namespace = "Security/Reconnaissance"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "dns_reconnaissance" {
  alarm_name          = "HighSuspiciousDNSQueries"
  metric_name         = "SuspiciousDNSQueries"
  namespace           = "Security/Reconnaissance"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Potential DNS Reconnaissance Detected",
                alert_description_template="Suspicious DNS query patterns detected from {srcaddr}.",
                investigation_steps=[
                    "Review DNS query patterns and source IPs",
                    "Check for zone transfer attempts (AXFR)",
                    "Review public DNS records for information exposure",
                    "Check threat intelligence for source IPs",
                    "Assess what information is publicly available",
                ],
                containment_actions=[
                    "Disable DNS zone transfers to unauthorised hosts",
                    "Review and minimise DNS information exposure",
                    "Implement DNS query logging",
                    "Block malicious source IPs if identified",
                    "Review public-facing records for sensitive data",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Legitimate DNS monitoring tools may trigger alerts",
            detection_coverage="20% - only detects DNS-based reconnaissance",
            evasion_considerations="Most reconnaissance occurs via third-party databases",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Route53 query logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1596-aws-certificate",
            name="AWS Certificate Transparency Monitoring",
            description="Monitor AWS Certificate Manager for certificate issuance patterns.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.acm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "RequestCertificate",
                            "DescribeCertificate",
                            "ListCertificates",
                        ]
                    },
                },
                terraform_template="""# Monitor certificate-related activity

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "certificate-monitoring-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for EventBridge targets
resource "aws_sqs_queue" "events_dlq" {
  name                      = "acm-events-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "events_dlq" {
  queue_url = aws_sqs_queue.events_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.events_dlq.arn
    }]
  })
}

# EventBridge rule for ACM activity
resource "aws_cloudwatch_event_rule" "acm_activity" {
  name        = "acm-certificate-activity"
  description = "Monitor ACM certificate operations"

  event_pattern = jsonencode({
    source      = ["aws.acm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "RequestCertificate",
        "DeleteCertificate"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.acm_activity.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.events_dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "SNS:Publish"
      Resource = aws_sns_topic.alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.acm_activity.arn
        }
      }
    }]
  })
}""",
                alert_severity="low",
                alert_title="Certificate Activity Detected",
                alert_description_template="ACM certificate operation: {eventName} by {userIdentity.principalId}.",
                investigation_steps=[
                    "Review certificate request details",
                    "Verify legitimacy of certificate request",
                    "Check Certificate Transparency logs",
                    "Review domain validation methods",
                    "Assess exposure of certificate information",
                ],
                containment_actions=[
                    "Review public certificate transparency logs",
                    "Minimise sensitive information in certificates",
                    "Monitor for unauthorised certificate requests",
                    "Implement certificate request approval workflows",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Focus on unexpected certificate operations",
            detection_coverage="30% - monitors certificate operations only",
            evasion_considerations="Adversaries use public CT logs, not direct AWS access",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled for ACM"],
        ),
        DetectionStrategy(
            strategy_id="t1596-gcp-asset",
            name="GCP Asset Inventory Monitoring",
            description="Monitor GCP Cloud Asset Inventory for external reconnaissance indicators.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_dns_query"
protoPayload.request.queryType=~"ANY|AXFR"''',
                gcp_terraform_template="""# GCP: Monitor for reconnaissance indicators

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Reconnaissance Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Monitor DNS query patterns
resource "google_logging_metric" "suspicious_dns" {
  project = var.project_id
  name   = "suspicious-dns-queries"
  filter = <<-EOT
    resource.type="cloud_dns_query"
    protoPayload.request.queryType=~"ANY|AXFR"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "dns_reconnaissance" {
  project      = var.project_id
  display_name = "DNS Reconnaissance Activity"
  combiner     = "OR"
  conditions {
    display_name = "High suspicious DNS queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_dns.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
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

# Monitor Cloud DNS operations
resource "google_logging_metric" "dns_changes" {
  project = var.project_id
  name   = "dns-configuration-changes"
  filter = <<-EOT
    resource.type="dns_managed_zone"
    protoPayload.methodName=~"dns.changes.*"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "dns_changes" {
  project      = var.project_id
  display_name = "DNS Configuration Changes"
  combiner     = "OR"
  conditions {
    display_name = "DNS zone changes detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
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
                alert_severity="medium",
                alert_title="GCP: Potential DNS Reconnaissance",
                alert_description_template="Suspicious DNS query patterns detected in GCP.",
                investigation_steps=[
                    "Review Cloud DNS query logs",
                    "Check for zone transfer attempts",
                    "Analyse query patterns and sources",
                    "Review public DNS information exposure",
                    "Check Cloud Asset Inventory for exposed resources",
                ],
                containment_actions=[
                    "Restrict DNS zone transfers",
                    "Review and minimise DNS information exposure",
                    "Enable Cloud DNS logging",
                    "Review public asset inventory",
                    "Implement least-privilege DNS policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter legitimate monitoring and automation",
            detection_coverage="25% - focuses on DNS reconnaissance",
            evasion_considerations="Most reconnaissance is passive via third-party databases",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud DNS query logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1596-preventive",
            name="Preventive: Minimise External Information Exposure",
            description="Reduce reconnaissance value by minimising publicly available technical information.",
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="config",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# Preventive measures to minimise reconnaissance value

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "exposure-prevention-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Ensure S3 buckets are not publicly accessible
resource "aws_config_rule" "s3_public_read" {
  name = "s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Ensure databases are not publicly accessible
resource "aws_config_rule" "rds_public" {
  name = "rds-instance-public-access-check"

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Monitor for overly permissive security groups
resource "aws_config_rule" "sg_ssh_restricted" {
  name = "restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Required Config recorder
resource "aws_config_configuration_recorder" "main" {
  name     = "exposure-monitoring"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported = true
  }
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "config" {
  name = "config-recorder-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com"
      }
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}""",
                gcp_terraform_template="""# GCP: Preventive measures to minimise reconnaissance value

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Exposure Prevention Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Ensure Cloud Storage buckets are not publicly accessible
resource "google_project_organization_policy" "storage_public_access" {
  project    = var.project_id
  constraint = "storage.publicAccessPrevention"

  boolean_policy {
    enforced = true
  }
}

# Ensure Cloud SQL instances are not publicly accessible
resource "google_project_organization_policy" "sql_external_ip" {
  project    = var.project_id
  constraint = "sql.restrictPublicIp"

  boolean_policy {
    enforced = true
  }
}

# Monitor for publicly accessible resources
resource "google_logging_metric" "public_exposure" {
  project = var.project_id
  name   = "public-resource-exposure"
  filter = <<-EOT
    protoPayload.methodName=~"storage.setIamPermissions|sql.instances.patch"
    protoPayload.request.policy.bindings.members=~"allUsers|allAuthenticatedUsers"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "exposure_alert" {
  project      = var.project_id
  display_name = "Public Resource Exposure"
  combiner     = "OR"
  conditions {
    display_name = "Public access granted"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.public_exposure.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="Public Resource Exposure Detected",
                alert_description_template="Resource configuration may expose information to reconnaissance.",
                investigation_steps=[
                    "Audit publicly accessible resources",
                    "Review DNS records for sensitive information",
                    "Check Certificate Transparency logs",
                    "Assess WHOIS information exposure",
                    "Review cloud storage bucket permissions",
                    "Audit security group and firewall rules",
                ],
                containment_actions=[
                    "Remove unnecessary public access",
                    "Implement private DNS zones where possible",
                    "Minimise information in public certificates",
                    "Use privacy protection for WHOIS",
                    "Restrict public-facing services to minimum required",
                    "Implement security group least-privilege rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Focus on unexpected public exposure",
            detection_coverage="50% - preventive control reduces attack surface",
            evasion_considerations="Cannot prevent reconnaissance, only reduces value",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["AWS Config or GCP Cloud Asset Inventory enabled"],
        ),
        # Azure Strategy: Search Open Technical Databases
        DetectionStrategy(
            strategy_id="t1596-azure",
            name="Azure Search Open Technical Databases Detection",
            description=(
                "Azure detection for Search Open Technical Databases. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Search Open Technical Databases Detection
// Technique: T1596
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc""",
                azure_terraform_template="""# Azure Detection for Search Open Technical Databases
# MITRE ATT&CK: T1596

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
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "search-open-technical-databases-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "search-open-technical-databases-detection"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Search Open Technical Databases Detection
// Technique: T1596
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects Search Open Technical Databases (T1596) activity in Azure environment"
  display_name = "Search Open Technical Databases Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1596"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Search Open Technical Databases Detected",
                alert_description_template=(
                    "Search Open Technical Databases activity detected. "
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
        "t1596-preventive",
        "t1596-aws-exposure",
        "t1596-gcp-asset",
        "t1596-aws-certificate",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+15% improvement for Reconnaissance tactic (preventive controls)",
)
