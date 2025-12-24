"""
T1584 - Compromise Infrastructure

Adversaries compromise third-party infrastructure to support operations rather than
purchasing or leasing their own. Infrastructure includes physical or cloud servers,
domains, network devices, and third-party web services.
Used by APT28, Chinese state-sponsored groups.
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
    technique_id="T1584",
    technique_name="Compromise Infrastructure",
    tactic_ids=["TA0042"],
    mitre_url="https://attack.mitre.org/techniques/T1584/",
    threat_context=ThreatContext(
        description=(
            "Adversaries compromise third-party infrastructure including physical or cloud servers, "
            "domains, network devices, DNS services, and web services. This enables staging, launching, "
            "and executing operations whilst blending malicious activity with legitimate traffic patterns. "
            "Compromised infrastructure supports phishing, command-and-control, proxying, and botnet operations."
        ),
        attacker_goal="Establish operational infrastructure through compromise rather than direct acquisition",
        why_technique=[
            "Blend malicious activity with legitimate traffic",
            "Avoid attribution through third-party resources",
            "Establish C2 channels appearing legitimate",
            "Support phishing using trusted domains",
            "Enable proximity-based attacks via compromised networks",
            "Lower operational costs versus purchasing infrastructure",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Nearest Neighbor",
                year=2023,
                description="APT28 compromised third-party infrastructure in physical proximity to targets for follow-on activities",
                reference_url="https://attack.mitre.org/campaigns/C0051/",
            ),
            Campaign(
                name="Indian Critical Infrastructure",
                year=2023,
                description="Chinese state-sponsored actors utilised compromised DVR and IP camera devices for ShadowPad C2 against Indian power grid",
                reference_url="https://attack.mitre.org/campaigns/C0043/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Pre-compromise technique enabling multiple attack vectors. Difficult to prevent as "
            "it occurs outside enterprise defences. Compromised infrastructure enables attribution "
            "evasion and trusted infrastructure abuse."
        ),
        business_impact=[
            "Enables subsequent attack stages",
            "Attribution evasion complicates incident response",
            "Legitimate infrastructure abuse damages reputation",
            "Difficult to detect pre-attack preparation",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1566", "T1071", "T1090", "T1583"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1584-aws-unusual-services",
            name="AWS Unusual Service Detection",
            description="Detect compromised AWS resources being used for unexpected services or C2 activity.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, eventName, sourceIPAddress, requestParameters
| filter eventName like /RunInstances|CreateFunction|CreateCluster/
| filter userAgent like /boto|python-requests|curl|wget/
| stats count(*) as api_calls by sourceIPAddress, userIdentity.principalId, bin(1h)
| filter api_calls > 50
| sort api_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect compromised AWS resources launching unusual services

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  UnusualServiceFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "RunInstances" || $.eventName = "CreateFunction" || $.eventName = "CreateCluster") && ($.userAgent = "*boto*" || $.userAgent = "*curl*" || $.userAgent = "*wget*") }'
      MetricTransformations:
        - MetricName: UnusualServiceLaunches
          MetricNamespace: Security
          MetricValue: "1"

  UnusualServiceAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CompromisedResourceActivity
      MetricName: UnusualServiceLaunches
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect compromised AWS resources launching unusual services

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "compromised-resource-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "unusual_services" {
  name           = "unusual-service-launches"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"RunInstances\" || $.eventName = \"CreateFunction\" || $.eventName = \"CreateCluster\") && ($.userAgent = \"*boto*\" || $.userAgent = \"*curl*\" || $.userAgent = \"*wget*\") }"

  metric_transformation {
    name      = "UnusualServiceLaunches"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "compromised_resource" {
  alarm_name          = "CompromisedResourceActivity"
  metric_name         = "UnusualServiceLaunches"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Compromised AWS Resource Detected",
                alert_description_template="Unusual service launches detected from {principalId} at {sourceIPAddress}.",
                investigation_steps=[
                    "Review the principal ID and associated IAM credentials",
                    "Check if API calls originate from expected IP addresses",
                    "Examine launched resources for C2 indicators",
                    "Review CloudTrail for privilege escalation events",
                    "Check for data exfiltration attempts",
                ],
                containment_actions=[
                    "Disable compromised IAM credentials immediately",
                    "Terminate suspicious EC2 instances or Lambda functions",
                    "Review and restrict security group rules",
                    "Enable VPC Flow Logs for network analysis",
                    "Rotate all potentially exposed credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune user agents and API call thresholds for legitimate automation tools",
            detection_coverage="50% - catches automated resource abuse",
            evasion_considerations="Adversaries using legitimate AWS tools may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["CloudTrail enabled", "CloudTrail logs sent to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1584-aws-dns-tunnelling",
            name="AWS DNS Tunnelling Detection",
            description="Detect compromised infrastructure using DNS for C2 communications via Route 53 query logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, query_name, query_type, srcaddr
| filter query_type = "TXT" or query_name like /[a-f0-9]{32,}/
| stats count(*) as dns_queries by srcaddr, bin(5m)
| filter dns_queries > 100
| sort dns_queries desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect DNS tunnelling via compromised infrastructure

Parameters:
  Route53QueryLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  DNSTunnelFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref Route53QueryLogGroup
      FilterPattern: '{ $.query_type = "TXT" }'
      MetricTransformations:
        - MetricName: SuspiciousDNSQueries
          MetricNamespace: Security
          MetricValue: "1"

  DNSTunnelAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: DNSTunnellingDetected
      MetricName: SuspiciousDNSQueries
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect DNS tunnelling via compromised infrastructure

variable "route53_query_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "dns-tunnel-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "dns_tunnel" {
  name           = "dns-tunnelling"
  log_group_name = var.route53_query_log_group
  pattern        = "{ $.query_type = \"TXT\" }"

  metric_transformation {
    name      = "SuspiciousDNSQueries"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "dns_tunnel_detected" {
  alarm_name          = "DNSTunnellingDetected"
  metric_name         = "SuspiciousDNSQueries"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="DNS Tunnelling Detected",
                alert_description_template="Suspicious DNS query pattern from {srcaddr} indicates potential C2 channel.",
                investigation_steps=[
                    "Analyse DNS query patterns for encoding schemes",
                    "Identify source IP addresses and associated resources",
                    "Review Route 53 hosted zones for unauthorised changes",
                    "Check for data exfiltration in query payloads",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Block suspicious domains at DNS resolver level",
                    "Isolate affected instances from network",
                    "Review and revoke compromised credentials",
                    "Implement DNS query rate limiting",
                    "Enable GuardDuty for additional DNS monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude legitimate TXT record queries from monitoring tools",
            detection_coverage="60% - catches DNS-based C2",
            evasion_considerations="Low-and-slow techniques may evade rate-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-35",
            prerequisites=["Route 53 Resolver Query Logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1584-gcp-compromised-compute",
            name="GCP Compromised Compute Instance Detection",
            description="Detect GCP compute instances exhibiting suspicious C2 or proxy behaviour.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName=~"compute.instances.(insert|start)"
protoPayload.request.machineType=~"n1-standard|e2-medium"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect compromised compute instances

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "suspicious_instance_creation" {
  name   = "suspicious-instance-creation"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~"compute.instances.(insert|start)"
    protoPayload.request.machineType=~"n1-standard|e2-medium"
    severity="NOTICE"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "compromised_instance" {
  display_name = "Compromised GCP Instance Activity"
  combiner     = "OR"
  conditions {
    display_name = "Unusual instance creation rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_instance_creation.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Compromised Instance Detected",
                alert_description_template="Suspicious compute instance activity detected in project.",
                investigation_steps=[
                    "Review instance creation audit logs",
                    "Check service account permissions",
                    "Analyse VPC Flow Logs for C2 traffic",
                    "Examine instance metadata for indicators",
                    "Review IAM policy changes",
                ],
                containment_actions=[
                    "Stop suspicious instances immediately",
                    "Revoke compromised service account keys",
                    "Update firewall rules to block C2 traffic",
                    "Enable VPC Service Controls",
                    "Review and restrict IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised automation service accounts",
            detection_coverage="55% - catches automated instance abuse",
            evasion_considerations="Adversaries using authorised service accounts may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled", "VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1584-gcp-dns-monitoring",
            name="GCP Cloud DNS Suspicious Query Detection",
            description="Detect compromised infrastructure using Cloud DNS for C2 via DNS query monitoring.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="dns_query"
jsonPayload.queryType="TXT"
jsonPayload.responseCode="NOERROR"''',
                gcp_terraform_template="""# GCP: Detect DNS-based C2 via Cloud DNS

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "dns_tunnel" {
  name   = "dns-tunnelling-attempts"
  filter = <<-EOT
    resource.type="dns_query"
    jsonPayload.queryType="TXT"
    jsonPayload.responseCode="NOERROR"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "dns_c2" {
  display_name = "DNS Tunnelling Detected"
  combiner     = "OR"
  conditions {
    display_name = "High TXT query rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_tunnel.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="critical",
                alert_title="GCP: DNS Tunnelling Detected",
                alert_description_template="Suspicious DNS query patterns indicate potential C2 communication.",
                investigation_steps=[
                    "Analyse DNS query logs for patterns",
                    "Identify source VMs or services",
                    "Review Cloud DNS zone configurations",
                    "Check for unauthorised DNS zone changes",
                    "Correlate with network flow data",
                ],
                containment_actions=[
                    "Block suspicious domains via Cloud DNS policies",
                    "Isolate affected instances",
                    "Review and rotate service account keys",
                    "Enable Cloud IDS for deeper inspection",
                    "Implement DNS Security Extensions (DNSSEC)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Baseline legitimate TXT queries from monitoring systems",
            detection_coverage="65% - catches DNS C2 channels",
            evasion_considerations="Low-frequency queries may evade rate thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["Cloud DNS query logging enabled"],
        ),
    ],
    recommended_order=[
        "t1584-aws-unusual-services",
        "t1584-gcp-compromised-compute",
        "t1584-aws-dns-tunnelling",
        "t1584-gcp-dns-monitoring",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+15% improvement for Resource Development tactic",
)
