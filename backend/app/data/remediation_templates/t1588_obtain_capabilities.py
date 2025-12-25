"""
T1588 - Obtain Capabilities

Adversaries acquire capabilities (malware, tools, exploits, certificates) for use
during targeting operations rather than developing them internally.
Used by APT28, APT29, APT41, Lazarus Group, Scattered Spider, LAPSUS$.
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
    technique_id="T1588",
    technique_name="Obtain Capabilities",
    tactic_ids=["TA0042"],
    mitre_url="https://attack.mitre.org/techniques/T1588/",
    threat_context=ThreatContext(
        description=(
            "Adversaries acquire capabilities including malware, tools, exploits, "
            "code-signing certificates, and vulnerability information through purchase, "
            "theft, or free download rather than developing them internally. This includes "
            "obtaining commercial tools like Cobalt Strike, open-source tools like Mimikatz, "
            "and leaked exploits like EternalBlue."
        ),
        attacker_goal="Obtain ready-made capabilities to support targeting and post-compromise operations",
        why_technique=[
            "Faster than developing capabilities in-house",
            "Access to sophisticated tools and exploits",
            "Obfuscates attribution by using shared tools",
            "Cost-effective for commodity malware",
            "Legitimate tools evade detection better",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Pre-compromise technique occurring outside enterprise visibility. "
            "Detection focuses on post-acquisition usage rather than acquisition itself. "
            "Use of shared tools complicates attribution but enables defenders to "
            "develop signatures for common capabilities."
        ),
        business_impact=[
            "Enables subsequent attack phases",
            "Complicates threat attribution",
            "Legitimate tool abuse evades defences",
            "Code-signing certificate theft enables trust exploitation",
        ],
        typical_attack_phase="resource_development",
        often_precedes=["T1204", "T1059", "T1003", "T1218", "T1055"],
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1588-aws-cobalt-strike",
            name="AWS Cobalt Strike Detection",
            description="Detect Cobalt Strike beaconing and C2 communication patterns.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, protocol, bytes
| filter (dstport = 443 or dstport = 80 or dstport = 8080)
| stats count(*) as conn_count, sum(bytes) as total_bytes by srcaddr, dstaddr, dstport, bin(1m)
| filter conn_count > 50 and total_bytes < 10000
| sort conn_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Cobalt Strike beaconing patterns

Parameters:
  VPCFlowLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for beacon patterns
  BeaconFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      # Regular beaconing to same destination
      FilterPattern: '[version, account, eni, source, destination, srcport, destport="443" || destport="80" || destport="8080", protocol, packets, bytes, windowstart, windowend, action="ACCEPT", flowlogstatus]'
      MetricTransformations:
        - MetricName: BeaconConnections
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Create alarm for high beacon activity
  BeaconAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CobaltStrikeBeaconDetected
      MetricName: BeaconConnections
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 2
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect Cobalt Strike beaconing patterns

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "cobalt-strike-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for beacon patterns
resource "aws_cloudwatch_log_metric_filter" "beacon_pattern" {
  name           = "cobalt-strike-beacon"
  log_group_name = var.vpc_flow_log_group
  # Regular beaconing to same destination
  pattern        = "[version, account, eni, source, destination, srcport, destport=443 || destport=80 || destport=8080, protocol, packets, bytes, windowstart, windowend, action=ACCEPT, flowlogstatus]"

  metric_transformation {
    name      = "BeaconConnections"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Create alarm for high beacon activity
resource "aws_cloudwatch_metric_alarm" "beacon_detected" {
  alarm_name          = "CobaltStrikeBeaconDetected"
  metric_name         = "BeaconConnections"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Cobalt Strike Beacon Detected",
                alert_description_template="Regular beaconing pattern detected from {srcaddr} to {dstaddr}.",
                investigation_steps=[
                    "Examine source instance for Cobalt Strike artefacts",
                    "Check beacon timing patterns and jitter",
                    "Review process execution history",
                    "Analyse memory for beacon configuration",
                    "Check for lateral movement from source",
                ],
                containment_actions=[
                    "Isolate affected instance",
                    "Block C2 destination at security group/NACL",
                    "Capture memory dump for forensics",
                    "Terminate suspicious processes",
                    "Review IAM credentials for compromise",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune beacon timing thresholds for environment",
            detection_coverage="50% - catches regular beacon patterns",
            evasion_considerations="Randomised jitter and sleep times may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1588-aws-suspicious-tools",
            name="AWS Suspicious Tool Execution",
            description="Detect execution of commonly obtained tools like Mimikatz, BloodHound, and AdFind.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters, responseElements
| filter eventName = "RunInstances" or eventName = "SendCommand"
| filter requestParameters.commandLine like /mimikatz|bloodhound|adfind|sharphound|psinject|invoke-mimikatz|powerup|powersploit/i
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect execution of commonly obtained attack tools

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for tool execution
  SuspiciousToolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "SendCommand") && ($.requestParameters.commandLine = "*mimikatz*" || $.requestParameters.commandLine = "*bloodhound*" || $.requestParameters.commandLine = "*adfind*" || $.requestParameters.commandLine = "*sharphound*") }'
      MetricTransformations:
        - MetricName: SuspiciousToolExecution
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Create alarm for tool detection
  ToolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousToolDetected
      MetricName: SuspiciousToolExecution
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect execution of commonly obtained attack tools

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "suspicious-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for tool execution
resource "aws_cloudwatch_log_metric_filter" "suspicious_tools" {
  name           = "suspicious-tool-execution"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"SendCommand\") && ($.requestParameters.commandLine = \"*mimikatz*\" || $.requestParameters.commandLine = \"*bloodhound*\" || $.requestParameters.commandLine = \"*adfind*\" || $.requestParameters.commandLine = \"*sharphound*\") }"

  metric_transformation {
    name      = "SuspiciousToolExecution"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Create alarm for tool detection
resource "aws_cloudwatch_metric_alarm" "tool_detected" {
  alarm_name          = "SuspiciousToolDetected"
  metric_name         = "SuspiciousToolExecution"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Suspicious Attack Tool Executed",
                alert_description_template="Detected execution of attack tool by {arn}.",
                investigation_steps=[
                    "Identify which tool was executed",
                    "Review command-line parameters and arguments",
                    "Check user identity and access keys",
                    "Examine recent access patterns for account",
                    "Review instances for additional indicators",
                ],
                containment_actions=[
                    "Disable compromised IAM credentials",
                    "Isolate affected instances",
                    "Terminate malicious processes",
                    "Review and rotate all credentials",
                    "Check for data exfiltration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate security testing",
            detection_coverage="60% - catches known tool names",
            evasion_considerations="Renamed binaries and obfuscation may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1588-gcp-tool-execution",
            name="GCP Suspicious Tool Execution",
            description="Detect execution of commonly obtained attack tools in GCP environments.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName="compute.instances.start"
OR protoPayload.methodName="compute.instances.insert"
OR protoPayload.serviceName="compute.googleapis.com"
(protoPayload.request.metadata.items.value=~"mimikatz|bloodhound|adfind|sharphound|psinject|invoke-mimikatz"
OR protoPayload.request.metadata.items.value=~"cobalt.strike|metasploit|empire|powersploit")""",
                gcp_terraform_template="""# GCP: Detect execution of commonly obtained attack tools

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Tool Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create log-based metric for suspicious tools
resource "google_logging_metric" "suspicious_tools" {
  name   = "suspicious-attack-tools"
  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName="compute.instances.start"
    OR protoPayload.methodName="compute.instances.insert"
    OR protoPayload.methodName="v1.compute.instances.addAccessConfig")
    (protoPayload.request.metadata.items.value=~"mimikatz|bloodhound|adfind|sharphound|cobalt.strike|metasploit|empire")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for tool detection
resource "google_monitoring_alert_policy" "tool_alerts" {
  display_name = "Suspicious Attack Tool Detected"
  combiner     = "OR"
  conditions {
    display_name = "Tool execution detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_tools.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "604800s"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Suspicious Attack Tool Detected",
                alert_description_template="Attack tool execution detected in GCP environment.",
                investigation_steps=[
                    "Identify specific tool and instance",
                    "Review instance metadata and startup scripts",
                    "Check service account permissions",
                    "Examine VPC flow logs for C2 communication",
                    "Review Cloud Audit logs for API activity",
                ],
                containment_actions=[
                    "Stop affected instance",
                    "Disable service account",
                    "Create firewall rules to block C2",
                    "Review all instances in project",
                    "Rotate service account keys",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised security testing",
            detection_coverage="60% - catches known tool signatures",
            evasion_considerations="Obfuscated tool names may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1588-aws-cert-anomaly",
            name="AWS Certificate Manager Anomalies",
            description="Detect unusual certificate requests that may indicate stolen or fraudulently obtained certificates.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.domainName, errorCode
| filter eventName like /Certificate/
| filter eventName = "RequestCertificate" or eventName = "ImportCertificate"
| sort @timestamp desc""",
                terraform_template="""# Detect unusual certificate operations

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "certificate-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for certificate operations
resource "aws_cloudwatch_log_metric_filter" "cert_ops" {
  name           = "certificate-operations"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"RequestCertificate\") || ($.eventName = \"ImportCertificate\") }"

  metric_transformation {
    name      = "CertificateOperations"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Create alarm for unusual activity
resource "aws_cloudwatch_metric_alarm" "cert_anomaly" {
  alarm_name          = "UnusualCertificateActivity"
  metric_name         = "CertificateOperations"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Unusual Certificate Activity Detected",
                alert_description_template="High volume of certificate operations by {arn}.",
                investigation_steps=[
                    "Review certificate domain names",
                    "Check user identity and access patterns",
                    "Verify certificate usage in applications",
                    "Look for typosquatting domains",
                    "Review associated CloudFront/ALB resources",
                ],
                containment_actions=[
                    "Revoke suspicious certificates",
                    "Disable compromised IAM credentials",
                    "Review certificate transparency logs",
                    "Block fraudulent domains",
                    "Report to certificate authorities",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal certificate request patterns",
            detection_coverage="40% - detects unusual volume",
            evasion_considerations="Low-volume activity may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes - 1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
    ],
    recommended_order=[
        "t1588-aws-suspicious-tools",
        "t1588-gcp-tool-execution",
        "t1588-aws-cobalt-strike",
        "t1588-aws-cert-anomaly",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+15% improvement for Resource Development tactic",
)
