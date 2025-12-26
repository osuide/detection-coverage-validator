"""
T1614 - System Location Discovery

Adversaries gather geographical location information about victim hosts to
shape follow-on attack behaviours based on system locale, timezone, keyboard
layouts, and IP geolocation.
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
    technique_id="T1614",
    technique_name="System Location Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1614/",
    threat_context=ThreatContext(
        description=(
            "Adversaries gather geographical location information from victim hosts including "
            "timezone settings, keyboard layouts, language configurations, and IP geolocation data. "
            "In cloud environments, attackers query instance metadata services for availability zone "
            "and region details. This reconnaissance enables geofencing, targeted attacks based on "
            "victim locality, and evasion of analysis environments in undesired locations."
        ),
        attacker_goal="Determine victim geographical location to customise attacks and avoid detection",
        why_technique=[
            "Implement geofencing to target specific countries/regions",
            "Avoid executing in analysis or sandbox environments",
            "Customise malware behaviour based on victim location",
            "Identify high-value targets in specific regions",
            "Evade detection by not executing in researcher locations",
            "Determine cloud region for resource targeting",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=5,
        severity_reasoning=(
            "Discovery technique with moderate impact. Whilst gathering location information "
            "itself causes no direct harm, it frequently precedes targeted attacks, ransomware "
            "deployment with geofencing, or malware that selectively executes based on victim "
            "location. Common in sophisticated attacks using evasion techniques. Important "
            "indicator when combined with other reconnaissance activities."
        ),
        business_impact=[
            "Indicates active reconnaissance in environment",
            "Precursor to geofenced malware deployment",
            "May signal targeted regional attacks",
            "Early warning for location-aware threats",
            "Potential evasion of security controls",
        ],
        typical_attack_phase="discovery",
        often_precedes=[
            "T1486",
            "T1485",
            "T1490",
        ],  # Data Encrypted for Impact, Data Destruction, Inhibit System Recovery
        often_follows=[
            "T1078",
            "T1059",
            "T1566",
        ],  # Valid Accounts, Command and Scripting Interpreter, Phishing
    ),
    detection_strategies=[
        # Strategy 1: AWS - EC2 Instance Metadata Queries
        DetectionStrategy(
            strategy_id="t1614-aws-metadata",
            name="AWS Instance Metadata Location Queries",
            description="Detect queries to EC2 instance metadata service for availability zone and region information.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, sourceIP
| filter @message like /169.254.169.254/
| filter @message like /(placement\\/availability-zone|placement\\/region|instance-id\\/az)/
| stats count(*) as metadata_queries by instanceId, sourceIP, bin(15m)
| filter metadata_queries > 3
| sort metadata_queries desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect instance metadata location discovery attempts

Parameters:
  VpcFlowLogsGroup:
    Type: String
    Description: CloudWatch log group for VPC Flow Logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Instance Metadata Location Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for metadata service queries
  MetadataLocationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VpcFlowLogsGroup
      FilterPattern: '[version, account, eni, source, destination="169.254.169.254", ...]'
      MetricTransformations:
        - MetricName: MetadataLocationQueries
          MetricNamespace: Security/Discovery
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alarm for unusual metadata queries
  MetadataLocationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: InstanceMetadataLocationDiscovery
      AlarmDescription: Multiple instance metadata location queries detected
      MetricName: MetadataLocationQueries
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 900
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect instance metadata location discovery

variable "vpc_flow_logs_group" {
  type        = string
  description = "CloudWatch log group for VPC Flow Logs"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "metadata_location_alerts" {
  name         = "instance-metadata-location-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Instance Metadata Location Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.metadata_location_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for metadata service queries
resource "aws_cloudwatch_log_metric_filter" "metadata_location" {
  name           = "instance-metadata-location-discovery"
  log_group_name = var.vpc_flow_logs_group
  pattern        = "[version, account, eni, source, destination=\"169.254.169.254\", ...]"

  metric_transformation {
    name          = "MetadataLocationQueries"
    namespace     = "Security/Discovery"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Alarm for unusual metadata queries
resource "aws_cloudwatch_metric_alarm" "metadata_location" {
  alarm_name          = "InstanceMetadataLocationDiscovery"
  alarm_description   = "Multiple instance metadata location queries detected"
  metric_name         = aws_cloudwatch_log_metric_filter.metadata_location.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.metadata_location.metric_transformation[0].namespace
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.metadata_location_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Instance Metadata Location Discovery Detected",
                alert_description_template="Multiple queries to EC2 instance metadata service for location information from instance {instanceId}. This may indicate malware checking victim location.",
                investigation_steps=[
                    "Identify the instance making metadata queries",
                    "Review running processes and their behaviour",
                    "Check for recently installed software or scripts",
                    "Examine network connections for C2 activity",
                    "Look for other reconnaissance activities (T1082, T1083)",
                    "Review CloudTrail for suspicious API calls from the instance",
                    "Check for known malware signatures or IOCs",
                ],
                containment_actions=[
                    "Consider isolating instance for forensic analysis",
                    "Implement IMDSv2 to require session tokens",
                    "Review instance security groups and IAM roles",
                    "Check for unauthorised scheduled tasks or persistence",
                    "Scan instance for malware and suspicious files",
                    "Review recent deployments and configuration changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Legitimate applications and AWS SDKs query metadata service for region/AZ "
                "information during startup. Whitelist known application patterns and adjust "
                "thresholds based on normal instance behaviour. Consider time-of-day patterns."
            ),
            detection_coverage="60% - catches metadata service queries but requires VPC Flow Logs",
            evasion_considerations=(
                "Attackers can rate-limit queries to stay below thresholds or use cached "
                "information. Direct API calls or reading from instance identity documents "
                "may not generate flow logs. Requires VPC Flow Logs enabled."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$12-20 (depends on VPC Flow Logs volume)",
            prerequisites=[
                "VPC Flow Logs enabled and sent to CloudWatch",
                "CloudWatch Logs retention configured",
                "Sufficient log retention for historical analysis",
            ],
        ),
        # Strategy 2: AWS - Locale and Timezone Discovery Commands
        DetectionStrategy(
            strategy_id="t1614-aws-locale",
            name="EC2 Locale and Timezone Discovery Detection",
            description="Detect locale, timezone, and keyboard layout queries via CloudWatch Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, instanceId, commandId
| filter @message like /(locale|localectl|timedatectl|Get-Culture|Get-WinSystemLocale|GetLocaleInfo|setxkbmap|GetKeyboardLayout|HKLM.*Keyboard Layout)/
| filter @message not like /(systemd|locale-gen|dpkg-reconfigure|yum|apt)/
| stats count(*) as locale_queries by instanceId, bin(1h)
| filter locale_queries > 5
| sort locale_queries desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect system locale and timezone discovery attempts

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: CloudWatch log group for EC2 system logs
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: System Location Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for locale discovery commands
  LocaleDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[timestamp, request_id, event_type=*locale* || event_type=*localectl* || event_type=*Get-Culture* || event_type=*GetLocaleInfo* || event_type=*GetKeyboardLayout*]'
      MetricTransformations:
        - MetricName: SystemLocationDiscovery
          MetricNamespace: Security/Discovery
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alarm for unusual locale queries
  LocaleDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SystemLocationDiscoveryDetected
      AlarmDescription: Multiple system locale/location queries detected
      MetricName: SystemLocationDiscovery
      Namespace: Security/Discovery
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect system locale and timezone discovery

variable "cloudwatch_log_group" {
  type        = string
  description = "CloudWatch log group for EC2 system logs"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "location_discovery_alerts" {
  name         = "system-location-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "System Location Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.location_discovery_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for locale discovery commands
resource "aws_cloudwatch_log_metric_filter" "locale_discovery" {
  name           = "system-location-discovery"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[timestamp, request_id, event_type=*locale* || event_type=*localectl* || event_type=*Get-Culture* || event_type=*GetLocaleInfo* || event_type=*GetKeyboardLayout*]"

  metric_transformation {
    name          = "SystemLocationDiscovery"
    namespace     = "Security/Discovery"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Alarm for unusual locale queries
resource "aws_cloudwatch_metric_alarm" "locale_discovery" {
  alarm_name          = "SystemLocationDiscoveryDetected"
  alarm_description   = "Multiple system locale/location queries detected"
  metric_name         = aws_cloudwatch_log_metric_filter.locale_discovery.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.locale_discovery.metric_transformation[0].namespace
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.location_discovery_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="System Location Discovery Detected",
                alert_description_template="Multiple locale/timezone queries detected from instance {instanceId}. This may indicate malware performing geofencing checks.",
                investigation_steps=[
                    "Identify the process and user executing location queries",
                    "Check if this is legitimate system administration activity",
                    "Review command history and recent process execution",
                    "Look for malware signatures or known IOCs",
                    "Check for other reconnaissance activities (T1082, T1124)",
                    "Review network connections for C2 communication",
                    "Investigate any recent software installations or updates",
                ],
                containment_actions=[
                    "Review user account permissions and recent activity",
                    "Scan system for malware and suspicious processes",
                    "Check for unauthorised scheduled tasks or persistence mechanisms",
                    "Consider isolating instance if malware is confirmed",
                    "Review and update endpoint protection signatures",
                    "Audit system logs for suspicious modifications",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist legitimate system administration tools, configuration management "
                "systems (Ansible, Puppet, Chef), and package managers. Filter locale-gen, "
                "dpkg-reconfigure, and systemd processes. Consider user context and time-of-day."
            ),
            detection_coverage="70% - catches explicit locale/timezone commands but may miss API calls",
            evasion_considerations=(
                "Attackers can use direct Windows API calls (GetLocaleInfoW, GetUserDefaultLocaleName) "
                "or registry queries instead of command-line utilities. API calls typically don't "
                "generate command logs. Queries spread over time evade thresholds."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-18 (depends on log volume)",
            prerequisites=[
                "CloudWatch Logs agent installed on EC2 instances",
                "System logs (syslog, Windows event logs) forwarded to CloudWatch",
                "Command execution logging enabled (audit logs, PowerShell logging)",
            ],
        ),
        # Strategy 3: AWS - Systems Manager Location Command Detection
        DetectionStrategy(
            strategy_id="t1614-aws-ssm",
            name="SSM Location Discovery Command Detection",
            description="Detect location-related commands executed via AWS Systems Manager.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["SendCommand"],
                        "requestParameters": {
                            "documentName": [
                                "AWS-RunShellScript",
                                "AWS-RunPowerShellScript",
                            ]
                        },
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect location discovery via Systems Manager

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: SSM Location Discovery Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for SSM location commands
  LocationDiscoveryRule:
    Type: AWS::Events::Rule
    Properties:
      Name: SSMLocationDiscoveryDetection
      Description: Detect location discovery commands via SSM
      State: ENABLED
      EventPattern:
        source:
          - aws.ssm
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - SendCommand
          requestParameters:
            documentName:
              - AWS-RunShellScript
              - AWS-RunPowerShellScript
      Targets:
        - Id: SecurityAlerts
          Arn: !Ref AlertTopic

  # Step 3: SNS topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# AWS: Detect location discovery via Systems Manager

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "ssm_location_alerts" {
  name         = "ssm-location-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "SSM Location Discovery Alerts"
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.ssm_location_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for EventBridge targets
resource "aws_sqs_queue" "events_dlq" {
  name                      = "ssm-location-dlq"
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

# Step 2: EventBridge rule for SSM location commands
resource "aws_cloudwatch_event_rule" "ssm_location_discovery" {
  name        = "SSMLocationDiscoveryDetection"
  description = "Detect location discovery commands via SSM"
  state       = "ENABLED"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["SendCommand"]
      requestParameters = {
        documentName = [
          "AWS-RunShellScript",
          "AWS-RunPowerShellScript"
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns_target" {
  rule      = aws_cloudwatch_event_rule.ssm_location_discovery.name
  target_id = "SecurityAlerts"
  arn       = aws_sns_topic.ssm_location_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.events_dlq.arn
  }
}

# Step 3: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.ssm_location_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssm_location_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Location Discovery Command via SSM",
                alert_description_template="Location-related command executed via Systems Manager. Requires manual review of command content.",
                investigation_steps=[
                    "Review the complete SSM command parameters in CloudTrail",
                    "Identify the IAM principal who executed the command",
                    "Check target instances for command execution results",
                    "Verify if this is authorised administrative activity",
                    "Look for patterns of multiple discovery commands",
                    "Review command output in Systems Manager console",
                ],
                containment_actions=[
                    "Review IAM permissions for SSM command execution",
                    "Check for unauthorised access to Systems Manager",
                    "Monitor target instances for suspicious activity",
                    "Consider restricting SSM command execution permissions",
                    "Enable SSM Session Manager logging for better visibility",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning=(
                "This rule captures all SSM shell/PowerShell commands, requiring additional "
                "filtering to identify actual location queries. Consider implementing Lambda-based "
                "filtering to parse command parameters, or use CloudWatch Logs Insights on SSM "
                "command output logs."
            ),
            detection_coverage="50% - captures SSM-based commands but requires content analysis",
            evasion_considerations="Attackers can use other remote execution methods (SSM Session Manager, EC2 Instance Connect, direct SSH)",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=[
                "CloudTrail enabled with SSM API logging",
                "Systems Manager in use for instance management",
            ],
        ),
        # Strategy 4: GCP - Compute Instance Location Discovery
        DetectionStrategy(
            strategy_id="t1614-gcp-compute",
            name="GCP Compute Instance Location Discovery",
            description="Detect system location queries on GCP Compute Engine instances via Cloud Logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(textPayload=~"locale" OR textPayload=~"localectl" OR textPayload=~"AppleLocale" OR textPayload=~"Get-Culture" OR textPayload=~"GetLocaleInfo" OR textPayload=~"keyboard.*layout")
-textPayload=~"(yum|apt|dpkg|systemd|locale-gen)"''',
                gcp_terraform_template="""# GCP: Detect system location discovery

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_alerts" {
  display_name = "Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for location discovery
resource "google_logging_metric" "location_discovery" {
  name    = "system-location-discovery"
  project = var.project_id
  filter  = <<-EOT
    resource.type="gce_instance"
    (textPayload=~"locale" OR textPayload=~"localectl" OR textPayload=~"AppleLocale" OR textPayload=~"Get-Culture" OR textPayload=~"GetLocaleInfo" OR textPayload=~"keyboard.*layout")
    -textPayload=~"(yum|apt|dpkg|systemd|locale-gen)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Alert policy for unusual location queries
resource "google_monitoring_alert_policy" "location_discovery_alert" {
  display_name = "System Location Discovery Detected"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "High volume of location queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.location_discovery.name}\" AND resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: System Location Discovery Detected",
                alert_description_template="Multiple system location queries detected on GCP Compute Engine instance.",
                investigation_steps=[
                    "Identify the GCE instance and user account",
                    "Review Cloud Logging for command execution context",
                    "Check if this is legitimate administrative activity",
                    "Look for other discovery techniques (metadata queries, network enumeration)",
                    "Review recent VM access logs and SSH sessions",
                    "Check for suspicious processes or scheduled tasks",
                    "Examine instance for malware or unauthorised software",
                ],
                containment_actions=[
                    "Review IAM permissions for instance access",
                    "Check for unauthorised SSH keys or service accounts",
                    "Monitor instance for malware execution patterns",
                    "Consider VPC Service Controls for additional protection",
                    "Review OS Login and metadata settings",
                    "Scan instance for malware and suspicious files",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist GCP-managed services, monitoring agents (Ops Agent, Cloud Logging agent), "
                "and configuration management tools. Filter package management activities and system "
                "initialisation processes."
            ),
            detection_coverage="65% - captures common location query commands in logs",
            evasion_considerations=(
                "Requires Cloud Logging agent configured to capture system commands. "
                "API-based queries or reading from system files without commands won't be logged."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$12-22 (depends on log volume)",
            prerequisites=[
                "Cloud Logging agent installed on GCE instances",
                "System logs ingested into Cloud Logging",
                "Audit logging enabled for Compute Engine",
            ],
        ),
        # Strategy 5: GCP - Instance Metadata Location Queries
        DetectionStrategy(
            strategy_id="t1614-gcp-metadata",
            name="GCP Instance Metadata Location Query Detection",
            description="Monitor queries to GCP metadata server for zone and region information.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
httpRequest.requestUrl=~"metadata.google.internal.*(zone|region)"
protoPayload.request.url=~"metadata.google.internal.*(zone|region)"''',
                gcp_terraform_template="""# GCP: Monitor metadata server location queries

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_alerts" {
  display_name = "Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for metadata location queries
resource "google_logging_metric" "metadata_location" {
  name    = "metadata-location-queries"
  project = var.project_id
  filter  = <<-EOT
    resource.type="gce_instance"
    (httpRequest.requestUrl=~"metadata.google.internal.*(zone|region)" OR
     protoPayload.request.url=~"metadata.google.internal.*(zone|region)")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "metadata_location_alert" {
  display_name = "Metadata Location Discovery"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "High volume metadata location queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.metadata_location.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Metadata Location Discovery",
                alert_description_template="Multiple queries to metadata server for location information detected.",
                investigation_steps=[
                    "Identify the instance making metadata queries",
                    "Review processes accessing the metadata server",
                    "Check if this is normal application behaviour",
                    "Look for recently deployed applications or changes",
                    "Review network connections for C2 activity",
                    "Check for known malware patterns or IOCs",
                    "Examine instance for unauthorised software",
                ],
                containment_actions=[
                    "Review instance security and IAM permissions",
                    "Consider implementing metadata server access controls",
                    "Monitor instance for suspicious activity",
                    "Check for unauthorised scheduled tasks",
                    "Scan for malware and suspicious processes",
                    "Review recent configuration changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Legitimate applications query metadata server for zone/region during startup "
                "or for multi-region deployments. Whitelist known application patterns and adjust "
                "thresholds based on normal behaviour."
            ),
            detection_coverage="55% - requires metadata server access logging",
            evasion_considerations="Requires detailed logging of HTTP requests; rate-limiting queries or caching results can evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "Cloud Logging enabled for GCE instances",
                "HTTP request logging configured",
                "Metadata server access logging enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1614-aws-locale",  # Best AWS coverage for explicit commands
        "t1614-aws-metadata",  # AWS metadata service monitoring
        "t1614-aws-ssm",  # Low effort AWS SSM monitoring
        "t1614-gcp-compute",  # Best GCP coverage for commands
        "t1614-gcp-metadata",  # GCP metadata service monitoring
    ],
    total_effort_hours=6.0,
    coverage_improvement="+7% improvement for Discovery tactic",
)
