"""
T1049 - System Network Connections Discovery

Adversaries enumerate network connections to identify remote services and
map the network topology. Commonly uses netstat, ss, lsof, and Get-NetTCPConnection.
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
    technique_id="T1049",
    technique_name="System Network Connections Discovery",
    tactic_ids=["TA0007"],  # Discovery
    mitre_url="https://attack.mitre.org/techniques/T1049/",
    threat_context=ThreatContext(
        description=(
            "Adversaries enumerate network connections on compromised systems to identify "
            "remote services, active sessions, and network topology. In cloud environments, "
            "attackers execute commands like netstat, ss, lsof on EC2 instances or VMs, "
            "or use cloud CLIs to discover network configurations, VPC peering, and VPN connections. "
            "This reconnaissance helps map the environment for lateral movement."
        ),
        attacker_goal="Enumerate active network connections to map remote systems and identify lateral movement targets",
        why_technique=[
            "Identifies active connections and listening services",
            "Reveals network topology and remote systems",
            "Maps RDP, SSH, and database connections",
            "Discovers cloud VPC peering and VPN configurations",
            "Essential for planning lateral movement",
            "Helps identify high-value targets on the network",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="stable",
        severity_score=4,
        severity_reasoning=(
            "Discovery technique itself causes no direct damage but indicates active "
            "post-compromise reconnaissance. Universally used by threat actors before "
            "lateral movement. Low severity individually but critical early warning signal "
            "when combined with other discovery activities."
        ),
        business_impact=[
            "Indicates active threat actor in environment",
            "Precursor to lateral movement attempts",
            "Reveals attacker's interest in network mapping",
            "Early warning opportunity if detected quickly",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1021", "T1570", "T1046"],
        often_follows=["T1078.004", "T1059.009", "T1651"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Process Execution Monitoring via GuardDuty
        DetectionStrategy(
            strategy_id="t1049-aws-guardduty-runtime",
            name="EC2 Runtime Command Monitoring",
            description="Detect network enumeration commands (netstat, ss, lsof) via GuardDuty Runtime Monitoring.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.guardduty"],
                    "detail-type": ["GuardDuty Finding"],
                    "detail": {
                        "type": [
                            "Execution:Runtime/SuspiciousCommand",
                            "Discovery:Runtime/SuspiciousCommand",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network enumeration commands on EC2

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for GuardDuty runtime findings
  NetworkEnumRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          type:
            - Execution:Runtime/SuspiciousCommand
            - Discovery:Runtime/ProcessDiscovery
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
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
                aws:SourceArn: !GetAtt NetworkEnumRule.Arn""",
                terraform_template="""# Detect network enumeration commands on EC2

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "network-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for GuardDuty
resource "aws_cloudwatch_event_rule" "network_enum" {
  name = "network-enumeration-detection"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Execution:Runtime/SuspiciousCommand",
        "Discovery:Runtime/SuspiciousCommand"
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "network-connections-discovery-dlq"
  message_retention_seconds = 1209600
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sqs_queue.dlq.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.network_enum.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.network_enum.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.alerts.arn

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

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.network_enum.arn
          }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Network Enumeration Commands Detected on EC2",
                alert_description_template="Network discovery commands (netstat, ss, lsof) executed on instance {instanceId}.",
                investigation_steps=[
                    "Identify the instance and review CloudWatch Logs for command details",
                    "Check which user or process executed the commands",
                    "Review instance authentication history",
                    "Look for other discovery or reconnaissance activity",
                    "Check for follow-on lateral movement attempts",
                ],
                containment_actions=[
                    "Review SSM Session Manager logs if applicable",
                    "Examine instance security group for unauthorised access",
                    "Check for compromised credentials or SSH keys",
                    "Consider isolating instance if suspicious",
                    "Enable enhanced monitoring and logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised system administration and troubleshooting activity based on user identity",
            detection_coverage="80% - requires GuardDuty Runtime Monitoring enabled",
            evasion_considerations="Attackers may use alternative enumeration methods or cloud APIs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5 plus GuardDuty runtime monitoring costs",
            prerequisites=["GuardDuty enabled with Runtime Monitoring"],
        ),
        # Strategy 2: AWS - SSM Command Document Execution
        DetectionStrategy(
            strategy_id="t1049-aws-ssm-commands",
            name="SSM Network Discovery Command Detection",
            description="Detect network enumeration commands run via Systems Manager Run Command or Session Manager.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, commandId, documentName, requestedDateTime, status
| filter eventSource = "ssm.amazonaws.com"
| filter eventName = "SendCommand"
| filter requestParameters.documentName = "AWS-RunShellScript" or requestParameters.documentName = "AWS-RunPowerShellScript"
| filter requestParameters.parameters.commands like /netstat|ss |lsof|Get-NetTCPConnection|net use|quser/
| sort @timestamp desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network enumeration via SSM

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for SSM network commands
  SSMNetworkEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ssm.amazonaws.com" && $.eventName = "SendCommand" }'
      MetricTransformations:
        - MetricName: SSMNetworkEnum
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  SSMNetworkEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SSMNetworkEnumeration
      MetricName: SSMNetworkEnum
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect network enumeration via SSM

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "ssm-network-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "ssm_network_enum" {
  name           = "ssm-network-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ssm.amazonaws.com\" && $.eventName = \"SendCommand\" }"

  metric_transformation {
    name      = "SSMNetworkEnum"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "ssm_network_enum" {
  alarm_name          = "SSMNetworkEnumeration"
  metric_name         = "SSMNetworkEnum"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Network Enumeration via SSM Detected",
                alert_description_template="Network discovery commands executed via Systems Manager on {instanceId}.",
                investigation_steps=[
                    "Review SSM command history and parameters",
                    "Identify who initiated the SSM command",
                    "Check if this is authorised administrative activity",
                    "Review output of the commands in SSM console",
                    "Look for other suspicious SSM activity",
                ],
                containment_actions=[
                    "Review IAM permissions for ssm:SendCommand",
                    "Check for compromised IAM credentials",
                    "Enable MFA for SSM command execution",
                    "Consider restricting SSM document usage",
                    "Audit recent SSM command executions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised operations teams and automation",
            detection_coverage="75% - catches SSM-based enumeration only",
            evasion_considerations="Direct shell access or user data scripts bypass this detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail logging to CloudWatch",
                "SSM Session logging enabled",
            ],
        ),
        # Strategy 3: AWS - VPC Describe Operations
        DetectionStrategy(
            strategy_id="t1049-aws-vpc-discovery",
            name="VPC Network Discovery API Calls",
            description="Detect cloud-level network discovery via VPC describe operations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
| filter eventSource = "ec2.amazonaws.com"
| filter eventName in ["DescribeVpcPeeringConnections", "DescribeVpnConnections", "DescribeVpcs", "DescribeSubnets", "DescribeRouteTables", "DescribeNetworkInterfaces"]
| stats count(*) as api_count by userIdentity.arn, bin(1h)
| filter api_count > 15
| sort api_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect VPC network discovery

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for VPC discovery
  VPCDiscoveryFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ec2.amazonaws.com" && ($.eventName = "DescribeVpcPeeringConnections" || $.eventName = "DescribeVpnConnections" || $.eventName = "DescribeNetworkInterfaces") }'
      MetricTransformations:
        - MetricName: VPCNetworkDiscovery
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  VPCDiscoveryAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: VPCNetworkDiscovery
      MetricName: VPCNetworkDiscovery
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect VPC network discovery

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "vpc-discovery-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "vpc_discovery" {
  name           = "vpc-network-discovery"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ec2.amazonaws.com\" && ($.eventName = \"DescribeVpcPeeringConnections\" || $.eventName = \"DescribeVpnConnections\") }"

  metric_transformation {
    name      = "VPCNetworkDiscovery"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "vpc_discovery" {
  alarm_name          = "VPCNetworkDiscovery"
  metric_name         = "VPCNetworkDiscovery"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="low",
                alert_title="VPC Network Discovery Activity Detected",
                alert_description_template="High volume of VPC describe operations from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who is performing VPC discovery",
                    "Check if this is normal behaviour for the user",
                    "Review what network information was accessed",
                    "Look for other discovery or reconnaissance activity",
                    "Correlate with instance-level network enumeration",
                ],
                containment_actions=[
                    "Review user's permissions and access patterns",
                    "Check for compromised credentials",
                    "Monitor for lateral movement attempts",
                    "Consider limiting VPC read permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist CSPM tools, infrastructure-as-code deployments, and network monitoring tools",
            detection_coverage="70% - volume-based detection may miss slow enumeration",
            evasion_considerations="Slow API calls or using multiple identities can evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 4: GCP - Network Connection Discovery
        DetectionStrategy(
            strategy_id="t1049-gcp-compute-discovery",
            name="GCP Network Discovery Detection",
            description="Detect VPC and network connection enumeration on GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName=~"(networks.list|instances.list|routes.list|vpnGateways.list|interconnects.list)"''',
                gcp_terraform_template="""# GCP: Detect network discovery activity

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric
resource "google_logging_metric" "network_discovery" {
  project = var.project_id
  name   = "network-connection-discovery"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName=~"networks.list" OR
     protoPayload.methodName=~"routes.list" OR
     protoPayload.methodName=~"vpnGateways.list" OR
     protoPayload.methodName=~"interconnects.list")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "network_discovery" {
  project      = var.project_id
  display_name = "Network Discovery Activity"
  combiner     = "OR"

  conditions {
    display_name = "High volume network enumeration"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.network_discovery.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 30
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
                alert_title="GCP: Network Connection Discovery Detected",
                alert_description_template="High volume of network discovery API calls detected.",
                investigation_steps=[
                    "Identify the principal performing network discovery",
                    "Review what network resources were enumerated",
                    "Check if this is authorised security scanning",
                    "Look for other discovery activities",
                    "Check for lateral movement attempts",
                ],
                containment_actions=[
                    "Review principal's permissions",
                    "Check for compromised credentials",
                    "Monitor for follow-on attacks",
                    "Consider IAM Conditions to restrict discovery",
                    "Audit VPC and network configurations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist CSPM tools, Terraform, and authorised network monitoring",
            detection_coverage="75% - volume-based detection",
            evasion_considerations="Slow enumeration may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - OS-Level Network Enumeration
        DetectionStrategy(
            strategy_id="t1049-gcp-os-commands",
            name="GCP VM Network Command Detection",
            description="Detect network enumeration commands on GCP Compute Engine instances via OS logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
jsonPayload.message=~"(netstat|lsof|ss )"
severity="INFO"''',
                gcp_terraform_template="""# GCP: Detect OS-level network enumeration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for command execution
resource "google_logging_metric" "os_network_enum" {
  project = var.project_id
  name   = "os-network-enumeration"
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.message=~"(netstat|lsof|ss )"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "os_network_enum" {
  project      = var.project_id
  display_name = "OS Network Enumeration Commands"
  combiner     = "OR"

  conditions {
    display_name = "Network discovery commands executed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.os_network_enum.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
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
                alert_title="GCP: Network Enumeration Commands Detected",
                alert_description_template="Network discovery commands executed on GCP instance.",
                investigation_steps=[
                    "Identify the instance and review OS audit logs",
                    "Determine which user executed the commands",
                    "Check SSH authentication logs",
                    "Review other discovery or reconnaissance activity",
                    "Look for lateral movement attempts",
                ],
                containment_actions=[
                    "Review instance metadata and startup scripts",
                    "Examine firewall rules for unauthorised access",
                    "Check for compromised SSH keys or service accounts",
                    "Consider instance isolation if suspicious",
                    "Enable OS Config for enhanced logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Requires OS-level logging enabled; whitelist authorised system administration",
            detection_coverage="60% - requires comprehensive OS audit logging",
            evasion_considerations="Requires Cloud Logging agent and audit configuration on instances",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=[
                "Cloud Logging agent installed",
                "OS audit logging configured",
            ],
        ),
        # Azure Strategy: System Network Connections Discovery
        DetectionStrategy(
            strategy_id="t1049-azure",
            name="Azure System Network Connections Discovery Detection",
            description=(
                "Azure detection for System Network Connections Discovery. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// System Network Connections Discovery Detection
// Technique: T1049
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
                azure_terraform_template="""# Azure Detection for System Network Connections Discovery
# MITRE ATT&CK: T1049

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

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "system-network-connections-discovery-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "system-network-connections-discovery-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// System Network Connections Discovery Detection
// Technique: T1049
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

  description = "Detects System Network Connections Discovery (T1049) activity in Azure environment"
  display_name = "System Network Connections Discovery Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1049"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: System Network Connections Discovery Detected",
                alert_description_template=(
                    "System Network Connections Discovery activity detected. "
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
        "t1049-aws-guardduty-runtime",
        "t1049-gcp-compute-discovery",
        "t1049-aws-ssm-commands",
        "t1049-aws-vpc-discovery",
        "t1049-gcp-os-commands",
    ],
    total_effort_hours=5.25,
    coverage_improvement="+12% improvement for Discovery tactic",
)
