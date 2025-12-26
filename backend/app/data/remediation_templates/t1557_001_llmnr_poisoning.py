"""
T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay

Adversaries spoof authoritative sources for name resolution to intercept network
traffic and harvest authentication credentials. By responding to LLMNR (UDP 5355)
and NBT-NS (UDP 137) broadcast queries, attackers capture NTLMv2 hashes for offline
cracking or relay them to access target systems. Used by Lazarus Group, Wizard Spider.

IMPORTANT DETECTION LIMITATIONS:
VPC Flow Logs and Cloud Logging CANNOT inspect packet contents. They show:
- Source/destination IP addresses
- Ports and protocol (UDP 5355/137)
- Bytes transferred and packet counts

VPC Flow Logs CANNOT determine:
- Whether LLMNR/NetBIOS responses are legitimate or spoofed
- Actual name resolution queries and responses
- If poisoning is occurring vs. normal name resolution

Coverage reality:
- VPC Flow Logs: ~25-30% (detects traffic volume anomalies, not actual poisoning)
- With VPC Traffic Mirroring + deep packet inspection: ~70%
- Windows Event Logs forwarded to cloud: ~80% (can detect actual attacks)

For accurate detection, either:
1. Disable LLMNR/NBT-NS via Group Policy (prevention)
2. Deploy VPC Traffic Mirroring with packet inspection tools
3. Forward Windows Event Logs (Event ID 4697, security logs) to CloudWatch/Cloud Logging
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
    technique_id="T1557.001",
    technique_name="Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
    tactic_ids=["TA0006", "TA0009"],  # Credential Access, Collection
    mitre_url="https://attack.mitre.org/techniques/T1557/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries spoof authoritative sources for name resolution on local networks "
            "to intercept traffic and harvest authentication credentials. By responding to "
            "LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) "
            "broadcast queries, attackers position themselves between victims and requested "
            "resources. When authentication is required, NTLMv1/v2 hashes are captured and "
            "either cracked offline or relayed to authenticate against other systems without "
            "needing plaintext passwords."
        ),
        attacker_goal="Capture NTLM authentication hashes and relay them to compromise Windows systems",
        why_technique=[
            "Passive exploitation of Windows name resolution protocols",
            "Captures authentication hashes without user interaction",
            "Enables lateral movement via SMB relay attacks",
            "Difficult to detect without network monitoring",
            "Works against legacy Windows systems and misconfigured networks",
            "Can be combined with downgrade attacks to force weaker authentication",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="high",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "LLMNR/NBT-NS poisoning is a highly effective credential harvesting technique "
            "that exploits fundamental Windows networking protocols. Captured NTLM hashes "
            "can be cracked offline or relayed for immediate lateral movement. The attack "
            "is passive, difficult to detect, and requires minimal attacker interaction. "
            "In cloud environments with Windows-based workloads, this technique remains "
            "a significant threat for initial access and privilege escalation."
        ),
        business_impact=[
            "Credential theft and account compromise",
            "Lateral movement across Windows infrastructure",
            "Privilege escalation to domain admin accounts",
            "Data exfiltration and ransomware deployment",
            "Compliance violations from unauthorised access",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1021.002", "T1078.002", "T1003.001", "T1550.002"],
        often_follows=["T1133", "T1078.004", "T1190"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - WorkSpaces and EC2 Windows Network Monitoring
        DetectionStrategy(
            strategy_id="t1557-001-aws-netbios",
            name="AWS Windows NetBIOS/LLMNR Traffic Detection",
            description="Detect LLMNR and NetBIOS name service traffic on Windows instances that may indicate poisoning attacks.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, srcport, dstport, protocol
| filter (dstport = 5355 or dstport = 137) and protocol = 17
| filter action = "ACCEPT"
| stats count() as queryCount by srcaddr, dstaddr, dstport
| filter queryCount > 50
| sort queryCount desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect LLMNR and NetBIOS traffic patterns

Parameters:
  VpcId:
    Type: String
    Description: VPC ID to monitor
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  # Step 1: Enable VPC Flow Logs
  FlowLogsLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/vpc/llmnr-detection
      RetentionInDays: 7

  FlowLogsRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: vpc-flow-logs.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: CloudWatchLogs
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !GetAtt FlowLogsLogGroup.Arn

  FlowLog:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceType: VPC
      ResourceIds:
        - !Ref VpcId
      TrafficType: ALL
      LogDestinationType: cloud-watch-logs
      LogGroupName: !Ref FlowLogsLogGroup
      DeliverLogsPermissionArn: !GetAtt FlowLogsRole.Arn

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Metric filter for LLMNR/NetBIOS traffic
  NetBIOSMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FlowLogsLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport="5355" || destport="137", protocol="17", packets, bytes, windowstart, windowend, action="ACCEPT", flowlogstatus]'
      MetricTransformations:
        - MetricName: LLMNRNetBIOSQueries
          MetricNamespace: Security/Network
          MetricValue: "1"

  HighNetBIOSAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousLLMNRNetBIOSActivity
      MetricName: LLMNRNetBIOSQueries
      Namespace: Security/Network
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect LLMNR and NetBIOS poisoning attempts

variable "vpc_id" {
  type        = string
  description = "VPC ID to monitor"
}

variable "alert_email" {
  type = string
}

# Step 1: CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/llmnr-detection"
  retention_in_days = 7
}

resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-llmnr-detection"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "cloudwatch-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = var.vpc_id
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "llmnr-netbios-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Metric filter and alarm
resource "aws_cloudwatch_log_metric_filter" "netbios" {
  name           = "llmnr-netbios-queries"
  log_group_name = aws_cloudwatch_log_group.flow_logs.name
  pattern        = "[version, account, eni, source, destination, srcport, destport=5355 || destport=137, protocol=17, packets, bytes, windowstart, windowend, action=ACCEPT, flowlogstatus]"

  metric_transformation {
    name      = "LLMNRNetBIOSQueries"
    namespace = "Security/Network"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "high_netbios" {
  alarm_name          = "SuspiciousLLMNRNetBIOSActivity"
  metric_name         = "LLMNRNetBIOSQueries"
  namespace           = "Security/Network"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious LLMNR/NetBIOS Name Resolution Traffic",
                alert_description_template="High volume of LLMNR (UDP 5355) or NetBIOS (UDP 137) traffic detected from {srcaddr}. Potential name resolution poisoning attack.",
                investigation_steps=[
                    "Identify source instances generating LLMNR/NetBIOS traffic",
                    "Review VPC Flow Logs for traffic patterns and destinations",
                    "Check if Windows instances have LLMNR/NetBIOS disabled",
                    "Examine CloudWatch Logs for SMB authentication failures",
                    "Review recent authentication activity for affected accounts",
                    "Check for installation of Responder, Inveigh, or similar tools",
                    "Analyse network captures for spoofed responses",
                ],
                containment_actions=[
                    "Isolate suspicious instances via security groups",
                    "Disable LLMNR and NetBIOS on all Windows instances via GPO",
                    "Enable SMB signing to prevent relay attacks",
                    "Reset credentials for potentially compromised accounts",
                    "Apply network ACLs to block UDP 5355 and 137",
                    "Deploy host-based firewall rules on Windows instances",
                    "Enable enhanced monitoring and logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal NetBIOS traffic; whitelist authorised Windows file servers",
            detection_coverage="25% - detects traffic volume anomalies only. Flow Logs CANNOT inspect packet contents to confirm actual poisoning.",
            evasion_considerations="Attackers may throttle responses to avoid volume-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30 (VPC Flow Logs + CloudWatch)",
            prerequisites=["VPC with Windows workloads", "VPC Flow Logs"],
        ),
        # Strategy 2: AWS - SMB Relay Detection via CloudTrail
        DetectionStrategy(
            strategy_id="t1557-001-aws-smb",
            name="AWS Directory Service and FSx SMB Authentication Monitoring",
            description="Monitor AWS Managed Microsoft AD and FSx for unusual SMB authentication patterns.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ds", "aws.fsx"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateMicrosoftAD",
                            "UpdateSettings",
                            "ResetUserPassword",
                            "CreateFileSystem",
                            "UpdateFileSystem",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor Directory Service and FSx for SMB-related changes

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

  # Step 2: EventBridge rule for Directory Service changes
  DirectoryServiceRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ds, aws.fsx]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateMicrosoftAD
            - UpdateSettings
            - ResetUserPassword
            - CreateFileSystem
            - UpdateFileSystem
      Targets:
        - Id: AlertTopic
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
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
                aws:SourceArn: !GetAtt DirectoryServiceRule.Arn""",
                terraform_template="""# AWS: Monitor Directory Service and FSx for SMB security

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "directory-service-smb-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for Directory Service
resource "aws_cloudwatch_event_rule" "directory_changes" {
  name = "directory-service-smb-monitoring"
  event_pattern = jsonencode({
    source      = ["aws.ds", "aws.fsx"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateMicrosoftAD",
        "UpdateSettings",
        "ResetUserPassword",
        "CreateFileSystem",
        "UpdateFileSystem"
      ]
    }
  })
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "dlq" {
  name                      = "directory-smb-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.directory_changes.arn }
      }
    }]
  })
}

# EventBridge target with retry and DLQ
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.directory_changes.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

# Step 3: SNS topic policy
data "aws_caller_identity" "current" {}

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
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.directory_changes.arn,
              aws_cloudwatch_event_rule.workspaces_auth.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="AWS Directory Service or FSx Configuration Changed",
                alert_description_template="Directory Service or FSx operation {eventName} performed by {userIdentity.principalId}. Review for unauthorised SMB configuration changes.",
                investigation_steps=[
                    "Verify the principal performing the operation",
                    "Review Directory Service security settings",
                    "Check FSx for Windows File Server SMB configuration",
                    "Examine CloudTrail for related suspicious activities",
                    "Review SMB signing and encryption settings",
                    "Check for password resets or user modifications",
                    "Validate Active Directory trust relationships",
                ],
                containment_actions=[
                    "Enable SMB signing on all FSx file systems",
                    "Configure Directory Service to require SMB encryption",
                    "Review and restrict Directory Service IAM permissions",
                    "Enable CloudWatch Logs for Directory Service",
                    "Implement least-privilege IAM policies",
                    "Enable MFA for privileged operations",
                    "Audit all Active Directory users and groups",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised administrators and automation",
            detection_coverage="85% - catches configuration changes via CloudTrail",
            evasion_considerations="Direct attacks on Windows instances bypass this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "AWS Managed Microsoft AD or FSx"],
        ),
        # Strategy 3: AWS - WorkSpaces Security Monitoring
        DetectionStrategy(
            strategy_id="t1557-001-aws-workspaces",
            name="Amazon WorkSpaces Authentication Monitoring",
            description="Detect suspicious authentication patterns in Amazon WorkSpaces that may indicate credential relay attacks.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter eventSource = "workspaces.amazonaws.com"
| filter eventName in ["AuthenticateUser", "CreateWorkspaces", "ModifyWorkspaceProperties"]
| stats count() as authCount by userIdentity.principalId, sourceIPAddress
| filter authCount > 10
| sort authCount desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor WorkSpaces for suspicious authentication activity

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

  # Step 2: EventBridge rule for WorkSpaces authentication
  WorkSpacesAuthRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.workspaces]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - AuthenticateUser
            - CreateWorkspaces
            - ModifyWorkspaceProperties
      Targets:
        - Id: AlertTopic
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
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
                aws:SourceArn: !GetAtt WorkSpacesAuthRule.Arn""",
                terraform_template="""# AWS: Monitor WorkSpaces authentication patterns

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "workspaces-auth-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for WorkSpaces
resource "aws_cloudwatch_event_rule" "workspaces_auth" {
  name = "workspaces-authentication-monitoring"
  event_pattern = jsonencode({
    source      = ["aws.workspaces"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthenticateUser",
        "CreateWorkspaces",
        "ModifyWorkspaceProperties"
      ]
    }
  })
}

# Dead Letter Queue for WorkSpaces auth events
resource "aws_sqs_queue" "workspaces_dlq" {
  name                      = "workspaces-auth-dlq"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sqs_queue_policy" "workspaces_dlq" {
  queue_url = aws_sqs_queue.workspaces_dlq.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.workspaces_dlq.arn
      Condition = {
        ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.workspaces_auth.arn }
      }
    }]
  })
}

# EventBridge target with retry and DLQ
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.workspaces_auth.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.workspaces_dlq.arn
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
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.directory_changes.arn,
              aws_cloudwatch_event_rule.workspaces_auth.arn,
            ]
          }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Suspicious WorkSpaces Authentication Activity",
                alert_description_template="Multiple WorkSpaces authentication events from {sourceIPAddress}. Potential credential relay or brute force attempt.",
                investigation_steps=[
                    "Review WorkSpaces authentication logs in CloudWatch",
                    "Identify source IP addresses and geolocations",
                    "Check for failed authentication attempts",
                    "Review user account activity across AWS services",
                    "Examine WorkSpaces security group configurations",
                    "Validate MFA status for affected users",
                    "Check for concurrent sessions from different locations",
                ],
                containment_actions=[
                    "Enforce MFA for all WorkSpaces users",
                    "Restrict WorkSpaces access by IP address",
                    "Enable CloudWatch Logs for detailed monitoring",
                    "Implement connection access controls",
                    "Review and update WorkSpaces directory settings",
                    "Reset credentials for suspicious accounts",
                    "Enable enhanced logging and monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal user authentication patterns; exclude travelling users",
            detection_coverage="70% - effective for WorkSpaces-based Windows environments",
            evasion_considerations="Legitimate credentials from relay attacks appear normal",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Amazon WorkSpaces deployed", "CloudTrail enabled"],
        ),
        # Strategy 4: GCP - Windows Instance Network Monitoring
        DetectionStrategy(
            strategy_id="t1557-001-gcp-netbios",
            name="GCP Windows VM NetBIOS/LLMNR Detection",
            description="Detect LLMNR and NetBIOS traffic patterns in GCP VPC Flow Logs.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/[PROJECT_ID]/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port=5355 OR jsonPayload.connection.dest_port=137
jsonPayload.connection.protocol=17""",
                gcp_terraform_template="""# GCP: Detect LLMNR and NetBIOS poisoning attempts

variable "project_id" {
  type = string
}

variable "network_name" {
  type = string
}

variable "subnet_name" {
  type = string
}

variable "region" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Enable VPC Flow Logs on subnet
resource "google_compute_subnetwork" "monitored" {
  name          = var.subnet_name
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = var.network_name

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Step 2: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Log-based metric for LLMNR/NetBIOS
resource "google_logging_metric" "netbios_traffic" {
  name   = "llmnr-netbios-queries"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    (jsonPayload.connection.dest_port=5355 OR jsonPayload.connection.dest_port=137)
    jsonPayload.connection.protocol=17
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "src_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }

  label_extractors = {
    "src_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
  }
}

# Alert policy
resource "google_monitoring_alert_policy" "netbios_alert" {
  display_name = "LLMNR/NetBIOS Poisoning Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume of name resolution queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.netbios_traffic.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.src_ip"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Suspicious LLMNR (UDP 5355) or NetBIOS (UDP 137) traffic detected. Potential name resolution poisoning attack."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: LLMNR/NetBIOS Name Resolution Poisoning Detected",
                alert_description_template="High volume of LLMNR or NetBIOS traffic from {srcIp}. Potential credential harvesting attack.",
                investigation_steps=[
                    "Identify source VM instances in VPC Flow Logs",
                    "Review flow logs for traffic patterns and destinations",
                    "Check if Windows VMs have LLMNR/NetBIOS disabled",
                    "Examine instance metadata and startup scripts",
                    "Review Cloud Audit Logs for suspicious VM modifications",
                    "Check for installation of Responder or similar tools",
                    "Analyse Serial Port Output for Windows Event Logs",
                ],
                containment_actions=[
                    "Isolate suspicious VMs via firewall rules",
                    "Disable LLMNR and NetBIOS on all Windows VMs",
                    "Enable SMB signing via group policy or local settings",
                    "Create VPC firewall rules to block UDP 5355 and 137",
                    "Reset credentials for potentially affected accounts",
                    "Deploy Cloud IDS for deep packet inspection",
                    "Enable Private Google Access to reduce exposure",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline legitimate Windows networking; whitelist file servers",
            detection_coverage="25% - detects traffic volume anomalies only. VPC Flow Logs CANNOT inspect packet contents to confirm actual poisoning.",
            evasion_considerations="Low-volume poisoning may avoid rate-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$20-40 (VPC Flow Logs + monitoring)",
            prerequisites=["VPC Flow Logs enabled", "Windows VMs in GCP"],
        ),
        # Strategy 5: GCP - Managed AD Security Monitoring
        DetectionStrategy(
            strategy_id="t1557-001-gcp-managed-ad",
            name="GCP Managed Service for Microsoft AD Monitoring",
            description="Monitor Managed AD for configuration changes that could enable LLMNR/NetBIOS attacks.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="managedidentities.googleapis.com"
protoPayload.methodName=~"(Create|Update|Patch)"
protoPayload.resourceName=~"domains"''',
                gcp_terraform_template="""# GCP: Monitor Managed AD for security changes

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for AD modifications
resource "google_logging_metric" "ad_changes" {
  name   = "managed-ad-configuration-changes"
  filter = <<-EOT
    protoPayload.serviceName="managedidentities.googleapis.com"
    protoPayload.methodName=~"(Create|Update|Patch)"
    protoPayload.resourceName=~"domains"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "ad_modification" {
  display_name = "Managed AD Configuration Changed"
  combiner     = "OR"

  conditions {
    display_name = "Active Directory modification detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ad_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Managed Service for Microsoft AD configuration changed. Review for unauthorised security modifications."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Managed AD Configuration Modified",
                alert_description_template="Managed AD domain {resourceName} modified via {methodName}. Review for security policy changes.",
                investigation_steps=[
                    "Review Cloud Audit Logs for AD modification details",
                    "Verify the principal performing the operation",
                    "Check AD trust relationships and security settings",
                    "Review domain controller configurations",
                    "Examine group policy objects for changes",
                    "Validate SMB signing and encryption settings",
                    "Check for unauthorised user or group additions",
                ],
                containment_actions=[
                    "Enable SMB signing on all domain controllers",
                    "Review and restrict Managed AD IAM permissions",
                    "Implement organisation policy constraints",
                    "Enable audit logging for all AD operations",
                    "Deploy Windows Admin Center for monitoring",
                    "Configure conditional access policies",
                    "Review and harden domain security policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised AD administrators and automation",
            detection_coverage="90% - catches AD configuration changes via audit logs",
            evasion_considerations="Direct attacks on domain controllers bypass this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "Managed Service for Microsoft AD",
                "Cloud Audit Logs enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1557-001-aws-netbios",
        "t1557-001-gcp-netbios",
        "t1557-001-aws-smb",
        "t1557-001-gcp-managed-ad",
        "t1557-001-aws-workspaces",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+22% improvement for Credential Access and Collection tactics",
)
