"""
T1046 - Network Service Discovery

Adversaries attempt to enumerate services running on remote hosts and network infrastructure.
Methods include port scans, vulnerability scans, and service enumeration across cloud environments.
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
    technique_id="T1046",
    technique_name="Network Service Discovery",
    tactic_ids=["TA0007"],  # Discovery
    mitre_url="https://attack.mitre.org/techniques/T1046/",
    threat_context=ThreatContext(
        description=(
            "Adversaries attempt to enumerate services running on remote hosts to identify "
            "vulnerabilities and potential attack vectors. In cloud environments, attackers use "
            "scanning tools to discover services on EC2 instances, GCE instances, and container hosts. "
            "This reconnaissance helps attackers map the network topology, identify running services, "
            "and locate vulnerable systems for further exploitation."
        ),
        attacker_goal="Identify running services and open ports to find vulnerable systems for exploitation",
        why_technique=[
            "Identifies vulnerable services and outdated software versions",
            "Maps network topology and service architecture",
            "Locates potential entry points for lateral movement",
            "Discovers misconfigured services and exposed management interfaces",
            "Enables targeted exploitation based on discovered services",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_high",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Network service discovery is a critical reconnaissance technique that enables attackers "
            "to identify vulnerable systems and plan targeted attacks. In cloud environments, scanning "
            "activity is common but unauthorised scans can quickly map the entire infrastructure. "
            "High severity due to its role as a precursor to exploitation and lateral movement."
        ),
        business_impact=[
            "Exposure of network topology and service architecture",
            "Identification of vulnerable and outdated services",
            "Reconnaissance enabling targeted attacks",
            "Potential discovery of exposed management interfaces",
            "Privacy concerns from unauthorised network scanning",
        ],
        typical_attack_phase="reconnaissance",
        often_precedes=["T1190", "T1210", "T1021", "T1570"],
        often_follows=["T1078.004", "T1110", "T1580"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - VPC Flow Logs Port Scanning Detection
        DetectionStrategy(
            strategy_id="t1046-aws-port-scan",
            name="AWS VPC Flow Logs Port Scanning Detection",
            description="Detect rapid sequential connection attempts across multiple ports from a single source, indicating port scanning activity.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, srcport, dstport, protocol, action
| filter action = "REJECT"
| stats count() as rejectCount, count_distinct(dstport) as uniquePorts by srcaddr, dstaddr, bin(5m)
| filter uniquePorts > 20 and rejectCount > 50
| sort rejectCount desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect port scanning activity in VPC Flow Logs

Parameters:
  VpcId:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable VPC Flow Logs
  FlowLog:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceType: VPC
      ResourceIds:
        - !Ref VpcId
      TrafficType: ALL
      LogDestinationType: cloud-watch-logs
      LogGroupName: /aws/vpc/flowlogs
      DeliverLogsPermissionArn: !GetAtt FlowLogRole.Arn

  FlowLogRole:
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
                Resource: !Sub arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/vpc/flowlogs:*

  FlowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/vpc/flowlogs
      RetentionInDays: 7

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: CloudWatch alarm for port scanning
  PortScanAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: port-scanning-detected
      AlarmDescription: Multiple rejected connections to different ports detected
      MetricName: IncomingBytes
      Namespace: AWS/EC2
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1000000
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect port scanning in VPC Flow Logs

variable "vpc_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: CloudWatch Log Group and VPC Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flowlogs"
  retention_in_days = 7
}

resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-role"

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
  name = "flow-logs-policy"
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
  name = "port-scanning-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Log metric filter for port scanning
resource "aws_cloudwatch_log_metric_filter" "port_scan" {
  name           = "port-scanning-detection"
  log_group_name = aws_cloudwatch_log_group.flow_logs.name
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action=REJECT, flowlogstatus]"

  metric_transformation {
    name      = "PortScanAttempts"
    namespace = "Security/NetworkScanning"
    value     = "1"
    dimensions = {
      SourceIP = "$source"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "port_scan" {
  alarm_name          = "port-scanning-detected"
  alarm_description   = "Multiple rejected connections indicating port scanning"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "PortScanAttempts"
  namespace           = "Security/NetworkScanning"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Port Scanning Activity Detected",
                alert_description_template="Multiple rejected connection attempts detected from {srcaddr} targeting {dstaddr} across {uniquePorts} different ports. This indicates port scanning reconnaissance.",
                investigation_steps=[
                    "Identify the source IP address and determine if it's internal or external",
                    "Check if source is an authorised security scanner",
                    "Review the target ports and protocols scanned",
                    "Examine CloudTrail logs for associated API activity",
                    "Check for successful connections following the scan attempts",
                    "Review security group rules for the targeted instances",
                ],
                containment_actions=[
                    "Block source IP using network ACLs if external attacker",
                    "Isolate compromised instance if internal source",
                    "Review and tighten security group rules",
                    "Enable GuardDuty for automated threat detection",
                    "Implement AWS Network Firewall for advanced filtering",
                    "Review IAM permissions if scanning from compromised credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised vulnerability scanners and security assessment tools. Adjust thresholds based on environment size.",
            detection_coverage="85% - catches systematic port scanning but may miss slow, stealthy scans",
            evasion_considerations="Slow scans with delays between probes may avoid detection thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 2: AWS - GuardDuty Reconnaissance Findings
        DetectionStrategy(
            strategy_id="t1046-aws-guardduty",
            name="AWS GuardDuty Network Scanning Detection",
            description="Leverage GuardDuty's built-in detection for reconnaissance and port scanning activities.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.guardduty"],
                    "detail-type": ["GuardDuty Finding"],
                    "detail": {
                        "type": [
                            "Recon:EC2/PortProbeUnprotectedPort",
                            "Recon:EC2/PortProbeEMRUnprotectedPort",
                            "Recon:EC2/Portscan",
                            "UnauthorizedAccess:EC2/TorIPCaller",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network scanning using GuardDuty findings

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty (manual step required)
  # Note: GuardDuty must be enabled through console or AWS CLI

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for GuardDuty findings
  GuardDutyReconRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-network-scanning
      Description: Alert on GuardDuty reconnaissance findings
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          type:
            - Recon:EC2/PortProbeUnprotectedPort
            - Recon:EC2/PortProbeEMRUnprotectedPort
            - Recon:EC2/Portscan
            - UnauthorizedAccess:EC2/TorIPCaller
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# AWS: GuardDuty reconnaissance detection

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true

  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "guardduty-recon-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for reconnaissance findings
resource "aws_cloudwatch_event_rule" "guardduty_recon" {
  name        = "guardduty-network-scanning"
  description = "Alert on GuardDuty reconnaissance findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Recon:EC2/PortProbeUnprotectedPort",
        "Recon:EC2/PortProbeEMRUnprotectedPort",
        "Recon:EC2/Portscan",
        "UnauthorizedAccess:EC2/TorIPCaller"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.guardduty_recon.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Network Reconnaissance Detected",
                alert_description_template="GuardDuty detected {type} activity targeting {resource}. Severity: {severity}",
                investigation_steps=[
                    "Review the GuardDuty finding details in the console",
                    "Identify the source IP and check threat intelligence",
                    "Examine the targeted resources and ports",
                    "Check if any connections succeeded after the scan",
                    "Review CloudTrail for associated API activity",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Block malicious source IPs using network ACLs",
                    "Review and restrict security group ingress rules",
                    "Enable AWS Network Firewall for advanced protection",
                    "Implement AWS WAF for public-facing applications",
                    "Consider enabling GuardDuty Malware Protection",
                    "Review IAM policies for overly permissive network access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses threat intelligence and machine learning to minimise false positives. Whitelist known scanners if needed.",
            detection_coverage="90% - GuardDuty provides comprehensive reconnaissance detection",
            evasion_considerations="Very slow scans or scans from trusted IP ranges may avoid detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$50-200 depending on data volume",
            prerequisites=["GuardDuty enabled (30-day free trial available)"],
        ),
        # Strategy 3: AWS - Security Group Modification After Scanning
        DetectionStrategy(
            strategy_id="t1046-aws-sg-recon",
            name="Security Group Enumeration Detection",
            description="Detect API calls attempting to enumerate security group rules, which attackers use to map network access controls.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, eventName, errorCode
| filter eventName in ["DescribeSecurityGroups", "DescribeSecurityGroupRules", "DescribeInstances", "DescribeNetworkInterfaces"]
| stats count() as apiCallCount by userIdentity.principalId, sourceIPAddress, bin(5m)
| filter apiCallCount > 50
| sort apiCallCount desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect excessive security group enumeration

Parameters:
  CloudTrailLogGroup:
    Type: String
    Default: /aws/cloudtrail/logs
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

  # Step 2: Metric filter for enumeration
  EnumerationMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = DescribeSecurityGroups) || ($.eventName = DescribeSecurityGroupRules) || ($.eventName = DescribeInstances) }'
      MetricTransformations:
        - MetricNamespace: Security/Reconnaissance
          MetricName: SecurityGroupEnumeration
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: CloudWatch alarm
  EnumerationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: security-group-enumeration
      AlarmDescription: Excessive security group enumeration detected
      MetricName: SecurityGroupEnumeration
      Namespace: Security/Reconnaissance
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Detect security group enumeration

variable "cloudtrail_log_group" {
  type    = string
  default = "/aws/cloudtrail/logs"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "sg-enumeration-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter
resource "aws_cloudwatch_log_metric_filter" "sg_enumeration" {
  name           = "security-group-enumeration"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ ($.eventName = DescribeSecurityGroups) || ($.eventName = DescribeSecurityGroupRules) || ($.eventName = DescribeInstances) }"

  metric_transformation {
    name      = "SecurityGroupEnumeration"
    namespace = "Security/Reconnaissance"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "sg_enumeration" {
  alarm_name          = "security-group-enumeration"
  alarm_description   = "Excessive security group enumeration detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SecurityGroupEnumeration"
  namespace           = "Security/Reconnaissance"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Excessive Security Group Enumeration",
                alert_description_template="Principal {principalId} made {apiCallCount} security group enumeration API calls from {sourceIPAddress}. This may indicate reconnaissance activity.",
                investigation_steps=[
                    "Identify the IAM principal making the API calls",
                    "Check if this is an authorised security scanner or audit tool",
                    "Review the source IP address for suspicious activity",
                    "Examine what other API calls the principal made",
                    "Check for successful authentication from unusual locations",
                    "Review recent IAM credential activity",
                ],
                containment_actions=[
                    "Rotate credentials if compromise suspected",
                    "Apply SCPs to restrict reconnaissance API calls",
                    "Implement condition keys requiring MFA for describe operations",
                    "Review and reduce overly broad IAM policies",
                    "Enable CloudTrail Insights for anomaly detection",
                    "Consider implementing AWS Config rules for compliance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised security tools, CI/CD pipelines, and infrastructure management tools",
            detection_coverage="75% - detects API-based enumeration but not network-level scanning",
            evasion_considerations="Attackers may use stolen credentials with existing authorised access",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        # Strategy 4: GCP - VPC Flow Logs Port Scanning Detection
        DetectionStrategy(
            strategy_id="t1046-gcp-port-scan",
            name="GCP VPC Flow Logs Port Scanning Detection",
            description="Detect rapid connection attempts across multiple ports indicating port scanning in GCP networks.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port>0
jsonPayload.reporter="DEST"
| filter jsonPayload.packets_sent < 5
| stats count() as connectionAttempts, count(distinct(jsonPayload.connection.dest_port)) as uniquePorts by jsonPayload.connection.src_ip, jsonPayload.connection.dest_ip, window(5m)
| filter uniquePorts > 20 and connectionAttempts > 50""",
                gcp_terraform_template="""# GCP: Detect port scanning in VPC Flow Logs

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

# Step 2: Log-based metric for port scanning
resource "google_logging_metric" "port_scan" {
  name   = "port-scanning-detection"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.reporter="DEST"
    jsonPayload.packets_sent<5
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP performing scanning"
    }
    labels {
      key         = "dest_ip"
      value_type  = "STRING"
      description = "Destination IP being scanned"
    }
  }

  label_extractors = {
    "source_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
    "dest_ip"   = "EXTRACT(jsonPayload.connection.dest_ip)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "port_scan" {
  display_name = "Port Scanning Activity Detected"
  combiner     = "OR"

  conditions {
    display_name = "Multiple connection attempts to different ports"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.port_scan.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Port scanning activity detected. Multiple rejected connections from a single source indicate reconnaissance."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Port Scanning Activity Detected",
                alert_description_template="Multiple connection attempts detected from {source_ip} targeting {dest_ip} across multiple ports. This indicates network service discovery scanning.",
                investigation_steps=[
                    "Identify the source IP and check if it's internal or external",
                    "Verify if source is an authorised security scanner",
                    "Review the target ports and services scanned",
                    "Check Cloud Audit Logs for associated API activity",
                    "Examine if any connections succeeded",
                    "Review firewall rules for the targeted instances",
                ],
                containment_actions=[
                    "Block source IP using VPC firewall rules if external",
                    "Isolate compromised instance if internal source",
                    "Review and restrict firewall ingress rules",
                    "Enable Cloud IDS for intrusion detection",
                    "Implement Cloud Armour for DDoS protection",
                    "Review service account permissions if scanning from GCP",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised vulnerability scanners and adjust thresholds for environment size",
            detection_coverage="85% - detects systematic scanning but may miss slow reconnaissance",
            evasion_considerations="Slow, distributed scans may avoid rate-based detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$15-40",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging"],
        ),
        # Strategy 5: GCP - API Enumeration Detection
        DetectionStrategy(
            strategy_id="t1046-gcp-api-enum",
            name="GCP Compute API Enumeration Detection",
            description="Detect excessive API calls to enumerate GCP compute resources, instances, and network configuration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="compute.googleapis.com"
(protoPayload.methodName=~"list" OR protoPayload.methodName=~"get")
(protoPayload.methodName=~"instances" OR protoPayload.methodName=~"firewalls" OR protoPayload.methodName=~"networks")
| stats count() as apiCalls by protoPayload.authenticationInfo.principalEmail, protoPayload.requestMetadata.callerIp
| filter apiCalls > 100""",
                gcp_terraform_template="""# GCP: Detect compute resource enumeration

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

# Step 2: Log-based metric for enumeration
resource "google_logging_metric" "compute_enumeration" {
  name   = "compute-resource-enumeration"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName=~".*list.*" OR protoPayload.methodName=~".*get.*")
    (protoPayload.methodName=~".*instances.*" OR
     protoPayload.methodName=~".*firewalls.*" OR
     protoPayload.methodName=~".*networks.*")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal performing enumeration"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "enumeration" {
  display_name = "Excessive Compute Resource Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "High volume of enumeration API calls"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.compute_enumeration.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Excessive compute resource enumeration detected. This may indicate reconnaissance activity."
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Excessive Compute Resource Enumeration",
                alert_description_template="Principal {principal} made {apiCalls} enumeration API calls. This may indicate network reconnaissance activity.",
                investigation_steps=[
                    "Identify the principal (user or service account)",
                    "Check if this is an authorised security tool or scanner",
                    "Review the source IP address for suspicious activity",
                    "Examine what other API calls were made",
                    "Check for recent authentication anomalies",
                    "Review IAM permissions for the principal",
                ],
                containment_actions=[
                    "Rotate service account keys if compromise suspected",
                    "Apply organisation policies to restrict enumeration",
                    "Implement VPC Service Controls for data perimeter",
                    "Review and reduce overly permissive IAM roles",
                    "Enable Cloud Asset Inventory for visibility",
                    "Consider implementing Context-Aware Access policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised infrastructure tools, CI/CD pipelines, and monitoring systems",
            detection_coverage="75% - detects API enumeration but not network-level scanning",
            evasion_considerations="Attackers using compromised service accounts with legitimate access may blend in",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1046-aws-guardduty",
        "t1046-gcp-port-scan",
        "t1046-aws-port-scan",
        "t1046-aws-sg-recon",
        "t1046-gcp-api-enum",
    ],
    total_effort_hours=3.5,
    coverage_improvement="+25% improvement for Discovery tactic coverage",
)
