"""
T1571 - Non-Standard Port

Adversaries communicate using protocol and port pairings that deviate from standard associations
to bypass network filtering and evade detection. Used by APT32, APT33, FIN7, Lazarus Group.
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
    technique_id="T1571",
    technique_name="Non-Standard Port",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1571/",
    threat_context=ThreatContext(
        description=(
            "Adversaries communicate using application-layer protocols over non-standard ports "
            "to bypass network-based filtering and evade detection. For example, using HTTPS "
            "over port 8088 or HTTP over port 14146 instead of the traditional ports 443 and 80. "
            "This technique enables attackers to circumvent security controls that block or monitor "
            "well-known ports whilst blending malicious traffic with legitimate services."
        ),
        attacker_goal="Establish command and control channels using non-standard ports to evade network security controls",
        why_technique=[
            "Bypasses port-based firewall rules and security controls",
            "Evades network monitoring focused on standard ports",
            "Blends malicious traffic with legitimate services",
            "Allows protocol tunnelling over unexpected ports",
            "Complicates traffic analysis and detection efforts",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Non-standard port usage is a highly effective evasion technique that significantly "
            "complicates detection efforts. By mimicking legitimate services on unusual ports, "
            "attackers can maintain persistent command and control channels whilst evading "
            "traditional port-based security controls. This technique is widely adopted across "
            "sophisticated threat actors and commodity malware alike, enabling long-term compromise."
        ),
        business_impact=[
            "Undetected command and control channels enable persistent access",
            "Data exfiltration through disguised communications",
            "Bypassed security controls reduce detection effectiveness",
            "Extended dwell time increases breach impact",
            "Compliance violations from unmonitored traffic",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1048", "T1071"],
        often_follows=["T1190", "T1078.004", "T1566"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Unusual Port Usage Detection
        DetectionStrategy(
            strategy_id="t1571-aws-nonstandard-ports",
            name="AWS Non-Standard Port Detection",
            description="Detect network connections to unusual ports via VPC Flow Logs analysis.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, srcport, dstport, protocol, bytes, packets
| filter action = "ACCEPT"
| filter (dstport > 1024 and dstport < 49152) or (srcport > 1024 and srcport < 49152)
| filter dstport not in [3306, 5432, 6379, 27017, 9200, 9300]
| stats count(*) as connection_count, sum(bytes) as total_bytes by srcaddr, dstport, bin(5m)
| filter connection_count > 50 or total_bytes > 10485760
| sort connection_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect non-standard port usage via VPC Flow Logs

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String
    Default: /aws/vpc/flowlogs

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for unusual port connections
  UnusualPortFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport > 1024 && dstport < 49152, protocol, packets > 50, bytes, ...]'
      MetricTransformations:
        - MetricName: UnusualPortConnections
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: CloudWatch alarm for non-standard ports
  UnusualPortAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Non-Standard-Port-Usage
      MetricName: UnusualPortConnections
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# AWS: Non-standard port detection via VPC Flow Logs

variable "alert_email" {
  type = string
}

variable "vpc_flow_log_group" {
  type    = string
  default = "/aws/vpc/flowlogs"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "non-standard-port-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for unusual port connections
resource "aws_cloudwatch_log_metric_filter" "unusual_ports" {
  name           = "unusual-port-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport > 1024 && dstport < 49152, protocol, packets > 50, bytes, ...]"

  metric_transformation {
    name      = "UnusualPortConnections"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "unusual_ports" {
  alarm_name          = "Non-Standard-Port-Usage"
  metric_name         = "UnusualPortConnections"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Non-Standard Port Usage Detected",
                alert_description_template="Unusual port usage detected from {srcaddr} to port {dstport}: {connection_count} connections, {total_bytes} bytes transferred.",
                investigation_steps=[
                    "Identify the source and destination instances",
                    "Determine the application or service using the non-standard port",
                    "Review recent security group and network ACL changes",
                    "Check if the port usage is documented and authorised",
                    "Examine CloudTrail logs for related API activity",
                    "Correlate with other security events and indicators",
                ],
                containment_actions=[
                    "Block unauthorised traffic via security group rules",
                    "Apply restrictive network ACLs to limit port usage",
                    "Isolate affected instances for forensic analysis",
                    "Review and update firewall rules to block suspicious ports",
                    "Enable enhanced monitoring on affected resources",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known application ports (databases, caching, microservices); establish baseline for normal port usage patterns",
            detection_coverage="75% - catches most non-standard port usage",
            evasion_considerations="Attackers may use commonly-allowed application ports or slow connection rates to avoid thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 2: AWS - Security Group Port Range Monitoring
        DetectionStrategy(
            strategy_id="t1571-aws-sg-changes",
            name="AWS Security Group Port Changes",
            description="Detect creation or modification of security groups allowing unusual port ranges.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "AuthorizeSecurityGroupIngress",
                            "AuthorizeSecurityGroupEgress",
                            "CreateSecurityGroup",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor security group changes for non-standard ports

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

  # Step 2: EventBridge rule for security group changes
  SecurityGroupRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - AuthorizeSecurityGroupIngress
            - AuthorizeSecurityGroupEgress
            - CreateSecurityGroup
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy to allow EventBridge
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
                aws:SourceArn: !GetAtt SecurityGroupRule.Arn""",
                terraform_template="""# AWS: Monitor security group changes

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "security-group-port-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for security group changes
resource "aws_cloudwatch_event_rule" "sg_changes" {
  name = "security-group-port-changes"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "CreateSecurityGroup"
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "non-standard-port-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.sg_changes.name
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.sg_changes.arn
        }
      }
    }]
  })
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
            "aws:SourceArn" = aws_cloudwatch_event_rule.sg_changes.arn
          }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Security Group Port Configuration Changed",
                alert_description_template="Security group {groupId} modified to allow port {toPort}. Review to ensure authorised access.",
                investigation_steps=[
                    "Identify who made the security group change",
                    "Review the specific port ranges and protocols added",
                    "Verify if the change was authorised and documented",
                    "Check if the ports are being actively used",
                    "Examine associated instances and their purpose",
                    "Review CloudTrail for context around the change",
                ],
                containment_actions=[
                    "Revert unauthorised security group rules",
                    "Apply least-privilege security group policies",
                    "Enable MFA for security group modifications",
                    "Implement AWS Config rules for security group compliance",
                    "Review IAM permissions for ec2:AuthorizeSecurityGroup* actions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised infrastructure teams; exclude known application port ranges; implement approval workflows",
            detection_coverage="90% - catches all security group API changes",
            evasion_considerations="Attacker may use pre-existing overly permissive security groups",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - Protocol-Port Mismatch Detection
        DetectionStrategy(
            strategy_id="t1571-aws-protocol-mismatch",
            name="AWS Protocol-Port Mismatch Detection",
            description="Detect traffic where the protocol does not match the expected protocol for the destination port.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, protocol, bytes
| filter action = "ACCEPT"
| filter (dstport = 443 and protocol != 6) or (dstport = 80 and protocol != 6) or (dstport = 53 and protocol not in [6, 17])
| stats count(*) as mismatches, sum(bytes) as total_bytes by srcaddr, dstaddr, dstport, protocol
| sort mismatches desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect protocol-port mismatches in network traffic

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String
    Default: /aws/vpc/flowlogs

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create CloudWatch Insights query (manual execution required)
  # Use the query provided in the detection strategy

  # Step 3: Lambda function to analyse flow logs (optional advanced implementation)
  ProtocolMismatchFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: protocol-port-mismatch-detector
      Runtime: python3.11
      Handler: index.handler
      Role: !GetAtt LambdaRole.Arn
      Code:
        ZipFile: |
          import json
          def handler(event, context):
              # Analyse VPC Flow Logs for protocol-port mismatches
              # Implementation would parse flow logs and detect anomalies
              return {'statusCode': 200}

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
        - arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess""",
                terraform_template="""# AWS: Protocol-port mismatch detection

variable "alert_email" {
  type = string
}

variable "vpc_flow_log_group" {
  type    = string
  default = "/aws/vpc/flowlogs"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "protocol-mismatch-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Log Insights query (run manually or via scheduled Lambda)
# Use the query provided in the detection strategy description

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Step 3: Optional - Lambda for automated analysis
resource "aws_iam_role" "lambda" {
  name = "protocol-mismatch-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnLike = {
          "aws:SourceArn" = "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess"
}""",
                alert_severity="high",
                alert_title="Protocol-Port Mismatch Detected",
                alert_description_template="Protocol mismatch detected: port {dstport} using protocol {protocol} from {srcaddr}.",
                investigation_steps=[
                    "Identify the source instance and application",
                    "Verify the expected protocol for the destination port",
                    "Check for protocol tunnelling or encapsulation",
                    "Review application logs for unusual behaviour",
                    "Examine network configuration for proxies or NAT",
                ],
                containment_actions=[
                    "Block suspicious traffic patterns via security groups",
                    "Investigate and isolate potentially compromised instances",
                    "Review and enforce protocol-specific network policies",
                    "Enable deep packet inspection where available",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Account for legitimate protocol variations; exclude known proxies and tunnelling services",
            detection_coverage="60% - catches obvious protocol mismatches",
            evasion_considerations="Sophisticated attackers may correctly implement protocols over non-standard ports",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs Insights"],
        ),
        # Strategy 4: GCP - Non-Standard Port Detection
        DetectionStrategy(
            strategy_id="t1571-gcp-nonstandard-ports",
            name="GCP Non-Standard Port Detection",
            description="Detect network connections to unusual ports via VPC Flow Logs analysis.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port>1024
jsonPayload.connection.dest_port<49152
NOT jsonPayload.connection.dest_port:(3306 OR 5432 OR 6379 OR 27017 OR 9200)""",
                gcp_terraform_template="""# GCP: Non-standard port detection via VPC Flow Logs

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for unusual port connections
resource "google_logging_metric" "unusual_ports" {
  name   = "unusual-port-connections"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port>1024
    jsonPayload.connection.dest_port<49152
    NOT jsonPayload.connection.dest_port:(3306 OR 5432 OR 6379 OR 27017 OR 9200)
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for non-standard ports
resource "google_monitoring_alert_policy" "unusual_ports" {
  display_name = "Non-Standard Port Usage Detected"
  combiner     = "OR"

  conditions {
    display_name = "Unusual port connections threshold"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.unusual_ports.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Non-Standard Port Usage Detected",
                alert_description_template="Unusual port usage detected in VPC flow logs. Review connections to ensure authorised traffic.",
                investigation_steps=[
                    "Identify the source and destination instances",
                    "Review the application or service using the port",
                    "Check firewall rules for recent changes",
                    "Verify if the port usage is documented",
                    "Examine Cloud Audit Logs for related activity",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Apply restrictive firewall rules to block suspicious ports",
                    "Isolate affected instances for investigation",
                    "Review and update VPC firewall configurations",
                    "Enable hierarchical firewall policies for enforcement",
                    "Implement organisation policy constraints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known application ports; establish baseline port usage patterns for workloads",
            detection_coverage="75% - catches most non-standard port usage",
            evasion_considerations="Attackers may blend with common application traffic or use slow connection rates",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging"],
        ),
        # Strategy 5: GCP - Firewall Rule Changes
        DetectionStrategy(
            strategy_id="t1571-gcp-firewall-changes",
            name="GCP Firewall Rule Monitoring",
            description="Detect creation or modification of firewall rules allowing unusual ports.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="compute.googleapis.com"
(protoPayload.methodName="v1.compute.firewalls.insert" OR
 protoPayload.methodName="v1.compute.firewalls.patch" OR
 protoPayload.methodName="v1.compute.firewalls.update")""",
                gcp_terraform_template="""# GCP: Monitor firewall rule changes

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

# Step 2: Log-based metric for firewall changes
resource "google_logging_metric" "firewall_changes" {
  name   = "firewall-rule-changes"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName="v1.compute.firewalls.insert" OR
     protoPayload.methodName="v1.compute.firewalls.patch" OR
     protoPayload.methodName="v1.compute.firewalls.update")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "firewall_changes" {
  display_name = "Firewall Rule Modified"
  combiner     = "OR"

  conditions {
    display_name = "Firewall rule created or modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.firewall_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Firewall Rule Modified",
                alert_description_template="Firewall rule created or modified. Review to ensure authorised network access changes.",
                investigation_steps=[
                    "Identify who made the firewall rule change",
                    "Review the specific ports and protocols allowed",
                    "Verify if the change was authorised and documented",
                    "Check if the ports are being actively used",
                    "Examine associated instances and workloads",
                    "Review Cloud Audit Logs for context",
                ],
                containment_actions=[
                    "Revert unauthorised firewall rules",
                    "Implement least-privilege firewall policies",
                    "Enable organisation policy constraints for firewall rules",
                    "Review IAM permissions for compute.firewalls.* operations",
                    "Implement approval workflows for firewall changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised network and platform teams; exclude known service deployments; implement change approval workflows",
            detection_coverage="95% - catches all firewall API changes",
            evasion_considerations="Attacker may leverage pre-existing overly permissive firewall rules",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1571-aws-nonstandard-ports",
        "t1571-gcp-nonstandard-ports",
        "t1571-aws-sg-changes",
        "t1571-gcp-firewall-changes",
        "t1571-aws-protocol-mismatch",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+25% improvement for Command and Control tactic",
)
