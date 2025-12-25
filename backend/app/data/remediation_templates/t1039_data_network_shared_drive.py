"""
T1039 - Data from Network Shared Drive

Adversaries may search network shares on computers they have compromised to find files of interest.
Sensitive data can be collected from remote systems via shared network drives.
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
    technique_id="T1039",
    technique_name="Data from Network Shared Drive",
    tactic_ids=["TA0009"],  # Collection
    mitre_url="https://attack.mitre.org/techniques/T1039/",
    threat_context=ThreatContext(
        description=(
            "Adversaries search network shares on compromised systems to locate and collect sensitive files "
            "before exfiltration. In cloud environments, this includes accessing shared file systems like "
            "Amazon EFS, FSx, or Google Filestore, as well as SMB/NFS mounts between instances. Attackers "
            "leverage standard system tools and commands to enumerate and copy files from network-accessible "
            "storage locations, often targeting documents, configuration files, and credentials."
        ),
        attacker_goal="Locate and collect sensitive files from network-accessible shared drives and file systems",
        why_technique=[
            "Network shares often contain valuable business data and documents",
            "File access blends with legitimate user and application behaviour",
            "Shared drives frequently have weak access controls or overprivileged permissions",
            "Standard system tools can be used, avoiding custom malware detection",
            "Cloud file systems may lack detailed access monitoring",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="steady",
        severity_score=7,
        severity_reasoning=(
            "Network shared drive access is a common collection technique enabling theft of sensitive "
            "business documents, intellectual property, and credentials. Whilst the technique relies on "
            "legitimate system features making prevention difficult, detection is possible through anomalous "
            "access patterns and file operations. Medium-high severity due to potential for large-scale "
            "data theft and the challenge of distinguishing malicious from legitimate activity."
        ),
        business_impact=[
            "Theft of sensitive business documents and intellectual property",
            "Exposure of credentials and configuration files",
            "Potential compliance violations from unauthorised data access",
            "Loss of competitive advantage from stolen proprietary information",
            "Regulatory penalties if customer or personal data is accessed",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1074", "T1560", "T1048", "T1041"],
        often_follows=["T1078.004", "T1083", "T1021"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - EFS File System Access Monitoring
        DetectionStrategy(
            strategy_id="t1039-aws-efs-access",
            name="AWS EFS Unusual Access Detection",
            description="Detect anomalous access patterns to Amazon EFS file systems that may indicate unauthorised file collection.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, requestParameters.fileSystemId as filesystem,
       sourceIPAddress, eventName
| filter eventSource = "elasticfilesystem.amazonaws.com"
| filter eventName in ["CreateAccessPoint", "CreateMountTarget", "DescribeFileSystems", "DescribeMountTargets"]
| stats count(*) as access_count by user, filesystem, bin(1h) as hour_window
| filter access_count >= 5
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual EFS file system access

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: EFS Access Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for EFS access
  EFSAccessMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = elasticfilesystem.amazonaws.com) && (($.eventName = CreateAccessPoint) || ($.eventName = CreateMountTarget) || ($.eventName = DescribeFileSystems)) }'
      MetricTransformations:
        - MetricName: EFSAccessActivity
          MetricNamespace: Security/T1039
          MetricValue: "1"

  # Step 3: CloudWatch alarm for unusual EFS access
  EFSAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1039-EFSUnusualAccess
      AlarmDescription: Unusual EFS access pattern detected
      MetricName: EFSAccessActivity
      Namespace: Security/T1039
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect unusual EFS file system access

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "efs_alerts" {
  name         = "efs-access-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "EFS Access Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.efs_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for EFS access
resource "aws_cloudwatch_log_metric_filter" "efs_access" {
  name           = "efs-access-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = elasticfilesystem.amazonaws.com) && (($.eventName = CreateAccessPoint) || ($.eventName = CreateMountTarget) || ($.eventName = DescribeFileSystems)) }"

  metric_transformation {
    name      = "EFSAccessActivity"
    namespace = "Security/T1039"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm for unusual EFS access
resource "aws_cloudwatch_metric_alarm" "efs_access" {
  alarm_name          = "T1039-EFSUnusualAccess"
  alarm_description   = "Unusual EFS access pattern detected"
  metric_name         = "EFSAccessActivity"
  namespace           = "Security/T1039"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.efs_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.efs_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.efs_alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Unusual EFS File System Access Detected",
                alert_description_template=(
                    "User {user} performed {access_count} EFS operations on file system {filesystem} in 1 hour. "
                    "This may indicate unauthorised file collection from shared storage."
                ),
                investigation_steps=[
                    "Identify the user/role accessing the EFS file system",
                    "Review which instances have the file system mounted",
                    "Check EFS access point configurations and permissions",
                    "Examine CloudWatch Logs for file-level operations if enabled",
                    "Verify if this matches the user's normal access patterns",
                    "Review recent authentication activity for the principal",
                ],
                containment_actions=[
                    "Remove unauthorised EFS access points and mount targets",
                    "Update EFS file system policies to restrict access",
                    "Review and tighten IAM permissions for EFS operations",
                    "Enable EFS access logging if not already configured",
                    "Rotate credentials for compromised users/roles",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal EFS access patterns; exclude application and backup service accounts",
            detection_coverage="70% - covers EFS API access but not file-level operations",
            evasion_considerations="Attackers may use existing mount points; file-level access not logged by default",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs configured"],
        ),
        # Strategy 2: AWS - FSx File System Access Monitoring
        DetectionStrategy(
            strategy_id="t1039-aws-fsx-access",
            name="AWS FSx Shared Drive Access Detection",
            description="Monitor Amazon FSx file systems for unusual access patterns indicating data collection from Windows or Lustre file shares.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.fsx"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateFileSystem",
                            "CreateDataRepositoryAssociation",
                            "DescribeFileSystems",
                            "DescribeBackups",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect FSx file system access for shared drive collection

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

  # Step 2: EventBridge rule for FSx access
  FSxAccessRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.fsx]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateFileSystem
            - CreateDataRepositoryAssociation
            - DescribeFileSystems
            - DescribeBackups
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect FSx file system access

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "fsx-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for FSx access
resource "aws_cloudwatch_event_rule" "fsx_access" {
  name = "fsx-access-detection"
  event_pattern = jsonencode({
    source      = ["aws.fsx"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateFileSystem",
        "CreateDataRepositoryAssociation",
        "DescribeFileSystems",
        "DescribeBackups"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.fsx_access.name
  arn  = aws_sns_topic.alerts.arn
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
    }]
  })
}""",
                alert_severity="medium",
                alert_title="FSx File System Access Detected",
                alert_description_template="FSx file system operation {eventName} performed. This may indicate access to shared Windows or Lustre file systems.",
                investigation_steps=[
                    "Identify the FSx file system being accessed",
                    "Review the user/role performing the operations",
                    "Check which EC2 instances have the file system mounted",
                    "Examine FSx audit logs for file-level access patterns",
                    "Verify if this matches expected application behaviour",
                    "Review security group rules for the file system",
                ],
                containment_actions=[
                    "Restrict FSx file system access using security groups",
                    "Update file system policies and Active Directory permissions",
                    "Review and restrict IAM permissions for FSx operations",
                    "Enable FSx audit logging to CloudWatch Logs",
                    "Consider enabling MFA for sensitive FSx operations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised backup and application service accounts",
            detection_coverage="65% - covers API access but not all file-level operations",
            evasion_considerations="Attackers may use existing connections; SMB/NFS file access not fully logged",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - SMB/NFS Network Share Enumeration
        DetectionStrategy(
            strategy_id="t1039-aws-share-enum",
            name="Network Share Enumeration Detection",
            description="Detect enumeration of network shares from EC2 instances using VPC Flow Logs and CloudWatch Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, protocol, action
| filter (dstport = 445 or dstport = 139 or dstport = 2049)
| filter protocol = 6
| stats count() as connection_count by srcaddr, dstaddr, dstport
| filter connection_count >= 10
| sort connection_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network share enumeration via SMB/NFS ports

Parameters:
  VpcId:
    Type: String
  LogGroupName:
    Type: String
    Default: /aws/vpc/flowlogs
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
      LogGroupName: !Ref LogGroupName
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
                Resource: !Sub arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:${LogGroupName}:*

  # Step 2: CloudWatch Log Group
  FlowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Ref LogGroupName
      RetentionInDays: 7

  # Step 3: SNS topic for manual review alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Network Share Enumeration Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail""",
                terraform_template="""# Detect network share enumeration

variable "vpc_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flowlogs-share-detection"
  retention_in_days = 7
}

# Step 2: IAM role for Flow Logs
resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-share-detection"

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

# Step 3: VPC Flow Log
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = var.vpc_id
}""",
                alert_severity="medium",
                alert_title="Network Share Enumeration Detected",
                alert_description_template="Instance {srcaddr} made {connection_count} connections to SMB/NFS ports on {dstaddr}. This may indicate network share enumeration.",
                investigation_steps=[
                    "Identify the source instance performing share enumeration",
                    "Review the target instances and their file shares",
                    "Check if the source instance has legitimate file server access needs",
                    "Examine CloudWatch Logs for related process execution",
                    "Review recent authentication events from the source instance",
                    "Verify security group rules allowing SMB/NFS traffic",
                ],
                containment_actions=[
                    "Restrict SMB/NFS traffic using security groups and NACLs",
                    "Isolate suspicious instances from the network",
                    "Review and update file share permissions",
                    "Enable detailed monitoring on affected instances",
                    "Consider implementing network microsegmentation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Baseline normal file server access; exclude file servers and backup systems from alerting",
            detection_coverage="60% - behavioural analysis of network patterns",
            evasion_considerations="Low-volume access may not trigger thresholds; encrypted protocols hide content",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 4: GCP - Filestore Access Detection
        DetectionStrategy(
            strategy_id="t1039-gcp-filestore",
            name="GCP Filestore Access Monitoring",
            description="Detect unusual access to Google Cloud Filestore instances that may indicate unauthorised file collection from shared NFS storage.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="file.googleapis.com"
protoPayload.methodName=~"google.cloud.filestore.v1.CloudFilestoreManager.(Get|List|Create)"
severity>=WARNING""",
                gcp_terraform_template="""# GCP: Detect Filestore access

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

# Step 2: Log-based metric for Filestore access
resource "google_logging_metric" "filestore_access" {
  name   = "filestore-access-activity"
  filter = <<-EOT
    protoPayload.serviceName="file.googleapis.com"
    protoPayload.methodName=~"google.cloud.filestore.v1.CloudFilestoreManager.(Get|List|Create)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for unusual Filestore access
resource "google_monitoring_alert_policy" "filestore_alert" {
  display_name = "Unusual Filestore Access Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume Filestore operations"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.filestore_access.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    notification_rate_limit {
      period = "3600s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Unusual Filestore Access Detected",
                alert_description_template="High volume of Filestore operations detected. This may indicate unauthorised access to shared NFS file storage.",
                investigation_steps=[
                    "Identify which Filestore instances were accessed",
                    "Review the principal performing the operations",
                    "Check which compute instances have the Filestore mounted",
                    "Examine VPC firewall rules for NFS traffic",
                    "Verify if this matches expected application behaviour",
                    "Review recent authentication events for the principal",
                ],
                containment_actions=[
                    "Restrict Filestore access using VPC firewall rules",
                    "Review and update Filestore instance IAM permissions",
                    "Enable VPC Service Controls to limit access",
                    "Review NFS export settings and allowed networks",
                    "Revoke service account credentials if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal Filestore access; exclude application and backup service accounts",
            detection_coverage="70% - covers API access but not file-level NFS operations",
            evasion_considerations="Attackers may use existing mounts; NFS file-level access not logged",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - Network File Access Pattern Detection
        DetectionStrategy(
            strategy_id="t1039-gcp-network-shares",
            name="GCP Network Share Access Pattern Detection",
            description="Analyse VPC Flow Logs for unusual SMB/NFS traffic patterns indicating network share enumeration and data collection.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
(jsonPayload.connection.dest_port=445 OR jsonPayload.connection.dest_port=139 OR jsonPayload.connection.dest_port=2049)
jsonPayload.connection.protocol=6""",
                gcp_terraform_template="""# GCP: Detect network share access patterns

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

# Step 2: Log-based metric for SMB/NFS traffic
resource "google_logging_metric" "share_access" {
  name   = "network-share-access"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
    (jsonPayload.connection.dest_port=445 OR jsonPayload.connection.dest_port=139 OR jsonPayload.connection.dest_port=2049)
    jsonPayload.connection.protocol=6
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for unusual share access
resource "google_monitoring_alert_policy" "share_access_alert" {
  display_name = "Network Share Access Pattern Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume SMB/NFS connections"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.share_access.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    notification_rate_limit {
      period = "3600s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Network Share Access Pattern Detected",
                alert_description_template="High volume of SMB/NFS connections detected. This may indicate network share enumeration or data collection activity.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review which instances have file sharing enabled",
                    "Check VPC firewall rules for SMB/NFS traffic",
                    "Examine instance logs for file access patterns",
                    "Verify if this is legitimate application behaviour",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Apply VPC firewall rules to restrict file sharing traffic",
                    "Review and update file share permissions",
                    "Enable enhanced monitoring on affected instances",
                    "Consider implementing network microsegmentation",
                    "Review service account permissions and rotate credentials",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Establish baselines for file server traffic; exclude legitimate file servers and backup systems",
            detection_coverage="60% - behavioural analysis of network traffic patterns",
            evasion_considerations="Low-volume access may not trigger alerts; encrypted protocols hide content",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging"],
        ),
    ],
    recommended_order=[
        "t1039-aws-efs-access",
        "t1039-gcp-filestore",
        "t1039-aws-fsx-access",
        "t1039-aws-share-enum",
        "t1039-gcp-network-shares",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+25% improvement for Collection tactic",
)
