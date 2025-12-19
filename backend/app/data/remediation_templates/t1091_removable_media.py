"""
T1091 - Replication Through Removable Media

Adversaries exploit removable media to spread malware across systems, particularly
air-gapped networks. Attack leverages Autorun features and may involve modified
USB devices, including malicious charging cables and mobile devices.
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
    technique_id="T1091",
    technique_name="Replication Through Removable Media",
    tactic_ids=["TA0001", "TA0008"],  # Initial Access, Lateral Movement
    mitre_url="https://attack.mitre.org/techniques/T1091/",

    threat_context=ThreatContext(
        description=(
            "Adversaries exploit removable media such as USB drives, external hard drives, "
            "and mobile devices to spread malware across systems. This technique is particularly "
            "effective against air-gapped networks and isolated environments. In cloud contexts, "
            "attackers target cloud workspaces, virtual desktop infrastructure (VDI), and EC2 "
            "instances where USB passthrough or device mounting is enabled. Notable malware using "
            "this vector includes Stuxnet, Conficker, Agent.btz, and Raspberry Robin."
        ),
        attacker_goal="Spread malware via removable media to compromise isolated or air-gapped systems",
        why_technique=[
            "Bypasses network-based security controls",
            "Effective against air-gapped and isolated networks",
            "Social engineering component makes detection difficult",
            "Can spread automatically via Autorun functionality",
            "Difficult to prevent in environments requiring USB access",
            "Works across network boundaries"
        ],
        known_threat_actors=[
            "APT28",
            "APT30",
            "Aoqin Dragon",
            "Darkhotel",
            "FIN7",
            "Gamaredon Group",
            "LuminousMoth",
            "Mustang Panda",
            "Tropic Trooper"
        ],
        recent_campaigns=[
            Campaign(
                name="FIN7 USB Ransomware Campaign",
                year=2021,
                description="FIN7 mailed USB drives containing ransomware to retail and hospitality companies, disguised as COVID-19 safety guidelines or customer complaints",
                reference_url="https://attack.mitre.org/groups/G0046/"
            ),
            Campaign(
                name="Raspberry Robin Worm",
                year=2022,
                description="Widespread worm spreading via USB drives and external drives, observed deploying additional malware including IcedID and Bumblebee",
                reference_url="https://attack.mitre.org/software/S1040/"
            ),
            Campaign(
                name="Gamaredon USB Spreading",
                year=2023,
                description="Gamaredon Group used USB-spreading malware to compromise Ukrainian government networks and spread laterally across air-gapped systems",
                reference_url="https://attack.mitre.org/groups/G0047/"
            ),
            Campaign(
                name="Agent.btz Pentagon Breach",
                year=2008,
                description="Nation-state malware spread via infected USB drive into classified US military networks, leading to creation of US Cyber Command",
                reference_url="https://attack.mitre.org/techniques/T1091/"
            )
        ],
        prevalence="moderate",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "High severity due to ability to bypass network controls and compromise air-gapped "
            "systems. Particularly dangerous for critical infrastructure and high-security "
            "environments. Historical precedent shows this vector can compromise highly secure "
            "networks (Stuxnet, Agent.btz). Social engineering component makes prevention difficult."
        ),
        business_impact=[
            "Compromise of air-gapped or isolated systems",
            "Bypass of network security controls",
            "Introduction of malware to secure environments",
            "Potential for widespread lateral movement",
            "Compliance violations in regulated environments",
            "Data exfiltration from isolated networks"
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1059.001", "T1071", "T1105", "T1570", "T1204.002"],
        often_follows=["T1566.001", "T1195.003"]
    ),

    detection_strategies=[
        # Strategy 1: AWS - WorkSpaces USB Device Detection
        DetectionStrategy(
            strategy_id="t1091-aws-workspaces-usb",
            name="AWS WorkSpaces USB Device Connection Detection",
            description="Detect USB device connections to Amazon WorkSpaces virtual desktops.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, @message, userIdentity.principalId
| filter @message like /USB/ or @message like /removable/ or @message like /storage device/
| filter @message like /connected|attached|mounted/
| stats count(*) as deviceConnections by userIdentity.principalId, bin(1h)
| filter deviceConnections > 0
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect USB device connections in AWS WorkSpaces

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: USB Device Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch Log Group for WorkSpaces
  WorkSpacesLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/workspaces/usb-monitoring
      RetentionInDays: 30

  # Step 3: Metric filter for USB connections
  USBConnectionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref WorkSpacesLogGroup
      FilterPattern: '[timestamp, workspace, level, msg="*USB*connect*" || msg="*removable*" || msg="*storage device*"]'
      MetricTransformations:
        - MetricName: USBDeviceConnections
          MetricNamespace: Security/RemovableMedia
          MetricValue: "1"

  # Step 4: CloudWatch alarm
  USBConnectionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: WorkSpaces-USB-Device-Connected
      AlarmDescription: Alert when USB devices connect to WorkSpaces
      MetricName: USBDeviceConnections
      Namespace: Security/RemovableMedia
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching''',
                terraform_template='''# AWS: Detect USB device connections in WorkSpaces

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "usb_alerts" {
  name         = "workspaces-usb-device-alerts"
  display_name = "USB Device Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.usb_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch Log Group
resource "aws_cloudwatch_log_group" "workspaces_usb" {
  name              = "/aws/workspaces/usb-monitoring"
  retention_in_days = 30
}

# Step 3: Metric filter for USB connections
resource "aws_cloudwatch_log_metric_filter" "usb_connection" {
  name           = "usb-device-connections"
  log_group_name = aws_cloudwatch_log_group.workspaces_usb.name
  pattern        = "[timestamp, workspace, level, msg=\"*USB*connect*\" || msg=\"*removable*\" || msg=\"*storage device*\"]"

  metric_transformation {
    name      = "USBDeviceConnections"
    namespace = "Security/RemovableMedia"
    value     = "1"
  }
}

# Step 4: CloudWatch alarm for USB connections
resource "aws_cloudwatch_metric_alarm" "usb_connection" {
  alarm_name          = "WorkSpaces-USB-Device-Connected"
  alarm_description   = "Alert when USB devices connect to WorkSpaces"
  metric_name         = "USBDeviceConnections"
  namespace           = "Security/RemovableMedia"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.usb_alerts.arn]
  treat_missing_data  = "notBreaching"
}''',
                alert_severity="high",
                alert_title="USB Device Connected to WorkSpace",
                alert_description_template="USB or removable storage device connected to WorkSpace {workspaceId} by user {principalId}.",
                investigation_steps=[
                    "Identify the WorkSpace and user involved",
                    "Determine if USB access is authorised for this user",
                    "Review files accessed or transferred during connection",
                    "Check for autorun.inf or suspicious executable files",
                    "Examine WorkSpace security logs for malware indicators",
                    "Verify the business justification for USB usage",
                    "Check if device is registered in asset management system"
                ],
                containment_actions=[
                    "Disable USB redirection for affected WorkSpace if unauthorised",
                    "Quarantine WorkSpace for forensic analysis if malware suspected",
                    "Run antimalware scan on WorkSpace",
                    "Review and restrict USB access policies organisation-wide",
                    "Enable USB device allowlisting if supported",
                    "Implement data loss prevention (DLP) for removable media",
                    "Document incident and update security policies"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised users and job roles requiring USB access; implement device registration system",
            detection_coverage="80% - covers WorkSpaces with USB redirection enabled",
            evasion_considerations="Does not detect USB connections to on-premises systems or EC2 instances without proper logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["WorkSpaces deployed", "USB redirection configured", "CloudWatch Logs enabled"]
        ),

        # Strategy 2: AWS - EC2 Systems Manager USB Device Inventory
        DetectionStrategy(
            strategy_id="t1091-aws-ssm-inventory",
            name="AWS Systems Manager USB Device Inventory",
            description="Use AWS Systems Manager Inventory to detect USB and removable storage devices connected to EC2 instances.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="systems_manager",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["Inventory Resource State Change"],
                    "detail": {
                        "resourceType": ["AWS:WindowsUpdate", "AWS:Application", "Custom:USBDevice"]
                    }
                },
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor USB devices via Systems Manager Inventory

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: USB Inventory Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Systems Manager Association for inventory
  InventoryAssociation:
    Type: AWS::SSM::Association
    Properties:
      Name: AWS-GatherSoftwareInventory
      ScheduleExpression: rate(30 minutes)
      Targets:
        - Key: InstanceIds
          Values:
            - "*"
      Parameters:
        applications:
          - Enabled
        customInventory:
          - Enabled
        windowsUpdates:
          - Enabled

  # Step 3: EventBridge rule for inventory changes
  InventoryChangeRule:
    Type: AWS::Events::Rule
    Properties:
      Name: usb-device-inventory-detection
      Description: Detect USB device inventory changes
      EventPattern:
        source:
          - aws.ssm
        detail-type:
          - Inventory Resource State Change
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 4: Topic policy
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
            Resource: !Ref AlertTopic''',
                terraform_template='''# AWS: Monitor USB devices via Systems Manager

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic
resource "aws_sns_topic" "inventory_alerts" {
  name = "usb-inventory-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.inventory_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Systems Manager Association
resource "aws_ssm_association" "inventory" {
  name                = "AWS-GatherSoftwareInventory"
  schedule_expression = "rate(30 minutes)"

  targets {
    key    = "InstanceIds"
    values = ["*"]
  }

  parameters = {
    applications     = "Enabled"
    customInventory  = "Enabled"
    windowsUpdates   = "Enabled"
  }
}

# Step 3: EventBridge rule
resource "aws_cloudwatch_event_rule" "inventory_change" {
  name        = "usb-device-inventory-detection"
  description = "Detect USB device inventory changes"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["Inventory Resource State Change"]
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.inventory_change.name
  target_id = "InventoryAlert"
  arn       = aws_sns_topic.inventory_alerts.arn
}

# Step 4: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.inventory_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.inventory_alerts.arn
    }]
  })
}''',
                alert_severity="medium",
                alert_title="USB Device Detected via Systems Manager Inventory",
                alert_description_template="New USB or removable storage device detected on instance {instanceId}.",
                investigation_steps=[
                    "Review Systems Manager inventory data for the instance",
                    "Identify the USB device type and manufacturer",
                    "Check if device is authorised in asset inventory",
                    "Review instance access logs around connection time",
                    "Examine files transferred to/from device",
                    "Check for malware signatures in transferred files",
                    "Verify business justification for device usage"
                ],
                containment_actions=[
                    "Disable USB ports via Group Policy if unauthorised",
                    "Run malware scan on affected instance",
                    "Isolate instance if malware detected",
                    "Implement USB device allowlisting",
                    "Enable USB storage encryption requirements",
                    "Review and update device control policies"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known-good USB devices and authorised users; implement device registration workflow",
            detection_coverage="70% - requires SSM agent on all instances",
            evasion_considerations="Requires Systems Manager agent installed and running; may miss short-lived connections",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["Systems Manager agent installed", "Inventory collection enabled", "EventBridge configured"]
        ),

        # Strategy 3: AWS - S3 Upload from Suspicious Sources
        DetectionStrategy(
            strategy_id="t1091-aws-s3-upload",
            name="S3 Uploads from Untrusted Devices",
            description="Detect file uploads to S3 that may originate from removable media or untrusted devices.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="s3",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["PutObject", "UploadPart", "CompleteMultipartUpload"]
                    }
                },
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious S3 uploads potentially from removable media

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts
  MonitoredBucket:
    Type: String
    Description: S3 bucket to monitor

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: S3 Upload Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for S3 uploads
  S3UploadRule:
    Type: AWS::Events::Rule
    Properties:
      Name: s3-suspicious-upload-detection
      EventPattern:
        source:
          - aws.s3
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - PutObject
            - UploadPart
            - CompleteMultipartUpload
          requestParameters:
            bucketName:
              - !Ref MonitoredBucket
      Targets:
        - Id: Alert
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
            Resource: !Ref AlertTopic''',
                terraform_template='''# AWS: Detect suspicious S3 uploads

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "monitored_bucket" {
  type        = string
  description = "S3 bucket to monitor for suspicious uploads"
}

# Step 1: SNS topic
resource "aws_sns_topic" "upload_alerts" {
  name = "s3-suspicious-upload-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.upload_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for S3 uploads
resource "aws_cloudwatch_event_rule" "s3_upload" {
  name        = "s3-suspicious-upload-detection"
  description = "Detect suspicious S3 uploads potentially from removable media"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutObject",
        "UploadPart",
        "CompleteMultipartUpload"
      ]
      requestParameters = {
        bucketName = [var.monitored_bucket]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.s3_upload.name
  target_id = "UploadAlert"
  arn       = aws_sns_topic.upload_alerts.arn
}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.upload_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.upload_alerts.arn
    }]
  })
}''',
                alert_severity="medium",
                alert_title="Suspicious S3 Upload Detected",
                alert_description_template="File uploaded to S3 bucket {bucketName} by {principalId}. Review for potential removable media transfer.",
                investigation_steps=[
                    "Identify the uploaded file and its source",
                    "Review user activity around upload time",
                    "Check for concurrent USB device connections",
                    "Scan uploaded file for malware",
                    "Examine file metadata and properties",
                    "Verify business justification for upload",
                    "Check if upload matches known file transfer patterns"
                ],
                containment_actions=[
                    "Quarantine suspicious files in S3",
                    "Run malware scanning on uploaded objects",
                    "Block further uploads from suspicious sources",
                    "Enable S3 Object Lock for critical buckets",
                    "Implement S3 bucket policies restricting upload sources",
                    "Enable MFA Delete on sensitive buckets"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Establish baseline upload patterns; whitelist known-good upload sources and automated processes",
            detection_coverage="60% - requires correlation with other signals",
            evasion_considerations="High false positive rate; requires correlation with USB detection for accuracy",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "S3 data events logged"]
        ),

        # Strategy 4: GCP - Compute Instance USB Device Detection
        DetectionStrategy(
            strategy_id="t1091-gcp-usb-detection",
            name="GCP Compute Instance USB Device Monitoring",
            description="Detect USB device connections to GCP Compute Engine instances via OS logging.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(logName=~"logs/syslog" OR logName=~"logs/windows")
AND (
  jsonPayload.message=~".*USB.*connect.*"
  OR jsonPayload.message=~".*removable.*storage.*"
  OR jsonPayload.message=~".*mass storage.*"
  OR jsonPayload.message=~".*usb-storage.*"
  OR textPayload=~".*USB.*device.*attached.*"
)''',
                gcp_terraform_template='''# GCP: Detect USB device connections to Compute instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "USB Device Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for USB connections
resource "google_logging_metric" "usb_connection" {
  project = var.project_id
  name    = "usb-device-connections"

  filter = <<-EOT
    resource.type="gce_instance"
    (logName=~"logs/syslog" OR logName=~"logs/windows")
    AND (
      jsonPayload.message=~".*USB.*connect.*"
      OR jsonPayload.message=~".*removable.*storage.*"
      OR jsonPayload.message=~".*mass storage.*"
      OR jsonPayload.message=~".*usb-storage.*"
      OR textPayload=~".*USB.*device.*attached.*"
    )
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Alert policy for USB connections
resource "google_monitoring_alert_policy" "usb_alert" {
  project      = var.project_id
  display_name = "USB Device Connection Detected"
  combiner     = "OR"

  conditions {
    display_name = "USB device connected to instance"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.usb_connection.name}\" AND resource.type=\"gce_instance\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }

  documentation {
    content   = "USB or removable storage device connected to Compute instance. Investigate for unauthorised device usage or potential malware."
    mime_type = "text/markdown"
  }
}''',
                alert_severity="high",
                alert_title="GCP: USB Device Connected to Compute Instance",
                alert_description_template="USB or removable storage device detected on instance {instance_name} in zone {zone}.",
                investigation_steps=[
                    "Identify the Compute instance and project",
                    "Review OS logs for device details",
                    "Check if USB passthrough is enabled and authorised",
                    "Examine files accessed during connection timeframe",
                    "Run malware scan on instance",
                    "Verify user authentication around connection time",
                    "Check for autorun scripts or suspicious executables"
                ],
                containment_actions=[
                    "Disable USB passthrough if unauthorised",
                    "Quarantine instance for forensic analysis",
                    "Run antimalware scan on affected instance",
                    "Implement organisation policy restricting USB access",
                    "Enable VM Manager for inventory tracking",
                    "Document incident and update security policies"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised users and instances requiring USB access; establish device registration process",
            detection_coverage="75% - requires OS logging enabled",
            evasion_considerations="Requires proper OS logging configuration; may miss brief connections",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled", "OS logs forwarded to Cloud Logging", "Syslog or Windows Event Forwarding configured"]
        ),

        # Strategy 5: GCP - Cloud Storage Unusual Upload Patterns
        DetectionStrategy(
            strategy_id="t1091-gcp-storage-upload",
            name="GCP Cloud Storage Unusual Upload Detection",
            description="Detect unusual file upload patterns to Cloud Storage that may indicate removable media transfers.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
OR protoPayload.methodName="storage.objects.update"
protoPayload.serviceName="storage.googleapis.com"''',
                gcp_terraform_template='''# GCP: Detect unusual Cloud Storage uploads

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "monitored_bucket" {
  type        = string
  description = "Cloud Storage bucket to monitor"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Storage Upload Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for storage uploads
resource "google_logging_metric" "storage_upload" {
  project = var.project_id
  name    = "unusual-storage-uploads"

  filter = <<-EOT
    resource.type="gcs_bucket"
    resource.labels.bucket_name="${var.monitored_bucket}"
    (protoPayload.methodName="storage.objects.create" OR
     protoPayload.methodName="storage.objects.update")
    protoPayload.serviceName="storage.googleapis.com"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for upload anomalies
resource "google_monitoring_alert_policy" "upload_alert" {
  project      = var.project_id
  display_name = "Unusual Cloud Storage Upload Pattern"
  combiner     = "OR"

  conditions {
    display_name = "High volume of uploads detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.storage_upload.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.bucket_name"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Unusual upload pattern detected. Review for potential removable media data transfer or bulk file upload from untrusted source."
    mime_type = "text/markdown"
  }
}''',
                alert_severity="medium",
                alert_title="GCP: Unusual Cloud Storage Upload Pattern",
                alert_description_template="High volume of uploads detected to bucket {bucket_name}. Review for potential removable media transfer.",
                investigation_steps=[
                    "Identify uploaded objects and their sources",
                    "Review authentication principal performing uploads",
                    "Check for concurrent USB device connections",
                    "Scan uploaded files for malware",
                    "Examine upload patterns and timing",
                    "Verify business justification for bulk upload",
                    "Check object metadata for source indicators"
                ],
                containment_actions=[
                    "Quarantine suspicious objects",
                    "Enable object versioning to preserve evidence",
                    "Run malware scanning on uploaded objects",
                    "Implement bucket ACLs restricting upload sources",
                    "Enable VPC Service Controls for bucket access",
                    "Review and restrict upload permissions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Baseline normal upload patterns; whitelist known backup and sync operations",
            detection_coverage="65% - requires correlation with other indicators",
            evasion_considerations="High false positive rate; best used with correlation to USB detection signals",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["Cloud Audit Logs enabled", "Data Access logs enabled for Cloud Storage"]
        )
    ],

    recommended_order=[
        "t1091-aws-workspaces-usb",
        "t1091-gcp-usb-detection",
        "t1091-aws-ssm-inventory",
        "t1091-aws-s3-upload",
        "t1091-gcp-storage-upload"
    ],
    total_effort_hours=7.5,
    coverage_improvement="+15% improvement for Initial Access and Lateral Movement tactics"
)
