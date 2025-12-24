"""
T1200 - Hardware Additions

Adversaries introduce physical computing devices into systems or networks to gain
access. Provides robust functionalities for network compromise including passive
network tapping, traffic modification, keystroke injection, kernel memory reading
via DMA, and wireless access point deployment.
Used by DarkVishnya.

IMPORTANT DETECTION LIMITATIONS:
Cloud-native detection (AWS CloudTrail/EventBridge, GCP Cloud Logging) CANNOT detect
physical USB device insertions or hardware-level events. These are OS/hardware layer
signals not exposed via cloud APIs. The detection strategies below monitor:
- AWS API calls for network interface and volume attachments (cloud-level indicators)
- Periodic OS-level hardware audits via Systems Manager (reactive, not real-time)

For real-time USB/hardware detection, deploy endpoint security solutions:
- AWS: GuardDuty Runtime Monitoring, CrowdStrike, SentinelOne, Carbon Black
- GCP: Chronicle Security, CrowdStrike, SentinelOne
- On-premises: OSSEC, Wazuh, Microsoft Defender for Endpoint
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
    technique_id="T1200",
    technique_name="Hardware Additions",
    tactic_ids=["TA0001"],  # Initial Access
    mitre_url="https://attack.mitre.org/techniques/T1200/",
    threat_context=ThreatContext(
        description=(
            "Adversaries introduce physical computing devices into systems or networks "
            "to gain access. Unlike simple removable media distribution, hardware additions "
            "provide robust functionalities for network compromise including passive network "
            "tapping, network traffic modification, keystroke injection, kernel memory reading "
            "via DMA, and wireless access point deployment."
        ),
        attacker_goal="Gain initial access by physically connecting unauthorised devices to the network",
        why_technique=[
            "Bypasses perimeter network security",
            "Provides persistent network access",
            "Enables traffic interception and modification",
            "Can exfiltrate data via wireless channels",
            "Difficult to detect without physical inspection",
            "Low-cost devices provide advanced capabilities",
        ],
        known_threat_actors=["DarkVishnya"],
        recent_campaigns=[
            Campaign(
                name="DarkVishnya Banking Attacks",
                year=2018,
                description="Physically connected Bash Bunny, Raspberry Pi, netbooks, and inexpensive laptops to target organisation's environment to access company's local network, specifically targeting banking institutions",
                reference_url="https://attack.mitre.org/groups/G0105/",
            )
        ],
        prevalence="rare",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "High severity due to bypass of network perimeter defences and potential "
            "for persistent access. Requires physical access which limits scalability, "
            "but successful deployment provides comprehensive network compromise capabilities."
        ),
        business_impact=[
            "Network perimeter bypass",
            "Unauthorised network access",
            "Traffic interception and data theft",
            "Lateral movement enabler",
            "Persistent backdoor access",
            "Compliance violations",
        ],
        typical_attack_phase="initial_access",
        often_precedes=[
            "T1040",
            "T1557",
            "T1021",
            "T1078",
        ],  # Network sniffing, AiTM, Remote Services, Valid Accounts
        often_follows=[],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1200-aws-network-interface",
            name="AWS Network Interface Attachment Detection (Cloud API Level)",
            description=(
                "Monitor CloudTrail for AWS API calls that attach network interfaces or volumes. "
                "LIMITATION: This detects cloud-level device attachments (ENI, EBS) via AWS APIs, "
                "NOT physical USB insertions or hardware-level events. For USB detection, deploy "
                "endpoint agents such as GuardDuty Runtime Monitoring or third-party EDR."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.requestParameters.networkInterfaceId, detail.userIdentity.principalId
| filter detail.eventName = "CreateNetworkInterface" or detail.eventName = "AttachNetworkInterface"
| filter detail.userIdentity.principalId not like /expected-service/
| stats count(*) as interfaces by detail.userIdentity.principalId, bin(1h)
| filter interfaces > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Detect AWS API calls for network interface additions.
  NOTE: This does NOT detect physical USB or hardware insertions.
  For USB detection, deploy GuardDuty Runtime Monitoring or endpoint agents.

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Network Interface Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for network interface API calls
  NetworkInterfaceRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1200-NetworkInterfaceAttachment
      Description: Alert on network interface attachments via AWS API (not USB)
      EventPattern:
        source:
          - aws.ec2
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - AttachNetworkInterface
            - CreateNetworkInterface
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: NetworkInterfaceAlert

  # Step 3: SNS topic policy for EventBridge
  SNSTopicPolicy:
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

Outputs:
  AlertTopicArn:
    Description: SNS Topic for network interface alerts
    Value: !Ref AlertTopic
  Limitations:
    Description: Detection limitations
    Value: "This detects AWS API calls only. Physical USB/hardware detection requires endpoint agents."
""",
                terraform_template="""# Detect AWS API calls for network interface additions
# LIMITATION: This does NOT detect physical USB or hardware insertions.
# For USB detection, deploy GuardDuty Runtime Monitoring or endpoint agents.

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name         = "network-interface-alerts"
  display_name = "Network Interface Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for network interface API calls
resource "aws_cloudwatch_event_rule" "network_interface" {
  name        = "network-interface-attachment"
  description = "Alert on network interface attachments via AWS API (not USB)"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["AttachNetworkInterface", "CreateNetworkInterface"]
    }
  })
}

resource "aws_cloudwatch_event_target" "network_interface_alert" {
  rule      = aws_cloudwatch_event_rule.network_interface.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn
}

# Step 3: SNS topic policy for EventBridge
resource "aws_sns_topic_policy" "allow_eventbridge" {
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
}

output "alert_topic_arn" {
  description = "SNS topic for alerts"
  value       = aws_sns_topic.alerts.arn
}

# NOTE: For physical USB/hardware detection, consider:
# - GuardDuty Runtime Monitoring (EC2, ECS, EKS)
# - Third-party EDR: CrowdStrike, SentinelOne, Carbon Black
# - Host-based: OSSEC, Wazuh with auditd rules""",
                alert_severity="medium",
                alert_title="Network Interface Attachment Detected (Cloud API)",
                alert_description_template="Network interface attached via AWS API by {principalId}. Note: This is a cloud-level API call, not physical hardware detection.",
                investigation_steps=[
                    "Verify the network interface attachment was authorised",
                    "Check CloudTrail for the API call source IP and user agent",
                    "Review the associated security groups and subnet",
                    "Examine if this was part of legitimate infrastructure provisioning",
                    "Check for subsequent suspicious API calls from the same principal",
                    "Review EC2 instance metadata access patterns",
                ],
                containment_actions=[
                    "Detach unauthorised network interface",
                    "Block source IP in NACLs if malicious",
                    "Review and update IAM permissions",
                    "Enable GuardDuty Runtime Monitoring for endpoint-level detection",
                    "Consider VPC flow logs analysis for the interface",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist expected automation and service principals (Terraform, CloudFormation, ASG).",
            detection_coverage="40% - detects cloud API calls for network device additions only. Does NOT detect physical USB/hardware.",
            evasion_considerations="Physical hardware additions completely bypass this detection. Requires endpoint agents for USB monitoring.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "EventBridge configured"],
        ),
        DetectionStrategy(
            strategy_id="t1200-aws-ssm-hardware-audit",
            name="AWS Systems Manager Periodic Hardware Audit (Reactive)",
            description=(
                "Use AWS Systems Manager to run periodic hardware audits on EC2 instances. "
                "LIMITATION: This is a SCHEDULED AUDIT (e.g., hourly), NOT real-time detection. "
                "It discovers devices that are currently connected but cannot alert on the moment "
                "of insertion. For real-time USB detection, deploy endpoint agents."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Periodic hardware audit via Systems Manager.
  LIMITATION: Scheduled audit only - NOT real-time USB detection.
  Runs hourly to inventory connected devices.

Parameters:
  InstanceId:
    Type: String
    Description: EC2 Instance ID to audit
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for audit results
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Hardware Audit Results
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: SSM Document for hardware inventory
  HardwareAuditDocument:
    Type: AWS::SSM::Document
    Properties:
      Name: T1200-HardwareInventoryAudit
      DocumentType: Command
      Content:
        schemaVersion: '2.2'
        description: |
          Periodic hardware device audit (not real-time detection).
          Lists currently connected USB, PCI, and network devices.
        mainSteps:
          - action: aws:runShellScript
            name: auditLinuxHardware
            precondition:
              StringEquals: [platformType, Linux]
            inputs:
              runCommand:
                - |
                  echo "=== Hardware Audit $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
                  echo ""
                  echo "--- USB Devices ---"
                  lsusb 2>/dev/null || echo "lsusb not available"
                  echo ""
                  echo "--- Block Devices ---"
                  lsblk -o NAME,SIZE,TYPE,MOUNTPOINT 2>/dev/null || echo "lsblk not available"
                  echo ""
                  echo "--- Network Interfaces ---"
                  ip link show 2>/dev/null || ifconfig -a
                  echo ""
                  echo "--- PCI Devices ---"
                  lspci 2>/dev/null | head -20 || echo "lspci not available"
          - action: aws:runPowerShellScript
            name: auditWindowsHardware
            precondition:
              StringEquals: [platformType, Windows]
            inputs:
              runCommand:
                - |
                  Write-Output "=== Hardware Audit $(Get-Date -Format o) ==="
                  Write-Output ""
                  Write-Output "--- USB Devices ---"
                  Get-PnpDevice -Class USB | Select-Object Status, Class, FriendlyName
                  Write-Output ""
                  Write-Output "--- Disk Drives ---"
                  Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle
                  Write-Output ""
                  Write-Output "--- Network Adapters ---"
                  Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress

  # Step 3: SSM Association for scheduled execution
  HardwareAuditAssociation:
    Type: AWS::SSM::Association
    Properties:
      Name: !Ref HardwareAuditDocument
      ScheduleExpression: rate(1 hour)
      Targets:
        - Key: InstanceIds
          Values: [!Ref InstanceId]
      OutputLocation:
        S3Location:
          OutputS3BucketName: !Ref AuditLogBucket
          OutputS3KeyPrefix: hardware-audits/

  # Step 4: S3 bucket for audit logs
  AuditLogBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AWS::StackName}-hardware-audit-logs"
      LifecycleConfiguration:
        Rules:
          - Id: ExpireOldAudits
            Status: Enabled
            ExpirationInDays: 90

Outputs:
  DocumentName:
    Description: SSM Document for hardware auditing
    Value: !Ref HardwareAuditDocument
  Limitations:
    Description: Detection limitations
    Value: "Scheduled audit only (hourly). NOT real-time USB detection. Deploy endpoint agents for real-time alerts."
""",
                terraform_template="""# Periodic hardware audit via Systems Manager
# LIMITATION: Scheduled audit only - NOT real-time USB detection.

variable "instance_id" {
  type        = string
  description = "EC2 Instance ID to audit"
}

variable "alert_email" {
  type        = string
  description = "Email for audit notifications"
}

# Step 1: S3 bucket for audit logs
resource "aws_s3_bucket" "audit_logs" {
  bucket = "hardware-audit-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    id     = "expire-old-audits"
    status = "Enabled"
    expiration {
      days = 90
    }
  }
}

data "aws_caller_identity" "current" {}

# Step 2: SSM Document for hardware inventory
resource "aws_ssm_document" "hardware_audit" {
  name          = "T1200-HardwareInventoryAudit"
  document_type = "Command"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Periodic hardware device audit (not real-time detection)"
    mainSteps = [
      {
        action = "aws:runShellScript"
        name   = "auditLinuxHardware"
        precondition = {
          StringEquals = ["platformType", "Linux"]
        }
        inputs = {
          runCommand = [
            "echo '=== Hardware Audit '$(date -u +%Y-%m-%dT%H:%M:%SZ)' ==='",
            "echo '--- USB Devices ---'",
            "lsusb 2>/dev/null || echo 'lsusb not available'",
            "echo '--- Block Devices ---'",
            "lsblk -o NAME,SIZE,TYPE,MOUNTPOINT 2>/dev/null || echo 'lsblk not available'",
            "echo '--- Network Interfaces ---'",
            "ip link show 2>/dev/null || ifconfig -a"
          ]
        }
      },
      {
        action = "aws:runPowerShellScript"
        name   = "auditWindowsHardware"
        precondition = {
          StringEquals = ["platformType", "Windows"]
        }
        inputs = {
          runCommand = [
            "Write-Output '=== Hardware Audit $(Get-Date -Format o) ==='",
            "Write-Output '--- USB Devices ---'",
            "Get-PnpDevice -Class USB | Select-Object Status, Class, FriendlyName",
            "Write-Output '--- Disk Drives ---'",
            "Get-Disk | Select-Object Number, FriendlyName, Size, PartitionStyle"
          ]
        }
      }
    ]
  })
}

# Step 3: SSM Association for scheduled execution
resource "aws_ssm_association" "hardware_audit" {
  name                = aws_ssm_document.hardware_audit.name
  schedule_expression = "rate(1 hour)"

  targets {
    key    = "InstanceIds"
    values = [var.instance_id]
  }

  output_location {
    s3_bucket_name = aws_s3_bucket.audit_logs.bucket
    s3_key_prefix  = "hardware-audits/"
  }
}

output "ssm_document_name" {
  description = "SSM Document for hardware auditing"
  value       = aws_ssm_document.hardware_audit.name
}

# NOTE: This is a SCHEDULED AUDIT, not real-time detection.
# For real-time USB alerting, deploy:
# - GuardDuty Runtime Monitoring
# - CrowdStrike, SentinelOne, or Carbon Black
# - OSSEC/Wazuh with auditd USB rules""",
                alert_severity="low",
                alert_title="Hardware Audit Completed (Scheduled)",
                alert_description_template="Periodic hardware inventory completed for instance {instance_id}. Review audit logs for connected devices.",
                investigation_steps=[
                    "Review the audit output for unexpected USB or storage devices",
                    "Compare with previous audit results to identify new devices",
                    "Verify any new devices are authorised",
                    "Check physical access logs for the data centre",
                    "Cross-reference with asset management system",
                ],
                containment_actions=[
                    "Physically disconnect unauthorised device if found",
                    "Isolate affected instance via security groups",
                    "Review and rotate credentials",
                    "Enable real-time endpoint monitoring",
                    "Update USB device control policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Compare audit results against known device baseline; whitelist expected devices.",
            detection_coverage="25% - scheduled inventory only. Cannot detect USB insertion events in real-time.",
            evasion_considerations="Devices connected and removed between audit intervals will not be detected. Short-lived attacks completely evade this detection.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Systems Manager agent installed",
                "SSM Run Command permissions",
                "S3 bucket for audit logs",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1200-gcp-compute-disk",
            name="GCP Compute Disk Attachment Detection (Cloud API Level)",
            description=(
                "Monitor GCP Cloud Logging for Compute Engine API calls that attach disks or modify "
                "instance metadata. LIMITATION: This detects cloud-level disk attachments via GCP APIs, "
                "NOT physical USB insertions. For USB detection, deploy endpoint security solutions."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName=~"compute.instances.attachDisk|compute.instances.setMetadata|compute.networks.addPeering"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect cloud-level disk attachments and network changes
# LIMITATION: This does NOT detect physical USB or hardware insertions.
# For USB detection, deploy endpoint agents (Chronicle Security, CrowdStrike, etc.)

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
  display_name = "Hardware Addition Alerts (Cloud API)"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Log-based metric for disk attachments
resource "google_logging_metric" "disk_attachment" {
  name   = "gce-disk-attachment-api-calls"
  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName="compute.instances.attachDisk" OR
     protoPayload.methodName="compute.instances.setMetadata" OR
     protoPayload.methodName="compute.networks.addPeering")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for disk attachments
resource "google_monitoring_alert_policy" "disk_attachment_alert" {
  display_name = "GCP Disk/Network Attachment (Cloud API)"
  combiner     = "OR"

  conditions {
    display_name = "Disk or network attachment via GCP API"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.disk_attachment.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content   = <<-EOT
      # Disk/Network Attachment Detected (Cloud API Level)

      A GCP API call attached a disk or modified network configuration.

      **LIMITATION**: This detects CLOUD API calls only. Physical USB or hardware
      insertions are NOT detected by this alert.

      For endpoint-level USB detection, deploy:
      - Chronicle Security with endpoint agents
      - CrowdStrike, SentinelOne, or Carbon Black
      - OSSEC/Wazuh with auditd USB rules
    EOT
    mime_type = "text/markdown"
  }
}

# Step 4: Log sink for audit trail
resource "google_logging_project_sink" "hardware_audit" {
  name        = "hardware-api-audit-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  filter      = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~"compute.*"
  EOT
}

resource "google_storage_bucket" "audit_logs" {
  name     = "${var.project_id}-hardware-api-audit-logs"
  location = "EU"

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}

output "alert_policy_id" {
  description = "Alert policy for disk attachments"
  value       = google_monitoring_alert_policy.disk_attachment_alert.id
}

# NOTE: For physical USB/hardware detection, consider:
# - Chronicle Security with endpoint integration
# - Third-party EDR: CrowdStrike, SentinelOne, Carbon Black
# - Host-based: OSSEC, Wazuh with auditd rules""",
                alert_severity="medium",
                alert_title="GCP: Disk/Network Attachment Detected (Cloud API)",
                alert_description_template="GCP API call detected for disk attachment or network modification. Note: This is a cloud-level API call, not physical hardware detection.",
                investigation_steps=[
                    "Review Cloud Audit Logs for API call details",
                    "Check identity and source IP of API caller",
                    "Verify the disk attachment was authorised",
                    "Examine the attached disk origin and contents",
                    "Review VPC Flow Logs for unusual traffic",
                    "Check for data exfiltration attempts",
                ],
                containment_actions=[
                    "Detach unauthorised disk",
                    "Isolate affected instance via firewall rules",
                    "Review and rotate service account keys",
                    "Take disk snapshot for forensics",
                    "Review IAM permissions",
                    "Deploy endpoint security for real-time USB detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised service accounts and maintenance windows. Exclude Terraform and deployment automation.",
            detection_coverage="40% - monitors cloud API calls only. Does NOT detect physical USB/hardware insertions.",
            evasion_considerations="Physical device additions completely bypass this detection. Requires endpoint agents for USB monitoring.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled", "Compute Engine API logging"],
        ),
        DetectionStrategy(
            strategy_id="t1200-endpoint-recommendation",
            name="Endpoint Agent Deployment for Real-Time USB Detection (Recommended)",
            description=(
                "Deploy endpoint security agents for real-time USB and hardware device detection. "
                "This is the ONLY way to detect physical hardware insertions in cloud VMs. "
                "Cloud-native APIs cannot see USB/hardware layer events."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:Runtime/NewBinaryExecuted",
                    "DefenseEvasion:Runtime/FilelessExecution",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Enable GuardDuty Runtime Monitoring for endpoint-level threat detection.
  This is the recommended approach for detecting suspicious activity that
  originates from physical hardware additions.

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Enable GuardDuty with Runtime Monitoring
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      Features:
        - Name: RUNTIME_MONITORING
          Status: ENABLED
          AdditionalConfiguration:
            - Name: EC2_AGENT_MANAGEMENT
              Status: ENABLED

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Runtime Security Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route runtime findings to alerts
  RuntimeFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1200-RuntimeSecurityAlerts
      Description: Alert on GuardDuty runtime findings
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "Execution:Runtime/"
            - prefix: "DefenseEvasion:Runtime/"
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  SNSTopicPolicy:
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

Outputs:
  GuardDutyDetectorId:
    Description: GuardDuty detector with runtime monitoring
    Value: !Ref GuardDutyDetector
  Recommendation:
    Description: Additional recommendations
    Value: |
      GuardDuty Runtime Monitoring provides endpoint-level visibility.
      For comprehensive USB detection, also consider:
      - Third-party EDR (CrowdStrike, SentinelOne, Carbon Black)
      - Host-based auditd rules for USB events""",
                terraform_template="""# Enable GuardDuty Runtime Monitoring for endpoint-level detection
# This is the RECOMMENDED approach for detecting malicious activity
# that may originate from physical hardware additions.

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Enable GuardDuty with Runtime Monitoring
resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# Step 2: SNS topic for alerts
resource "aws_sns_topic" "runtime_alerts" {
  name         = "runtime-security-alerts"
  display_name = "Runtime Security Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.runtime_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route runtime findings to alerts
resource "aws_cloudwatch_event_rule" "runtime_findings" {
  name        = "guardduty-runtime-findings"
  description = "Alert on GuardDuty runtime findings"

  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "Execution:Runtime/" },
        { prefix = "DefenseEvasion:Runtime/" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.runtime_findings.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.runtime_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.runtime_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.runtime_alerts.arn
    }]
  })
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID with runtime monitoring"
  value       = aws_guardduty_detector.main.id
}

# RECOMMENDED: For comprehensive hardware security, also deploy:
# - USB device control policies via Group Policy or MDM
# - Third-party EDR with USB monitoring capabilities
# - Host-based auditd rules: auditctl -w /dev -p wa -k usb_devices""",
                alert_severity="high",
                alert_title="Runtime Security Alert - Suspicious Execution",
                alert_description_template="GuardDuty Runtime Monitoring detected suspicious execution that may indicate compromise from hardware addition.",
                investigation_steps=[
                    "Review the GuardDuty finding details",
                    "Identify the affected EC2 instance or container",
                    "Check for recently executed binaries or scripts",
                    "Review process tree for suspicious parent-child relationships",
                    "Check for USB device connection logs (if auditd configured)",
                    "Analyse network connections from the affected process",
                ],
                containment_actions=[
                    "Isolate the affected instance immediately",
                    "Terminate suspicious processes",
                    "Capture memory and disk for forensic analysis",
                    "Rotate credentials accessible from the instance",
                    "Review and revoke IAM roles/instance profiles",
                    "Deploy additional USB controls if physical access suspected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate binaries and DevOps automation. Exclude known deployment tools.",
            detection_coverage="70% - detects suspicious activity from any source including hardware additions. Best option for cloud environments.",
            evasion_considerations="Sophisticated attacks may use fileless techniques or disable the agent. Combine with multiple detection layers.",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$4.60 per EC2 instance (Runtime Monitoring pricing)",
            prerequisites=[
                "AWS account with GuardDuty access",
                "EC2 instances with SSM agent for automated deployment",
            ],
        ),
    ],
    recommended_order=[
        "t1200-endpoint-recommendation",
        "t1200-aws-network-interface",
        "t1200-gcp-compute-disk",
        "t1200-aws-ssm-hardware-audit",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+10% improvement for Initial Access tactic (endpoint agents required for full coverage)",
)
