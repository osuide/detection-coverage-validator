"""
T1200 - Hardware Additions

Adversaries introduce physical computing devices into systems or networks to gain
access. Provides robust functionalities for network compromise including passive
network tapping, traffic modification, keystroke injection, kernel memory reading
via DMA, and wireless access point deployment.
Used by DarkVishnya.
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
            strategy_id="t1200-aws-usb",
            name="AWS EC2 USB Device Detection",
            description="Monitor EC2 instance metadata and CloudWatch for USB device connections via Systems Manager.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, detail.instance-id, detail.device-type, detail.device-name
| filter @message like /USB|Thunderbolt|PCI/
| filter detail.event-name = "DeviceConnected"
| stats count(*) as devices by detail.instance-id, detail.device-type, bin(1h)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised USB/hardware device connections on EC2

Parameters:
  InstanceId:
    Type: String
    Description: EC2 Instance ID to monitor
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # EventBridge rule for USB device detection
  USBDeviceRule:
    Type: AWS::Events::Rule
    Properties:
      Name: USBDeviceConnections
      Description: Detect USB device connections
      EventPattern:
        source:
          - aws.ec2
        detail-type:
          - EC2 Instance State-change Notification
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - AttachNetworkInterface
            - AttachVolume
      State: ENABLED
      Targets:
        - Arn: !Ref AlertTopic
          Id: USBAlertTarget

  # Systems Manager document to audit hardware
  HardwareAuditDocument:
    Type: AWS::SSM::Document
    Properties:
      DocumentType: Command
      Content:
        schemaVersion: '2.2'
        description: Audit hardware devices
        mainSteps:
          - action: aws:runShellScript
            name: auditHardware
            inputs:
              runCommand:
                - |
                  # Linux: Check for new USB devices
                  if [ -f /var/log/syslog ]; then
                    grep -i "usb.*new.*device" /var/log/syslog | tail -20
                  fi
                  lsusb
                  # Check for network interfaces
                  ip link show

  HardwareAuditAssociation:
    Type: AWS::SSM::Association
    Properties:
      Name: !Ref HardwareAuditDocument
      Targets:
        - Key: InstanceIds
          Values: [!Ref InstanceId]
      ScheduleExpression: rate(1 hour)""",
                terraform_template="""# Detect unauthorised USB/hardware device connections on EC2

variable "instance_id" {
  type        = string
  description = "EC2 Instance ID to monitor"
}

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "hardware-addition-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule for device connections
resource "aws_cloudwatch_event_rule" "usb_device" {
  name        = "usb-device-connections"
  description = "Detect USB and network device connections"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["EC2 Instance State-change Notification", "AWS API Call via CloudTrail"]
    detail = {
      eventName = ["AttachNetworkInterface", "AttachVolume"]
    }
  })
}

resource "aws_cloudwatch_event_target" "usb_alert" {
  rule      = aws_cloudwatch_event_rule.usb_device.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn
}

# Systems Manager document for hardware auditing
resource "aws_ssm_document" "hardware_audit" {
  name          = "HardwareDeviceAudit"
  document_type = "Command"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Audit hardware devices"
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "auditHardware"
      inputs = {
        runCommand = [
          "# Linux: Check for new USB devices",
          "if [ -f /var/log/syslog ]; then grep -i 'usb.*new.*device' /var/log/syslog | tail -20; fi",
          "lsusb",
          "# Check for network interfaces",
          "ip link show"
        ]
      }
    }]
  })
}

resource "aws_ssm_association" "hardware_audit" {
  name                = aws_ssm_document.hardware_audit.name
  schedule_expression = "rate(1 hour)"

  targets {
    key    = "InstanceIds"
    values = [var.instance_id]
  }
}""",
                alert_severity="high",
                alert_title="Unauthorised Hardware Device Detected",
                alert_description_template="USB or hardware device connected to instance {instance_id}.",
                investigation_steps=[
                    "Verify device connection is authorised",
                    "Check Systems Manager hardware audit logs",
                    "Review physical access logs for the data centre",
                    "Inspect instance for unfamiliar network interfaces",
                    "Check for unusual network traffic patterns",
                    "Review user login activity around device connection time",
                ],
                containment_actions=[
                    "Physically disconnect unauthorised device",
                    "Isolate affected instance via security groups",
                    "Review and rotate credentials",
                    "Image instance for forensic analysis",
                    "Enable USB device restrictions",
                    "Review physical security controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter for authorised device types and scheduled maintenance windows",
            detection_coverage="50% - requires Systems Manager agent and monitoring",
            evasion_considerations="Sophisticated devices may masquerade as legitimate hardware",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "Systems Manager agent installed",
                "EventBridge enabled",
                "CloudWatch Logs",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1200-aws-network",
            name="AWS Network Interface Anomaly Detection",
            description="Detect unauthorised network interfaces and unusual DHCP activity.",
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
                terraform_template="""# Detect unauthorised network interface additions

variable "vpc_flow_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "network-interface-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "new_interface" {
  name           = "unauthorised-network-interface"
  log_group_name = var.vpc_flow_log_group
  pattern        = "{ $.eventName = \"CreateNetworkInterface\" || $.eventName = \"AttachNetworkInterface\" }"

  metric_transformation {
    name      = "NewNetworkInterface"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "interface_alarm" {
  alarm_name          = "UnauthorisedNetworkInterface"
  metric_name         = "NewNetworkInterface"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Unauthorised Network Interface Detected",
                alert_description_template="New network interface created by {principalId}.",
                investigation_steps=[
                    "Verify network interface creation is authorised",
                    "Check CloudTrail for API call source IP",
                    "Review associated security groups",
                    "Check for data exfiltration attempts",
                    "Inspect VPC Flow Logs for unusual traffic",
                ],
                containment_actions=[
                    "Detach unauthorised network interface",
                    "Block source IP in NACLs",
                    "Review and update IAM permissions",
                    "Enable GuardDuty if not active",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist expected automation and service principals",
            detection_coverage="60% - detects network-level device additions",
            evasion_considerations="May not detect devices using existing interfaces",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "CloudTrail logging"],
        ),
        DetectionStrategy(
            strategy_id="t1200-gcp-compute",
            name="GCP Compute Instance Hardware Monitoring",
            description="Monitor GCP Compute instances for unauthorised hardware additions and network interface changes.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName=~"compute.instances.attachDisk|compute.instances.insert|compute.instances.setMetadata"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect hardware additions and network changes

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Hardware Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "hardware_changes" {
  name   = "unauthorised-hardware-changes"
  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName="compute.instances.attachDisk" OR
     protoPayload.methodName="compute.instances.insert" OR
     protoPayload.methodName="compute.instances.setMetadata" OR
     protoPayload.methodName="compute.networks.addPeering")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "hardware_alert" {
  display_name = "Unauthorised Hardware Additions"
  combiner     = "OR"
  conditions {
    display_name = "Hardware change detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.hardware_changes.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "1800s"
  }
}

# Log sink for hardware audit
resource "google_logging_project_sink" "hardware_audit" {
  name        = "hardware-audit-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  filter      = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~"compute.*"
  EOT
}

resource "google_storage_bucket" "audit_logs" {
  name     = "${var.project_id}-hardware-audit-logs"
  location = "EU"

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Hardware Addition Detected",
                alert_description_template="Hardware or network changes detected on GCP Compute instance.",
                investigation_steps=[
                    "Review Cloud Logging for API call details",
                    "Check identity and source IP of API caller",
                    "Verify changes are authorised",
                    "Inspect attached disks and network interfaces",
                    "Review VPC Flow Logs for unusual traffic",
                    "Check for data exfiltration attempts",
                ],
                containment_actions=[
                    "Detach unauthorised hardware",
                    "Isolate affected instance via firewall rules",
                    "Review and rotate service account keys",
                    "Take disk snapshot for forensics",
                    "Review IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter for authorised service accounts and maintenance windows",
            detection_coverage="65% - monitors compute-level hardware changes",
            evasion_considerations="Physical device additions may not trigger API calls",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["Cloud Logging enabled", "Compute Engine API logging"],
        ),
        DetectionStrategy(
            strategy_id="t1200-gcp-dhcp",
            name="GCP DHCP Lease Anomaly Detection",
            description="Monitor VPC network logs for unexpected DHCP leases indicating unauthorised devices.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
jsonPayload.event_type="DHCP_LEASE"
jsonPayload.lease_action="ASSIGN"''',
                gcp_terraform_template="""# GCP: Detect unauthorised DHCP activity

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "DHCP Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "dhcp_leases" {
  name   = "unauthorised-dhcp-leases"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.event_type="DHCP_LEASE"
    jsonPayload.lease_action="ASSIGN"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "mac_address"
      value_type  = "STRING"
      description = "MAC address of device"
    }
  }
  label_extractors = {
    "mac_address" = "EXTRACT(jsonPayload.mac_address)"
  }
}

resource "google_monitoring_alert_policy" "dhcp_alert" {
  display_name = "Unauthorised DHCP Activity"
  combiner     = "OR"
  conditions {
    display_name = "New DHCP lease"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dhcp_leases.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Unauthorised DHCP Activity",
                alert_description_template="Unusual DHCP lease activity detected in VPC network.",
                investigation_steps=[
                    "Review DHCP lease logs for MAC addresses",
                    "Check if devices are registered in asset inventory",
                    "Correlate with physical access logs",
                    "Inspect VPC Flow Logs for device traffic",
                    "Verify subnet configurations are correct",
                ],
                containment_actions=[
                    "Block MAC address at network level",
                    "Implement 802.1x authentication",
                    "Restrict DHCP to known devices only",
                    "Review firewall rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist known MAC addresses and expected device types",
            detection_coverage="40% - depends on DHCP logging configuration",
            evasion_considerations="Devices with static IPs bypass DHCP detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["VPC Flow Logs with DHCP events", "Cloud Logging"],
        ),
    ],
    recommended_order=[
        "t1200-aws-usb",
        "t1200-aws-network",
        "t1200-gcp-compute",
        "t1200-gcp-dhcp",
    ],
    total_effort_hours=10.0,
    coverage_improvement="+15% improvement for Initial Access tactic",
)
