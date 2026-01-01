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
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
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
      KmsMasterKeyId: alias/aws/sns
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
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt NetworkInterfaceRule.Arn

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
  kms_master_key_id = "alias/aws/sns"
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

# DLQ for failed EventBridge deliveries
resource "aws_sqs_queue" "dlq" {
  name                      = "network-interface-dlq"
  message_retention_seconds = 1209600
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.network_interface.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "network_interface_alert" {
  rule      = aws_cloudwatch_event_rule.network_interface.name
  target_id = "SendToSNS"
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

# Step 3: SNS topic policy for EventBridge
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
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
          "aws:SourceArn" = aws_cloudwatch_event_rule.network_interface.arn
        }
      }
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
            strategy_id="t1200-aws-realtime-block-device",
            name="AWS Real-Time Block Device Monitoring (Endpoint Agent via SSM)",
            description=(
                "Deploy real-time block device detection using Linux udev rules and systemd services. "
                "This approach provides SUB-SECOND alerting when new block devices (USB drives, external "
                "disks, NVMe devices) are physically connected to EC2 instances. Events are logged as "
                "structured JSON and shipped to CloudWatch Logs via the CloudWatch Agent for metric "
                "filtering and alerting. This is the BEST cloud-native approach for hardware detection "
                "without third-party EDR. Distro-aware: supports Amazon Linux, Ubuntu, RHEL."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, ts, host, event, devkernel, devpath
| filter event = "block_device_add"
| stats count(*) as device_adds by host, bin(1h)
| filter device_adds > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Real-time block device detection using udev + systemd.
  Provides sub-second alerting when USB/block devices are connected.
  Requires SSM agent and CloudWatch Agent on target instances.

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  LogGroupName:
    Type: String
    Default: /security/block-device-monitor
    Description: CloudWatch Logs log group for events
  MonitorTagKey:
    Type: String
    Default: BlockDeviceMonitor
    Description: Tag key to identify instances for monitoring
  MonitorTagValue:
    Type: String
    Default: 'true'
    Description: Tag value to identify instances for monitoring
  LogRetentionDays:
    Type: Number
    Default: 30

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Block Device Monitor Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic

  # Step 2: CloudWatch Log Group
  BlockDeviceLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Ref LogGroupName
      RetentionInDays: !Ref LogRetentionDays

  # Step 3: Metric filter for block device add events (JSON format)
  BlockDeviceAddMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref BlockDeviceLogGroup
      FilterPattern: '{ $.event = "block_device_add" }'
      MetricTransformations:
        - MetricName: BlockDeviceAddCount
          MetricNamespace: Security/BlockDeviceMonitor
          MetricValue: "1"

  # Step 4: CloudWatch alarm
  BlockDeviceAddAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1200-BlockDeviceDetected
      AlarmDescription: New block device (USB/external disk) connected to EC2 instance
      MetricName: BlockDeviceAddCount
      Namespace: Security/BlockDeviceMonitor
      Statistic: Sum
      Period: 60
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  # Step 5: SSM Document for udev + systemd installation
  BlockDeviceMonitorDocument:
    Type: AWS::SSM::Document
    Properties:
      Name: T1200-BlockDeviceMonitor-Install
      DocumentType: Command
      DocumentFormat: YAML
      Content:
        schemaVersion: '2.2'
        description: |
          Install real-time block device monitoring via udev + systemd.
          Logs to /var/log/block-device-monitor.log and ships to CloudWatch.
        parameters:
          LogGroupName:
            type: String
            description: CloudWatch Logs log group name
          LogStreamPrefix:
            type: String
            default: '{instance_id}'
          InstallCloudWatchAgent:
            type: String
            default: 'true'
          SuppressDeviceRegex:
            type: String
            default: ''
          EnableRootDeviceSuppression:
            type: String
            default: 'true'
        mainSteps:
          - action: aws:runShellScript
            name: InstallBlockDeviceMonitoring
            inputs:
              runCommand:
                - |
                  #!/usr/bin/env bash
                  set -euo pipefail

                  LOG_GROUP="{{ LogGroupName }}"
                  LOG_STREAM_PREFIX="{{ LogStreamPrefix }}"
                  INSTALL_CWA="{{ InstallCloudWatchAgent }}"
                  SUPPRESS_REGEX="{{ SuppressDeviceRegex }}"
                  SUPPRESS_ROOT="{{ EnableRootDeviceSuppression }}"

                  RULE_PATH="/etc/udev/rules.d/99-block-device-monitor.rules"
                  UNIT_PATH="/etc/systemd/system/block-device-added@.service"
                  SCRIPT_PATH="/usr/local/bin/block-device-added.sh"
                  LOG_FILE="/var/log/block-device-monitor.log"
                  CWA_CFG="/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json"

                  changed=0
                  log() { echo "[block-device-monitor] $*" ; }

                  # OS detection
                  OS_ID=""
                  OS_LIKE=""
                  if [[ -r /etc/os-release ]]; then
                    . /etc/os-release
                    OS_ID="${ID:-}"
                    OS_LIKE="${ID_LIKE:-}"
                  fi

                  has_cmd() { command -v "$1" >/dev/null 2>&1; }

                  PM=""
                  if has_cmd dnf; then PM="dnf"; fi
                  if has_cmd yum; then PM="${PM:-yum}"; fi
                  if has_cmd apt-get; then PM="${PM:-apt}"; fi

                  ensure_pkgs() {
                    case "${PM}" in
                      apt) DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y util-linux curl ca-certificates ;;
                      yum) yum install -y util-linux curl ca-certificates ;;
                      dnf) dnf install -y util-linux curl ca-certificates ;;
                      *) log "No supported package manager found"; exit 1 ;;
                    esac
                  }

                  install_file_if_changed() {
                    local mode="$1"; shift
                    local path="$1"; shift
                    local tmp; tmp="$(mktemp)"
                    cat > "${tmp}"
                    if [[ ! -f "${path}" ]] || ! cmp -s "${tmp}" "${path}"; then
                      install -D -m "${mode}" "${tmp}" "${path}"
                      changed=1
                      log "Updated: ${path}"
                    fi
                    rm -f "${tmp}"
                  }

                  ensure_pkgs

                  # udev rule
                  install_file_if_changed 0644 "${RULE_PATH}" <<'UDEV_EOF'
                  ACTION=="add", SUBSYSTEM=="block", DEVTYPE=="disk", KERNEL=="nvme*n*|xvd*|sd*|vd*", ENV{SYSTEMD_WANTS}="block-device-added@%k.service"
                  UDEV_EOF

                  # systemd unit
                  install_file_if_changed 0644 "${UNIT_PATH}" <<'UNIT_EOF'
                  [Unit]
                  Description=Block device add monitor for %I
                  [Service]
                  Type=oneshot
                  ExecStart=/usr/local/bin/block-device-added.sh %I
                  TimeoutStartSec=30
                  [Install]
                  WantedBy=multi-user.target
                  UNIT_EOF

                  # handler script
                  install_file_if_changed 0755 "${SCRIPT_PATH}" <<'SCRIPT_EOF'
                  #!/usr/bin/env bash
                  set -euo pipefail
                  DEVKERNEL="${1:-unknown}"
                  DEVPATH="/dev/${DEVKERNEL}"
                  LOG="/var/log/block-device-monitor.log"
                  SUPPRESS_ROOT="${SUPPRESS_ROOT_DEVICE:-true}"

                  # Suppress root disk
                  if [[ "${SUPPRESS_ROOT,,}" == "true" ]]; then
                    ROOT_SRC="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
                    if [[ -n "${ROOT_SRC}" ]]; then
                      ROOT_DISK="$(lsblk -no PKNAME "${ROOT_SRC}" 2>/dev/null || true)"
                      if [[ -z "${ROOT_DISK}" ]]; then
                        ROOT_DISK="$(basename "${ROOT_SRC}" | sed -E 's/p?[0-9]+$//')"
                      fi
                      if [[ -n "${ROOT_DISK}" && "${DEVKERNEL}" == "${ROOT_DISK}" ]]; then
                        exit 0
                      fi
                    fi
                  fi

                  TS="$(date -Is)"
                  HOST="$(hostname -f 2>/dev/null || hostname)"

                  # JSON log line for CloudWatch metric filter
                  printf '%s\n' "{\"ts\":\"${TS}\",\"host\":\"${HOST}\",\"event\":\"block_device_add\",\"devkernel\":\"${DEVKERNEL}\",\"devpath\":\"${DEVPATH}\"}" >> "${LOG}"

                  # Evidence snapshot
                  {
                    echo "lsblk=$(lsblk -J -o NAME,KNAME,TYPE,SIZE,MODEL,SERIAL,WWN,UUID,FSTYPE,MOUNTPOINT,ROTA,TRAN 2>/dev/null || echo '{}')"
                    echo "blkid=$(blkid "${DEVPATH}" 2>/dev/null || true)"
                    echo "---"
                  } >> "${LOG}"
                  SCRIPT_EOF

                  if [[ "${changed}" -eq 1 ]]; then
                    systemctl daemon-reload
                    udevadm control --reload-rules
                    log "Reloaded systemd + udev rules"
                  fi

                  # CloudWatch Agent configuration
                  if has_cmd /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl; then
                    mkdir -p "$(dirname "${CWA_CFG}")"
                    cat > "${CWA_CFG}" <<CWA_EOF
                  {
                    "logs": {
                      "logs_collected": {
                        "files": {
                          "collect_list": [
                            {
                              "file_path": "${LOG_FILE}",
                              "log_group_name": "${LOG_GROUP}",
                              "log_stream_name": "${LOG_STREAM_PREFIX}/block-device-monitor"
                            }
                          ]
                        }
                      }
                    }
                  }
                  CWA_EOF
                    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c "file:${CWA_CFG}" -s
                    log "CloudWatch Agent configured"
                  else
                    log "CloudWatch Agent not installed; logs remain local at ${LOG_FILE}"
                  fi

                  log "Block device monitoring deployment complete"

  # Step 6: SSM Association for tag-based deployment
  BlockDeviceMonitorAssociation:
    Type: AWS::SSM::Association
    Properties:
      Name: !Ref BlockDeviceMonitorDocument
      Targets:
        - Key: !Sub "tag:${MonitorTagKey}"
          Values: [!Ref MonitorTagValue]
      Parameters:
        LogGroupName: [!Ref LogGroupName]
        LogStreamPrefix: ['{instance_id}']
        InstallCloudWatchAgent: ['true']
        SuppressDeviceRegex: ['']
        EnableRootDeviceSuppression: ['true']

Outputs:
  LogGroupName:
    Description: CloudWatch Log Group for block device events
    Value: !Ref BlockDeviceLogGroup
  SSMDocumentName:
    Description: SSM Document for deploying monitoring
    Value: !Ref BlockDeviceMonitorDocument
  AlertTopicArn:
    Description: SNS Topic for alerts
    Value: !Ref AlertTopic
  Advantages:
    Description: Key advantages of this approach
    Value: "Real-time detection (sub-second), structured JSON logs, evidence collection, distro-aware, fleet deployment via tags"
""",
                terraform_template="""# Real-time block device detection via udev + systemd + CloudWatch
# Provides sub-second alerting when USB/block devices are connected.
# Distro-aware: supports Amazon Linux, Ubuntu, RHEL.

variable "alert_email" {
  type        = string
  description = "Email address for alerts (SNS subscription requires confirmation)"
}

variable "log_group_name" {
  type        = string
  default     = "/security/block-device-monitor"
  description = "CloudWatch Logs log group for block device events"
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "monitor_tag_key" {
  type        = string
  default     = "BlockDeviceMonitor"
  description = "Instances with this tag key receive the SSM association"
}

variable "monitor_tag_value" {
  type        = string
  default     = "true"
  description = "Instances with this tag value receive the SSM association"
}

# Step 1: SNS Topic for Alerts
resource "aws_sns_topic" "alerts" {
  name         = "block-device-monitor-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Block Device Monitor Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_iam_policy_document" "sns_allow_cloudwatch" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_sns_topic_policy" "alerts_policy" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.sns_allow_cloudwatch.json
}

# Step 2: CloudWatch Log Group + Metric Filter + Alarm
resource "aws_cloudwatch_log_group" "block_device_monitor" {
  name              = var.log_group_name
  retention_in_days = var.log_retention_days
}

locals {
  metric_namespace = "Security/BlockDeviceMonitor"
  metric_name      = "BlockDeviceAddCount"
}

resource "aws_cloudwatch_log_metric_filter" "block_device_add" {
  name           = "block-device-add"
  log_group_name = aws_cloudwatch_log_group.block_device_monitor.name
  pattern        = "{ $.event = \"block_device_add\" }"

  metric_transformation {
    name      = local.metric_name
    namespace = local.metric_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "block_device_add" {
  alarm_name          = "T1200-block-device-add-detected"
  alarm_description   = "A new block device was detected on an instance (udev event)"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  threshold           = 1
  period              = 60
  statistic           = "Sum"
  namespace           = local.metric_namespace
  metric_name         = local.metric_name
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: SSM Document for udev + systemd installation
resource "aws_ssm_document" "block_device_monitor" {
  name            = "T1200-BlockDeviceMonitor-Install"
  document_type   = "Command"
  document_format = "YAML"

  content = <<-YAML
schemaVersion: '2.2'
description: |
  Install real-time block device monitoring via udev + systemd.
  Logs JSON events to CloudWatch for metric filtering and alerting.
parameters:
  LogGroupName:
    type: String
    description: CloudWatch Logs log group name
  LogStreamPrefix:
    type: String
    default: '{instance_id}'
  InstallCloudWatchAgent:
    type: String
    default: 'true'
  EnableRootDeviceSuppression:
    type: String
    default: 'true'
mainSteps:
  - action: aws:runShellScript
    name: InstallBlockDeviceMonitoring
    inputs:
      runCommand:
        - |
          #!/usr/bin/env bash
          set -euo pipefail

          LOG_GROUP="{{ LogGroupName }}"
          LOG_STREAM_PREFIX="{{ LogStreamPrefix }}"
          SUPPRESS_ROOT="{{ EnableRootDeviceSuppression }}"

          RULE_PATH="/etc/udev/rules.d/99-block-device-monitor.rules"
          UNIT_PATH="/etc/systemd/system/block-device-added@.service"
          SCRIPT_PATH="/usr/local/bin/block-device-added.sh"
          LOG_FILE="/var/log/block-device-monitor.log"
          CWA_CFG="/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json"

          changed=0
          log() { echo "[block-device-monitor] $*" ; }

          # OS detection
          OS_ID=""
          if [[ -r /etc/os-release ]]; then
            . /etc/os-release
            OS_ID="$${ID:-}"
          fi

          has_cmd() { command -v "$1" >/dev/null 2>&1; }

          PM=""
          if has_cmd dnf; then PM="dnf"; fi
          if has_cmd yum; then PM="$${PM:-yum}"; fi
          if has_cmd apt-get; then PM="$${PM:-apt}"; fi

          ensure_pkgs() {
            case "$${PM}" in
              apt) DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y util-linux curl ;;
              yum) yum install -y util-linux curl ;;
              dnf) dnf install -y util-linux curl ;;
              *) log "No supported package manager"; exit 1 ;;
            esac
          }

          install_file_if_changed() {
            local mode="$1"; shift
            local path="$1"; shift
            local tmp; tmp="$(mktemp)"
            cat > "$${tmp}"
            if [[ ! -f "$${path}" ]] || ! cmp -s "$${tmp}" "$${path}"; then
              install -D -m "$${mode}" "$${tmp}" "$${path}"
              changed=1
              log "Updated: $${path}"
            fi
            rm -f "$${tmp}"
          }

          ensure_pkgs

          # udev rule for block device add events
          install_file_if_changed 0644 "$${RULE_PATH}" <<'UDEV_EOF'
          ACTION=="add", SUBSYSTEM=="block", DEVTYPE=="disk", KERNEL=="nvme*n*|xvd*|sd*|vd*", ENV{SYSTEMD_WANTS}="block-device-added@%k.service"
          UDEV_EOF

          # systemd oneshot service
          install_file_if_changed 0644 "$${UNIT_PATH}" <<'UNIT_EOF'
          [Unit]
          Description=Block device add monitor for %I
          [Service]
          Type=oneshot
          ExecStart=/usr/local/bin/block-device-added.sh %I
          TimeoutStartSec=30
          UNIT_EOF

          # handler script with JSON logging
          install_file_if_changed 0755 "$${SCRIPT_PATH}" <<'SCRIPT_EOF'
          #!/usr/bin/env bash
          set -euo pipefail
          DEVKERNEL="$${1:-unknown}"
          DEVPATH="/dev/$${DEVKERNEL}"
          LOG="/var/log/block-device-monitor.log"

          # Suppress root disk at boot
          ROOT_SRC="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
          if [[ -n "$${ROOT_SRC}" ]]; then
            ROOT_DISK="$(lsblk -no PKNAME "$${ROOT_SRC}" 2>/dev/null || basename "$${ROOT_SRC}" | sed -E 's/p?[0-9]+$//')"
            if [[ "$${DEVKERNEL}" == "$${ROOT_DISK}" ]]; then exit 0; fi
          fi

          TS="$(date -Is)"
          HOST="$(hostname -f 2>/dev/null || hostname)"

          # JSON log for CloudWatch metric filter
          printf '%s\\n' "{\"ts\":\"$${TS}\",\"host\":\"$${HOST}\",\"event\":\"block_device_add\",\"devkernel\":\"$${DEVKERNEL}\",\"devpath\":\"$${DEVPATH}\"}" >> "$${LOG}"

          # Evidence collection
          echo "lsblk=$(lsblk -J -o NAME,KNAME,TYPE,SIZE,MODEL,SERIAL 2>/dev/null || echo '{}')" >> "$${LOG}"
          echo "---" >> "$${LOG}"
          SCRIPT_EOF

          if [[ "$${changed}" -eq 1 ]]; then
            systemctl daemon-reload
            udevadm control --reload-rules
            log "Reloaded systemd + udev rules"
          fi

          # Configure CloudWatch Agent if present
          if has_cmd /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl; then
            mkdir -p "$(dirname "$${CWA_CFG}")"
            cat > "$${CWA_CFG}" <<CWA_EOF
          {"logs":{"logs_collected":{"files":{"collect_list":[{"file_path":"$${LOG_FILE}","log_group_name":"$${LOG_GROUP}","log_stream_name":"$${LOG_STREAM_PREFIX}/block-device-monitor"}]}}}}
          CWA_EOF
            /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c "file:$${CWA_CFG}" -s
            log "CloudWatch Agent configured"
          fi

          log "Block device monitoring complete"
YAML
}

# Step 4: SSM Association for tag-based fleet deployment
resource "aws_ssm_association" "block_device_monitor" {
  name = aws_ssm_document.block_device_monitor.name

  targets {
    key    = "tag:$${var.monitor_tag_key}"
    values = [var.monitor_tag_value]
  }

  parameters = {
    LogGroupName              = var.log_group_name
    LogStreamPrefix           = "{instance_id}"
    InstallCloudWatchAgent    = "true"
    EnableRootDeviceSuppression = "true"
  }
}

output "log_group_name" {
  description = "CloudWatch Log Group for block device events"
  value       = aws_cloudwatch_log_group.block_device_monitor.name
}

output "ssm_document_name" {
  description = "SSM Document for deploying monitoring"
  value       = aws_ssm_document.block_device_monitor.name
}

output "alert_topic_arn" {
  description = "SNS Topic for alerts"
  value       = aws_sns_topic.alerts.arn
}

# KEY ADVANTAGES:
# - Real-time detection (sub-second vs hourly polling)
# - Structured JSON logs for reliable metric filtering
# - Evidence collection (lsblk, device details)
# - Distro-aware (Amazon Linux, Ubuntu, RHEL)
# - Fleet deployment via tags
# - Root device suppression to reduce noise""",
                alert_severity="high",
                alert_title="Block Device Addition Detected (Real-Time)",
                alert_description_template="New block device {devkernel} connected to host {host} at {ts}. This may indicate unauthorised USB or external storage connection.",
                investigation_steps=[
                    "Review the CloudWatch Log event for device details (devkernel, devpath)",
                    "Check the evidence snapshot (lsblk output) for device type and characteristics",
                    "Identify the EC2 instance from the log stream name",
                    "Verify physical access to the data centre or if this is a cloud-attached volume",
                    "Check if the device has a known serial number or model",
                    "Review security camera footage if physical access is suspected",
                    "Examine mount points and file system type for data exfiltration risk",
                    "Check for subsequent file copy or data staging activity",
                ],
                containment_actions=[
                    "Immediately isolate the affected instance via security groups",
                    "Connect via SSM Session Manager to investigate (avoid SSH which may be compromised)",
                    "Run 'lsblk' and 'mount' to identify the connected device",
                    "If unauthorised, unmount and disconnect the device",
                    "Capture disk image for forensic analysis if data exfiltration suspected",
                    "Rotate any credentials accessible from the instance",
                    "Review IAM role and instance profile permissions",
                    "Deploy USB device control policies for prevention",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Root device is automatically suppressed. Add regex patterns for known devices (e.g., ^loop for loop devices). Review boot-time device adds.",
            detection_coverage="85% - real-time kernel-level detection of all block device additions. Best cloud-native approach without third-party EDR.",
            evasion_considerations="Sophisticated attackers may disable udev rules or systemd services. Combine with file integrity monitoring on /etc/udev/rules.d/ and regular SSM state verification.",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "SSM agent installed on instances",
                "CloudWatch Agent installed (for log shipping)",
                "Instances tagged with BlockDeviceMonitor=true",
                "Linux instances (Amazon Linux, Ubuntu, RHEL supported)",
            ],
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
      KmsMasterKeyId: alias/aws/sns
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
      KmsMasterKeyId: alias/aws/sns
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
      # Hardware additions not directly detectable - use post-compromise indicators
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - "Execution:Runtime/NewBinaryExecuted"
            - "Execution:Runtime/MaliciousFileExecuted"
            - "Execution:Runtime/SuspiciousCommand"
            - "Backdoor:EC2/C&CActivity.B"
          severity:
            - numeric:
                - ">="
                - 4
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
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt RuntimeFindingsRule.Arn

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
  kms_master_key_id = "alias/aws/sns"
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

  # Hardware additions not directly detectable - use post-compromise indicators
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        "Execution:Runtime/NewBinaryExecuted",
        "Execution:Runtime/MaliciousFileExecuted",
        "Execution:Runtime/SuspiciousCommand",
        "Backdoor:EC2/C&CActivity.B"
      ]
      # Severity >= 4 (MEDIUM or above) to filter noise
      severity = [{ numeric = [">=", 4] }]
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
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.runtime_findings.arn
          }
      }
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
# - Host-based auditd rules: auditctl -w /dev -p wa -k peripheral_devices""",
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
        "t1200-aws-realtime-block-device",  # Best cloud-native approach for Linux
        "t1200-aws-network-interface",
        "t1200-gcp-compute-disk",
        "t1200-aws-ssm-hardware-audit",  # Fallback for Windows or non-real-time needs
    ],
    total_effort_hours=5.5,
    coverage_improvement="+10% improvement for Initial Access tactic (endpoint agents required for full coverage)",
)
