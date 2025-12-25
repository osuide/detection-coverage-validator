"""
T1021 - Remote Services

Adversaries exploit valid accounts to access remote services (SSH, RDP, VNC, SMB, WinRM,
cloud services) for lateral movement. This parent technique covers all remote service abuse.
Used by Aquatic Panda, Ember Bear, Wizard Spider.
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
    technique_id="T1021",
    technique_name="Remote Services",
    tactic_ids=["TA0008"],  # Lateral Movement
    mitre_url="https://attack.mitre.org/techniques/T1021/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit valid accounts to access remote services including SSH, RDP, "
            "VNC, SMB/Windows Admin Shares, DCOM, WinRM, and cloud services. These legitimate "
            "remote access protocols enable lateral movement across networked systems and cloud "
            "environments, appearing as normal administrative activity."
        ),
        attacker_goal="Move laterally across networks using legitimate remote access protocols with valid credentials",
        why_technique=[
            "Appears as legitimate remote access",
            "Built-in protocols on most systems",
            "Valid credentials bypass security controls",
            "Difficult to distinguish from normal admin activity",
            "Multiple protocols provide redundancy",
            "Enables rapid lateral movement",
            "Cloud services provide cross-environment access",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Remote services are fundamental for lateral movement in most attacks. "
            "Difficult to detect when using valid credentials and appearing as legitimate "
            "administrative activity. Critical for ransomware and data exfiltration campaigns."
        ),
        business_impact=[
            "Lateral movement enabling domain-wide compromise",
            "Ransomware deployment across multiple systems",
            "Data exfiltration from sensitive systems",
            "Privilege escalation opportunities",
            "Extended attacker dwell time",
            "Compliance violations (PCI-DSS, ISO 27001)",
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1486", "T1485", "T1530", "T1078.004"],
        often_follows=["T1078", "T1110", "T1003"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1021-aws-ssm-unusual",
            name="AWS Systems Manager Session Activity",
            description="Detect unusual or suspicious SSM session activity for lateral movement.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, sourceIPAddress, requestParameters.target
| filter eventSource = "ssm.amazonaws.com"
| filter eventName in ["StartSession", "ResumeSession", "TerminateSession"]
| stats count(*) as session_count by userIdentity.arn, requestParameters.target, bin(1h)
| filter session_count > 3
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual SSM session activity for lateral movement

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      DisplayName: SSM Lateral Movement Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  SSMSessionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ssm.amazonaws.com" && ($.eventName = "StartSession" || $.eventName = "ResumeSession") }'
      MetricTransformations:
        - MetricName: SSMSessionActivity
          MetricNamespace: Security
          MetricValue: "1"

  SSMSessionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualSSMSessionActivity
      AlarmDescription: Detects unusual SSM session patterns
      MetricName: SSMSessionActivity
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unusual SSM session activity

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name         = "ssm-lateral-movement-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "SSM Lateral Movement Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "ssm_sessions" {
  name           = "unusual-ssm-sessions"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ssm.amazonaws.com\" && ($.eventName = \"StartSession\" || $.eventName = \"ResumeSession\") }"

  metric_transformation {
    name      = "SSMSessionActivity"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "ssm_lateral" {
  alarm_name          = "UnusualSSMSessionActivity"
  alarm_description   = "Detects unusual SSM session patterns"
  metric_name         = "SSMSessionActivity"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unusual SSM Session Activity Detected",
                alert_description_template="Multiple SSM sessions initiated by {userIdentity.arn} to instances.",
                investigation_steps=[
                    "Review SSM session targets and commands executed",
                    "Check user identity and verify legitimacy",
                    "Review session timing and frequency patterns",
                    "Check for subsequent suspicious API calls",
                    "Review CloudTrail for associated events",
                    "Examine session command history if available",
                ],
                containment_actions=[
                    "Terminate active suspicious SSM sessions",
                    "Revoke compromised IAM credentials",
                    "Review and restrict SSM access policies",
                    "Enable session logging to S3",
                    "Review affected instances for compromise",
                    "Implement least-privilege access controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal SSM session patterns per administrator. Filter automated deployment sessions.",
            detection_coverage="75% - catches SSM-based lateral movement",
            evasion_considerations="Attackers may throttle sessions to avoid thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "SSM Session Manager enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1021-aws-ec2-remote-access",
            name="AWS EC2 Instance Remote Access Detection",
            description="Detect SSH/RDP connections between EC2 instances for lateral movement.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="vpc_flow_logs",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, srcport, dstport, action
| filter dstport in [22, 3389, 5985, 5986, 445]
| filter action = "ACCEPT"
| stats count(*) as connection_count by srcaddr, dstaddr, dstport, bin(5m)
| filter connection_count > 2
| sort connection_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect lateral movement via remote protocols

Parameters:
  VPCFlowLogsGroup:
    Type: String
    Description: VPC Flow Logs CloudWatch log group
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  LateralMovementFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogsGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport="22" || destport="3389" || destport="5985" || destport="5986" || destport="445", protocol, packets, bytes, windowstart, windowend, action="ACCEPT", flowlogstatus]'
      MetricTransformations:
        - MetricName: InternalRemoteConnections
          MetricNamespace: Security
          MetricValue: "1"

  LateralMovementAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: InternalLateralMovement
      MetricName: InternalRemoteConnections
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect lateral movement via remote protocols

variable "vpc_flow_logs_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "lateral-movement-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "lateral_movement" {
  name           = "internal-lateral-movement"
  log_group_name = var.vpc_flow_logs_group
  pattern        = "[version, account, eni, source, destination, srcport, destport=\"22\" || destport=\"3389\" || destport=\"5985\" || destport=\"5986\" || destport=\"445\", protocol, packets, bytes, windowstart, windowend, action=\"ACCEPT\", flowlogstatus]"

  metric_transformation {
    name      = "InternalRemoteConnections"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "lateral_movement" {
  alarm_name          = "InternalLateralMovement"
  metric_name         = "InternalRemoteConnections"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Internal Lateral Movement Detected",
                alert_description_template="Multiple remote protocol connections from {srcaddr} to {dstaddr} on port {dstport}.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Review authentication logs on both systems",
                    "Check for unusual processes or connections",
                    "Review security group rules",
                    "Check for credential access attempts",
                    "Examine command execution history",
                ],
                containment_actions=[
                    "Isolate suspicious instances",
                    "Block traffic between compromised systems",
                    "Rotate credentials on affected systems",
                    "Review and tighten security group rules",
                    "Enable enhanced monitoring",
                    "Check for persistence mechanisms",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal administrative patterns. Allowlist legitimate management servers.",
            detection_coverage="80% - catches network-based lateral movement",
            evasion_considerations="Cannot evade if VPC Flow Logs enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["VPC Flow Logs enabled and sent to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1021-aws-ecs-exec",
            name="AWS ECS Exec Session Detection",
            description="Detect ECS Exec usage for container access and lateral movement.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ecs"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["ExecuteCommand"]},
                },
                terraform_template="""# Detect ECS Exec usage for lateral movement

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ecs-exec-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "ecs_exec" {
  name        = "ecs-exec-detection"
  description = "Detect ECS Exec command execution"

  event_pattern = jsonencode({
    source      = ["aws.ecs"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail      = {
      eventName = ["ExecuteCommand"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ecs_exec.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn
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
                alert_severity="medium",
                alert_title="ECS Exec Command Execution",
                alert_description_template="ECS Exec command executed by {userIdentity.arn} on task {requestParameters.task}.",
                investigation_steps=[
                    "Review user identity executing ECS Exec",
                    "Check target container and task",
                    "Review executed commands if logging enabled",
                    "Check for unusual timing or frequency",
                    "Review container image for compromise",
                    "Check for subsequent suspicious activities",
                ],
                containment_actions=[
                    "Disable ECS Exec if not required",
                    "Revoke IAM permissions if compromised",
                    "Stop suspicious tasks",
                    "Review task definitions",
                    "Enable container insights logging",
                    "Implement least-privilege policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Filter known debugging sessions. Baseline normal operational patterns.",
            detection_coverage="90% - catches ECS Exec usage",
            evasion_considerations="Cannot evade if CloudTrail enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "ECS Exec enabled on tasks"],
        ),
        DetectionStrategy(
            strategy_id="t1021-gcp-ssh-lateral",
            name="GCP SSH Lateral Movement Detection",
            description="Detect SSH connections between GCP instances for lateral movement.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
protoPayload.methodName=~"compute.instances.osLogin"
OR (resource.type="gce_subnetwork"
    jsonPayload.connection.dest_port=22
    jsonPayload.connection.src_ip=~"10\\..*|172\\..*|192\\.168\\..*")""",
                gcp_terraform_template="""# GCP: Detect SSH-based lateral movement

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "ssh_lateral" {
  name   = "ssh-lateral-movement"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName=~"compute.instances.osLogin"
    OR (resource.type="gce_subnetwork"
        jsonPayload.connection.dest_port=22
        jsonPayload.connection.src_ip=~"10\\..*|172\\..*|192\\.168\\..*")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "ssh_lateral" {
  display_name = "SSH Lateral Movement"
  combiner     = "OR"
  conditions {
    display_name = "Internal SSH activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ssh_lateral.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 15
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: SSH Lateral Movement Detected",
                alert_description_template="Internal SSH connections detected between GCP instances.",
                investigation_steps=[
                    "Review source and destination instances",
                    "Check OS Login audit logs",
                    "Review SSH key usage",
                    "Check for unusual timing patterns",
                    "Review executed commands if available",
                    "Check for privilege escalation attempts",
                ],
                containment_actions=[
                    "Remove unauthorised SSH keys",
                    "Enable VPC Service Controls",
                    "Restrict firewall rules",
                    "Enable OS Login with 2FA",
                    "Review instance metadata",
                    "Implement bastion host architecture",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal SSH patterns. Filter automation and orchestration tools.",
            detection_coverage="75% - catches SSH-based lateral movement",
            evasion_considerations="May appear as legitimate administrative access",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1021-gcp-gke-exec",
            name="GCP GKE Container Exec Detection",
            description="Detect kubectl exec and GKE container access for lateral movement.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_cluster"
protoPayload.methodName="io.k8s.core.v1.pods.exec.create"
OR protoPayload.methodName="io.k8s.core.v1.pods.portforward.create"''',
                gcp_terraform_template="""# GCP: Detect GKE container access

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "gke_exec" {
  name   = "gke-container-access"
  filter = <<-EOT
    resource.type="k8s_cluster"
    (protoPayload.methodName="io.k8s.core.v1.pods.exec.create"
     OR protoPayload.methodName="io.k8s.core.v1.pods.portforward.create")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "gke_exec" {
  display_name = "GKE Container Access"
  combiner     = "OR"
  conditions {
    display_name = "Container exec or port-forward detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gke_exec.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: GKE Container Access Detected",
                alert_description_template="Container exec or port-forward operation detected in GKE cluster.",
                investigation_steps=[
                    "Review user identity and permissions",
                    "Check target pod and namespace",
                    "Review executed commands if audit policy enabled",
                    "Check for unusual timing or frequency",
                    "Review RBAC permissions",
                    "Check for subsequent suspicious activities",
                ],
                containment_actions=[
                    "Review and restrict RBAC permissions",
                    "Enable Binary Authorisation",
                    "Implement Pod Security Standards",
                    "Enable GKE audit logging",
                    "Review service account permissions",
                    "Implement network policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal debugging and operational access patterns. Filter CI/CD systems.",
            detection_coverage="85% - catches GKE container access",
            evasion_considerations="Cannot evade if GKE audit logging enabled",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["GKE cluster with audit logging enabled"],
        ),
    ],
    recommended_order=[
        "t1021-aws-ec2-remote-access",  # Broad coverage of lateral movement
        "t1021-aws-ssm-unusual",  # AWS-specific detection
        "t1021-gcp-ssh-lateral",  # GCP lateral movement
        "t1021-aws-ecs-exec",  # Container-specific
        "t1021-gcp-gke-exec",  # GKE-specific
    ],
    total_effort_hours=6.5,
    coverage_improvement="+20% improvement for Lateral Movement tactic",
)
