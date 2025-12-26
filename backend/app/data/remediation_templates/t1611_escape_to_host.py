"""
T1611 - Escape to Host

Adversaries break out of containerised or virtualised environments to access
the underlying host system. Common methods include privileged containers,
bind mounts, docker.sock exploitation, and syscall abuse.

MITRE ATT&CK Reference: https://attack.mitre.org/techniques/T1611/
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
    technique_id="T1611",
    technique_name="Escape to Host",
    tactic_ids=["TA0004"],  # Privilege Escalation
    mitre_url="https://attack.mitre.org/techniques/T1611/",
    threat_context=ThreatContext(
        description=(
            "Adversaries break out of containerised or virtualised environments to gain "
            "access to the underlying host system. Common escape methods include mounting "
            "the host filesystem via bind mounts, running privileged containers, exploiting "
            "the Docker socket (docker.sock), abusing syscalls (unshare, keyctl), and "
            "leveraging hypervisor vulnerabilities."
        ),
        attacker_goal="Escape container/VM isolation to access the underlying host system",
        why_technique=[
            "Access other containers and VMs on the host",
            "Execute commands with host-level privileges",
            "Deploy persistent malware on the host",
            "Steal secrets and credentials from host",
            "Pivot to other systems via host network",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Container escape grants host-level access, completely bypassing isolation. "
            "Attackers gain full control of the host, all containers, and can access "
            "sensitive credentials, deploy persistent malware, and pivot to other systems. "
            "This represents a complete security boundary violation."
        ),
        business_impact=[
            "Complete host system compromise",
            "Access to all containers on the host",
            "Credential and secret theft",
            "Persistent malware deployment",
            "Lateral movement to other hosts",
        ],
        typical_attack_phase="privilege_escalation",
        often_precedes=["T1078.004", "T1552.001", "T1021.007"],
        often_follows=["T1525", "T1204.003", "T1648"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Privileged Container Detection
        DetectionStrategy(
            strategy_id="t1611-aws-privileged",
            name="Privileged Container and Bind Mount Detection",
            description="Detect privileged containers and suspicious bind mounts in ECS/EKS.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.taskDefinition, requestParameters.containerDefinitions
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "RegisterTaskDefinition"
| filter requestParameters.containerDefinitions.0.privileged = true
   or requestParameters.containerDefinitions.0.mountPoints.0.sourceVolume = "/"
   or requestParameters.containerDefinitions.0.mountPoints.0.sourceVolume = "/var/run/docker.sock"
| fields @timestamp, userIdentity.arn, requestParameters.family, requestParameters.containerDefinitions.0.privileged, requestParameters.containerDefinitions.0.mountPoints""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect privileged containers and risky bind mounts

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  PrivilegedContainerFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "ecs.amazonaws.com" && $.eventName = "RegisterTaskDefinition" && ($.requestParameters.containerDefinitions[0].privileged = true || $.requestParameters.containerDefinitions[0].mountPoints[0].sourceVolume = "/" || $.requestParameters.containerDefinitions[0].mountPoints[0].sourceVolume = "/var/run/docker.sock") }'
      MetricTransformations:
        - MetricName: PrivilegedContainerCreation
          MetricNamespace: Security
          MetricValue: "1"

  PrivilegedContainerAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: PrivilegedContainerDetected
      MetricName: PrivilegedContainerCreation
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect privileged containers and risky bind mounts

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "privileged-container-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "privileged_container" {
  name           = "privileged-container-creation"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"ecs.amazonaws.com\" && $.eventName = \"RegisterTaskDefinition\" && ($.requestParameters.containerDefinitions[0].privileged = true || $.requestParameters.containerDefinitions[0].mountPoints[0].sourceVolume = \"/\" || $.requestParameters.containerDefinitions[0].mountPoints[0].sourceVolume = \"/var/run/docker.sock\") }"

  metric_transformation {
    name      = "PrivilegedContainerCreation"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "privileged_container" {
  alarm_name          = "PrivilegedContainerDetected"
  metric_name         = "PrivilegedContainerCreation"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Privileged Container or Risky Bind Mount Detected",
                alert_description_template="Privileged container or risky bind mount created in task definition {taskDefinition} by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who registered the task definition",
                    "Review container configuration for privileged flag",
                    "Check bind mounts for host filesystem access",
                    "Verify if docker.sock is mounted",
                    "Review container image source and integrity",
                    "Check for container runtime activity on host",
                ],
                containment_actions=[
                    "Stop and delete unauthorised tasks",
                    "Revoke task registration permissions",
                    "Implement SCPs to prevent privileged containers",
                    "Enable GuardDuty runtime monitoring",
                    "Audit all task definitions for privileged settings",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate system containers requiring privileged access",
            detection_coverage="90% - catches privileged containers and bind mounts",
            evasion_considerations="Cannot evade if CloudTrail is enabled; may use service roles",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with ECS data events"],
        ),
        # Strategy 2: AWS - Container Runtime Security
        DetectionStrategy(
            strategy_id="t1611-aws-runtime",
            name="Container Runtime Escape Detection (GuardDuty)",
            description="Detect container escape attempts using GuardDuty Runtime Monitoring.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "PrivilegeEscalation:Runtime/DockerSocketAccessed",
                    "PrivilegeEscalation:Runtime/RuncContainerEscape",
                    "Execution:Runtime/NewBinaryExecuted",
                    "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty container escape detection via EventBridge

Parameters:
  AlertEmail:
    Type: String

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  ContainerEscapeRule:
    Type: AWS::Events::Rule
    Properties:
      # Scoped to specific container escape finding types to avoid alert fatigue
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          type:
            # Container escape specific findings
            - "PrivilegeEscalation:Runtime/RuncContainerEscape"
            - "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified"
            - "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory"
            - "PrivilegeEscalation:Runtime/DockerSocketAccessed"
            - "Execution:Runtime/NewBinaryExecuted"
          severity:
            - numeric:
                - ">="
                - 4
      Targets:
        - Id: Alert
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
                terraform_template="""# GuardDuty container escape detection

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "container-escape-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for EventBridge targets
resource "aws_sqs_queue" "events_dlq" {
  name                      = "container-escape-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue_policy" "events_dlq" {
  queue_url = aws_sqs_queue.events_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.events_dlq.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "container_escape" {
  name = "guardduty-container-escape"
  # Scoped to specific container escape finding types to avoid alert fatigue
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        # Container escape specific findings
        "PrivilegeEscalation:Runtime/RuncContainerEscape",
        "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified",
        "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
        "PrivilegeEscalation:Runtime/DockerSocketAccessed",
        "Execution:Runtime/NewBinaryExecuted"
      ]
      # Severity >= 4 (MEDIUM or above) to filter noise
      severity = [{ numeric = [">=", 4] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.container_escape.name
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.events_dlq.arn
  }
}

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
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Container Escape Attempt Detected",
                alert_description_template="GuardDuty detected container escape behaviour: {detail.type}.",
                investigation_steps=[
                    "Review GuardDuty finding details",
                    "Identify affected container and task",
                    "Check container image provenance",
                    "Review syscalls and process tree",
                    "Investigate host-level activity",
                    "Check for lateral movement",
                ],
                containment_actions=[
                    "Immediately stop affected tasks",
                    "Isolate affected host instances",
                    "Review and rotate credentials",
                    "Scan container images for malware",
                    "Implement runtime security policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Minimal tuning needed; GuardDuty has built-in ML",
            detection_coverage="95% - detects runtime escape attempts",
            evasion_considerations="Difficult to evade GuardDuty runtime monitoring",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$15-30 (GuardDuty EKS/ECS runtime monitoring)",
            prerequisites=["GuardDuty enabled with EKS/ECS runtime monitoring"],
        ),
        # Strategy 3: GCP - Privileged Container Detection
        DetectionStrategy(
            strategy_id="t1611-gcp-privileged",
            name="GCP Privileged Container Detection",
            description="Detect privileged containers and host mounts in GKE.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_cluster"
protoPayload.request.spec.containers.securityContext.privileged=true
OR protoPayload.request.spec.volumes.hostPath.path="/"
OR protoPayload.request.spec.volumes.hostPath.path="/var/run/docker.sock"''',
                gcp_terraform_template="""# GCP: Detect privileged containers and host mounts

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "privileged_container" {
  name   = "privileged-container-creation"
  filter = <<-EOT
    resource.type="k8s_cluster"
    (protoPayload.request.spec.containers.securityContext.privileged=true
    OR protoPayload.request.spec.volumes.hostPath.path="/"
    OR protoPayload.request.spec.volumes.hostPath.path="/var/run/docker.sock")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "privileged_container" {
  display_name = "Privileged Container Detected"
  combiner     = "OR"

  conditions {
    display_name = "Privileged container creation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.privileged_container.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="critical",
                alert_title="GCP: Privileged Container Detected",
                alert_description_template="Privileged container or risky host mount detected in GKE cluster.",
                investigation_steps=[
                    "Identify the pod and namespace",
                    "Review pod security context settings",
                    "Check volume mounts for host filesystem",
                    "Verify pod creator and RBAC permissions",
                    "Review container image source",
                    "Check for runtime escape activity",
                ],
                containment_actions=[
                    "Delete unauthorised pods immediately",
                    "Enforce Pod Security Standards/Policies",
                    "Review RBAC permissions",
                    "Enable GKE Binary Authorisation",
                    "Implement Workload Identity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist system DaemonSets requiring privileged access",
            detection_coverage="90% - catches privileged pods and host mounts",
            evasion_considerations="Cannot evade if audit logs are enabled",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["GKE audit logging enabled", "Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - Runtime Security with Security Command Center
        DetectionStrategy(
            strategy_id="t1611-gcp-scc",
            name="GKE Runtime Security Monitoring",
            description="Detect container escape attempts using Security Command Center.",
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                scc_finding_categories=[
                    "Persistence: Launch Suspicious Process",
                    "Privilege Escalation: Anomalous Multistep Privilege Escalation",
                    "Execution: Suspicious Process",
                ],
                gcp_terraform_template="""# GCP: Security Command Center container escape detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_pubsub_topic" "scc_findings" {
  name = "scc-container-escape-findings"
}

resource "google_pubsub_subscription" "scc_findings" {
  name  = "scc-container-escape-sub"
  topic = google_pubsub_topic.scc_findings.name
}

resource "google_scc_notification_config" "container_escape" {
  config_id    = "container-escape-notifications"
  organization = var.project_id
  pubsub_topic = google_pubsub_topic.scc_findings.id

  streaming_config {
    filter = <<-EOT
      category="Persistence: Launch Suspicious Process"
      OR category="Privilege Escalation: Anomalous Multistep Privilege Escalation"
      OR category="Execution: Suspicious Process"
    EOT
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Container Escape Activity Detected",
                alert_description_template="Security Command Center detected suspicious container activity indicating escape attempt.",
                investigation_steps=[
                    "Review SCC finding details and evidence",
                    "Identify affected workload and cluster",
                    "Analyse process tree and syscalls",
                    "Check for privilege escalation chains",
                    "Review container image and vulnerabilities",
                    "Investigate lateral movement",
                ],
                containment_actions=[
                    "Terminate affected pods immediately",
                    "Isolate compromised nodes",
                    "Rotate service account keys",
                    "Implement runtime security policies",
                    "Enable GKE Sandbox (gVisor)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Minimal tuning; SCC uses threat intelligence",
            detection_coverage="95% - detects runtime escape attempts",
            evasion_considerations="Difficult to evade SCC runtime detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$20-40 (Security Command Center Premium)",
            prerequisites=[
                "Security Command Center Premium",
                "GKE Security Posture enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1611-aws-runtime",
        "t1611-aws-privileged",
        "t1611-gcp-scc",
        "t1611-gcp-privileged",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+25% improvement for Privilege Escalation tactic",
)
