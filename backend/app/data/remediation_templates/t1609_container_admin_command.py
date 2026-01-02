"""
T1609 - Container Administration Command

Adversaries abuse container administration services (Docker daemon, Kubernetes API,
kubelet) to execute commands within containers. Used by TeamTNT, Siloscape.
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
    technique_id="T1609",
    technique_name="Container Administration Command",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1609/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse container administration services such as Docker daemon, "
            "Kubernetes API server, or kubelet to execute commands within containers. "
            "Attackers leverage tools like docker exec, kubectl exec, or API calls to run "
            "malicious code with container privileges."
        ),
        attacker_goal="Execute arbitrary commands in containers via administration services",
        why_technique=[
            "Legitimate admin tools bypass security",
            "Commands run with container privileges",
            "Hard to distinguish from normal operations",
            "Direct access to running workloads",
            "Can pivot across containers",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Direct code execution in production containers. Difficult to detect amongst "
            "legitimate operations. Can lead to lateral movement and data theft. "
            "Commonly exploited by container-focused threat actors."
        ),
        business_impact=[
            "Unauthorised code execution",
            "Container compromise",
            "Lateral movement in cluster",
            "Data exfiltration",
            "Cryptomining deployment",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1496.001", "T1530", "T1552.001"],
        often_follows=["T1190", "T1078.004", "T1552.005"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1609-aws-ecs-exec",
            name="AWS ECS Exec Command Detection",
            description=(
                "Detect ECS exec commands via EventBridge (CloudTrail integration). "
                "Near real-time detection with human-readable alerts and reliable delivery."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.cluster, requestParameters.task, requestParameters.container
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "ExecuteCommand"
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  Detect ECS container exec commands (T1609)
  Uses EventBridge for near real-time detection via CloudTrail

Parameters:
  AlertEmail:
    Type: String
    Description: Email for alerts (requires SNS subscription confirmation)

Resources:
  # SNS topic for alerts
  ECSExecAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: t1609-ecs-exec-alerts
      KmsMasterKeyId: alias/aws/sns
      DisplayName: ECS Exec Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # DLQ for delivery failures
  ECSExecDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: t1609-ecs-exec-dlq
      MessageRetentionPeriod: 1209600  # 14 days

  # EventBridge rule: detect ECS ExecuteCommand via CloudTrail
  ECSExecRule:
    Type: AWS::Events::Rule
    Properties:
      Name: t1609-ecs-executecommand
      Description: Detect ECS Exec (ExecuteCommand) via CloudTrail (T1609)
      EventPattern:
        source:
          - aws.ecs
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventSource:
            - ecs.amazonaws.com
          eventName:
            - ExecuteCommand
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref ECSExecAlertTopic
          DeadLetterConfig:
            Arn: !GetAtt ECSExecDLQ.Arn
          RetryPolicy:
            MaximumEventAgeInSeconds: 3600
            MaximumRetryAttempts: 8
          InputTransformer:
            InputPathsMap:
              time: $.time
              account: $.account
              region: $.detail.awsRegion
              actor: $.detail.userIdentity.arn
              srcip: $.detail.sourceIPAddress
              useragent: $.detail.userAgent
              cluster: $.detail.requestParameters.cluster
              task: $.detail.requestParameters.task
              container: $.detail.requestParameters.container
              command: $.detail.requestParameters.command
            InputTemplate: |
              "ALERT: ECS Exec detected (T1609)
              time=<time>
              account=<account> region=<region>
              actor=<actor>
              source_ip=<srcip>
              cluster=<cluster>
              task=<task>
              container=<container>
              command=<command>
              user_agent=<useragent>"

  # SNS topic policy with scoped conditions
  ECSExecTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref ECSExecAlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref ECSExecAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ECSExecRule.Arn

  # Allow EventBridge to send to DLQ
  ECSExecDLQPolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues:
        - !Ref ECSExecDLQ
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sqs:SendMessage
            Resource: !GetAtt ECSExecDLQ.Arn
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ECSExecRule.Arn

Outputs:
  AlertTopicArn:
    Description: SNS topic for ECS Exec alerts
    Value: !Ref ECSExecAlertTopic
  EventRuleArn:
    Description: EventBridge rule ARN
    Value: !GetAtt ECSExecRule.Arn
  DLQUrl:
    Description: Dead letter queue URL for failed deliveries
    Value: !Ref ECSExecDLQ""",
                terraform_template="""# Detect ECS container exec commands (T1609)
# Uses EventBridge for near real-time detection via CloudTrail
# Optimised pattern: fewer moving parts, human-readable alerts, reliable delivery

variable "name_prefix" {
  type        = string
  default     = "t1609-ecs-exec"
  description = "Prefix for resource names"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts (SNS subscription confirmation required)"
}

data "aws_caller_identity" "current" {}

# SNS topic for alerts
resource "aws_sns_topic" "ecs_exec_alerts" {
  name              = "$${var.name_prefix}-alerts"
  display_name      = "ECS Exec Alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ecs_exec_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule: detect ECS ExecuteCommand calls via CloudTrail
resource "aws_cloudwatch_event_rule" "ecs_exec" {
  name        = "$${var.name_prefix}-executecommand"
  description = "Detect ECS Exec (ExecuteCommand) via CloudTrail (T1609)"

  event_pattern = jsonencode({
    source        = ["aws.ecs"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ecs.amazonaws.com"]
      eventName   = ["ExecuteCommand"]
    }
  })
}

# DLQ for delivery failures (14 day retention)
resource "aws_sqs_queue" "ecs_exec_dlq" {
  name                      = "$${var.name_prefix}-dlq"
  message_retention_seconds = 1209600
}

# Route to SNS with input transformer for human-readable alerts
resource "aws_cloudwatch_event_target" "ecs_exec_to_sns" {
  rule      = aws_cloudwatch_event_rule.ecs_exec.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.ecs_exec_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.ecs_exec_dlq.arn
  }

  input_transformer {
    input_paths = {
      time      = "$.time"
      account   = "$.account"
      region    = "$.detail.awsRegion"
      actor     = "$.detail.userIdentity.arn"
      srcip     = "$.detail.sourceIPAddress"
      useragent = "$.detail.userAgent"
      cluster   = "$.detail.requestParameters.cluster"
      task      = "$.detail.requestParameters.task"
      container = "$.detail.requestParameters.container"
      command   = "$.detail.requestParameters.command"
    }

    input_template = <<-EOT
"ALERT: ECS Exec detected (T1609)
time=<time>
account=<account> region=<region>
actor=<actor>
source_ip=<srcip>
cluster=<cluster>
task=<task>
container=<container>
command=<command>
user_agent=<useragent>"
EOT
  }
}

# SNS topic policy with scoped conditions for least privilege
resource "aws_sns_topic_policy" "allow_eventbridge_publish" {
  arn = aws_sns_topic.ecs_exec_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ecs_exec_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.ecs_exec.arn
        }
      }
    }]
  })
}

# Allow EventBridge to send to DLQ
resource "aws_sqs_queue_policy" "ecs_exec_dlq" {
  queue_url = aws_sqs_queue.ecs_exec_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.ecs_exec_dlq.arn
    }]
  })
}

output "alert_topic_arn" {
  description = "SNS topic for ECS Exec alerts"
  value       = aws_sns_topic.ecs_exec_alerts.arn
}

output "event_rule_arn" {
  description = "EventBridge rule ARN"
  value       = aws_cloudwatch_event_rule.ecs_exec.arn
}

output "dlq_url" {
  description = "Dead letter queue URL for failed deliveries"
  value       = aws_sqs_queue.ecs_exec_dlq.url
}""",
                alert_severity="high",
                alert_title="ECS Container Exec Command Executed",
                alert_description_template="User {userIdentity.arn} executed command in ECS container {container} on task {task}.",
                investigation_steps=[
                    "Verify the user is authorised for container access",
                    "Review the command executed (check ECS audit logs)",
                    "Check if exec was from expected IP/location",
                    "Examine container for malicious activity",
                    "Review user's recent activity for anomalies",
                ],
                containment_actions=[
                    "Disable ECS exec if not required",
                    "Restrict exec permissions via IAM",
                    "Rotate credentials if compromised",
                    "Isolate affected containers",
                    "Enable ECS task audit logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised DevOps roles and scheduled maintenance windows",
            detection_coverage="95% - captures all ECS exec commands in near real-time",
            evasion_considerations="Cannot evade if using ECS exec; attacker may use SSH instead",
            implementation_effort=EffortLevel.LOW,
            implementation_time="20 minutes",
            estimated_monthly_cost="$1-3 (EventBridge + SNS, no log ingestion)",
            prerequisites=[
                "CloudTrail enabled (management events)",
                "ECS exec enabled on cluster",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1609-gcp-gke-exec",
            name="GCP GKE Exec Command Detection",
            description="Detect kubectl exec commands in GKE clusters.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_cluster"
protoPayload.methodName="io.k8s.core.v1.pods.exec.create"
OR protoPayload.methodName="io.k8s.core.v1.pods.attach.create"''',
                gcp_terraform_template="""# GCP: Detect kubectl exec commands in GKE

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Log-based metric for kubectl exec
resource "google_logging_metric" "kubectl_exec" {
  project = var.project_id
  name    = "kubectl-exec-commands"
  filter  = <<-EOT
    resource.type="k8s_cluster"
    protoPayload.methodName="io.k8s.core.v1.pods.exec.create"
    OR protoPayload.methodName="io.k8s.core.v1.pods.attach.create"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User executing command"
    }
    labels {
      key         = "namespace"
      value_type  = "STRING"
      description = "Kubernetes namespace"
    }
  }

  label_extractors = {
    "user"      = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "namespace" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for exec commands
resource "google_monitoring_alert_policy" "kubectl_exec" {
  project      = var.project_id
  display_name = "GKE Container Exec Command"
  combiner     = "OR"

  conditions {
    display_name = "kubectl exec detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.kubectl_exec.name}\" AND resource.type=\"k8s_cluster\""
      duration        = "0s"
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
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "kubectl exec command detected in GKE cluster. Investigate user activity and command executed."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: GKE Container Exec Command Detected",
                alert_description_template="kubectl exec command executed in cluster by {principalEmail} on pod {resourceName}.",
                investigation_steps=[
                    "Verify user is authorised for cluster access",
                    "Review the command executed in audit logs",
                    "Check source IP and location",
                    "Examine pod for suspicious activity",
                    "Review user's recent Kubernetes API calls",
                ],
                containment_actions=[
                    "Revoke user's cluster access if unauthorised",
                    "Use Pod Security Policies to restrict exec",
                    "Enable Binary Authorization",
                    "Implement RBAC restrictions",
                    "Delete compromised pods",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist service accounts used by authorised DevOps teams",
            detection_coverage="95% - captures all kubectl exec/attach commands",
            evasion_considerations="Cannot evade API audit logging; attacker may use node access instead",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["GKE audit logging enabled", "Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1609-aws-eks-exec",
            name="AWS EKS Exec Command Detection",
            description="Detect kubectl exec commands in EKS clusters.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, objectRef.namespace, objectRef.name, user.username, sourceIPs.0
| filter objectRef.resource = "pods"
| filter verb = "create"
| filter objectRef.subresource = "exec" or objectRef.subresource = "attach"
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EKS kubectl exec commands

Parameters:
  EKSAuditLogGroup:
    Type: String
    Description: EKS cluster audit log group (e.g., /aws/eks/cluster-name/cluster)
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: EKS Exec Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for kubectl exec
  KubectlExecFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref EKSAuditLogGroup
      FilterPattern: '{ $.objectRef.resource = "pods" && $.verb = "create" && ($.objectRef.subresource = "exec" || $.objectRef.subresource = "attach") }'
      MetricTransformations:
        - MetricName: KubectlExecCommands
          MetricNamespace: Security/EKS
          MetricValue: "1"
          DefaultValue: 0

  # Alarm for kubectl exec
  KubectlExecAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EKS-Kubectl-Exec-Alert
      AlarmDescription: Alert on kubectl exec commands in EKS
      MetricName: KubectlExecCommands
      Namespace: Security/EKS
      Statistic: Sum
      Period: 300
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect EKS kubectl exec commands

variable "eks_audit_log_group" {
  description = "EKS cluster audit log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# SNS topic for alerts
resource "aws_sns_topic" "eks_exec_alerts" {
  name         = "eks-kubectl-exec-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "EKS Exec Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.eks_exec_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for kubectl exec
resource "aws_cloudwatch_log_metric_filter" "kubectl_exec" {
  name           = "kubectl-exec-commands"
  log_group_name = var.eks_audit_log_group
  pattern        = "{ $.objectRef.resource = \"pods\" && $.verb = \"create\" && ($.objectRef.subresource = \"exec\" || $.objectRef.subresource = \"attach\") }"

  metric_transformation {
    name      = "KubectlExecCommands"
    namespace = "Security/EKS"
    value     = "1"
    default_value = 0
  }
}

# Alarm for kubectl exec
resource "aws_cloudwatch_metric_alarm" "kubectl_exec" {
  alarm_name          = "eks-kubectl-exec-alert"
  alarm_description   = "Alert on kubectl exec commands in EKS"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "KubectlExecCommands"
  namespace           = "Security/EKS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.eks_exec_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "eks_exec_alerts" {
  arn = aws_sns_topic.eks_exec_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.eks_exec_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="EKS kubectl Exec Command Executed",
                alert_description_template="kubectl exec executed by {user.username} on pod {objectRef.name} in namespace {objectRef.namespace}.",
                investigation_steps=[
                    "Verify user is authorised for pod exec",
                    "Review command executed in audit logs",
                    "Check source IP matches expected location",
                    "Examine pod for malicious processes",
                    "Review user's recent Kubernetes operations",
                ],
                containment_actions=[
                    "Revoke user's cluster access",
                    "Use RBAC to restrict exec permissions",
                    "Enable Pod Security Standards",
                    "Isolate affected pods",
                    "Rotate service account tokens",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist service accounts for CI/CD and monitoring",
            detection_coverage="95% - captures all exec and attach operations",
            evasion_considerations="Cannot evade audit logs; attacker may compromise node directly",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$3-7",
            prerequisites=[
                "EKS control plane logging enabled",
                "CloudWatch Logs configured",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1609-docker-exec",
            name="Docker Exec Command Detection",
            description="Detect docker exec commands on container hosts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @message like /docker exec/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect docker exec commands (requires CloudWatch agent)

Parameters:
  SystemLogGroup:
    Type: String
    Description: EC2 system log group name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      DisplayName: Docker Exec Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Metric filter for docker exec
  DockerExecFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemLogGroup
      FilterPattern: '[time, type, user, command="docker", action="exec", ...]'
      MetricTransformations:
        - MetricName: DockerExecCommands
          MetricNamespace: Security/Docker
          MetricValue: "1"
          DefaultValue: 0

  # Alarm for docker exec
  DockerExecAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Docker-Exec-Command-Alert
      AlarmDescription: Alert on docker exec commands
      MetricName: DockerExecCommands
      Namespace: Security/Docker
      Statistic: Sum
      Period: 300
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId""",
                terraform_template="""# Detect docker exec commands (requires audit logging)

variable "system_log_group" {
  description = "EC2 system log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# SNS topic for alerts
resource "aws_sns_topic" "docker_exec_alerts" {
  name         = "docker-exec-alerts"
  kms_master_key_id = "alias/aws/sns"
  display_name = "Docker Exec Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.docker_exec_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for docker exec
resource "aws_cloudwatch_log_metric_filter" "docker_exec" {
  name           = "docker-exec-commands"
  log_group_name = var.system_log_group
  pattern        = "[time, type, user, command=\"docker\", action=\"exec\", ...]"

  metric_transformation {
    name      = "DockerExecCommands"
    namespace = "Security/Docker"
    value     = "1"
    default_value = 0
  }
}

# Alarm for docker exec
resource "aws_cloudwatch_metric_alarm" "docker_exec" {
  alarm_name          = "docker-exec-alert"
  alarm_description   = "Alert on docker exec commands"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DockerExecCommands"
  namespace           = "Security/Docker"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.docker_exec_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "docker_exec_alerts" {
  arn = aws_sns_topic.docker_exec_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.docker_exec_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Docker Exec Command Detected",
                alert_description_template="docker exec command executed on host.",
                investigation_steps=[
                    "Identify user who executed command",
                    "Review command and container targeted",
                    "Check if action was authorised",
                    "Examine container for malicious activity",
                    "Review host audit logs for context",
                ],
                containment_actions=[
                    "Restrict Docker socket access",
                    "Use read-only containers where possible",
                    "Implement Docker authorisation plugins",
                    "Enable comprehensive audit logging",
                    "Isolate affected containers",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Requires comprehensive audit logging; whitelist authorised operations",
            detection_coverage="70% - depends on audit logging configuration",
            evasion_considerations="Attacker may disable logging or use alternative execution methods",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "Docker audit logging enabled",
                "CloudWatch agent configured",
            ],
        ),
    ],
    recommended_order=[
        "t1609-aws-ecs-exec",
        "t1609-gcp-gke-exec",
        "t1609-aws-eks-exec",
        "t1609-docker-exec",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+18% improvement for Execution tactic",
)
