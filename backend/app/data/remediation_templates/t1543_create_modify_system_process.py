"""
T1543 - Create or Modify System Process

Adversaries establish persistence by creating or modifying system-level processes.
Used by Exaramel, LITTLELAMB.WOOLTEA, and various container malware.
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
    technique_id="T1543",
    technique_name="Create or Modify System Process",
    tactic_ids=["TA0003", "TA0004"],  # Persistence, Privilege Escalation
    mitre_url="https://attack.mitre.org/techniques/T1543/",
    threat_context=ThreatContext(
        description=(
            "Adversaries establish persistence by creating or modifying system-level processes "
            "that execute malicious payloads repeatedly. In cloud environments, this includes "
            "modifying ECS/EKS task definitions, Lambda functions, Cloud Run services, and "
            "container startup configurations. These processes can be configured to run at "
            "startup or regular intervals and may escalate privileges by executing under "
            "elevated contexts."
        ),
        attacker_goal="Establish persistent execution via system-level process modification",
        why_technique=[
            "Provides automatic re-execution on system restart",
            "Can run with elevated privileges",
            "Difficult to detect without baseline monitoring",
            "Survives user logout and session termination",
            "Can be disguised as legitimate system services",
            "Enables long-term access to compromised environments",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Exaramel Linux Daemon Persistence",
                year=2024,
                description="Exaramel for Linux achieves persistence via Upstart or System V when running as root, creating system services for backdoor execution",
                reference_url="https://attack.mitre.org/software/S0401/",
            ),
            Campaign(
                name="LITTLELAMB.WOOLTEA Daemon Operations",
                year=2024,
                description="LITTLELAMB.WOOLTEA initialises as a daemon for persistent background operation in compromised environments",
                reference_url="https://attack.mitre.org/software/S1084/",
            ),
            Campaign(
                name="Container Service Persistence",
                year=2024,
                description="Adversaries modify container restart policies and service definitions to maintain persistence across container restarts",
                reference_url="https://attack.mitre.org/techniques/T1543/005/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "High risk due to ability to maintain persistent access with elevated privileges. "
            "Commonly used for cryptomining, backdoor persistence, and data exfiltration. "
            "Can survive system restarts and provide automatic re-infection."
        ),
        business_impact=[
            "Persistent unauthorised access",
            "Privilege escalation opportunities",
            "Cryptomining resource abuse",
            "Backdoor installation",
            "Data exfiltration infrastructure",
            "Compliance violations",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1496.001", "T1053", "T1068"],
        often_follows=["T1078.004", "T1190", "T1068"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1543-aws-ecs",
            name="AWS ECS Task Definition Modification Detection",
            description="Detect modifications to ECS task definitions that could establish persistence via system processes.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.taskDefinition, requestParameters.containerDefinitions.0.command
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "RegisterTaskDefinition" or eventName = "UpdateService"
| filter requestParameters.containerDefinitions.0.command like /systemd|init|cron|service/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect ECS task definition modifications for persistence

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Detect task definition modifications
  TaskDefModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "RegisterTaskDefinition") || ($.eventName = "UpdateService") }'
      MetricTransformations:
        - MetricName: ECSTaskDefinitionChanges
          MetricNamespace: Security
          MetricValue: "1"

  TaskDefModificationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousECSTaskDefModification
      MetricName: ECSTaskDefinitionChanges
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect ECS task definition modifications for persistence

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ecs-task-modification-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for task definition changes
resource "aws_cloudwatch_log_metric_filter" "task_def_mod" {
  name           = "ecs-task-definition-changes"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = RegisterTaskDefinition) || ($.eventName = UpdateService) }"

  metric_transformation {
    name      = "ECSTaskDefinitionChanges"
    namespace = "Security"
    value     = "1"
  }
}

# Alert on suspicious modifications
resource "aws_cloudwatch_metric_alarm" "task_def_mod" {
  alarm_name          = "SuspiciousECSTaskDefModification"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ECSTaskDefinitionChanges"
  namespace           = "Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects suspicious ECS task definition modifications"
}""",
                alert_severity="high",
                alert_title="Suspicious ECS Task Definition Modification",
                alert_description_template="ECS task definition modified: {taskDefinition} by {principalId}.",
                investigation_steps=[
                    "Review task definition changes (compare with previous version)",
                    "Check for system process references (systemd, init, cron)",
                    "Verify modification was authorised",
                    "Review principal's recent activity",
                    "Check restart policies and service configurations",
                    "Inspect container entry points and commands",
                ],
                containment_actions=[
                    "Rollback to previous task definition version",
                    "Revoke unauthorised ECS permissions",
                    "Implement task definition approval workflow",
                    "Enable ECS Exec logging and audit",
                    "Review and restrict IAM roles",
                    "Implement service control policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised CI/CD pipelines and deployment roles",
            detection_coverage="75% - catches task definition modifications",
            evasion_considerations="Attackers may use stolen authorised credentials or make incremental changes",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs Insights"],
        ),
        DetectionStrategy(
            strategy_id="t1543-aws-lambda",
            name="AWS Lambda Function Modification Detection",
            description="Detect modifications to Lambda functions that could be used for persistent execution.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.functionName, responseElements.functionArn
| filter eventSource = "lambda.amazonaws.com"
| filter eventName = "UpdateFunctionCode20150331v2" or eventName = "UpdateFunctionConfiguration20150331v2" or eventName = "CreateEventSourceMapping20150331"
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda function modifications for persistence

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Detect Lambda function modifications
  LambdaModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "UpdateFunctionCode20150331v2") || ($.eventName = "UpdateFunctionConfiguration20150331v2") || ($.eventName = "CreateEventSourceMapping20150331") }'
      MetricTransformations:
        - MetricName: LambdaFunctionModifications
          MetricNamespace: Security
          MetricValue: "1"

  LambdaModificationAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SuspiciousLambdaModification
      MetricName: LambdaFunctionModifications
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect Lambda function modifications for persistence

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "lambda-modification-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for Lambda modifications
resource "aws_cloudwatch_log_metric_filter" "lambda_mod" {
  name           = "lambda-function-modifications"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = UpdateFunctionCode20150331v2) || ($.eventName = UpdateFunctionConfiguration20150331v2) || ($.eventName = CreateEventSourceMapping20150331) }"

  metric_transformation {
    name      = "LambdaFunctionModifications"
    namespace = "Security"
    value     = "1"
  }
}

# Alert on suspicious Lambda modifications
resource "aws_cloudwatch_metric_alarm" "lambda_mod" {
  alarm_name          = "SuspiciousLambdaModification"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "LambdaFunctionModifications"
  namespace           = "Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects suspicious Lambda function modifications"
}""",
                alert_severity="high",
                alert_title="Suspicious Lambda Function Modification",
                alert_description_template="Lambda function modified: {functionName} by {principalId}.",
                investigation_steps=[
                    "Review function code changes (compare versions)",
                    "Check event source mappings for new triggers",
                    "Verify modification was authorised",
                    "Review environment variables for credentials",
                    "Check function execution role permissions",
                    "Inspect function layers and dependencies",
                ],
                containment_actions=[
                    "Rollback to previous function version",
                    "Remove unauthorised event triggers",
                    "Revoke excessive Lambda permissions",
                    "Enable Lambda function versioning",
                    "Implement deployment approval process",
                    "Review and restrict execution roles",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known deployment services and CI/CD tools",
            detection_coverage="80% - catches Lambda modifications and event mappings",
            evasion_considerations="Attackers may use existing event sources or modify functions slowly",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Lambda execution logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1543-aws-eks",
            name="AWS EKS SystemD Service Creation Detection",
            description="Detect creation of systemd services and init processes within EKS containers.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, user.username, objectRef.namespace, objectRef.name, requestObject.spec.containers.0.command
| filter objectRef.resource = "pods"
| filter verb = "create"
| filter requestObject.spec.containers.0.command.0 like /systemctl|systemd|init.d|service|cron/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect systemd service creation in EKS containers

Parameters:
  EKSClusterName:
    Type: String
    Description: EKS cluster name
  AlertEmail:
    Type: String
    Description: Email for alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Query definition for system process creation
  SystemProcessQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: SystemProcessCreation
      LogGroupNames:
        - !Sub "/aws/eks/${EKSClusterName}/cluster"
      QueryString: |
        fields @timestamp, user.username, objectRef.name, requestObject.spec.containers.0.command
        | filter objectRef.resource = "pods"
        | filter verb = "create"
        | filter requestObject.spec.containers.0.command.0 like /systemctl|systemd|init.d|service|cron/""",
                terraform_template="""# Detect systemd service creation in EKS

variable "eks_cluster_name" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "eks-system-process-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Query definition for system process detection
resource "aws_cloudwatch_query_definition" "system_process" {
  name = "SystemProcessCreation"

  log_group_names = [
    "/aws/eks/${var.eks_cluster_name}/cluster"
  ]

  query_string = <<-EOT
    fields @timestamp, user.username, objectRef.name, requestObject.spec.containers.0.command
    | filter objectRef.resource = "pods"
    | filter verb = "create"
    | filter requestObject.spec.containers.0.command.0 like /systemctl|systemd|init.d|service|cron/
  EOT
}

# Metric filter for system process creation
resource "aws_cloudwatch_log_metric_filter" "system_process" {
  name           = "system-process-creation"
  log_group_name = "/aws/eks/${var.eks_cluster_name}/cluster"
  pattern        = "{ $.objectRef.resource = pods && $.verb = create }"

  metric_transformation {
    name      = "SystemProcessCreation"
    namespace = "Security/EKS"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "system_process" {
  alarm_name          = "SuspiciousSystemProcessCreation"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SystemProcessCreation"
  namespace           = "Security/EKS"
  period              = 300
  statistic           = "Sum"
  threshold           = 2
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Suspicious System Process Creation in EKS",
                alert_description_template="System process creation detected in namespace {namespace} by {username}.",
                investigation_steps=[
                    "Check container entry point and command arguments",
                    "Review pod security context and capabilities",
                    "Verify deploying user's authorisation",
                    "Inspect for systemd/init process references",
                    "Check container restart policies",
                    "Review pod lifecycle hooks",
                ],
                containment_actions=[
                    "Delete unauthorised pods",
                    "Implement Pod Security Standards",
                    "Use admission controllers to block system processes",
                    "Restrict CAP_SYS_ADMIN capability",
                    "Enable seccomp profiles",
                    "Review and restrict RBAC permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist legitimate system pods in kube-system namespace",
            detection_coverage="70% - catches pod-level system process creation",
            evasion_considerations="Attackers may use exec into running pods instead of creating new ones",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["EKS control plane logging enabled", "Audit logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1543-gcp-cloud-run",
            name="GCP Cloud Run Service Modification Detection",
            description="Detect modifications to Cloud Run services that could establish persistence.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="run.googleapis.com"
protoPayload.methodName=~"google.cloud.run.v1.Services.CreateService|google.cloud.run.v1.Services.ReplaceService"
(protoPayload.request.spec.template.spec.containers.command=~"systemd|init|cron|service"
OR protoPayload.request.spec.template.metadata.annotations."run.googleapis.com/execution-environment"="gen2")""",
                gcp_terraform_template="""# GCP: Detect Cloud Run service modifications

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for Cloud Run modifications
resource "google_logging_metric" "cloud_run_mod" {
  name   = "cloud-run-service-modifications"
  filter = <<-EOT
    protoPayload.serviceName="run.googleapis.com"
    protoPayload.methodName=~"CreateService|ReplaceService"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "service_name"
      value_type  = "STRING"
      description = "Cloud Run service name"
    }
  }
  label_extractors = {
    "service_name" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for service modifications
resource "google_monitoring_alert_policy" "cloud_run_mod" {
  display_name = "Suspicious Cloud Run Service Modification"
  combiner     = "OR"
  conditions {
    display_name = "Service modification detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cloud_run_mod.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content   = "Cloud Run service modification detected. Review service configuration changes."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Cloud Run Service Modified",
                alert_description_template="Cloud Run service modification detected.",
                investigation_steps=[
                    "Review service configuration changes",
                    "Check container entry point and command",
                    "Verify modification was authorised",
                    "Review service account permissions",
                    "Check environment variables for credentials",
                    "Inspect ingress and scaling settings",
                ],
                containment_actions=[
                    "Rollback to previous service revision",
                    "Delete unauthorised services",
                    "Require deployment approvals",
                    "Implement Binary Authorization",
                    "Use Org Policies to restrict modifications",
                    "Review service account permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD service accounts and authorised deployers",
            detection_coverage="85% - catches Cloud Run service modifications",
            evasion_considerations="Attackers may use stolen authorised credentials",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1543-gcp-gke",
            name="GCP GKE System Process Detection",
            description="Detect creation of systemd services and init processes in GKE containers.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_cluster"
protoPayload.resourceName=~"pods"
protoPayload.methodName="create"
protoPayload.request.spec.containers.command=~"systemctl|systemd|init.d|service|cron"''',
                gcp_terraform_template="""# GCP: Detect GKE system process creation

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for system process creation
resource "google_logging_metric" "system_process" {
  name   = "gke-system-process-creation"
  filter = <<-EOT
    resource.type="k8s_cluster"
    protoPayload.resourceName=~"pods"
    protoPayload.methodName="create"
    protoPayload.request.spec.containers.command=~"systemctl|systemd|init.d|service|cron"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "namespace"
      value_type  = "STRING"
      description = "Kubernetes namespace"
    }
  }
  label_extractors = {
    "namespace" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for system process creation
resource "google_monitoring_alert_policy" "system_process" {
  display_name = "Suspicious GKE System Process Creation"
  combiner     = "OR"
  conditions {
    display_name = "System process creation detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.system_process.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content   = "System process creation detected in GKE. Investigate pod and namespace."
    mime_type = "text/markdown"
  }
}

# Pod Security Policy to restrict system processes
resource "google_gke_hub_feature" "policycontroller" {
  name     = "policycontroller"
  location = "global"
  fleet_default_member_config {
    policycontroller {
      policy_controller_hub_config {
        install_spec = "INSTALL_SPEC_ENABLED"
        policy_content {
          bundles {
            bundle_name = "pss-baseline"
          }
        }
      }
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious GKE System Process Creation",
                alert_description_template="System process creation detected in GKE cluster.",
                investigation_steps=[
                    "Check pod container commands and entry points",
                    "Review pod security context",
                    "Verify deploying service account",
                    "Inspect for systemd/init references",
                    "Check restart policies and lifecycle hooks",
                    "Review RBAC permissions",
                ],
                containment_actions=[
                    "Delete unauthorised pods",
                    "Enable Pod Security Policies/Standards",
                    "Use admission controllers to block system processes",
                    "Implement Policy Controller constraints",
                    "Restrict privileged containers",
                    "Review service account permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist system namespaces (kube-system, gke-system)",
            detection_coverage="75% - catches system process creation in pods",
            evasion_considerations="Attackers may modify existing pods instead of creating new ones",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["GKE audit logging enabled", "Cloud Logging API enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1543-gcp-cloud-functions",
            name="GCP Cloud Functions Modification Detection",
            description="Detect modifications to Cloud Functions that could be used for persistent execution.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="cloudfunctions.googleapis.com"
protoPayload.methodName=~"google.cloud.functions.v1.CloudFunctionsService.CreateFunction|google.cloud.functions.v1.CloudFunctionsService.UpdateFunction"''',
                gcp_terraform_template="""# GCP: Detect Cloud Functions modifications

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for Cloud Functions modifications
resource "google_logging_metric" "function_mod" {
  name   = "cloud-functions-modifications"
  filter = <<-EOT
    protoPayload.serviceName="cloudfunctions.googleapis.com"
    protoPayload.methodName=~"CreateFunction|UpdateFunction"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "function_name"
      value_type  = "STRING"
      description = "Function name"
    }
  }
  label_extractors = {
    "function_name" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for function modifications
resource "google_monitoring_alert_policy" "function_mod" {
  display_name = "Cloud Functions Modification Detected"
  combiner     = "OR"
  conditions {
    display_name = "Function created or modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_mod.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  documentation {
    content   = "Cloud Function modification detected. Review function configuration and code."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Function Modified",
                alert_description_template="Cloud Function modification detected.",
                investigation_steps=[
                    "Review function code changes",
                    "Check event triggers and sources",
                    "Verify modification was authorised",
                    "Review environment variables",
                    "Check service account permissions",
                    "Inspect function dependencies",
                ],
                containment_actions=[
                    "Rollback to previous function version",
                    "Delete unauthorised functions",
                    "Remove suspicious event triggers",
                    "Require deployment approvals",
                    "Implement Org Policies",
                    "Review service account permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD service accounts",
            detection_coverage="85% - catches Cloud Functions modifications",
            evasion_considerations="Difficult to evade if audit logs are enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1543-aws-lambda",
        "t1543-gcp-cloud-functions",
        "t1543-aws-ecs",
        "t1543-gcp-cloud-run",
        "t1543-aws-eks",
        "t1543-gcp-gke",
    ],
    total_effort_hours=9.0,
    coverage_improvement="+15% improvement for Persistence and Privilege Escalation tactics",
)
