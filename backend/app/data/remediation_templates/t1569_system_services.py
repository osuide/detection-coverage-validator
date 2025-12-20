"""
T1569 - System Services

Adversaries abuse system services or daemons to execute commands or programs.
Used by APT32, APT38, APT39, APT41, FIN6, FIN7, and Wizard Spider.
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
    technique_id="T1569",
    technique_name="System Services",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1569/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse system services or daemons to execute malicious commands or programs. "
            "This includes Windows Service Control Manager, Linux systemd/systemctl, and macOS launchd. "
            "Services can provide persistence or temporary execution, often with elevated privileges."
        ),
        attacker_goal="Execute malicious code via system service mechanisms",
        why_technique=[
            "Services often run with SYSTEM/root privileges",
            "Can provide persistence across reboots",
            "Legitimate admin tools make detection difficult",
            "Remote service execution enables lateral movement",
            "Service creation may bypass application controls",
        ],
        known_threat_actors=[
            "APT32",
            "APT38",
            "APT39",
            "APT41",
            "FIN6",
            "FIN7",
            "Wizard Spider",
            "Chimera",
            "Blue Mockingbird",
        ],
        recent_campaigns=[
            Campaign(
                name="APT41 Cobalt Strike Service Execution",
                year=2024,
                description="Used svchost.exe and Net to launch Cobalt Strike BEACON loaders via Windows services",
                reference_url="https://attack.mitre.org/groups/G0096/",
            ),
            Campaign(
                name="FIN7 Encoded PowerShell Services",
                year=2024,
                description="Created Windows services executing encoded PowerShell commands for malware deployment",
                reference_url="https://attack.mitre.org/groups/G0046/",
            ),
            Campaign(
                name="Wizard Spider Ransomware Services",
                year=2024,
                description="Leveraged services.exe for lateral movement and ransomware deployment",
                reference_url="https://attack.mitre.org/groups/G0102/",
            ),
        ],
        prevalence="high",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "System services run with elevated privileges. "
            "Commonly used for persistence and lateral movement. "
            "Difficult to distinguish malicious from legitimate service activity."
        ),
        business_impact=[
            "Arbitrary code execution with elevated privileges",
            "Malware persistence",
            "Lateral movement to other systems",
            "Ransomware deployment",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1486", "T1485", "T1570"],
        often_follows=["T1078", "T1021"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1569-aws-ssm-automation",
            name="AWS SSM Automation Document Execution Detection",
            description="Detect execution of SSM Automation documents that may run commands on EC2 instances.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "StartAutomationExecution",
                            "SendCommand",
                            "CreateDocument",
                            "UpdateDocument",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect SSM service-like command execution

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: ssm-service-execution-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # EventBridge rule to detect SSM automation/command execution
  SSMServiceExecutionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: ssm-service-execution-detection
      Description: Detects SSM automation and command execution activities
      EventPattern:
        source: [aws.ssm]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - StartAutomationExecution
            - SendCommand
            - CreateDocument
            - UpdateDocument
      State: ENABLED
      Targets:
        - Id: SecurityAlertTopic
          Arn: !Ref AlertTopic

  # Allow EventBridge to publish to SNS
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

Outputs:
  AlertTopicArn:
    Value: !Ref AlertTopic
    Description: SNS topic for SSM execution alerts""",
                terraform_template="""# AWS: Detect SSM service-like command execution

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# SNS topic for security alerts
resource "aws_sns_topic" "ssm_alerts" {
  name = "ssm-service-execution-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule to detect SSM automation/command execution
resource "aws_cloudwatch_event_rule" "ssm_execution" {
  name        = "ssm-service-execution-detection"
  description = "Detects SSM automation and command execution activities"

  event_pattern = jsonencode({
    source      = ["aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "StartAutomationExecution",
        "SendCommand",
        "CreateDocument",
        "UpdateDocument"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ssm_execution.name
  target_id = "SecurityAlertTopic"
  arn       = aws_sns_topic.ssm_alerts.arn
}

# Allow EventBridge to publish to SNS
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.ssm_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssm_alerts.arn
    }]
  })
}

output "alert_topic_arn" {
  value       = aws_sns_topic.ssm_alerts.arn
  description = "SNS topic for SSM execution alerts"
}""",
                alert_severity="high",
                alert_title="SSM Service Execution Detected",
                alert_description_template="SSM automation or command execution by {userIdentity.arn} targeting {instanceIds}.",
                investigation_steps=[
                    "Verify the automation/command was authorised",
                    "Review the document content or command parameters",
                    "Check the user/role that initiated the execution",
                    "Review target instances for signs of compromise",
                    "Examine command output in SSM Run Command history",
                ],
                containment_actions=[
                    "Terminate unauthorised automation executions",
                    "Review and restrict SSM document permissions",
                    "Audit IAM policies granting ssm:SendCommand",
                    "Enable SSM Session Manager logging to S3",
                    "Isolate compromised instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known automation tools, patching systems, and CI/CD pipelines",
            detection_coverage="90% - catches SSM-based service execution on EC2",
            evasion_considerations="Attackers may use direct SSH/RDP instead, or compromise instances without SSM agent",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled with SSM events"],
        ),
        DetectionStrategy(
            strategy_id="t1569-aws-ecs-task-execution",
            name="AWS ECS Task Execution Detection",
            description="Detect execution of new ECS tasks that may be used as service-like execution mechanisms.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ecs"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["RunTask", "StartTask", "RegisterTaskDefinition"]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect ECS task execution for service-like behaviour

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: ecs-task-execution-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # EventBridge rule to detect ECS task execution
  ECSTaskExecutionRule:
    Type: AWS::Events::Rule
    Properties:
      Name: ecs-task-execution-detection
      Description: Detects ECS task execution activities
      EventPattern:
        source: [aws.ecs]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - RunTask
            - StartTask
            - RegisterTaskDefinition
      State: ENABLED
      Targets:
        - Id: SecurityAlertTopic
          Arn: !Ref AlertTopic

  # Allow EventBridge to publish to SNS
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

Outputs:
  AlertTopicArn:
    Value: !Ref AlertTopic
    Description: SNS topic for ECS task execution alerts""",
                terraform_template="""# AWS: Detect ECS task execution for service-like behaviour

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# SNS topic for security alerts
resource "aws_sns_topic" "ecs_alerts" {
  name = "ecs-task-execution-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ecs_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule to detect ECS task execution
resource "aws_cloudwatch_event_rule" "ecs_execution" {
  name        = "ecs-task-execution-detection"
  description = "Detects ECS task execution activities"

  event_pattern = jsonencode({
    source      = ["aws.ecs"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "RunTask",
        "StartTask",
        "RegisterTaskDefinition"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.ecs_execution.name
  target_id = "SecurityAlertTopic"
  arn       = aws_sns_topic.ecs_alerts.arn
}

# Allow EventBridge to publish to SNS
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.ecs_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ecs_alerts.arn
    }]
  })
}

output "alert_topic_arn" {
  value       = aws_sns_topic.ecs_alerts.arn
  description = "SNS topic for ECS task execution alerts"
}""",
                alert_severity="medium",
                alert_title="ECS Task Execution Detected",
                alert_description_template="ECS task execution by {userIdentity.arn} in cluster {cluster}.",
                investigation_steps=[
                    "Verify the task execution was authorised",
                    "Review the task definition and container image",
                    "Check the IAM role attached to the task",
                    "Examine task logs in CloudWatch Logs",
                    "Review network connections from the task",
                ],
                containment_actions=[
                    "Stop unauthorised tasks",
                    "Review ECS task execution permissions",
                    "Audit container images in ECR",
                    "Enable ECS Exec logging",
                    "Review VPC flow logs for suspicious traffic",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known application deployments and CI/CD pipelines",
            detection_coverage="85% - catches ECS-based service execution",
            evasion_considerations="Attackers may use EC2 instances directly or Lambda functions",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled with ECS events"],
        ),
        DetectionStrategy(
            strategy_id="t1569-gcp-compute-startup-scripts",
            name="GCP Compute Instance Startup Script Detection",
            description="Detect modifications to VM instance metadata that include startup scripts (service-like execution).",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="v1.compute.instances.setMetadata"
AND protoPayload.request.metadata.items.key=~"startup-script|windows-startup-script-ps1"''',
                gcp_terraform_template="""# GCP: Detect startup script modifications (service-like execution)

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Notification channel for email alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Startup Scripts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Log-based metric for startup script modifications
resource "google_logging_metric" "startup_script_modification" {
  name   = "compute-startup-script-modification"
  filter = <<-EOT
    protoPayload.methodName="v1.compute.instances.setMetadata"
    AND protoPayload.request.metadata.items.key=~"startup-script|windows-startup-script-ps1"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }

  project = var.project_id
}

# Alert policy for startup script modifications
resource "google_monitoring_alert_policy" "startup_script_alert" {
  display_name = "Compute Instance Startup Script Modified"
  combiner     = "OR"

  conditions {
    display_name = "Startup script modification detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.startup_script_modification.name}\" AND resource.type=\"gce_instance\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  project = var.project_id
}

output "metric_name" {
  value       = google_logging_metric.startup_script_modification.name
  description = "Log-based metric for startup script modifications"
}""",
                alert_severity="medium",
                alert_title="GCP: Compute Instance Startup Script Modified",
                alert_description_template="VM instance startup script modified, enabling service-like execution.",
                investigation_steps=[
                    "Verify the metadata modification was authorised",
                    "Review the startup script content",
                    "Check the user/service account that made the change",
                    "Examine instance logs for suspicious activity",
                    "Review instance IAM permissions",
                ],
                containment_actions=[
                    "Revert unauthorised metadata changes",
                    "Review and restrict compute.instances.setMetadata permissions",
                    "Audit VM instance configurations",
                    "Enable OS Config for centralised management",
                    "Isolate compromised instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known infrastructure-as-code deployments and automation tools",
            detection_coverage="80% - catches startup script modifications",
            evasion_considerations="Attackers may use direct SSH access or OS-level systemd modifications",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"],
        ),
        DetectionStrategy(
            strategy_id="t1569-gcp-cloud-run-deployment",
            name="GCP Cloud Run Service Deployment Detection",
            description="Detect deployment of Cloud Run services that may execute arbitrary code (service-like execution).",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"google.cloud.run.v1.Services.CreateService|google.cloud.run.v1.Services.ReplaceService"''',
                gcp_terraform_template="""# GCP: Detect Cloud Run service deployments (service-like execution)

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Notification channel for email alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Cloud Run"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Log-based metric for Cloud Run service deployments
resource "google_logging_metric" "cloud_run_deployment" {
  name   = "cloud-run-service-deployment"
  filter = <<-EOT
    protoPayload.methodName=~"google.cloud.run.v1.Services.CreateService|google.cloud.run.v1.Services.ReplaceService"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }

  project = var.project_id
}

# Alert policy for Cloud Run deployments
resource "google_monitoring_alert_policy" "cloud_run_alert" {
  display_name = "Cloud Run Service Deployed"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Run service deployment detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cloud_run_deployment.name}\" AND resource.type=\"cloud_run_revision\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }

  project = var.project_id
}

output "metric_name" {
  value       = google_logging_metric.cloud_run_deployment.name
  description = "Log-based metric for Cloud Run deployments"
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Run Service Deployed",
                alert_description_template="Cloud Run service deployed, potentially executing arbitrary code.",
                investigation_steps=[
                    "Verify the deployment was authorised",
                    "Review the container image and source",
                    "Check the service account attached to the service",
                    "Examine Cloud Run logs for suspicious activity",
                    "Review service configuration and environment variables",
                ],
                containment_actions=[
                    "Delete unauthorised Cloud Run services",
                    "Review and restrict run.services.create permissions",
                    "Audit container images in Artifact Registry",
                    "Enable Binary Authorisation for container validation",
                    "Review VPC connector configurations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known application deployments and CI/CD pipelines",
            detection_coverage="90% - catches Cloud Run service deployments",
            evasion_considerations="Attackers may use GKE or Compute Engine instead",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Cloud Run"],
        ),
    ],
    recommended_order=[
        "t1569-aws-ssm-automation",
        "t1569-aws-ecs-task-execution",
        "t1569-gcp-compute-startup-scripts",
        "t1569-gcp-cloud-run-deployment",
    ],
    total_effort_hours=2.5,
    coverage_improvement="+20% improvement for Execution tactic",
)
