"""
T1053 - Scheduled Task/Job

Adversaries abuse task scheduling functionality to facilitate initial or recurring
execution of malicious code. In cloud environments, this includes EventBridge Scheduler,
Lambda scheduled events, Cloud Scheduler, and Kubernetes CronJobs.
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
    technique_id="T1053",
    technique_name="Scheduled Task/Job",
    tactic_ids=[
        "TA0002",
        "TA0003",
        "TA0004",
    ],  # Execution, Persistence, Privilege Escalation
    mitre_url="https://attack.mitre.org/techniques/T1053/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse task scheduling functionality across operating systems and cloud "
            "platforms to facilitate initial or recurring execution of malicious code. In cloud "
            "environments, this includes EventBridge Scheduler, Lambda event triggers, Cloud Scheduler, "
            "and Kubernetes CronJobs. Scheduled tasks enable persistence, privilege escalation through "
            "execution under elevated contexts, and masking malicious activity under trusted system processes."
        ),
        attacker_goal="Establish persistence and execute malicious code on a schedule",
        why_technique=[
            "Enables persistent execution without user interaction",
            "Can execute with elevated privileges",
            "Blends in with legitimate scheduled tasks",
            "Survives system reboots and restarts",
            "Difficult to detect among numerous legitimate jobs",
            "Provides automated recurring execution",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Lokibot Scheduled Execution",
                year=2024,
                description="Lokibot's second stage DLL set a timer using timeSetEvent to schedule its next execution",
                reference_url="https://attack.mitre.org/software/S0447/",
            ),
            Campaign(
                name="APT32 VBA Macro Scheduled Task",
                year=2024,
                description="APT32 used scheduled tasks in malicious VBA macros to run Regsvr32.exe every 30 minutes for persistence",
                reference_url="https://attack.mitre.org/techniques/T1053/",
            ),
        ],
        prevalence="very_common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Scheduled tasks are the 7th most prevalent ATT&CK technique used by adversaries. "
            "They enable persistent execution with elevated privileges and are difficult to detect "
            "among legitimate scheduled jobs. Cloud-native scheduling services provide additional "
            "attack vectors through event-driven architectures."
        ),
        business_impact=[
            "Persistent malware execution",
            "Privilege escalation via scheduled jobs",
            "Cryptomining and resource abuse",
            "Data exfiltration on schedule",
            "Lateral movement automation",
            "Compliance violations",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1496.001", "T1530", "T1087.004"],
        often_follows=["T1078.004", "T1098.003", "T1190"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1053-aws-eventbridge",
            name="AWS EventBridge Scheduler Rule Creation",
            description="Detect creation or modification of EventBridge rules and schedules that could be used for persistence.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.events", "aws.scheduler"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "PutRule",
                            "CreateSchedule",
                            "UpdateSchedule",
                            "PutTargets",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EventBridge rule and schedule creation

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Detect EventBridge rule creation/modification
  EventBridgeRuleDetection:
    Type: AWS::Events::Rule
    Properties:
      Name: detect-eventbridge-scheduler-changes
      Description: Alert on EventBridge rule and schedule changes
      EventPattern:
        source: [aws.events, aws.scheduler]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PutRule
            - CreateSchedule
            - UpdateSchedule
            - PutTargets
      State: ENABLED
      Targets:
        - Id: AlertTarget
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
                terraform_template="""# Detect EventBridge rule and schedule creation

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "eventbridge-scheduler-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Detect EventBridge rule/schedule changes
resource "aws_cloudwatch_event_rule" "scheduler_changes" {
  name        = "detect-eventbridge-scheduler-changes"
  description = "Alert on EventBridge rule and schedule creation/modification"

  event_pattern = jsonencode({
    source      = ["aws.events", "aws.scheduler"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutRule",
        "CreateSchedule",
        "UpdateSchedule",
        "PutTargets"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.scheduler_changes.name
  arn  = aws_sns_topic.alerts.arn
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
                alert_title="EventBridge Rule/Schedule Created or Modified",
                alert_description_template="EventBridge rule or schedule {ruleName} was created/modified by {userIdentity.principalId}",
                investigation_steps=[
                    "Verify the rule/schedule creation was authorised",
                    "Review the schedule expression and targets",
                    "Check the IAM principal that created the rule",
                    "Inspect the target resources (Lambda, ECS, etc.)",
                    "Review rule permissions and IAM roles",
                    "Check for unusual schedule patterns (every minute, etc.)",
                ],
                containment_actions=[
                    "Disable suspicious EventBridge rules",
                    "Delete unauthorised schedules",
                    "Review and restrict EventBridge permissions",
                    "Implement SCPs to limit rule creation",
                    "Enable EventBridge rule approval workflow",
                    "Audit all existing scheduled rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known automation accounts and CI/CD pipelines",
            detection_coverage="95% - catches all rule and schedule creation",
            evasion_considerations="Attackers may use stolen authorised credentials or modify existing rules",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "EventBridge events logged"],
        ),
        DetectionStrategy(
            strategy_id="t1053-aws-lambda-schedule",
            name="AWS Lambda Scheduled Event Detection",
            description="Detect Lambda functions with scheduled event triggers that could be used for recurring malicious execution.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.functionName, requestParameters.rule
| filter eventSource = "lambda.amazonaws.com" or eventSource = "events.amazonaws.com"
| filter eventName = "AddPermission20150331v2" or eventName = "PutTargets"
| filter requestParameters.statementId like /ScheduledEvent/ or requestParameters.rule like /schedule/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda scheduled event triggers

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

  # Detect Lambda scheduled triggers
  LambdaScheduleTriggerFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "AddPermission20150331v2") && ($.requestParameters.statementId = "*ScheduledEvent*") }'
      MetricTransformations:
        - MetricName: LambdaScheduledTriggers
          MetricNamespace: Security/Lambda
          MetricValue: "1"

  LambdaScheduleAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: LambdaScheduledEventAdded
      MetricName: LambdaScheduledTriggers
      Namespace: Security/Lambda
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect Lambda scheduled event triggers

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "lambda-schedule-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for Lambda scheduled triggers
resource "aws_cloudwatch_log_metric_filter" "lambda_schedule" {
  name           = "lambda-scheduled-triggers"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = AddPermission20150331v2) && ($.requestParameters.statementId = *ScheduledEvent*) }"

  metric_transformation {
    name      = "LambdaScheduledTriggers"
    namespace = "Security/Lambda"
    value     = "1"
  }
}

# Alert on scheduled trigger addition
resource "aws_cloudwatch_metric_alarm" "lambda_schedule" {
  alarm_name          = "LambdaScheduledEventAdded"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "LambdaScheduledTriggers"
  namespace           = "Security/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects Lambda functions with new scheduled event triggers"
}""",
                alert_severity="medium",
                alert_title="Lambda Scheduled Event Trigger Added",
                alert_description_template="Lambda function {functionName} was given a scheduled event trigger by {principalId}",
                investigation_steps=[
                    "Review the Lambda function code for malicious behaviour",
                    "Check the schedule frequency (every minute may indicate abuse)",
                    "Verify the principal that added the trigger was authorised",
                    "Review Lambda function IAM role permissions",
                    "Check Lambda execution logs for suspicious activity",
                    "Inspect function environment variables for credentials",
                ],
                containment_actions=[
                    "Remove unauthorised event triggers",
                    "Delete suspicious Lambda functions",
                    "Review Lambda deployment permissions",
                    "Implement function code approval process",
                    "Enable Lambda function URL restrictions",
                    "Audit all Lambda scheduled triggers",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known scheduled Lambda functions for backups, monitoring, etc.",
            detection_coverage="90% - catches scheduled event trigger additions",
            evasion_considerations="Attackers may use infrequent schedules or modify existing functions",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Lambda API calls logged"],
        ),
        DetectionStrategy(
            strategy_id="t1053-aws-ecs-scheduled",
            name="AWS ECS Scheduled Task Detection",
            description="Detect creation of scheduled ECS tasks that could provide persistence.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.principalId, requestParameters.taskDefinition, requestParameters.launchType
| filter eventSource = "ecs.amazonaws.com"
| filter eventName = "RunTask" or eventName = "RegisterTaskDefinition"
| filter requestParameters.schedulingStrategy = "DAEMON" or requestParameters.launchType = "FARGATE"
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect ECS scheduled task creation

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

  # Detect ECS scheduled tasks via EventBridge
  ECSScheduledTaskFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "ecs.amazonaws.com") && (($.eventName = "RunTask") || ($.eventName = "RegisterTaskDefinition")) }'
      MetricTransformations:
        - MetricName: ECSScheduledTasks
          MetricNamespace: Security/ECS
          MetricValue: "1"

  ECSScheduledTaskAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ECSScheduledTaskCreated
      MetricName: ECSScheduledTasks
      Namespace: Security/ECS
      Statistic: Sum
      Period: 300
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect ECS scheduled task creation

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "ecs-scheduled-task-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for ECS scheduled tasks
resource "aws_cloudwatch_log_metric_filter" "ecs_scheduled" {
  name           = "ecs-scheduled-tasks"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = ecs.amazonaws.com) && (($.eventName = RunTask) || ($.eventName = RegisterTaskDefinition)) }"

  metric_transformation {
    name      = "ECSScheduledTasks"
    namespace = "Security/ECS"
    value     = "1"
  }
}

# Alert on excessive scheduled task activity
resource "aws_cloudwatch_metric_alarm" "ecs_scheduled" {
  alarm_name          = "ECSScheduledTaskCreated"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ECSScheduledTasks"
  namespace           = "Security/ECS"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects creation of ECS scheduled tasks"
}""",
                alert_severity="medium",
                alert_title="ECS Scheduled Task Created",
                alert_description_template="ECS task {taskDefinition} scheduled by {principalId}",
                investigation_steps=[
                    "Review task definition for suspicious containers",
                    "Check schedule rule in EventBridge",
                    "Verify task execution role permissions",
                    "Inspect container images for malware",
                    "Review task networking configuration",
                    "Check for privileged container settings",
                ],
                containment_actions=[
                    "Stop unauthorised scheduled tasks",
                    "Delete suspicious task definitions",
                    "Disable associated EventBridge rules",
                    "Review ECS task execution roles",
                    "Implement task definition approval",
                    "Enable container image scanning",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known batch processing and ETL tasks",
            detection_coverage="85% - catches ECS scheduled task activity",
            evasion_considerations="Attackers may use infrequent schedules or modify existing tasks",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "ECS API calls logged"],
        ),
        DetectionStrategy(
            strategy_id="t1053-gcp-scheduler",
            name="GCP Cloud Scheduler Job Creation",
            description="Detect creation or modification of Cloud Scheduler jobs that could be used for persistence.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="cloudscheduler.googleapis.com"
protoPayload.methodName=~"google.cloud.scheduler.v1.CloudScheduler.(CreateJob|UpdateJob|PauseJob|ResumeJob)"''',
                gcp_terraform_template="""# GCP: Detect Cloud Scheduler job creation

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for Cloud Scheduler changes
resource "google_logging_metric" "scheduler_changes" {
  name   = "cloud-scheduler-job-changes"
  filter = <<-EOT
    protoPayload.serviceName="cloudscheduler.googleapis.com"
    protoPayload.methodName=~"CreateJob|UpdateJob|PauseJob|ResumeJob"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "job_name"
      value_type  = "STRING"
      description = "Cloud Scheduler job name"
    }
  }

  label_extractors = {
    "job_name" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Alert policy for scheduler changes
resource "google_monitoring_alert_policy" "scheduler_changes" {
  display_name = "Cloud Scheduler Job Created or Modified"
  combiner     = "OR"

  conditions {
    display_name = "Scheduler job changes detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.scheduler_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Cloud Scheduler job was created or modified. Review job target and schedule for authorisation."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Scheduler Job Created or Modified",
                alert_description_template="Cloud Scheduler job was created or modified",
                investigation_steps=[
                    "Review the job's target URL or Pub/Sub topic",
                    "Check the schedule frequency (*/1 * * * * may indicate abuse)",
                    "Verify the principal that created the job was authorised",
                    "Inspect the job's HTTP headers and payload",
                    "Review the service account assigned to the job",
                    "Check job execution history for suspicious patterns",
                ],
                containment_actions=[
                    "Pause or delete unauthorised scheduler jobs",
                    "Review Cloud Scheduler IAM permissions",
                    "Implement job creation approval workflow",
                    "Audit all existing scheduled jobs",
                    "Enable VPC Service Controls",
                    "Restrict scheduler job targets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known automation service accounts",
            detection_coverage="95% - catches all scheduler job changes",
            evasion_considerations="Attackers may use infrequent schedules or legitimate-looking job names",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled", "Cloud Logging API enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1053-k8s-cronjob",
            name="Kubernetes CronJob Creation Detection",
            description="Detect creation of Kubernetes CronJobs in EKS/GKE clusters that could provide persistence.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, user.username, objectRef.namespace, objectRef.name, requestObject.spec.schedule
| filter objectRef.resource = "cronjobs"
| filter verb = "create" or verb = "update"
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Kubernetes CronJob creation in EKS

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

  # Query definition for CronJob creation
  CronJobQueryDefinition:
    Type: AWS::Logs::QueryDefinition
    Properties:
      Name: KubernetesCronJobCreation
      LogGroupNames:
        - !Sub "/aws/eks/${EKSClusterName}/cluster"
      QueryString: |
        fields @timestamp, user.username, objectRef.namespace, objectRef.name, requestObject.spec.schedule
        | filter objectRef.resource = "cronjobs"
        | filter verb = "create" or verb = "update"
        | sort @timestamp desc""",
                terraform_template="""# Detect Kubernetes CronJob creation

variable "eks_cluster_name" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "k8s-cronjob-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# CloudWatch query for CronJob creation
resource "aws_cloudwatch_query_definition" "cronjob_creation" {
  name = "KubernetesCronJobCreation"

  log_group_names = [
    "/aws/eks/${var.eks_cluster_name}/cluster"
  ]

  query_string = <<-EOT
    fields @timestamp, user.username, objectRef.namespace, objectRef.name, requestObject.spec.schedule
    | filter objectRef.resource = "cronjobs"
    | filter verb = "create" or verb = "update"
    | sort @timestamp desc
  EOT
}

# Metric filter for CronJob creation
resource "aws_cloudwatch_log_metric_filter" "cronjob_creation" {
  name           = "k8s-cronjob-creation"
  log_group_name = "/aws/eks/${var.eks_cluster_name}/cluster"
  pattern        = "{ ($.objectRef.resource = cronjobs) && (($.verb = create) || ($.verb = update)) }"

  metric_transformation {
    name      = "K8sCronJobCreation"
    namespace = "Security/Kubernetes"
    value     = "1"
  }
}

# Alert on CronJob creation
resource "aws_cloudwatch_metric_alarm" "cronjob_creation" {
  alarm_name          = "KubernetesCronJobCreated"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "K8sCronJobCreation"
  namespace           = "Security/Kubernetes"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
  alarm_description   = "Detects Kubernetes CronJob creation or modification"
}""",
                alert_severity="high",
                alert_title="Kubernetes CronJob Created",
                alert_description_template="CronJob {name} created in namespace {namespace} by {username}",
                investigation_steps=[
                    "Review CronJob schedule (*/1 * * * * indicates every minute)",
                    "Inspect the container image used in the CronJob",
                    "Verify the creating user was authorised",
                    "Check the service account assigned to the CronJob",
                    "Review job template for privileged containers",
                    "Inspect volume mounts for host filesystem access",
                    "Check namespace for other suspicious resources",
                ],
                containment_actions=[
                    "Delete unauthorised CronJobs immediately",
                    "Suspend suspicious CronJobs for investigation",
                    "Implement admission controllers (OPA/Kyverno)",
                    "Enforce Pod Security Standards for CronJobs",
                    "Require image signatures via admission webhook",
                    "Enable Kubernetes audit logging",
                    "Review RBAC permissions for CronJob creation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known system namespaces and automation service accounts",
            detection_coverage="90% - catches CronJob creation in EKS",
            evasion_considerations="Attackers may use infrequent schedules or deploy in less-monitored namespaces",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=[
                "EKS control plane logging enabled",
                "Kubernetes audit logs enabled",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1053-gcp-k8s-cronjob",
            name="GCP GKE CronJob Creation Detection",
            description="Detect creation of Kubernetes CronJobs in GKE clusters for persistence detection.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="k8s_cluster"
protoPayload.resourceName=~"cronjobs"
(protoPayload.methodName="create" OR protoPayload.methodName="update" OR protoPayload.methodName="patch")""",
                gcp_terraform_template="""# GCP: Detect GKE CronJob creation

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Log metric for CronJob creation
resource "google_logging_metric" "cronjob_creation" {
  name   = "gke-cronjob-creation"
  filter = <<-EOT
    resource.type="k8s_cluster"
    protoPayload.resourceName=~"cronjobs"
    (protoPayload.methodName="create" OR protoPayload.methodName="update" OR protoPayload.methodName="patch")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "namespace"
      value_type  = "STRING"
      description = "Kubernetes namespace"
    }
    labels {
      key         = "cronjob_name"
      value_type  = "STRING"
      description = "CronJob name"
    }
  }

  label_extractors = {
    "namespace"    = "EXTRACT(protoPayload.request.metadata.namespace)"
    "cronjob_name" = "EXTRACT(protoPayload.request.metadata.name)"
  }
}

# Alert policy for CronJob creation
resource "google_monitoring_alert_policy" "cronjob_creation" {
  display_name = "GKE CronJob Created or Modified"
  combiner     = "OR"

  conditions {
    display_name = "CronJob creation detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cronjob_creation.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Kubernetes CronJob was created or modified. Review schedule, container image, and service account for authorisation."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: GKE CronJob Created or Modified",
                alert_description_template="CronJob created or modified in GKE cluster",
                investigation_steps=[
                    "Review CronJob schedule for suspicious frequency",
                    "Verify container image source and reputation",
                    "Check the principal that created the CronJob",
                    "Inspect job template for security context",
                    "Review service account permissions",
                    "Check for volume mounts to host filesystem",
                    "Inspect RBAC bindings for the namespace",
                ],
                containment_actions=[
                    "Delete unauthorised CronJobs",
                    "Suspend CronJobs pending investigation",
                    "Enable Binary Authorization for GKE",
                    "Implement Pod Security Policies/Standards",
                    "Use admission controllers for validation",
                    "Require image attestations",
                    "Audit RBAC permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist system namespaces and known automation accounts",
            detection_coverage="90% - catches CronJob creation in GKE",
            evasion_considerations="Attackers may use legitimate-looking names or infrequent schedules",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["GKE audit logging enabled", "Cloud Logging API enabled"],
        ),
    ],
    recommended_order=[
        "t1053-k8s-cronjob",
        "t1053-gcp-k8s-cronjob",
        "t1053-aws-eventbridge",
        "t1053-gcp-scheduler",
        "t1053-aws-lambda-schedule",
        "t1053-aws-ecs-scheduled",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+12% improvement for Persistence and Execution tactics",
)
