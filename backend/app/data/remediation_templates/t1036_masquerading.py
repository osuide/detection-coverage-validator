"""
T1036 - Masquerading

Adversaries manipulate features of their artefacts to make them appear legitimate or benign
to users and security tools, including file renaming, metadata spoofing, and process name manipulation.
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
    technique_id="T1036",
    technique_name="Masquerading",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1036/",
    threat_context=ThreatContext(
        description=(
            "Adversaries manipulate features of their artefacts to make them appear legitimate "
            "or benign to users and security tools. In cloud environments, this includes "
            "renaming malicious binaries to mimic system processes, using misleading Lambda "
            "function names, creating deceptive container images, or masquerading malicious "
            "services and tasks with legitimate-sounding names."
        ),
        attacker_goal="Evade detection by disguising malicious artefacts as legitimate system components",
        why_technique=[
            "Bypasses signature-based detection systems",
            "Reduces scrutiny during manual security reviews",
            "Exploits trust in familiar system processes and services",
            "Simple to implement with high effectiveness",
            "Commonly used alongside other defence evasion techniques",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="APT28 WinRAR Masquerading",
                year=2024,
                description="APT28 renamed WinRAR utility to avoid detection during reconnaissance operations",
                reference_url="https://attack.mitre.org/groups/G0007/",
            ),
            Campaign(
                name="APT32 Cobalt Strike Disguise",
                year=2023,
                description="APT32 disguised Cobalt Strike beacon as Flash Installer to trick users and security tools",
                reference_url="https://attack.mitre.org/groups/G0050/",
            ),
            Campaign(
                name="Lazarus Group Fake Recruitment",
                year=2024,
                description="Used masqueraded files in fake recruitment campaigns, hiding malware as legitimate documents",
                reference_url="https://attack.mitre.org/campaigns/C0022/",
            ),
            Campaign(
                name="FIN13 Certutil Abuse",
                year=2023,
                description="Used certutil to generate fake Base64-encoded certificates to disguise malicious activity",
                reference_url="https://attack.mitre.org/groups/G1016/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "Masquerading is a fundamental defence evasion technique used by most sophisticated "
            "threat actors. Whilst not directly damaging, it enables other attack phases to proceed "
            "undetected. The technique's simplicity and effectiveness make it a persistent threat "
            "across all cloud platforms."
        ),
        business_impact=[
            "Delayed detection of malicious activity",
            "Increased attacker dwell time in environment",
            "Potential compliance violations due to undetected threats",
            "Resource consumption from hidden malicious processes",
            "Difficulty in forensic investigation and incident response",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1059", "T1105", "T1496.001", "T1530"],
        often_follows=["T1078.004", "T1190", "T1552.005"],
    ),
    detection_strategies=[
        # AWS Strategy 1: GuardDuty Process Anomalies
        DetectionStrategy(
            strategy_id="t1036-aws-guardduty",
            name="AWS GuardDuty Execution Anomaly Detection",
            description=(
                "GuardDuty detects unusual process executions and binary behaviour that may "
                "indicate masquerading, including processes running from unusual locations."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Execution:EC2/MaliciousFile",
                    "Execution:Runtime/NewBinaryExecuted",
                    "DefenseEvasion:EC2/UnusualProcessName",
                    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty detection for masquerading attempts

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for GuardDuty alerts
  GuardDutyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: guardduty-masquerading-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for masquerading findings
  MasqueradingEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-masquerading-detection
      Description: Alert on GuardDuty masquerading and execution anomaly findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Execution:EC2"
            - prefix: "DefenseEvasion:EC2"
            - "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom"
      State: ENABLED
      Targets:
        - Arn: !Ref GuardDutyAlertTopic
          Id: SNSTarget

  # Step 3: Grant EventBridge permission to publish to SNS
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref GuardDutyAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref GuardDutyAlertTopic""",
                terraform_template="""# AWS: GuardDuty masquerading detection

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-masquerading-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for masquerading findings
resource "aws_cloudwatch_event_rule" "masquerading" {
  name        = "guardduty-masquerading-detection"
  description = "Alert on GuardDuty masquerading and execution anomaly findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Execution:EC2" },
        { prefix = "DefenseEvasion:EC2" },
        "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom"
      ]
    }
  })
}

# Step 3: Configure target to send alerts to SNS
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.masquerading.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn
}

resource "aws_sns_topic_policy" "guardduty_publish" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "SNS:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Potential Masquerading Detected",
                alert_description_template=(
                    "GuardDuty detected suspicious execution behaviour on instance {instanceId}: {finding_type}. "
                    "This may indicate masquerading or process manipulation."
                ),
                investigation_steps=[
                    "Review GuardDuty finding details and severity score",
                    "Identify the process name and execution path",
                    "Check if binary is in expected system location",
                    "Compare process behaviour with known baselines",
                    "Review instance timeline for other suspicious activity",
                    "Verify process digital signatures and metadata",
                ],
                containment_actions=[
                    "Isolate affected instance immediately",
                    "Terminate suspicious processes",
                    "Create forensic snapshot of instance",
                    "Revoke instance credentials",
                    "Block any malicious IPs at network level",
                    "Consider instance replacement if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review suppression rules for known legitimate processes; whitelist authorised custom applications",
            detection_coverage="75% - covers process-level masquerading on EC2",
            evasion_considerations="Sophisticated attackers may use memory-only execution or process injection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$1-5 (requires GuardDuty)",
            prerequisites=["AWS GuardDuty enabled with Runtime Monitoring"],
        ),
        # AWS Strategy 2: Lambda Function Name Monitoring
        DetectionStrategy(
            strategy_id="t1036-aws-lambda-names",
            name="AWS Lambda Suspicious Function Names",
            description=(
                "Monitor for Lambda functions with names designed to mimic AWS services "
                "or contain suspicious patterns often used for masquerading."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, requestParameters.functionName, eventName
| filter eventSource = "lambda.amazonaws.com"
| filter eventName in ["CreateFunction", "UpdateFunctionCode", "UpdateFunctionConfiguration"]
| filter requestParameters.functionName =~ /^(aws-|amazon-|system|svc-|service-|backup-|log-|monitor-)/
| filter requestParameters.functionName !~ /^(aws-lambda-|aws-sam-)/
| sort @timestamp desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda functions with suspicious masquerading names

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Create metric filter for suspicious Lambda names
  SuspiciousLambdaFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "lambda.amazonaws.com") && ($.eventName = "CreateFunction" || $.eventName = "UpdateFunctionCode") && ($.requestParameters.functionName = "aws-*" || $.requestParameters.functionName = "system*" || $.requestParameters.functionName = "svc-*") }'
      MetricTransformations:
        - MetricName: SuspiciousLambdaNames
          MetricNamespace: Security/T1036
          MetricValue: "1"
          DefaultValue: 0

  # Step 2: Create alarm for suspicious Lambda naming
  SuspiciousLambdaAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1036-SuspiciousLambdaNames
      AlarmDescription: Detects Lambda functions with masquerading names
      MetricName: SuspiciousLambdaNames
      Namespace: Security/T1036
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn
      TreatMissingData: notBreaching

  # Step 3: Create EventBridge rule for real-time detection
  LambdaMasqueradingRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1036-LambdaMasquerading
      Description: Detect Lambda functions with suspicious names
      EventPattern:
        source:
          - aws.lambda
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventSource:
            - lambda.amazonaws.com
          eventName:
            - CreateFunction
            - UpdateFunctionCode
      State: ENABLED
      Targets:
        - Id: SNSAlert
          Arn: !Ref SNSTopicArn""",
                terraform_template="""# AWS: Detect Lambda functions with masquerading names

variable "cloudtrail_log_group" {
  description = "CloudTrail log group name"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic for alerts"
  type        = string
}

# Step 1: Create metric filter for suspicious Lambda names
resource "aws_cloudwatch_log_metric_filter" "suspicious_lambda" {
  name           = "suspicious-lambda-names"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"lambda.amazonaws.com\") && ($.eventName = \"CreateFunction\" || $.eventName = \"UpdateFunctionCode\") && ($.requestParameters.functionName = \"aws-*\" || $.requestParameters.functionName = \"system*\" || $.requestParameters.functionName = \"svc-*\") }"

  metric_transformation {
    name          = "SuspiciousLambdaNames"
    namespace     = "Security/T1036"
    value         = "1"
    default_value = 0
  }
}

# Step 2: Create alarm for suspicious Lambda naming
resource "aws_cloudwatch_metric_alarm" "lambda_masquerading" {
  alarm_name          = "T1036-SuspiciousLambdaNames"
  alarm_description   = "Detects Lambda functions with masquerading names"
  metric_name         = "SuspiciousLambdaNames"
  namespace           = "Security/T1036"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"
}

# Step 3: Create EventBridge rule for real-time detection
resource "aws_cloudwatch_event_rule" "lambda_masquerading" {
  name        = "T1036-LambdaMasquerading"
  description = "Detect Lambda functions with suspicious names"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["lambda.amazonaws.com"]
      eventName   = ["CreateFunction", "UpdateFunctionCode"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_alert" {
  rule = aws_cloudwatch_event_rule.lambda_masquerading.name
  arn  = var.sns_topic_arn
}""",
                alert_severity="medium",
                alert_title="Suspicious Lambda Function Name Detected",
                alert_description_template=(
                    "User {user} created or updated Lambda function '{functionName}' which uses a name pattern "
                    "commonly associated with masquerading. Source IP: {sourceIPAddress}."
                ),
                investigation_steps=[
                    "Review the Lambda function code and configuration",
                    "Check the IAM role attached to the function",
                    "Verify the identity that created the function",
                    "Review function's execution history and invocation sources",
                    "Check for similar functions with suspicious names",
                    "Analyse function environment variables and layers",
                ],
                containment_actions=[
                    "Delete or disable suspicious Lambda function",
                    "Review and revoke function's IAM role permissions",
                    "Block the creating user if unauthorised",
                    "Enable Lambda function URL authentication",
                    "Implement Lambda naming convention policies",
                    "Review all functions for similar patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known legitimate functions; implement organisation naming standards",
            detection_coverage="60% - detects name-based masquerading for serverless",
            evasion_considerations="Attackers may use subtle variations or non-English characters",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail enabled with Lambda API logging",
                "CloudWatch Logs integration",
            ],
        ),
        # AWS Strategy 3: ECS/Container Masquerading
        DetectionStrategy(
            strategy_id="t1036-aws-ecs-containers",
            name="AWS ECS Suspicious Container/Task Names",
            description=(
                "Monitor for ECS tasks and containers with names designed to mimic AWS services "
                "or legitimate workloads, often used to hide malicious containers."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, requestParameters.taskDefinition, requestParameters.containerDefinitions[0].name
| filter eventSource = "ecs.amazonaws.com"
| filter eventName in ["RegisterTaskDefinition", "RunTask"]
| filter requestParameters.taskDefinition =~ /^(aws-|amazon-|system|kube-|docker-|svc-)/
| sort @timestamp desc
| limit 100""",
                terraform_template="""# AWS: Detect ECS tasks/containers with masquerading names

variable "cloudtrail_log_group" {
  description = "CloudTrail log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "ecs-masquerading-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for suspicious ECS names
resource "aws_cloudwatch_log_metric_filter" "ecs_masquerading" {
  name           = "suspicious-ecs-names"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"ecs.amazonaws.com\") && ($.eventName = \"RegisterTaskDefinition\" || $.eventName = \"RunTask\") && ($.requestParameters.taskDefinition = \"aws-*\" || $.requestParameters.taskDefinition = \"system*\") }"

  metric_transformation {
    name          = "SuspiciousECSNames"
    namespace     = "Security/T1036"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious ECS naming
resource "aws_cloudwatch_metric_alarm" "ecs_alert" {
  alarm_name          = "ECS-SuspiciousTaskNames"
  alarm_description   = "Detects ECS tasks/containers with masquerading names"
  metric_name         = "SuspiciousECSNames"
  namespace           = "Security/T1036"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Suspicious ECS Task/Container Name Detected",
                alert_description_template=(
                    "ECS task '{taskDefinition}' created with suspicious name. "
                    "Created by: {user}. This may indicate container masquerading."
                ),
                investigation_steps=[
                    "Review task definition and container image source",
                    "Check container image repository and tags",
                    "Verify the identity that registered the task",
                    "Analyse container environment variables and secrets",
                    "Review network configuration and security groups",
                    "Check for cryptocurrency mining or data exfiltration patterns",
                ],
                containment_actions=[
                    "Stop running tasks immediately",
                    "Deregister suspicious task definitions",
                    "Block container image in ECR",
                    "Review IAM roles attached to tasks",
                    "Implement container image scanning",
                    "Enable ECS Exec auditing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish naming conventions; whitelist approved task definitions",
            detection_coverage="65% - covers container-level masquerading",
            evasion_considerations="Attackers may use legitimate-looking custom names or rename at runtime",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled with ECS API logging",
                "CloudWatch Logs integration",
            ],
        ),
        # GCP Strategy 1: VM Instance Suspicious Process Names
        DetectionStrategy(
            strategy_id="t1036-gcp-vm-processes",
            name="GCP VM Suspicious Process Execution",
            description=(
                "Detect processes running on GCP VM instances with names that mimic system "
                "processes or are executed from unusual locations."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(jsonPayload.message=~"^(aws|amazon|google|gcp|system|svc|service)" OR
 protoPayload.request.command=~"/tmp/.*|/dev/shm/.*|/var/tmp/.*")
NOT jsonPayload.message=~"^(google-|gce-)"
severity>="WARNING"''',
                gcp_terraform_template="""# GCP: Detect suspicious process execution on VM instances

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Process Masquerading"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for suspicious processes
resource "google_logging_metric" "suspicious_processes" {
  name   = "suspicious-process-names"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.message=~"^(aws|amazon|google|gcp|system|svc|service)" OR
     protoPayload.request.command=~"/tmp/.*|/dev/shm/.*|/var/tmp/.*")
    NOT jsonPayload.message=~"^(google-|gce-)"
    severity>="WARNING"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "VM instance ID"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy for suspicious processes
resource "google_monitoring_alert_policy" "process_alert" {
  display_name = "GCE Suspicious Process Masquerading"
  combiner     = "OR"

  conditions {
    display_name = "Masquerading processes detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_processes.name}\" AND resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious Process Execution Detected",
                alert_description_template=(
                    "VM instance {instance_id} executed processes with suspicious names or from unusual locations. "
                    "This may indicate masquerading behaviour."
                ),
                investigation_steps=[
                    "Review VM instance logs for process details",
                    "Check process execution path and parent process",
                    "Verify process binary location and metadata",
                    "Analyse service account permissions",
                    "Review network connections from the instance",
                    "Check for persistence mechanisms",
                ],
                containment_actions=[
                    "Isolate VM using firewall rules",
                    "Terminate suspicious processes via OS Login",
                    "Create disk snapshot for forensic analysis",
                    "Revoke service account access",
                    "Review and harden VM metadata settings",
                    "Consider VM replacement if compromised",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known custom applications and deployment tools; whitelist approved process names",
            detection_coverage="70% - covers VM-level process masquerading",
            evasion_considerations="Memory-only execution or process injection may evade logging",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Logging enabled for GCE",
                "OS Login or system logging configured",
            ],
        ),
        # GCP Strategy 2: Cloud Functions Suspicious Names
        DetectionStrategy(
            strategy_id="t1036-gcp-cloud-functions",
            name="GCP Cloud Functions Masquerading Detection",
            description=(
                "Monitor for Cloud Functions with names designed to mimic GCP services "
                "or contain suspicious patterns commonly used for masquerading."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
protoPayload.methodName=~"google.cloud.functions.*.(CreateFunction|UpdateFunction)"
(protoPayload.request.name=~"gcp-|google-|system-|svc-|service-|backup-|log-|monitor-" OR
 protoPayload.request.function.name=~"gcp-|google-|system-|svc-|service-")
NOT protoPayload.request.name=~"gcf-|cf-"''',
                gcp_terraform_template="""# GCP: Detect Cloud Functions with masquerading names

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Function Masquerading"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for suspicious function names
resource "google_logging_metric" "suspicious_functions" {
  name   = "suspicious-cloud-function-names"
  filter = <<-EOT
    resource.type="cloud_function"
    protoPayload.methodName=~"google.cloud.functions.*.(CreateFunction|UpdateFunction)"
    (protoPayload.request.name=~"gcp-|google-|system-|svc-|service-|backup-|log-|monitor-" OR
     protoPayload.request.function.name=~"gcp-|google-|system-|svc-|service-")
    NOT protoPayload.request.name=~"gcf-|cf-"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "function_name"
      value_type  = "STRING"
      description = "Cloud Function name"
    }
  }

  label_extractors = {
    "function_name" = "EXTRACT(protoPayload.request.name)"
  }
}

# Step 3: Create alert for suspicious function names
resource "google_monitoring_alert_policy" "function_alert" {
  display_name = "Cloud Function Masquerading Detection"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious function names detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_functions.name}\""
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
    auto_close = "1800s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Suspicious Cloud Function Name Detected",
                alert_description_template=(
                    "Cloud Function '{function_name}' created or updated with suspicious name pattern. "
                    "This may indicate masquerading to evade detection."
                ),
                investigation_steps=[
                    "Review function source code and deployment package",
                    "Check the service account attached to the function",
                    "Verify the identity that deployed the function",
                    "Review function's invocation history and triggers",
                    "Analyse function environment variables",
                    "Check for similar functions with suspicious names",
                ],
                containment_actions=[
                    "Delete or disable suspicious Cloud Function",
                    "Revoke function's service account permissions",
                    "Block the deploying user if unauthorised",
                    "Enable Cloud Functions VPC connector restrictions",
                    "Implement function naming standards via policies",
                    "Review all functions for similar patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Implement organisation naming standards; whitelist known legitimate patterns",
            detection_coverage="60% - detects serverless function masquerading",
            evasion_considerations="Subtle name variations or non-standard character sets may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud Logging enabled for Cloud Functions"],
        ),
        # GCP Strategy 3: GKE Pod/Container Masquerading
        DetectionStrategy(
            strategy_id="t1036-gcp-gke-containers",
            name="GCP GKE Suspicious Container Names",
            description=(
                "Detect Kubernetes pods and containers in GKE with names that mimic system "
                "components or legitimate workloads to hide malicious activity."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="k8s_pod"
(resource.labels.pod_name=~"^(kube-|system-|google-|gcp-|aws-|svc-|daemon-)" OR
 resource.labels.container_name=~"^(kube-|system-|google-|gcp-|aws-|svc-|daemon-)")
NOT resource.labels.namespace_name="kube-system"
NOT resource.labels.pod_name=~"^(kube-proxy|kube-dns|kube-apiserver)"''',
                gcp_terraform_template="""# GCP: Detect GKE pods/containers with masquerading names

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - GKE Masquerading"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for suspicious pod names
resource "google_logging_metric" "suspicious_pods" {
  name   = "suspicious-gke-pod-names"
  filter = <<-EOT
    resource.type="k8s_pod"
    (resource.labels.pod_name=~"^(kube-|system-|google-|gcp-|aws-|svc-|daemon-)" OR
     resource.labels.container_name=~"^(kube-|system-|google-|gcp-|aws-|svc-|daemon-)")
    NOT resource.labels.namespace_name="kube-system"
    NOT resource.labels.pod_name=~"^(kube-proxy|kube-dns|kube-apiserver)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "pod_name"
      value_type  = "STRING"
      description = "Pod name"
    }
    labels {
      key         = "namespace"
      value_type  = "STRING"
      description = "Kubernetes namespace"
    }
  }

  label_extractors = {
    "pod_name"  = "EXTRACT(resource.labels.pod_name)"
    "namespace" = "EXTRACT(resource.labels.namespace_name)"
  }
}

# Step 3: Create alert for suspicious pod names
resource "google_monitoring_alert_policy" "pod_alert" {
  display_name = "GKE Pod/Container Masquerading"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious pod names detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_pods.name}\" AND resource.type=\"k8s_pod\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 1
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious GKE Pod/Container Name Detected",
                alert_description_template=(
                    "GKE pod '{pod_name}' in namespace '{namespace}' uses suspicious naming pattern. "
                    "This may indicate container masquerading."
                ),
                investigation_steps=[
                    "Review pod specification and container images",
                    "Check container image source and registry",
                    "Verify the identity that deployed the pod",
                    "Analyse pod resource requests and limits",
                    "Review network policies and service accounts",
                    "Check for cryptocurrency mining or unusual processes",
                ],
                containment_actions=[
                    "Delete suspicious pod immediately",
                    "Block container image in Artifact Registry",
                    "Review deployment/statefulset configurations",
                    "Revoke service account permissions",
                    "Implement pod security policies/standards",
                    "Enable GKE Binary Authorisation",
                    "Review admission controllers configuration",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist approved pod naming patterns; implement naming conventions via policies",
            detection_coverage="65% - covers Kubernetes-level masquerading",
            evasion_considerations="Attackers may use legitimate-looking names or rename containers at runtime",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "GKE cluster with Cloud Logging enabled",
                "Workload Identity configured",
            ],
        ),
    ],
    recommended_order=[
        "t1036-aws-guardduty",
        "t1036-gcp-vm-processes",
        "t1036-aws-ecs-containers",
        "t1036-gcp-gke-containers",
        "t1036-aws-lambda-names",
        "t1036-gcp-cloud-functions",
    ],
    total_effort_hours=8.5,
    coverage_improvement="+35% improvement for Defence Evasion tactic",
)
