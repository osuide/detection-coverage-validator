"""
T1505 - Server Software Component

Adversaries install malicious components on servers to establish persistence.
Includes web shells, SQL procedures, IIS components, and other server extensions.
Used by APT28, APT29, APT40, APT41, Silk Typhoon, Emissary Panda.
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
    technique_id="T1505",
    technique_name="Server Software Component",
    tactic_ids=["TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1505/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse legitimate server extensibility features to establish "
            "persistence. This includes installing web shells, malicious IIS components, "
            "SQL stored procedures, and other server extensions. In cloud environments, "
            "attackers may deploy malicious code on compromised web servers, application "
            "servers, or serverless functions."
        ),
        attacker_goal="Establish persistent access via malicious server components",
        why_technique=[
            "Blends with legitimate server activity",
            "Survives application restarts",
            "Provides command execution capabilities",
            "Often bypasses traditional security tools",
            "Difficult to detect without file integrity monitoring",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Provides persistent access to web-facing systems. Often used after "
            "initial compromise to maintain access. Web shells are particularly "
            "dangerous as they provide direct command execution on compromised servers."
        ),
        business_impact=[
            "Persistent backdoor access",
            "Data exfiltration risk",
            "Lateral movement enabler",
            "Compliance violations",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1078.004", "T1530", "T1552.005"],
        often_follows=["T1190", "T1078.004"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1505-aws-ec2-file-integrity",
            name="AWS EC2 File Integrity Monitoring",
            description="Detect unauthorised file modifications on web servers using CloudWatch Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, fileName, changeType, user
| filter changeType = "MODIFIED" or changeType = "CREATED"
| filter fileName like /\\.php$|\\.aspx$|\\.jsp$|\\.cgi$|web\\.config|httpd\\.conf/
| filter fileName like /var\\/www|inetpub|apache|nginx/
| stats count(*) as changes by fileName, user, bin(1h)
| filter changes > 0
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unauthorised web server file modifications

Parameters:
  LogGroupName:
    Type: String
    Description: CloudWatch Logs group for file integrity monitoring
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

  WebFileChangeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref LogGroupName
      FilterPattern: '{ ($.fileName = "*.php" || $.fileName = "*.aspx" || $.fileName = "*.jsp") && ($.changeType = "MODIFIED" || $.changeType = "CREATED") }'
      MetricTransformations:
        - MetricName: WebFileChanges
          MetricNamespace: Security
          MetricValue: "1"

  WebFileChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnauthorisedWebFileChanges
      MetricName: WebFileChanges
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unauthorised web server file modifications

variable "log_group_name" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "web-file-change-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "web_file_changes" {
  name           = "web-file-changes"
  log_group_name = var.log_group_name
  pattern        = "{ ($.fileName = \"*.php\" || $.fileName = \"*.aspx\" || $.fileName = \"*.jsp\") && ($.changeType = \"MODIFIED\" || $.changeType = \"CREATED\") }"

  metric_transformation {
    name      = "WebFileChanges"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "web_file_changes" {
  alarm_name          = "UnauthorisedWebFileChanges"
  metric_name         = "WebFileChanges"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unauthorised Web Server File Modification",
                alert_description_template="Unauthorised modification detected on web server: {fileName}",
                investigation_steps=[
                    "Identify which user/process modified the file",
                    "Review file contents for malicious code",
                    "Check file creation/modification timestamps",
                    "Search for known web shell patterns (e.g., China Chopper, WSO)",
                    "Review web server access logs for suspicious requests",
                    "Check for other modified files in web directories",
                ],
                containment_actions=[
                    "Isolate affected EC2 instances",
                    "Remove malicious files",
                    "Restore from known-good backups",
                    "Review IAM permissions and SSH keys",
                    "Enable AWS Systems Manager for compliance scanning",
                    "Implement file integrity monitoring (e.g., AIDE, Tripwire)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised deployment processes and maintenance windows",
            detection_coverage="75% - requires file integrity monitoring agent",
            evasion_considerations="Attackers may disable monitoring agents or use in-memory execution",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "File integrity monitoring agent (e.g., osquery, AIDE) with CloudWatch Logs integration"
            ],
        ),
        DetectionStrategy(
            strategy_id="t1505-aws-alb-webshell",
            name="AWS ALB Web Shell Pattern Detection",
            description="Detect web shell activity via suspicious HTTP requests in ALB logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, client_ip, request_url, user_agent, elb_status_code
| filter request_url like /cmd=|exec|eval\\(|system\\(|passthru|shell_exec|base64_decode/
| filter elb_status_code = 200
| stats count(*) as requests by client_ip, request_url, bin(5m)
| filter requests > 0
| sort @timestamp desc""",
                terraform_template="""# Detect web shell activity via ALB logs

variable "alb_log_group" { type = string }
variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "webshell-detection-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_log_metric_filter" "webshell_patterns" {
  name           = "webshell-patterns"
  log_group_name = var.alb_log_group
  pattern        = "[\"cmd=\", \"exec(\", \"eval(\", \"system(\", \"base64_decode\"]"

  metric_transformation {
    name      = "WebShellRequests"
    namespace = "Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "webshell_activity" {
  alarm_name          = "WebShellActivity"
  metric_name         = "WebShellRequests"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Potential Web Shell Activity Detected",
                alert_description_template="Suspicious web shell patterns from {client_ip}",
                investigation_steps=[
                    "Review full request URL and parameters",
                    "Check web server for suspicious files at requested path",
                    "Review source IP reputation",
                    "Check for successful command execution (200 status codes)",
                    "Review web server process list for suspicious activity",
                    "Search for lateral movement attempts",
                ],
                containment_actions=[
                    "Block source IP at WAF/security group",
                    "Remove identified web shells",
                    "Rotate credentials accessed by compromised server",
                    "Enable AWS WAF with managed rule groups",
                    "Review and patch web application vulnerabilities",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Pattern-based detection is generally reliable for web shell signatures",
            detection_coverage="60% - catches common web shell patterns",
            evasion_considerations="Encoded or obfuscated web shells may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["ALB with access logging enabled to CloudWatch Logs"],
        ),
        DetectionStrategy(
            strategy_id="t1505-aws-lambda-persistence",
            name="AWS Lambda Function Modification Detection",
            description="Detect unauthorised modifications to Lambda functions that could serve as persistence.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.lambda"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "UpdateFunctionCode20150331v2",
                            "UpdateFunctionConfiguration20150331v2",
                            "CreateFunction20150331",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda function modifications

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

  LambdaModificationRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.lambda]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [UpdateFunctionCode20150331v2, UpdateFunctionConfiguration20150331v2, CreateFunction20150331]
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt LambdaModificationRule.Arn""",
                terraform_template="""# Detect Lambda function modifications

variable "alert_email" { type = string }

resource "aws_sns_topic" "alerts" {
  name = "lambda-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "lambda_modification" {
  name = "lambda-function-modifications"
  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["UpdateFunctionCode20150331v2", "UpdateFunctionConfiguration20150331v2", "CreateFunction20150331"]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "lambda-modification-dlq"
  message_retention_seconds = 1209600
}

data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sqs_queue.dlq.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.lambda_modification.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.lambda_modification.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
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
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.lambda_modification.arn
          }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Lambda Function Modified",
                alert_description_template="Lambda function {functionName} modified by {userIdentity.principalId}",
                investigation_steps=[
                    "Verify modification was authorised",
                    "Review who made the change",
                    "Compare function code versions",
                    "Check for suspicious code (e.g., backdoors, data exfiltration)",
                    "Review function's IAM role permissions",
                    "Check function invocation logs for unusual activity",
                ],
                containment_actions=[
                    "Revert to previous function version",
                    "Delete unauthorised functions",
                    "Review and restrict Lambda:UpdateFunctionCode permissions",
                    "Enable Lambda code signing",
                    "Implement CI/CD controls for function deployments",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD pipeline roles and scheduled deployments",
            detection_coverage="95% - catches all API-based modifications",
            evasion_considerations="Cannot evade CloudTrail logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled with Lambda data events"],
        ),
        DetectionStrategy(
            strategy_id="t1505-gcp-compute-metadata",
            name="GCP Compute Instance Metadata Modification",
            description="Detect modifications to instance metadata that could enable persistence.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.setMetadata"
OR protoPayload.methodName="beta.compute.instances.setMetadata"
OR protoPayload.methodName="v1.compute.instances.addAccessConfig"''',
                gcp_terraform_template="""# GCP: Detect instance metadata modifications

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "metadata_modification" {
  project = var.project_id
  name   = "instance-metadata-modification"
  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName="v1.compute.instances.setMetadata"
    OR protoPayload.methodName="beta.compute.instances.setMetadata"
    OR protoPayload.methodName="v1.compute.instances.addAccessConfig")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "metadata_modification" {
  project      = var.project_id
  display_name = "Instance Metadata Modification"
  combiner     = "OR"
  conditions {
    display_name = "Metadata modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.metadata_modification.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Instance Metadata Modified",
                alert_description_template="Instance metadata modified for {resource.labels.instance_id}",
                investigation_steps=[
                    "Verify modification was authorised",
                    "Check what metadata was changed (startup scripts, SSH keys)",
                    "Review who made the change",
                    "Check for suspicious startup scripts or custom metadata",
                    "Review instance for signs of compromise",
                ],
                containment_actions=[
                    "Revert unauthorised metadata changes",
                    "Remove suspicious startup scripts",
                    "Review and restrict compute.instances.setMetadata permissions",
                    "Enable OS Config for compliance monitoring",
                    "Implement change management for instance modifications",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude authorised service accounts and maintenance windows",
            detection_coverage="90% - catches metadata API calls",
            evasion_considerations="Cannot evade Cloud Audit Logs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"],
        ),
        DetectionStrategy(
            strategy_id="t1505-gcp-app-engine-deploy",
            name="GCP App Engine Deployment Detection",
            description="Detect unauthorised App Engine deployments that could serve as persistence.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gae_app"
protoPayload.methodName="google.appengine.v1.Versions.CreateVersion"
OR protoPayload.methodName="google.appengine.v1.Services.UpdateService"''',
                gcp_terraform_template="""# GCP: Detect App Engine deployments

variable "project_id" { type = string }
variable "alert_email" { type = string }

resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_logging_metric" "app_engine_deploy" {
  project = var.project_id
  name   = "app-engine-deployment"
  filter = <<-EOT
    resource.type="gae_app"
    (protoPayload.methodName="google.appengine.v1.Versions.CreateVersion"
    OR protoPayload.methodName="google.appengine.v1.Services.UpdateService")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "app_engine_deploy" {
  project      = var.project_id
  display_name = "App Engine Deployment"
  combiner     = "OR"
  conditions {
    display_name = "New deployment detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.app_engine_deploy.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP: App Engine Deployment Detected",
                alert_description_template="App Engine deployment by {protoPayload.authenticationInfo.principalEmail}",
                investigation_steps=[
                    "Verify deployment was authorised",
                    "Review deployed code for malicious content",
                    "Check deploying identity",
                    "Review application version history",
                    "Check for suspicious endpoints or handlers",
                ],
                containment_actions=[
                    "Delete unauthorised versions",
                    "Revert to previous known-good version",
                    "Review and restrict App Engine deployment permissions",
                    "Implement CI/CD controls with code review",
                    "Enable Binary Authorization for App Engine",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD service accounts and scheduled deployments",
            detection_coverage="95% - catches all deployments",
            evasion_considerations="Cannot evade audit logging",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled for App Engine"],
        ),
    ],
    recommended_order=[
        "t1505-aws-alb-webshell",
        "t1505-aws-ec2-file-integrity",
        "t1505-aws-lambda-persistence",
        "t1505-gcp-compute-metadata",
        "t1505-gcp-app-engine-deploy",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+18% improvement for Persistence tactic",
)
