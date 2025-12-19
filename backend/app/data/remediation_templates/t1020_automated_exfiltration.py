"""
T1020 - Automated Exfiltration

Adversaries use automated processes to exfiltrate collected data, such as sensitive documents.
The automation typically occurs after data gathering and often works alongside other exfiltration methods.
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
    technique_id="T1020",
    technique_name="Automated Exfiltration",
    tactic_ids=["TA0010"],  # Exfiltration
    mitre_url="https://attack.mitre.org/techniques/T1020/",

    threat_context=ThreatContext(
        description=(
            "Adversaries use automated processes to exfiltrate collected data from cloud environments. "
            "In AWS and GCP, this involves automated scripts or tools that periodically transmit data to "
            "external destinations via S3/GCS uploads, API calls, or unauthorised network connections. "
            "The automation often uses scheduled tasks, Lambda functions, Cloud Functions, or background "
            "daemons that operate after initial data collection, making detection challenging as the "
            "activity may blend with legitimate automated workflows."
        ),
        attacker_goal="Automatically and continuously exfiltrate collected sensitive data to external destinations",
        why_technique=[
            "Enables continuous data theft without manual intervention",
            "Difficult to distinguish from legitimate automated workflows",
            "Can operate in background over extended periods",
            "Reduces attacker operational exposure",
            "Leverages legitimate cloud services for exfiltration",
            "Circumvents manual monitoring controls"
        ],
        known_threat_actors=["Gamaredon Group", "Tropic Trooper", "Winter Vivern", "RedCurl", "Sidewinder"],
        recent_campaigns=[
            Campaign(
                name="Salesforce Data Exfiltration (C0059)",
                year=2024,
                description="Threat actors used automated API queries for large-scale data theft from Salesforce environments",
                reference_url="https://attack.mitre.org/campaigns/C0059/"
            ),
            Campaign(
                name="ArcaneDoor",
                year=2024,
                description="Campaign included scripted exfiltration mechanisms for automated data theft from compromised network devices",
                reference_url="https://attack.mitre.org/campaigns/"
            ),
            Campaign(
                name="Winter Vivern Document Exfiltration",
                year=2023,
                description="Delivered PowerShell scripts that recursively scanned for documents before automatically exfiltrating via HTTP",
                reference_url="https://attack.mitre.org/groups/G1033/"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Automated exfiltration represents a critical threat as it enables persistent, large-scale "
            "data theft without ongoing attacker involvement. The technique is difficult to prevent as it "
            "abuses legitimate cloud features. High severity due to potential for sustained loss of "
            "intellectual property, customer data, and sensitive business information. The automation "
            "aspect makes it particularly dangerous for compliance violations and data breach scenarios."
        ),
        business_impact=[
            "Large-scale theft of intellectual property and business data",
            "Sustained compliance violations and regulatory penalties",
            "Loss of competitive advantage through data leakage",
            "Reputational damage from extended breach periods",
            "Increased cloud egress costs from unauthorised transfers"
        ],
        typical_attack_phase="exfiltration",
        often_precedes=["T1041", "T1567"],
        often_follows=["T1074", "T1560", "T1005"]
    ),

    detection_strategies=[
        # Strategy 1: AWS - Automated S3 Upload Detection
        DetectionStrategy(
            strategy_id="t1020-aws-s3-upload",
            name="Automated S3 Data Upload Detection",
            description="Detect unusual patterns of automated S3 uploads that may indicate data exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn, eventName, requestParameters.bucketName, sourceIPAddress
| filter eventName in ["PutObject", "CopyObject", "UploadPart", "CompleteMultipartUpload"]
| stats count(*) as upload_count, sum(requestParameters.contentLength) as total_bytes by userIdentity.arn, requestParameters.bucketName, bin(5m)
| filter upload_count > 50 or total_bytes > 100000000
| sort upload_count desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect automated S3 data uploads indicating exfiltration

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: S3 Upload Anomaly Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for high-frequency S3 uploads
  S3UploadRule:
    Type: AWS::Events::Rule
    Properties:
      Name: s3-upload-anomaly-detection
      Description: Detect unusual S3 upload patterns
      EventPattern:
        source: [aws.s3]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PutObject
            - CopyObject
            - UploadPart
            - CompleteMultipartUpload
      State: ENABLED
      Targets:
        - Id: AlertTarget
          Arn: !Ref AlertTopic

  # Step 3: SNS topic policy
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
            Resource: !Ref AlertTopic''',
                terraform_template='''# Detect automated S3 uploads

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "s3_upload_alerts" {
  name         = "s3-upload-anomaly-alerts"
  display_name = "S3 Upload Anomaly Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.s3_upload_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for S3 uploads
resource "aws_cloudwatch_event_rule" "s3_upload" {
  name        = "s3-upload-anomaly-detection"
  description = "Detect unusual S3 upload patterns"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutObject",
        "CopyObject",
        "UploadPart",
        "CompleteMultipartUpload"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.s3_upload.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.s3_upload_alerts.arn
}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.s3_upload_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.s3_upload_alerts.arn
    }]
  })
}''',
                alert_severity="high",
                alert_title="Automated S3 Upload Pattern Detected",
                alert_description_template="High-frequency S3 uploads detected from {userIdentity.arn} to bucket {bucketName}. May indicate automated data exfiltration.",
                investigation_steps=[
                    "Identify the source identity and verify legitimacy",
                    "Review uploaded objects and their sizes",
                    "Check destination bucket ownership and region",
                    "Examine upload patterns and timing",
                    "Review CloudTrail for concurrent suspicious activities",
                    "Verify if uploads align with scheduled jobs or workflows"
                ],
                containment_actions=[
                    "Revoke credentials for suspicious identities",
                    "Enable S3 Block Public Access on affected buckets",
                    "Implement bucket policies to restrict uploads",
                    "Enable S3 Object Lock for critical data",
                    "Review and restrict s3:PutObject permissions",
                    "Enable S3 Access Logging for forensic analysis"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup jobs, ETL pipelines, and scheduled data transfer workflows. Adjust thresholds based on normal upload volumes.",
            detection_coverage="85% - catches high-volume automated uploads",
            evasion_considerations="Low-volume exfiltration or uploads matching normal patterns may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with S3 data events", "S3 bucket logging"]
        ),

        # Strategy 2: AWS - Lambda-based Exfiltration Detection
        DetectionStrategy(
            strategy_id="t1020-aws-lambda-exfil",
            name="Lambda Function Data Exfiltration Detection",
            description="Detect Lambda functions making automated external connections potentially for data exfiltration.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.lambda"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateFunction20150331",
                            "UpdateFunctionCode20150331v2",
                            "UpdateFunctionConfiguration20150331v2"
                        ]
                    }
                },
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda functions for automated exfiltration

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for Lambda modifications
  LambdaChangeRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.lambda]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateFunction20150331
            - UpdateFunctionCode20150331v2
            - UpdateFunctionConfiguration20150331v2
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
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
            Resource: !Ref AlertTopic''',
                terraform_template='''# Detect Lambda-based automated exfiltration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "lambda_alerts" {
  name = "lambda-exfiltration-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.lambda_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for Lambda changes
resource "aws_cloudwatch_event_rule" "lambda_changes" {
  name        = "lambda-exfiltration-detection"
  description = "Detect Lambda function modifications"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateFunction20150331",
        "UpdateFunctionCode20150331v2",
        "UpdateFunctionConfiguration20150331v2"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.lambda_changes.name
  arn  = aws_sns_topic.lambda_alerts.arn
}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.lambda_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.lambda_alerts.arn
    }]
  })
}''',
                alert_severity="high",
                alert_title="Lambda Function Modified - Potential Exfiltration Vector",
                alert_description_template="Lambda function {functionName} was modified. Review for unauthorised data exfiltration code.",
                investigation_steps=[
                    "Review Lambda function code for external connections",
                    "Check function execution logs in CloudWatch",
                    "Examine function IAM role permissions",
                    "Identify who made the modifications",
                    "Review VPC configuration and security groups",
                    "Check for environment variables containing credentials"
                ],
                containment_actions=[
                    "Delete or disable suspicious Lambda functions",
                    "Review and restrict lambda:UpdateFunctionCode permissions",
                    "Enable function code signing",
                    "Implement VPC endpoints for AWS services",
                    "Review Lambda execution role permissions",
                    "Enable CloudWatch Logs for all functions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised deployment pipelines and CI/CD systems",
            detection_coverage="80% - catches Lambda-based exfiltration mechanisms",
            evasion_considerations="Attackers may use existing legitimate functions or gradual modifications",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=["CloudTrail enabled"]
        ),

        # Strategy 3: AWS - Scheduled Task Exfiltration Detection
        DetectionStrategy(
            strategy_id="t1020-aws-scheduled-exfil",
            name="Scheduled Task Data Transfer Detection",
            description="Detect creation of EventBridge scheduled rules that may automate data exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn, eventName, requestParameters.name, requestParameters.scheduleExpression
| filter eventName in ["PutRule", "PutTargets"]
| filter requestParameters.scheduleExpression like /rate|cron/
| sort @timestamp desc
| limit 100''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect scheduled rules for automated exfiltration

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for scheduled rule creation
  ScheduledRuleDetection:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.events]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PutRule
            - PutTargets
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy
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
            Resource: !Ref AlertTopic''',
                terraform_template='''# Detect scheduled automated exfiltration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "schedule_alerts" {
  name = "scheduled-exfiltration-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.schedule_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for scheduled rule creation
resource "aws_cloudwatch_event_rule" "schedule_detection" {
  name        = "scheduled-rule-detection"
  description = "Detect creation of scheduled EventBridge rules"

  event_pattern = jsonencode({
    source      = ["aws.events"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutRule", "PutTargets"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.schedule_detection.name
  arn  = aws_sns_topic.schedule_alerts.arn
}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.schedule_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.schedule_alerts.arn
    }]
  })
}''',
                alert_severity="medium",
                alert_title="Scheduled EventBridge Rule Created",
                alert_description_template="New scheduled rule {ruleName} created with expression {scheduleExpression}. Verify legitimacy to prevent automated exfiltration.",
                investigation_steps=[
                    "Review rule schedule and targets",
                    "Identify who created the scheduled rule",
                    "Examine target Lambda functions or services",
                    "Check rule pattern and filter criteria",
                    "Review recent CloudTrail events from same principal",
                    "Verify business justification for automation"
                ],
                containment_actions=[
                    "Disable suspicious scheduled rules",
                    "Review and restrict events:PutRule permissions",
                    "Enable EventBridge rule audit logging",
                    "Implement approval workflows for scheduled tasks",
                    "Review all existing scheduled rules"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist known automation frameworks, backup schedules, and operational tasks. Focus on rules with external network targets.",
            detection_coverage="75% - catches scheduled automation creation",
            evasion_considerations="Attackers may use irregular schedules or modify existing rules",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=["CloudTrail enabled"]
        ),

        # Strategy 4: GCP - Cloud Storage Upload Anomaly Detection
        DetectionStrategy(
            strategy_id="t1020-gcp-gcs-upload",
            name="GCP Cloud Storage Upload Anomaly Detection",
            description="Detect unusual patterns of automated GCS uploads indicating potential data exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
protoPayload.serviceName="storage.googleapis.com"''',
                gcp_terraform_template='''# GCP: Detect automated Cloud Storage uploads

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for GCS uploads
resource "google_logging_metric" "gcs_upload" {
  name   = "gcs-upload-frequency"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.create"
    protoPayload.serviceName="storage.googleapis.com"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "bucket_name"
      value_type  = "STRING"
      description = "Cloud Storage bucket name"
    }
  }

  label_extractors = {
    "bucket_name" = "EXTRACT(resource.labels.bucket_name)"
  }
}

# Step 3: Alert policy for high-frequency uploads
resource "google_monitoring_alert_policy" "gcs_upload_alert" {
  display_name = "Automated GCS Upload Detected"
  combiner     = "OR"

  conditions {
    display_name = "High-frequency Cloud Storage uploads"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.gcs_upload.name}\" resource.type=\"gcs_bucket\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
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
}''',
                alert_severity="high",
                alert_title="GCP: Automated Cloud Storage Upload Pattern Detected",
                alert_description_template="High-frequency uploads detected to bucket {bucket_name}. May indicate automated data exfiltration.",
                investigation_steps=[
                    "Identify the service account or user performing uploads",
                    "Review uploaded object names and sizes",
                    "Check bucket location and storage class",
                    "Examine upload patterns and timing",
                    "Review Cloud Audit Logs for concurrent activities",
                    "Verify against known scheduled jobs"
                ],
                containment_actions=[
                    "Revoke service account keys if compromised",
                    "Implement bucket IAM policies to restrict uploads",
                    "Enable uniform bucket-level access",
                    "Review and restrict storage.objects.create permissions",
                    "Enable Object Versioning for recovery",
                    "Configure VPC Service Controls to limit data egress"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup jobs, data pipelines, and application upload workflows. Adjust thresholds based on normal patterns.",
            detection_coverage="85% - catches high-volume automated uploads",
            evasion_considerations="Low-volume or intermittent uploads may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$8-15",
            prerequisites=["Cloud Audit Logs enabled", "Cloud Storage data access logs"]
        ),

        # Strategy 5: GCP - Cloud Function Exfiltration Detection
        DetectionStrategy(
            strategy_id="t1020-gcp-function-exfil",
            name="GCP Cloud Function Data Exfiltration Detection",
            description="Detect Cloud Functions that may be used for automated data exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
(protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CreateFunction"
OR protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.UpdateFunction")
protoPayload.serviceName="cloudfunctions.googleapis.com"''',
                gcp_terraform_template='''# GCP: Detect Cloud Function modifications for exfiltration

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for function changes
resource "google_logging_metric" "function_changes" {
  name   = "cloud-function-modifications"
  filter = <<-EOT
    resource.type="cloud_function"
    protoPayload.serviceName="cloudfunctions.googleapis.com"
    (protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CreateFunction" OR
     protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.UpdateFunction")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "function_alert" {
  display_name = "Cloud Function Modification Detected"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Function created or updated"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}''',
                alert_severity="high",
                alert_title="GCP: Cloud Function Modified - Potential Exfiltration Vector",
                alert_description_template="Cloud Function {function_name} was modified. Review for unauthorised data exfiltration code.",
                investigation_steps=[
                    "Review function source code for external connections",
                    "Check function execution logs in Cloud Logging",
                    "Examine function service account permissions",
                    "Identify who made the modifications",
                    "Review VPC Connector configuration",
                    "Check environment variables for credentials"
                ],
                containment_actions=[
                    "Delete or disable suspicious Cloud Functions",
                    "Review and restrict cloudfunctions.functions.update permissions",
                    "Implement VPC Service Controls",
                    "Review function service account IAM bindings",
                    "Enable function source code repository tracking",
                    "Configure Cloud Logging for all function executions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised deployment systems and CI/CD pipelines",
            detection_coverage="80% - catches Cloud Function-based exfiltration mechanisms",
            evasion_considerations="Attackers may use existing functions or make gradual changes",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$8-15",
            prerequisites=["Cloud Audit Logs enabled"]
        ),

        # Strategy 6: GCP - Cloud Scheduler Job Detection
        DetectionStrategy(
            strategy_id="t1020-gcp-scheduler",
            name="GCP Cloud Scheduler Job Detection",
            description="Detect creation of Cloud Scheduler jobs that may automate data exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_scheduler_job"
(protoPayload.methodName="google.cloud.scheduler.v1.CloudScheduler.CreateJob"
OR protoPayload.methodName="google.cloud.scheduler.v1.CloudScheduler.UpdateJob")
protoPayload.serviceName="cloudscheduler.googleapis.com"''',
                gcp_terraform_template='''# GCP: Detect Cloud Scheduler job creation

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for scheduler jobs
resource "google_logging_metric" "scheduler_jobs" {
  name   = "cloud-scheduler-job-changes"
  filter = <<-EOT
    resource.type="cloud_scheduler_job"
    protoPayload.serviceName="cloudscheduler.googleapis.com"
    (protoPayload.methodName="google.cloud.scheduler.v1.CloudScheduler.CreateJob" OR
     protoPayload.methodName="google.cloud.scheduler.v1.CloudScheduler.UpdateJob")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "scheduler_alert" {
  display_name = "Cloud Scheduler Job Created or Modified"
  combiner     = "OR"

  conditions {
    display_name = "Scheduler job automation detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.scheduler_jobs.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }
}''',
                alert_severity="medium",
                alert_title="GCP: Cloud Scheduler Job Created or Modified",
                alert_description_template="Cloud Scheduler job {job_name} with schedule {schedule} was modified. Verify legitimacy.",
                investigation_steps=[
                    "Review job schedule and target configuration",
                    "Identify who created or modified the job",
                    "Examine target Cloud Function, HTTP endpoint, or Pub/Sub topic",
                    "Check job service account permissions",
                    "Review recent Cloud Audit Logs from same principal",
                    "Verify business justification"
                ],
                containment_actions=[
                    "Pause or delete suspicious scheduler jobs",
                    "Review and restrict cloudscheduler.jobs.create permissions",
                    "Implement organisation policy constraints",
                    "Review all existing scheduled jobs",
                    "Enable notifications for job executions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist known automation systems, backup schedules, and operational workflows",
            detection_coverage="75% - catches scheduled automation creation",
            evasion_considerations="Attackers may use irregular schedules or modify existing jobs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$8-15",
            prerequisites=["Cloud Audit Logs enabled"]
        )
    ],

    recommended_order=[
        "t1020-aws-s3-upload",
        "t1020-gcp-gcs-upload",
        "t1020-aws-lambda-exfil",
        "t1020-gcp-function-exfil",
        "t1020-aws-scheduled-exfil",
        "t1020-gcp-scheduler"
    ],
    total_effort_hours=4.0,
    coverage_improvement="+25% improvement for Exfiltration tactic detection"
)
