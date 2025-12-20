"""
T1030 - Data Transfer Size Limits

Adversaries exfiltrate data in fixed-size chunks to evade detection systems.
Used by APT28, APT41, LuminousMoth, Play ransomware, Threat Group-3390.
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
    technique_id="T1030",
    technique_name="Data Transfer Size Limits",
    tactic_ids=["TA0010"],  # Exfiltration
    mitre_url="https://attack.mitre.org/techniques/T1030/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exfiltrate data in fixed-size chunks instead of whole files or "
            "limit packet sizes below certain thresholds to evade network detection systems. "
            "In cloud environments, this manifests as uniform S3/GCS uploads, consistent API "
            "call patterns, or network transfers with fixed payload sizes at regular intervals. "
            "This technique helps bypass data loss prevention systems that look for large file "
            "transfers and avoid triggering bandwidth anomaly alerts."
        ),
        attacker_goal="Exfiltrate data in small, consistent chunks to evade detection and bypass DLP controls",
        why_technique=[
            "Bypasses DLP systems monitoring for large file transfers",
            "Evades bandwidth anomaly detection",
            "Blends with legitimate application traffic patterns",
            "Avoids triggering network monitoring thresholds",
            "Can maintain persistence over extended periods",
            "Reduces likelihood of connection timeouts",
        ],
        known_threat_actors=[
            "APT28",
            "APT41",
            "LuminousMoth",
            "Play",
            "Threat Group-3390",
        ],
        recent_campaigns=[
            Campaign(
                name="APT28 Archive Chunking",
                year=2024,
                description="APT28 split RAR archives into chunks smaller than 1MB to evade detection during exfiltration",
                reference_url="https://attack.mitre.org/groups/G0007/",
            ),
            Campaign(
                name="LuminousMoth File Fragmentation",
                year=2023,
                description="LuminousMoth fragmented stolen files into chunks to bypass 5MB file transfer limits",
                reference_url="https://attack.mitre.org/groups/G0133/",
            ),
            Campaign(
                name="Play Ransomware Data Theft",
                year=2023,
                description="Play ransomware group split victim files into uniform chunks before exfiltration",
                reference_url="https://attack.mitre.org/software/S1062/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Data transfer size limits is a sophisticated evasion technique that can bypass "
            "traditional network monitoring and DLP solutions. The technique's effectiveness "
            "lies in its ability to blend with legitimate traffic patterns whilst exfiltrating "
            "significant volumes of data over time. High severity due to difficulty of detection "
            "and potential for sustained data loss. The technique is increasingly used by APT "
            "groups and ransomware operators."
        ),
        business_impact=[
            "Sustained data exfiltration over extended periods",
            "Intellectual property and trade secret theft",
            "Customer data breaches and regulatory violations",
            "Delayed incident detection and response",
            "Increased cloud egress costs from slow exfiltration",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1560", "T1074", "T1020", "T1530", "T1552.001"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Uniform S3 Upload Pattern Detection
        DetectionStrategy(
            strategy_id="t1030-aws-s3-chunked",
            name="AWS S3 Uniform Upload Pattern Detection",
            description="Detect S3 uploads with consistent file sizes at regular intervals indicating chunked exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, requestParameters.bucketName, requestParameters.key,
       requestParameters.contentLength as size
| filter eventName = "PutObject"
| stats count(*) as upload_count,
        avg(size) as avg_size,
        stddev(size) as size_stddev,
        min(size) as min_size,
        max(size) as max_size
  by userIdentity.arn, requestParameters.bucketName, bin(15m)
| filter upload_count > 10 and size_stddev < (avg_size * 0.1)
| sort upload_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect chunked S3 uploads indicating data exfiltration

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: S3 Chunked Upload Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for uniform upload patterns
  ChunkedUploadFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "PutObject") && ($.requestParameters.contentLength >= 1000000) && ($.requestParameters.contentLength <= 10000000) }'
      MetricTransformations:
        - MetricName: UniformS3Uploads
          MetricNamespace: Security/Exfiltration
          MetricValue: "1"
          Unit: Count

  # Step 3: CloudWatch alarm for repeated uniform uploads
  ChunkedUploadAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: S3-Chunked-Upload-Pattern
      AlarmDescription: Detects uniform S3 upload patterns indicating chunked exfiltration
      MetricName: UniformS3Uploads
      Namespace: Security/Exfiltration
      Statistic: Sum
      Period: 900
      Threshold: 15
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]
      TreatMissingData: notBreaching""",
                terraform_template="""# Detect chunked S3 uploads

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "chunked_upload_alerts" {
  name         = "s3-chunked-upload-alerts"
  display_name = "S3 Chunked Upload Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.chunked_upload_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for uniform upload patterns
resource "aws_cloudwatch_log_metric_filter" "chunked_upload" {
  name           = "s3-chunked-uploads"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"PutObject\") && ($.requestParameters.contentLength >= 1000000) && ($.requestParameters.contentLength <= 10000000) }"

  metric_transformation {
    name      = "UniformS3Uploads"
    namespace = "Security/Exfiltration"
    value     = "1"
    unit      = "Count"
  }
}

# Step 3: CloudWatch alarm for repeated uniform uploads
resource "aws_cloudwatch_metric_alarm" "chunked_upload" {
  alarm_name          = "S3-Chunked-Upload-Pattern"
  alarm_description   = "Detects uniform S3 upload patterns indicating chunked exfiltration"
  metric_name         = "UniformS3Uploads"
  namespace           = "Security/Exfiltration"
  statistic           = "Sum"
  period              = 900
  threshold           = 15
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.chunked_upload_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="S3 Chunked Upload Pattern Detected",
                alert_description_template="Uniform S3 upload pattern detected from {userIdentity.arn} to {bucketName}: {upload_count} uploads with avg size {avg_size} bytes.",
                investigation_steps=[
                    "Identify the source identity and verify legitimacy",
                    "Review upload timestamps for regular intervals",
                    "Calculate file size variance to confirm uniform chunks",
                    "Examine destination bucket ownership and location",
                    "Check uploaded file names for sequential patterns",
                    "Review CloudTrail for concurrent suspicious activities",
                    "Verify if uploads correlate with legitimate workflows",
                ],
                containment_actions=[
                    "Revoke credentials for suspicious identities",
                    "Block uploads to suspicious buckets",
                    "Enable S3 Object Lock on critical buckets",
                    "Implement bucket policies to restrict uploads",
                    "Review and restrict s3:PutObject permissions",
                    "Enable MFA Delete on sensitive buckets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup systems, log aggregators, and data pipelines that perform chunked uploads. Adjust size ranges and count thresholds.",
            detection_coverage="75% - catches uniform S3 upload patterns",
            evasion_considerations="Randomised chunk sizes, irregular timing, using existing backup patterns",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with S3 data events"],
        ),
        # Strategy 2: AWS - Network Transfer Pattern Detection
        DetectionStrategy(
            strategy_id="t1030-aws-network-chunks",
            name="AWS Network Chunked Transfer Detection",
            description="Detect network connections with consistent packet sizes indicating chunked data exfiltration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, packets
| filter action = "ACCEPT" and bytes > 1000
| stats count(*) as transfer_count,
        avg(bytes) as avg_bytes,
        stddev(bytes) as bytes_stddev,
        sum(bytes) as total_bytes
  by srcAddr, dstAddr, dstPort, bin(10m)
| filter transfer_count > 20 and bytes_stddev < (avg_bytes * 0.15)
| sort transfer_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect uniform network transfer patterns via VPC Flow Logs

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for uniform network transfers
  UniformTransferFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes > 10000 && bytes < 1000000, ...]'
      MetricTransformations:
        - MetricName: UniformNetworkTransfers
          MetricNamespace: Security/Exfiltration
          MetricValue: "1"

  # Step 3: CloudWatch alarm
  UniformTransferAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Network-Chunked-Transfer-Pattern
      MetricName: UniformNetworkTransfers
      Namespace: Security/Exfiltration
      Statistic: Sum
      Period: 600
      Threshold: 30
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect uniform network transfer patterns

variable "alert_email" {
  type = string
}

variable "vpc_flow_log_group" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "network_chunk_alerts" {
  name = "network-chunked-transfer-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.network_chunk_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for uniform network transfers
resource "aws_cloudwatch_log_metric_filter" "uniform_transfer" {
  name           = "uniform-network-transfers"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes > 10000 && bytes < 1000000, ...]"

  metric_transformation {
    name      = "UniformNetworkTransfers"
    namespace = "Security/Exfiltration"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "uniform_transfer" {
  alarm_name          = "Network-Chunked-Transfer-Pattern"
  metric_name         = "UniformNetworkTransfers"
  namespace           = "Security/Exfiltration"
  statistic           = "Sum"
  period              = 600
  threshold           = 30
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.network_chunk_alerts.arn]
}""",
                alert_severity="high",
                alert_title="Network Chunked Transfer Pattern Detected",
                alert_description_template="Uniform network transfer pattern from {srcAddr} to {dstAddr}:{dstPort}: {transfer_count} transfers with avg {avg_bytes} bytes.",
                investigation_steps=[
                    "Identify source and destination systems",
                    "Analyse transfer timing for regular intervals",
                    "Review packet size distribution",
                    "Check for legitimate applications using chunked transfers",
                    "Examine destination IP reputation",
                    "Correlate with CloudTrail for API activity",
                ],
                containment_actions=[
                    "Isolate source instance from network",
                    "Block traffic to suspicious destinations",
                    "Review and restrict security group rules",
                    "Enable VPC Flow Logs if not already enabled",
                    "Implement network ACLs to limit egress",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known streaming services, backup systems, and applications with consistent packet sizes. Tune byte range thresholds.",
            detection_coverage="70% - catches uniform network transfer patterns",
            evasion_considerations="Randomised packet sizes, low-volume transfers, using encrypted protocols",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        # Strategy 3: AWS - Lambda Scheduled Chunked Transfers
        DetectionStrategy(
            strategy_id="t1030-aws-lambda-scheduled",
            name="AWS Lambda Scheduled Transfer Detection",
            description="Detect Lambda functions executing at regular intervals for chunked data transfers.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, requestParameters.functionName, requestParameters.rule
| filter eventSource = "lambda.amazonaws.com"
| filter eventName in ["Invoke"]
| stats count(*) as invocation_count by requestParameters.functionName, bin(15m)
| filter invocation_count > 5
| sort invocation_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Lambda functions with regular execution patterns

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for frequent Lambda invocations
  FrequentLambdaRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.lambda]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [Invoke]
      State: ENABLED
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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect Lambda scheduled chunked transfers

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "lambda_schedule_alerts" {
  name = "lambda-scheduled-transfer-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.lambda_schedule_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for frequent Lambda invocations
resource "aws_cloudwatch_event_rule" "frequent_lambda" {
  name        = "frequent-lambda-invocations"
  description = "Detect Lambda functions with regular execution patterns"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["Invoke"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.frequent_lambda.name
  arn  = aws_sns_topic.lambda_schedule_alerts.arn
}

# Step 3: Topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.lambda_schedule_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.lambda_schedule_alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Lambda Scheduled Execution Pattern Detected",
                alert_description_template="Lambda function {functionName} executing at regular intervals: {invocation_count} invocations.",
                investigation_steps=[
                    "Review Lambda function code for data transfer logic",
                    "Check function execution logs for patterns",
                    "Examine EventBridge rules triggering the function",
                    "Review function IAM role permissions",
                    "Verify network connections from function",
                    "Check for legitimate scheduled workflows",
                ],
                containment_actions=[
                    "Disable suspicious EventBridge rules",
                    "Delete or quarantine suspicious Lambda functions",
                    "Review and restrict lambda:InvokeFunction permissions",
                    "Enable function code signing requirements",
                    "Implement VPC endpoints for AWS service access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist known scheduled functions for backups, monitoring, and automation. Focus on functions with external network access.",
            detection_coverage="60% - catches Lambda-based scheduled transfers",
            evasion_considerations="Irregular schedules, using existing legitimate functions",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 4: GCP - Cloud Storage Uniform Upload Detection
        DetectionStrategy(
            strategy_id="t1030-gcp-gcs-chunked",
            name="GCP Cloud Storage Chunked Upload Detection",
            description="Detect GCS uploads with consistent object sizes at regular intervals.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gcs_bucket"
protoPayload.methodName="storage.objects.create"
protoPayload.request.size >= 1000000
protoPayload.request.size <= 10000000""",
                gcp_terraform_template="""# GCP: Detect chunked Cloud Storage uploads

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alert Email"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for uniform GCS uploads
resource "google_logging_metric" "chunked_upload" {
  name   = "gcs-chunked-uploads"
  filter = <<-EOT
    resource.type="gcs_bucket"
    protoPayload.methodName="storage.objects.create"
    protoPayload.request.size >= 1000000
    protoPayload.request.size <= 10000000
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
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

# Step 3: Alert policy for frequent uniform uploads
resource "google_monitoring_alert_policy" "chunked_upload" {
  display_name = "GCS Chunked Upload Pattern Detected"
  combiner     = "OR"

  conditions {
    display_name = "Uniform Cloud Storage uploads"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.chunked_upload.name}\" resource.type=\"gcs_bucket\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 15
      aggregations {
        alignment_period   = "900s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content = "Uniform GCS upload pattern detected. Review for potential chunked data exfiltration."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Chunked Cloud Storage Upload Pattern Detected",
                alert_description_template="Uniform upload pattern to bucket {bucket_name}: frequent uploads with consistent sizes.",
                investigation_steps=[
                    "Identify the service account or user performing uploads",
                    "Review upload timestamps for regular intervals",
                    "Analyse object size distribution",
                    "Check bucket location and storage class",
                    "Examine object naming patterns for sequences",
                    "Review Cloud Audit Logs for concurrent activities",
                    "Verify against known data pipelines",
                ],
                containment_actions=[
                    "Revoke service account keys if compromised",
                    "Implement bucket IAM policies to restrict uploads",
                    "Enable uniform bucket-level access",
                    "Review and restrict storage.objects.create permissions",
                    "Enable Object Versioning and retention policies",
                    "Configure VPC Service Controls to limit data egress",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup systems, log collectors, and ETL pipelines. Adjust size range and frequency thresholds.",
            detection_coverage="75% - catches uniform GCS upload patterns",
            evasion_considerations="Randomised sizes, irregular timing, mimicking backup patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled for Cloud Storage"],
        ),
        # Strategy 5: GCP - Network Flow Pattern Detection
        DetectionStrategy(
            strategy_id="t1030-gcp-network-chunks",
            name="GCP VPC Flow Uniform Transfer Detection",
            description="Detect network flows with consistent transfer sizes indicating chunked exfiltration.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
log_name="compute.googleapis.com/vpc_flows"
jsonPayload.bytes_sent > 10000
jsonPayload.bytes_sent < 1000000""",
                gcp_terraform_template="""# GCP: Detect uniform network transfer patterns

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

# Step 2: Log-based metric for uniform network transfers
resource "google_logging_metric" "network_chunks" {
  name   = "vpc-uniform-transfers"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    log_name="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.bytes_sent > 10000
    jsonPayload.bytes_sent < 1000000
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "source_ip"
      value_type  = "STRING"
      description = "Source IP address"
    }
  }

  label_extractors = {
    "source_ip" = "EXTRACT(jsonPayload.connection.src_ip)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "network_chunks" {
  display_name = "VPC Uniform Transfer Pattern Detected"
  combiner     = "OR"

  conditions {
    display_name = "Frequent uniform network transfers"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.network_chunks.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 30
      aggregations {
        alignment_period   = "600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content = "Uniform network transfer pattern detected via VPC Flow Logs. Investigate for chunked data exfiltration."
  }
}""",
                alert_severity="high",
                alert_title="GCP: Uniform Network Transfer Pattern Detected",
                alert_description_template="Uniform network transfers from {source_ip}: frequent connections with consistent byte sizes.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Analyse transfer timing patterns",
                    "Review byte size distribution for uniformity",
                    "Check destination IP addresses and locations",
                    "Examine firewall rules and network routes",
                    "Correlate with application logs",
                ],
                containment_actions=[
                    "Isolate source instance via firewall rules",
                    "Block traffic to suspicious destinations",
                    "Review and restrict egress firewall rules",
                    "Enable Private Google Access where appropriate",
                    "Implement VPC Service Controls",
                    "Enable Packet Mirroring for deep inspection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known streaming applications, backup systems, and services with consistent packet sizes. Tune byte ranges.",
            detection_coverage="70% - catches uniform network transfer patterns",
            evasion_considerations="Randomised transfer sizes, irregular intervals, encrypted tunnels",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["VPC Flow Logs enabled on subnets"],
        ),
        # Strategy 6: GCP - Cloud Function Scheduled Execution
        DetectionStrategy(
            strategy_id="t1030-gcp-function-scheduled",
            name="GCP Cloud Function Scheduled Transfer Detection",
            description="Detect Cloud Functions with regular execution patterns for chunked transfers.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_function"
protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CallFunction"
severity="INFO"''',
                gcp_terraform_template="""# GCP: Detect Cloud Function scheduled executions

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

# Step 2: Log-based metric for function invocations
resource "google_logging_metric" "function_frequency" {
  name   = "function-invocation-frequency"
  filter = <<-EOT
    resource.type="cloud_function"
    protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CallFunction"
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
    "function_name" = "EXTRACT(resource.labels.function_name)"
  }
}

# Step 3: Alert policy for frequent executions
resource "google_monitoring_alert_policy" "function_frequency" {
  display_name = "Cloud Function Frequent Execution Detected"
  combiner     = "OR"

  conditions {
    display_name = "Function executing at regular intervals"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.function_frequency.name}\""
      duration        = "900s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "900s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
  }

  documentation {
    content = "Cloud Function executing frequently at regular intervals. Review for scheduled chunked transfers."
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Cloud Function Frequent Execution Pattern",
                alert_description_template="Cloud Function {function_name} executing at regular intervals.",
                investigation_steps=[
                    "Review function source code for data transfer logic",
                    "Check function execution logs for patterns",
                    "Examine Cloud Scheduler jobs or Pub/Sub triggers",
                    "Review function service account permissions",
                    "Check for outbound network connections",
                    "Verify against legitimate scheduled workflows",
                ],
                containment_actions=[
                    "Pause or delete Cloud Scheduler jobs",
                    "Disable suspicious Cloud Functions",
                    "Review and restrict cloudfunctions.functions.call permissions",
                    "Implement VPC Service Controls",
                    "Review function service account IAM bindings",
                    "Enable function source code repository tracking",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist known scheduled functions for monitoring, backups, and automation. Focus on functions with external network access.",
            detection_coverage="60% - catches Cloud Function-based scheduled transfers",
            evasion_considerations="Irregular schedules, using existing legitimate functions",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1030-aws-s3-chunked",
        "t1030-gcp-gcs-chunked",
        "t1030-aws-network-chunks",
        "t1030-gcp-network-chunks",
        "t1030-aws-lambda-scheduled",
        "t1030-gcp-function-scheduled",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+18% improvement for Exfiltration tactic detection",
)
