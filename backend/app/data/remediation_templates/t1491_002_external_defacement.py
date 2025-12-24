"""
T1491.002 - Defacement: External Defacement

Adversaries modify visual content available to external users to deliver messaging,
intimidate, or otherwise mislead an organisation or users. This frequently includes
defacement of public-facing websites, often targeting cloud-hosted static sites.
Used by Ember Bear, Sandworm Team.
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
    technique_id="T1491.002",
    technique_name="Defacement: External Defacement",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1491/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify systems external to an organisation to deliver messaging, "
            "intimidate, or otherwise mislead an organisation or users. This frequently targets "
            "externally-facing websites hosted on cloud infrastructure (AWS S3, Azure Blob). "
            "Defacement can undermine confidence in system integrity and serve as a precursor "
            "to additional attacks such as drive-by compromise through web shell deployment."
        ),
        attacker_goal="Modify public-facing content to push political messages, intimidate, or facilitate further compromise",
        why_technique=[
            "High-visibility impact for propaganda purposes",
            "Undermines trust in organisation's systems",
            "Can precede drive-by compromise attacks",
            "Cloud-hosted static sites often have weak access controls",
            "Web shells can be deployed during defacement",
            "Frequently used in geopolitical conflicts",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Significant reputational damage and undermines trust. "
            "Can serve as precursor to additional attacks. "
            "Disrupts public-facing services and organisational image."
        ),
        business_impact=[
            "Reputational damage and loss of customer trust",
            "Potential for follow-on attacks via web shells",
            "Disruption of public-facing services",
            "Regulatory compliance concerns",
            "Investigation and remediation costs",
        ],
        typical_attack_phase="impact",
        often_precedes=["T1190", "T1189"],
        often_follows=["T1078.004", "T1552.001", "T1190"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1491.002-aws-s3-content",
            name="AWS S3 Website Content Modification Detection",
            description=(
                "Detect unauthorised modifications to S3-hosted static website content, "
                "including HTML, JavaScript, and CSS file uploads."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["PutObject", "DeleteObject", "DeleteObjects"],
                        "requestParameters": {
                            "key": [
                                {"suffix": ".html"},
                                {"suffix": ".htm"},
                                {"suffix": ".js"},
                                {"suffix": ".css"},
                            ]
                        },
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect S3 website defacement attempts

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for defacement alerts

Resources:
  # Step 1: Create SNS topic for defacement alerts
  DefacementAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: s3-defacement-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule to detect web content modifications
  S3ContentModificationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: s3-website-defacement-detection
      Description: Detect modifications to S3-hosted website content
      EventPattern:
        source:
          - aws.s3
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - PutObject
            - DeleteObject
            - DeleteObjects
          requestParameters:
            key:
              - suffix: .html
              - suffix: .htm
              - suffix: .js
              - suffix: .css
      State: ENABLED
      Targets:
        - Id: DefacementAlert
          Arn: !Ref DefacementAlertTopic
          InputTransformer:
            InputPathsMap:
              bucket: $.detail.requestParameters.bucketName
              key: $.detail.requestParameters.key
              user: $.detail.userIdentity.arn
              ip: $.detail.sourceIPAddress
              event: $.detail.eventName
            InputTemplate: |
              "ALERT: S3 Website Content Modified
              Bucket: <bucket>
              File: <key>
              Action: <event>
              User: <user>
              Source IP: <ip>
              This may indicate website defacement."

  # Step 3: Grant EventBridge permission to publish to SNS
  SNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref DefacementAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref DefacementAlertTopic""",
                terraform_template="""# AWS: Detect S3 website defacement

variable "alert_email" {
  type        = string
  description = "Email address for defacement alerts"
}

# Step 1: Create SNS topic for defacement alerts
resource "aws_sns_topic" "defacement_alerts" {
  name = "s3-defacement-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.defacement_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule to detect web content modifications
resource "aws_cloudwatch_event_rule" "s3_content_modification" {
  name        = "s3-website-defacement-detection"
  description = "Detect modifications to S3-hosted website content"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutObject", "DeleteObject", "DeleteObjects"]
      requestParameters = {
        key = [
          { suffix = ".html" },
          { suffix = ".htm" },
          { suffix = ".js" },
          { suffix = ".css" }
        ]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "defacement_alert" {
  rule = aws_cloudwatch_event_rule.s3_content_modification.name
  arn  = aws_sns_topic.defacement_alerts.arn

  input_transformer {
    input_paths = {
      bucket = "$.detail.requestParameters.bucketName"
      key    = "$.detail.requestParameters.key"
      user   = "$.detail.userIdentity.arn"
      ip     = "$.detail.sourceIPAddress"
      event  = "$.detail.eventName"
    }
    input_template = "\"ALERT: S3 Website Content Modified\\nBucket: <bucket>\\nFile: <key>\\nAction: <event>\\nUser: <user>\\nSource IP: <ip>\\nThis may indicate website defacement.\""
  }
}

# Step 3: Grant EventBridge permission to publish to SNS
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.defacement_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.defacement_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="S3 Website Content Modified",
                alert_description_template=(
                    "S3-hosted website content modified. Bucket: {bucket}, File: {key}. "
                    "Action: {eventName} by {user} from IP {sourceIPAddress}. "
                    "This may indicate website defacement."
                ),
                investigation_steps=[
                    "Immediately review the modified content for unauthorised changes",
                    "Compare current content with known-good backups or version history",
                    "Verify if the user/principal that made changes was authorised",
                    "Check CloudTrail for suspicious access patterns leading up to modification",
                    "Review source IP address and geolocation for anomalies",
                    "Check for web shell uploads or malicious JavaScript injection",
                    "Examine other S3 buckets for similar unauthorised modifications",
                ],
                containment_actions=[
                    "Immediately restore known-good content from backups or S3 versioning",
                    "Revoke credentials for compromised user/role if unauthorised",
                    "Enable S3 Object Lock to prevent future unauthorised modifications",
                    "Implement bucket policies restricting PutObject to specific principals",
                    "Enable MFA Delete on critical website buckets",
                    "Review and tighten IAM policies for S3 access",
                    "Consider enabling S3 Versioning for rollback capability",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist authorised deployment pipelines and CI/CD service accounts. "
                "Filter out scheduled content updates from known sources."
            ),
            detection_coverage="85% - catches direct S3 content modifications",
            evasion_considerations=(
                "Attackers may use legitimate deployment credentials. "
                "Gradual modifications over time may blend with normal updates."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "S3 static website hosting",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1491.002-aws-cloudfront",
            name="CloudFront Origin Access Pattern Monitoring",
            description=(
                "Monitor CloudFront distributions for unusual origin access patterns "
                "that may indicate content defacement or unauthorised content delivery."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, cs-method, cs-uri-stem, sc-status, c-ip, cs-user-agent
| filter sc-status >= 200 and sc-status < 300
| filter cs-uri-stem like /index\.html|main\.js|styles\.css/
| stats count(*) as requests, count_distinct(c-ip) as unique_ips by bin(5m)
| filter requests > 1000 or unique_ips > 100
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor CloudFront for unusual access patterns indicating defacement

Parameters:
  CloudFrontLogGroup:
    Type: String
    Description: CloudWatch log group for CloudFront access logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for unusual traffic spikes
  UnusualTrafficFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudFrontLogGroup
      FilterPattern: '[... , status=2*, ...]'
      MetricTransformations:
        - MetricName: CloudFrontSuccessfulRequests
          MetricNamespace: Security/Defacement
          MetricValue: "1"

  # Step 3: Create alarm for traffic anomalies
  TrafficAnomalyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CloudFront-Unusual-Traffic-Pattern
      AlarmDescription: Unusual CloudFront traffic may indicate defaced content
      MetricName: CloudFrontSuccessfulRequests
      Namespace: Security/Defacement
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1000
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# AWS: Monitor CloudFront for defacement indicators

variable "cloudfront_log_group" {
  type        = string
  description = "CloudWatch log group for CloudFront access logs"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "cloudfront-defacement-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for unusual traffic spikes
resource "aws_cloudwatch_log_metric_filter" "unusual_traffic" {
  name           = "cloudfront-unusual-traffic"
  log_group_name = var.cloudfront_log_group
  pattern        = "[... , status=2*, ...]"

  metric_transformation {
    name      = "CloudFrontSuccessfulRequests"
    namespace = "Security/Defacement"
    value     = "1"
  }
}

# Step 3: Create alarm for traffic anomalies
resource "aws_cloudwatch_metric_alarm" "traffic_anomaly" {
  alarm_name          = "CloudFront-Unusual-Traffic-Pattern"
  alarm_description   = "Unusual CloudFront traffic may indicate defaced content"
  metric_name         = "CloudFrontSuccessfulRequests"
  namespace           = "Security/Defacement"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1000
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="CloudFront Unusual Traffic Pattern Detected",
                alert_description_template=(
                    "CloudFront distribution experiencing unusual traffic pattern. "
                    "This may indicate defaced content being heavily accessed or shared."
                ),
                investigation_steps=[
                    "Review CloudFront distribution content for unauthorised changes",
                    "Check recent S3 origin modifications in CloudTrail",
                    "Analyse user-agent strings for scraping or botnet activity",
                    "Review geographic distribution of traffic for anomalies",
                    "Check social media and defacement archives for mentions",
                    "Verify content hash against known-good baseline",
                ],
                containment_actions=[
                    "Invalidate CloudFront cache if content is compromised",
                    "Update origin to known-good content immediately",
                    "Consider temporarily disabling distribution whilst investigating",
                    "Review and restrict origin access identity permissions",
                    "Implement CloudFront signed URLs for sensitive content",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning=(
                "Establish baseline traffic patterns for your site. "
                "Adjust thresholds based on normal traffic volumes. "
                "Account for marketing campaigns and legitimate traffic spikes."
            ),
            detection_coverage="60% - indicates potential defacement via traffic anomalies",
            evasion_considerations=(
                "Low-profile defacements may not generate unusual traffic. "
                "Attackers may not publicise defacement immediately."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudFront access logging enabled",
                "Logs sent to CloudWatch",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1491.002-aws-integrity",
            name="S3 Object Integrity Monitoring",
            description=(
                "Monitor S3 object ETags and metadata to detect unauthorised modifications "
                "to website content through hash comparison."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, requestParameters.bucketName as bucket,
       requestParameters.key as file_path, userIdentity.arn as user,
       sourceIPAddress, responseElements.eTag as etag
| filter eventName = "PutObject"
| filter file_path like /\\.html$|\\.js$|\\.css$/
| stats latest(@timestamp) as last_modified, latest(etag) as current_etag,
  latest(user) as last_user, latest(sourceIPAddress) as last_ip
  by bucket, file_path
| sort last_modified desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: S3 object integrity monitoring for defacement detection

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String
  MonitoredBucket:
    Type: String
    Description: S3 bucket hosting website content

Resources:
  # Step 1: Create SNS topic for integrity alerts
  IntegrityAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for critical file modifications
  CriticalFileModificationFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: !Sub '{ ($.eventName = "PutObject") && ($.requestParameters.bucketName = "${MonitoredBucket}") && ($.requestParameters.key = "index.html" || $.requestParameters.key = "*.html" || $.requestParameters.key = "*.js") }'
      MetricTransformations:
        - MetricName: CriticalWebFileModifications
          MetricNamespace: Security/Defacement
          MetricValue: "1"

  # Step 3: Create alarm for any critical file modification
  CriticalFileAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Critical-Website-File-Modified
      AlarmDescription: Critical website file modified - possible defacement
      MetricName: CriticalWebFileModifications
      Namespace: Security/Defacement
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref IntegrityAlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: S3 object integrity monitoring for defacement

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

variable "monitored_bucket" {
  type        = string
  description = "S3 bucket hosting website content"
}

# Step 1: Create SNS topic for integrity alerts
resource "aws_sns_topic" "integrity_alerts" {
  name = "s3-integrity-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.integrity_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for critical file modifications
resource "aws_cloudwatch_log_metric_filter" "critical_file_mods" {
  name           = "critical-web-file-modifications"
  log_group_name = var.cloudtrail_log_group

  pattern = format(
    "{ ($.eventName = \"PutObject\") && ($.requestParameters.bucketName = \"%s\") && ($.requestParameters.key = \"index.html\" || $.requestParameters.key = \"*.html\" || $.requestParameters.key = \"*.js\") }",
    var.monitored_bucket
  )

  metric_transformation {
    name      = "CriticalWebFileModifications"
    namespace = "Security/Defacement"
    value     = "1"
  }
}

# Step 3: Create alarm for any critical file modification
resource "aws_cloudwatch_metric_alarm" "critical_file_alarm" {
  alarm_name          = "Critical-Website-File-Modified"
  alarm_description   = "Critical website file modified - possible defacement"
  metric_name         = "CriticalWebFileModifications"
  namespace           = "Security/Defacement"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.integrity_alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="critical",
                alert_title="Critical Website File Modified",
                alert_description_template=(
                    "Critical website file {file_path} in bucket {bucket} was modified. "
                    "User: {user}. Source IP: {sourceIPAddress}. "
                    "Immediate verification required - possible defacement."
                ),
                investigation_steps=[
                    "Immediately download and inspect the modified file content",
                    "Compare file hash/ETag with known-good baseline",
                    "Review complete file diff against previous version",
                    "Verify the modifying user's authorisation and recent activity",
                    "Check for malicious content (web shells, redirects, injected scripts)",
                    "Review all files in bucket for additional unauthorised changes",
                    "Check S3 access logs for the modification timeframe",
                ],
                containment_actions=[
                    "Restore file from S3 versioning to previous known-good version",
                    "Enable S3 Object Lock on critical files to prevent deletions",
                    "Implement bucket policy requiring MFA for PutObject operations",
                    "Revoke credentials if unauthorised access confirmed",
                    "Enable S3 Versioning if not already active",
                    "Invalidate CloudFront cache if distribution is in use",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Whitelist CI/CD pipeline roles and scheduled deployment windows. "
                "Exclude automated content management system updates."
            ),
            detection_coverage="90% - detects any modification to monitored files",
            evasion_considerations=(
                "Cannot evade if CloudTrail logging is enabled. "
                "Attackers may target non-monitored files or directories."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "S3 Versioning enabled for rollback capability",
                "Baseline of critical file paths established",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1491.002-gcp-storage",
            name="GCP Storage Website Defacement Detection",
            description=(
                "Detect unauthorised modifications to Cloud Storage-hosted static website "
                "content through audit log monitoring."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="storage.objects.create" OR
protoPayload.methodName="storage.objects.update" OR
protoPayload.methodName="storage.objects.delete"
protoPayload.resourceName=~".*\\.(html|htm|js|css)$"''',
                gcp_terraform_template="""# GCP: Detect Cloud Storage website defacement

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for defacement alerts"
}

variable "monitored_bucket" {
  type        = string
  description = "Cloud Storage bucket hosting website content"
}

# Step 1: Create notification channel for email alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Website Defacement Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Create log-based metric for website content modifications
resource "google_logging_metric" "website_content_modification" {
  name    = "website-content-modification"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="storage.googleapis.com"
    (protoPayload.methodName="storage.objects.create" OR
     protoPayload.methodName="storage.objects.update" OR
     protoPayload.methodName="storage.objects.delete")
    protoPayload.resourceName=~".*\\.(html|htm|js|css)$"
    resource.labels.bucket_name="${var.monitored_bucket}"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User who modified content"
    }
  }

  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for content modifications
resource "google_monitoring_alert_policy" "defacement_detection" {
  display_name = "Website Defacement Detection"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Website content modified"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.website_content_modification.name}\""
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
  }

  documentation {
    content = <<-EOT
      ## Website Defacement Alert

      Unauthorised modification detected to Cloud Storage website content.

      **Immediate Actions:**
      1. Review the modified object in Cloud Storage
      2. Verify the user who made the modification
      3. Compare content with known-good backups
      4. Check for web shells or malicious code injection
      5. Restore from object versioning if compromised

      **Investigation:**
      - Review Cloud Audit Logs for access patterns
      - Check IAM permissions for the modifying principal
      - Examine source IP and user agent
      - Look for additional unauthorised modifications
    EOT
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Cloud Storage Website Content Modified",
                alert_description_template=(
                    "Cloud Storage website content modified in bucket {bucket}. "
                    "User: {principalEmail}. File: {resourceName}. "
                    "Verify this change is authorised - possible defacement."
                ),
                investigation_steps=[
                    "Review the modified object in Cloud Storage console",
                    "Download and inspect the file content for malicious changes",
                    "Verify the principal email and IAM role authorisation",
                    "Check Cloud Audit Logs for suspicious access patterns",
                    "Compare content with backups or object versioning history",
                    "Search for web shells, redirects, or injected scripts",
                    "Review all objects in bucket for additional modifications",
                ],
                containment_actions=[
                    "Restore object from versioning to previous known-good state",
                    "Enable Object Versioning if not already enabled",
                    "Revoke IAM permissions for compromised principal",
                    "Implement IAM Conditions requiring specific IP ranges",
                    "Enable retention policies to prevent unauthorised deletions",
                    "Invalidate CDN cache if Cloud CDN is in use",
                    "Review and tighten bucket IAM policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Whitelist service accounts used by CI/CD pipelines. "
                "Filter out scheduled content updates from known automation."
            ),
            detection_coverage="85% - catches direct Cloud Storage content modifications",
            evasion_considerations=(
                "Attackers using legitimate deployment credentials may blend in. "
                "Gradual modifications may appear as normal updates."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Object Versioning enabled for rollback capability",
                "Cloud Storage bucket configured for static website hosting",
            ],
        ),
    ],
    recommended_order=[
        "t1491.002-aws-s3-content",
        "t1491.002-aws-integrity",
        "t1491.002-gcp-storage",
        "t1491.002-aws-cloudfront",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+30% improvement for Impact tactic",
)
