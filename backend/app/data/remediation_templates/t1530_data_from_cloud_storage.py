"""
T1530 - Data from Cloud Storage

Adversaries may access data from cloud storage objects to collect sensitive information.
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
)

TEMPLATE = RemediationTemplate(
    technique_id="T1530",
    technique_name="Data from Cloud Storage",
    tactic_ids=["TA0009"],
    mitre_url="https://attack.mitre.org/techniques/T1530/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may access data stored in cloud storage objects such as S3 buckets. "
            "Cloud storage often contains sensitive data including backups, logs, credentials, "
            "and business-critical information that can be valuable for extortion or intelligence."
        ),
        attacker_goal="Exfiltrate sensitive data from cloud storage for espionage, extortion, or sale",
        why_technique=[
            "S3 buckets often contain vast amounts of sensitive data",
            "Misconfigured buckets may allow public or overly permissive access",
            "Data exfiltration can occur at scale with simple API calls",
            "Backups in S3 may contain database dumps with credentials",
            "Logs and configuration files can reveal additional attack vectors",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="Capital One Breach",
                year=2019,
                description="Attacker exploited SSRF to access S3 buckets containing 100M+ customer records",
                reference_url="https://www.capitalone.com/digital/facts2019/",
            ),
            Campaign(
                name="Twitch Source Code Leak",
                year=2021,
                description="Complete source code and internal data exfiltrated from misconfigured cloud storage",
                reference_url="https://blog.twitch.tv/en/2021/10/06/updates-on-the-twitch-security-incident/",
            ),
            Campaign(
                name="LAPSUS$ Data Theft",
                year=2022,
                description="Accessed and exfiltrated source code and data from major tech companies' cloud storage",
                reference_url="https://www.microsoft.com/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Cloud storage data theft can result in massive data breaches. "
            "S3 buckets frequently contain highly sensitive data and are often misconfigured. "
            "The ease of bulk data access makes this a high-impact technique."
        ),
        business_impact=[
            "Large-scale data breach affecting customers and partners",
            "Regulatory fines (GDPR, CCPA, HIPAA violations)",
            "Intellectual property theft",
            "Ransomware/extortion leverage",
            "Reputational damage and loss of customer trust",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1567", "T1537"],
        often_follows=["T1078", "T1552", "T1190"],
    ),
    detection_strategies=[
        # Strategy 1: GuardDuty S3 Protection
        DetectionStrategy(
            strategy_id="t1530-guardduty",
            name="Enable GuardDuty S3 Protection",
            description=(
                "AWS GuardDuty S3 Protection analyses CloudTrail S3 data events to detect "
                "suspicious access patterns and potential data exfiltration."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Exfiltration:S3/MaliciousIPCaller",
                    "Exfiltration:S3/ObjectRead.Unusual",
                    "Discovery:S3/TorIPCaller",
                    "Discovery:S3/MaliciousIPCaller.Custom",
                    "UnauthorizedAccess:S3/TorIPCaller",
                    "UnauthorizedAccess:S3/MaliciousIPCaller.Custom",
                    "Policy:S3/BucketBlockPublicAccessDisabled",
                    "Policy:S3/BucketAnonymousAccessGranted",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty + email alerts for S3 data theft

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty with S3 protection
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      DataSources:
        S3Logs:
          Enable: true

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route S3 findings to email
  S3FindingsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "Exfiltration:S3"
            - prefix: "UnauthorizedAccess:S3"
            - prefix: "Discovery:S3"
            - prefix: "Policy:S3"
      Targets:
        - Id: Email
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
                terraform_template="""# GuardDuty + email alerts for S3 data theft

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty with S3 protection
resource "aws_guardduty_detector" "main" {
  enable = true
  datasources {
    s3_logs {
      enable = true
    }
  }
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "guardduty-s3-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route S3 findings to email
resource "aws_cloudwatch_event_rule" "s3_findings" {
  name = "guardduty-s3-alerts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "Exfiltration:S3" },
        { prefix = "UnauthorizedAccess:S3" },
        { prefix = "Discovery:S3" },
        { prefix = "Policy:S3" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.s3_findings.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
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
                alert_severity="high",
                alert_title="GuardDuty: Suspicious S3 Access Detected",
                alert_description_template=(
                    "GuardDuty detected suspicious S3 activity: {finding_type}. "
                    "Bucket: {bucket}. Source IP: {source_ip}. "
                    "This may indicate data exfiltration."
                ),
                investigation_steps=[
                    "Identify which S3 buckets were accessed",
                    "Review the source IP and determine if it's known",
                    "Check what data was accessed or downloaded",
                    "Verify if the accessing principal should have this access",
                    "Review access patterns for unusual volume or timing",
                ],
                containment_actions=[
                    "Block the source IP at bucket policy or WAF level",
                    "Revoke access for the compromised principal",
                    "Enable S3 Object Lock if data integrity is critical",
                    "Review and restrict bucket policies",
                    "Consider enabling bucket versioning for recovery",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Add known data processing IPs to trusted IP lists",
            detection_coverage="70% - covers anomalous S3 access patterns",
            evasion_considerations="Slow exfiltration, use of legitimate-looking IPs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million S3 data events",
            prerequisites=[
                "AWS account with appropriate IAM permissions",
                "S3 data events enabled",
            ],
        ),
        # Strategy 2: Unusual S3 Access Volume
        DetectionStrategy(
            strategy_id="t1530-bulk-access",
            name="Bulk S3 Data Access Detection",
            description=(
                "Detect unusual volumes of S3 GetObject requests that may indicate "
                "bulk data exfiltration attempts."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, requestParameters.bucketName as bucket,
       sourceIPAddress, bytesTransferredOut
| filter eventName = "GetObject"
| stats count(*) as object_count, sum(bytesTransferredOut) as total_bytes
  by user, bucket, sourceIPAddress, bin(1h) as hour_window
| filter object_count >= 100 or total_bytes >= 1073741824
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Bulk S3 access detection for T1530

Parameters:
  CloudTrailLogGroup:
    Type: String
  SNSTopicArn:
    Type: String
  ObjectCountThreshold:
    Type: Number
    Default: 100

Resources:
  BulkS3AccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "GetObject" }'
      MetricTransformations:
        - MetricName: S3ObjectDownloads
          MetricNamespace: Security/T1530
          MetricValue: "1"

  BulkS3AccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1530-BulkS3Access
      AlarmDescription: High volume of S3 object downloads detected
      MetricName: S3ObjectDownloads
      Namespace: Security/T1530
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: !Ref ObjectCountThreshold
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn""",
                alert_severity="high",
                alert_title="Bulk S3 Data Access Detected",
                alert_description_template=(
                    "User {user} accessed {object_count} objects ({total_bytes} bytes) from bucket {bucket} in 1 hour. "
                    "Source IP: {sourceIPAddress}. This may indicate data exfiltration."
                ),
                investigation_steps=[
                    "Identify what data was accessed from the bucket",
                    "Verify if this access pattern is normal for the user",
                    "Check the source IP geolocation and reputation",
                    "Review if the data accessed was sensitive or regulated",
                    "Compare with the user's historical access patterns",
                ],
                containment_actions=[
                    "Temporarily revoke the user's S3 access",
                    "Add source IP to bucket policy deny list",
                    "Enable S3 access logging if not already enabled",
                    "Review and tighten bucket access policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal access patterns; exclude known data pipeline roles",
            detection_coverage="80% - catches bulk download attempts",
            evasion_considerations="Slow, distributed exfiltration over extended periods",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=[
                "CloudTrail S3 data events enabled",
                "CloudTrail logs in CloudWatch",
            ],
        ),
        # Strategy 3: Sensitive Bucket Access
        DetectionStrategy(
            strategy_id="t1530-sensitive-buckets",
            name="Sensitive Bucket Access Monitoring",
            description=(
                "Monitor access to buckets containing sensitive data such as backups, "
                "logs, or configuration files."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.s3"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["s3.amazonaws.com"],
                        "eventName": ["GetObject", "ListObjects", "ListObjectsV2"],
                        "requestParameters": {
                            "bucketName": [
                                {"prefix": "backup"},
                                {"prefix": "logs"},
                                {"prefix": "config"},
                                {"suffix": "-sensitive"},
                                {"suffix": "-pii"},
                            ]
                        },
                    },
                },
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Sensitive S3 bucket access monitoring

Parameters:
  SNSTopicArn:
    Type: String

Resources:
  SensitiveBucketAccessRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1530-SensitiveBucketAccess
      Description: Monitor access to sensitive S3 buckets
      EventPattern:
        source:
          - aws.s3
        detail-type:
          - "AWS API Call via CloudTrail"
        detail:
          eventSource:
            - s3.amazonaws.com
          eventName:
            - GetObject
            - ListObjects
            - ListObjectsV2
      State: ENABLED
      Targets:
        - Id: SNSAlert
          Arn: !Ref SNSTopicArn
          InputTransformer:
            InputPathsMap:
              bucket: "$.detail.requestParameters.bucketName"
              user: "$.detail.userIdentity.arn"
              ip: "$.detail.sourceIPAddress"
            InputTemplate: |
              "Sensitive bucket <bucket> accessed by <user> from IP <ip>"''',
                alert_severity="medium",
                alert_title="Sensitive S3 Bucket Access",
                alert_description_template=(
                    "User {user} accessed sensitive bucket {bucket}. "
                    "Source IP: {sourceIPAddress}. "
                    "Verify this access is authorised."
                ),
                investigation_steps=[
                    "Verify the user's business need to access this bucket",
                    "Check what specific objects were accessed",
                    "Review the user's role and normal access patterns",
                    "Confirm the source IP is expected for this user",
                    "Check if any data was downloaded or copied",
                ],
                containment_actions=[
                    "Contact the user to verify the access",
                    "Review and update bucket access policies",
                    "Consider implementing S3 Access Points for granular control",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Customise bucket name patterns; whitelist specific roles",
            detection_coverage="60% - depends on bucket naming conventions",
            evasion_considerations="Attackers may target buckets with generic names",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail S3 data events enabled",
                "Consistent bucket naming",
            ],
        ),
        # Strategy 4: Cross-Account Access
        DetectionStrategy(
            strategy_id="t1530-cross-account",
            name="Cross-Account S3 Access Detection",
            description=(
                "Detect when S3 objects are accessed by principals from external AWS accounts, "
                "which may indicate data exfiltration to attacker-controlled infrastructure."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.accountId as caller_account,
       userIdentity.arn as user, requestParameters.bucketName as bucket,
       sourceIPAddress, eventName
| filter eventName in ["GetObject", "CopyObject", "UploadPartCopy"]
| filter userIdentity.accountId != "YOUR_ACCOUNT_ID"
| stats count(*) as access_count by caller_account, user, bucket, bin(1h) as hour_window
| sort access_count desc""",
                alert_severity="high",
                alert_title="Cross-Account S3 Access Detected",
                alert_description_template=(
                    "Account {caller_account} ({user}) accessed bucket {bucket} {access_count} times. "
                    "Verify this cross-account access is authorised."
                ),
                investigation_steps=[
                    "Identify the external account accessing your buckets",
                    "Verify if this account is a known partner or service",
                    "Review bucket policies for overly permissive cross-account access",
                    "Check what data was accessed by the external account",
                    "Determine if the access pattern is normal",
                ],
                containment_actions=[
                    "Update bucket policy to restrict external access",
                    "Implement VPC endpoints for S3 if applicable",
                    "Review and audit all cross-account access policies",
                    "Consider using AWS RAM for controlled resource sharing",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Maintain list of trusted partner account IDs",
            detection_coverage="70% - catches cross-account exfiltration",
            evasion_considerations="Attackers may use compromised accounts within the organisation",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "CloudTrail S3 data events enabled",
                "Account ID documented",
            ],
        ),
    ],
    recommended_order=[
        "t1530-guardduty",
        "t1530-bulk-access",
        "t1530-sensitive-buckets",
        "t1530-cross-account",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+35% improvement for Collection tactic",
)
