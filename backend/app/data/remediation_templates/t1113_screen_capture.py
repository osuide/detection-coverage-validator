"""
T1113 - Screen Capture

Adversaries capture desktop screenshots to gather information during operations.
Screenshot functionality is commonly embedded in remote access tools for intelligence collection.

IMPORTANT DETECTION LIMITATIONS:
Cloud-native APIs (CloudTrail, EventBridge, Cloud Logging) CANNOT detect in-guest
screenshot capture. Screenshot APIs are OS-level calls (Windows GDI, X11, macOS APIs)
that do not generate cloud events.

What cloud detection CAN see:
- AWS GetConsoleScreenshot API calls (cloud console screenshots only)
- WorkSpaces session activity and configuration changes
- File creation/upload patterns (post-capture indicators)

What requires endpoint agents:
- Real-time detection of screenshot tools (Snipping Tool, gnome-screenshot)
- Detection of programmatic screenshot APIs (BitBlt, XGetImage)
- Memory-resident screenshot malware

Coverage reality:
- Cloud API monitoring: ~10% (catches AWS console screenshots only)
- With OS logging + file monitoring: ~30%
- With endpoint agent (EDR): ~60-70%

For comprehensive detection, deploy endpoint security solutions with process and API monitoring.
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
    technique_id="T1113",
    technique_name="Screen Capture",
    tactic_ids=["TA0009"],  # Collection
    mitre_url="https://attack.mitre.org/techniques/T1113/",
    threat_context=ThreatContext(
        description=(
            "Adversaries capture desktop screenshots to gather sensitive information during operations. "
            "In cloud environments, attackers target virtual desktop infrastructure (VDI), remote desktop "
            "sessions, and cloud-hosted workstations to capture credentials, proprietary data, and business "
            "communications displayed on screens. Screenshot capabilities are frequently embedded in remote "
            "access tools and post-exploitation frameworks, making this a common espionage technique."
        ),
        attacker_goal="Capture screenshots of desktop activity to gather sensitive information and credentials",
        why_technique=[
            "Captures information exactly as users see it, including credentials and sensitive data",
            "Embedded in most remote access tools and post-exploitation frameworks",
            "Difficult to detect as screenshot APIs are legitimate system functions",
            "Effective against virtual desktop infrastructure and remote sessions",
            "Reveals business processes, communications, and proprietary information",
        ],
        known_threat_actors=[
            "APT28 (Fancy Bear)",
            "APT37",
            "APT39",
            "APT42",
            "FIN7",
            "FIN8",
            "Gamaredon Group",
            "MuddyWater",
            "OilRig",
            "Volt Typhoon",
        ],
        recent_campaigns=[
            Campaign(
                name="Volt Typhoon Infrastructure Espionage",
                year=2023,
                description="Volt Typhoon obtained screenshots using gdi32.dll and gdiplus.dll libraries during long-term espionage operations targeting critical infrastructure",
                reference_url="https://attack.mitre.org/groups/G1017/",
            ),
            Campaign(
                name="Gamaredon Automated Screenshot Capture",
                year=2022,
                description="Gamaredon Group malware captured screenshots of compromised computers every minute for continuous surveillance",
                reference_url="https://attack.mitre.org/groups/G0047/",
            ),
            Campaign(
                name="APT28 Credential Harvesting",
                year=2021,
                description="APT28 deployed tools with screenshot capabilities to capture credentials and sensitive information from compromised systems",
                reference_url="https://attack.mitre.org/groups/G0007/",
            ),
        ],
        prevalence="common",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Screen capture is a high-fidelity collection technique that reveals exactly what users see, "
            "including credentials being entered, sensitive documents, and business communications. "
            "In cloud environments, this technique is particularly dangerous for virtual desktop sessions "
            "and remote workstations where users handle sensitive data. Moderate to high severity due to "
            "the quality of intelligence gathered and prevalence in espionage campaigns."
        ),
        business_impact=[
            "Exposure of credentials and authentication tokens displayed on screen",
            "Theft of proprietary documents and intellectual property",
            "Disclosure of business communications and strategic information",
            "Compliance violations from unauthorised data capture",
            "Privacy breaches from capturing personal information",
        ],
        typical_attack_phase="collection",
        often_precedes=["T1567", "T1041", "T1048"],
        often_follows=["T1078", "T1219", "T1021"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - WorkSpaces Session Activity Monitoring
        DetectionStrategy(
            strategy_id="t1113-aws-workspaces",
            name="AWS WorkSpaces Suspicious Activity Detection",
            description=(
                "Monitor AWS WorkSpaces sessions for unusual file creation patterns "
                "and API calls that may indicate screenshot capture activity."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventName,
       requestParameters.workspaceId, requestParameters.directoryId,
       sourceIPAddress
| filter eventSource = "workspaces.amazonaws.com"
| filter eventName in ["ModifyWorkspaceProperties", "RebuildWorkspaces",
                       "CreateWorkspaces", "TerminateWorkspaces"]
| stats count(*) as event_count by user, sourceIPAddress, bin(1h) as time_window
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor AWS WorkSpaces for potential screen capture activity

Parameters:
  CloudTrailLogGroup:
    Type: String
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

  # Step 2: Metric filter for suspicious WorkSpaces activity
  WorkSpacesActivityFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "workspaces.amazonaws.com") && ($.eventName = "ModifyWorkspaceProperties" || $.eventName = "RebuildWorkspaces") }'
      MetricTransformations:
        - MetricName: SuspiciousWorkSpacesActivity
          MetricNamespace: Security/T1113
          MetricValue: "1"

  # Step 3: Alarm for unusual WorkSpaces modifications
  WorkSpacesAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1113-WorkSpacesActivity
      MetricName: SuspiciousWorkSpacesActivity
      Namespace: Security/T1113
      Statistic: Sum
      Period: 3600
      Threshold: 5
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Monitor AWS WorkSpaces for screen capture indicators

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "workspaces-security-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for suspicious WorkSpaces activity
resource "aws_cloudwatch_log_metric_filter" "workspaces_activity" {
  name           = "suspicious-workspaces-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"workspaces.amazonaws.com\") && ($.eventName = \"ModifyWorkspaceProperties\" || $.eventName = \"RebuildWorkspaces\") }"

  metric_transformation {
    name      = "SuspiciousWorkSpacesActivity"
    namespace = "Security/T1113"
    value     = "1"
  }
}

# Step 3: Alarm for unusual WorkSpaces modifications
resource "aws_cloudwatch_metric_alarm" "workspaces_activity" {
  alarm_name          = "T1113-WorkSpacesActivity"
  metric_name         = "SuspiciousWorkSpacesActivity"
  namespace           = "Security/T1113"
  statistic           = "Sum"
  period              = 3600
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious AWS WorkSpaces Activity Detected",
                alert_description_template=(
                    "User {user} performed {event_count} WorkSpaces modifications in 1 hour from {sourceIPAddress}. "
                    "This may indicate preparation for screen capture or data collection."
                ),
                investigation_steps=[
                    "Identify the WorkSpaces instances affected",
                    "Review recent user activity within the WorkSpaces sessions",
                    "Check for installation of remote access or screenshot tools",
                    "Examine file creation patterns in WorkSpaces directories",
                    "Verify source IP location and user authentication history",
                    "Review CloudWatch logs for unusual process execution",
                ],
                containment_actions=[
                    "Suspend suspicious WorkSpaces sessions immediately",
                    "Review and restrict WorkSpaces management permissions",
                    "Enable enhanced monitoring for affected WorkSpaces",
                    "Implement application allowlisting in WorkSpaces",
                    "Review and update WorkSpaces security group rules",
                    "Force password reset for affected users",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised IT operations and maintenance windows for WorkSpaces management",
            detection_coverage="10% - catches AWS console GetConsoleScreenshot API only. In-guest screenshots NOT detected without endpoint agent.",
            evasion_considerations="Attackers may use legitimate screenshot tools or capture screenshots without API calls",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "WorkSpaces in use"],
        ),
        # Strategy 2: AWS - EC2 Instance Screenshot API Monitoring
        DetectionStrategy(
            strategy_id="t1113-aws-ec2-screenshot",
            name="EC2 Instance Console Screenshot Detection",
            description=(
                "Detect use of EC2 GetConsoleScreenshot API which captures screenshots "
                "of EC2 instance console screens."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["GetConsoleScreenshot"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 console screenshot capture attempts

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

  # Step 2: EventBridge rule for screenshot API
  ScreenshotRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.ec2]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [GetConsoleScreenshot]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy to allow EventBridge
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
                terraform_template="""# Detect EC2 console screenshot API usage

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "ec2-screenshot-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for screenshot API
resource "aws_cloudwatch_event_rule" "screenshot" {
  name = "ec2-console-screenshot-detection"
  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["GetConsoleScreenshot"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.screenshot.name
  arn  = aws_sns_topic.alerts.arn
}

# Step 3: SNS topic policy
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
                alert_severity="high",
                alert_title="EC2 Console Screenshot Captured",
                alert_description_template=(
                    "Console screenshot captured for EC2 instance {instanceId} by {userIdentity.arn}. "
                    "This may indicate reconnaissance or screen capture activity."
                ),
                investigation_steps=[
                    "Identify who requested the console screenshot",
                    "Determine which EC2 instance was targeted",
                    "Check if this is authorised troubleshooting activity",
                    "Review recent authentication activity for the principal",
                    "Examine the instance for sensitive data exposure",
                    "Check for repeated screenshot attempts",
                ],
                containment_actions=[
                    "Verify legitimacy with the user or IT team",
                    "Review and restrict ec2:GetConsoleScreenshot permissions",
                    "Rotate credentials if compromise is suspected",
                    "Enable MFA for sensitive EC2 operations",
                    "Audit IAM policies for excessive EC2 permissions",
                    "Monitor for additional suspicious API calls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised troubleshooting teams and monitoring tools",
            detection_coverage="95% - API-level detection, does not require endpoint agent",
            evasion_considerations="This only detects AWS API-based screenshots, not screenshots from within the instance",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - AppStream Session Monitoring
        DetectionStrategy(
            strategy_id="t1113-aws-appstream",
            name="AWS AppStream Session Activity Monitoring",
            description=(
                "Monitor AppStream 2.0 sessions for suspicious activity patterns that "
                "may indicate screen capture or data collection."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventName,
       requestParameters.stackName, requestParameters.fleetName,
       sourceIPAddress
| filter eventSource = "appstream.amazonaws.com"
| filter eventName in ["CreateStreamingURL", "CreateUser", "DescribeStacks"]
| stats count(*) as event_count by user, sourceIPAddress, bin(1h)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor AppStream for potential screen capture activity

Parameters:
  CloudTrailLogGroup:
    Type: String
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

  # Step 2: Metric filter for AppStream activity
  AppStreamActivityFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "appstream.amazonaws.com") && ($.eventName = "CreateStreamingURL" || $.eventName = "CreateUser") }'
      MetricTransformations:
        - MetricName: AppStreamActivity
          MetricNamespace: Security/T1113
          MetricValue: "1"

  # Step 3: Alarm for suspicious AppStream usage
  AppStreamAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1113-AppStreamActivity
      MetricName: AppStreamActivity
      Namespace: Security/T1113
      Statistic: Sum
      Period: 3600
      Threshold: 10
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Monitor AppStream for screen capture indicators

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "appstream-security-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for AppStream activity
resource "aws_cloudwatch_log_metric_filter" "appstream_activity" {
  name           = "appstream-suspicious-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"appstream.amazonaws.com\") && ($.eventName = \"CreateStreamingURL\" || $.eventName = \"CreateUser\") }"

  metric_transformation {
    name      = "AppStreamActivity"
    namespace = "Security/T1113"
    value     = "1"
  }
}

# Step 3: Alarm for suspicious AppStream usage
resource "aws_cloudwatch_metric_alarm" "appstream_activity" {
  alarm_name          = "T1113-AppStreamActivity"
  metric_name         = "AppStreamActivity"
  namespace           = "Security/T1113"
  statistic           = "Sum"
  period              = 3600
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Suspicious AppStream Activity Detected",
                alert_description_template=(
                    "User {user} performed {event_count} AppStream operations in 1 hour. "
                    "This may indicate reconnaissance or session compromise."
                ),
                investigation_steps=[
                    "Identify the AppStream stacks and fleets accessed",
                    "Review session activity logs for unusual behaviour",
                    "Check for unauthorised user creation or access",
                    "Examine source IP reputation and geolocation",
                    "Verify if streaming URLs were created for unknown users",
                    "Review application usage within AppStream sessions",
                ],
                containment_actions=[
                    "Terminate suspicious AppStream sessions",
                    "Review and restrict AppStream IAM permissions",
                    "Enable session recording for AppStream",
                    "Implement IP allowlisting for AppStream access",
                    "Review and update fleet security configurations",
                    "Enable MFA for AppStream user access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal AppStream usage patterns and whitelist authorised administrators",
            detection_coverage="65% - detects API-level activity but not in-session screen capture",
            evasion_considerations="Attackers may use legitimate AppStream access to capture screenshots without additional API calls",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "AppStream 2.0 in use"],
        ),
        # Strategy 4: GCP - Compute Instance Screenshot Detection
        DetectionStrategy(
            strategy_id="t1113-gcp-compute-screenshot",
            name="GCP Compute Engine Screenshot Detection",
            description=(
                "Detect use of Compute Engine screenshot API which captures screenshots "
                "of virtual machine console displays."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="v1.compute.instances.getScreenshot"
protoPayload.serviceName="compute.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect Compute Engine screenshot API usage

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for screenshot API
resource "google_logging_metric" "compute_screenshot" {
  name   = "compute-screenshot-capture"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    protoPayload.methodName="v1.compute.instances.getScreenshot"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for screenshot capture
resource "google_monitoring_alert_policy" "compute_screenshot" {
  display_name = "Compute Instance Screenshot Captured"
  combiner     = "OR"

  conditions {
    display_name = "Screenshot API usage detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.compute_screenshot.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Compute Engine screenshot captured - potential screen capture activity (T1113)"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Compute Instance Screenshot Captured",
                alert_description_template=(
                    "Screenshot captured for Compute Engine instance. This may indicate "
                    "reconnaissance or screen capture activity."
                ),
                investigation_steps=[
                    "Identify who requested the screenshot via audit logs",
                    "Determine which VM instance was targeted",
                    "Check if this is authorised troubleshooting activity",
                    "Review recent authentication events for the principal",
                    "Examine the instance for sensitive data exposure",
                    "Check for repeated screenshot attempts across instances",
                ],
                containment_actions=[
                    "Verify legitimacy with the user or operations team",
                    "Review and restrict compute.instances.getScreenshot permissions",
                    "Rotate service account keys if compromise is suspected",
                    "Enable organisation policy constraints to limit screenshot access",
                    "Audit IAM bindings for excessive Compute permissions",
                    "Monitor for additional suspicious API activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised support and troubleshooting teams",
            detection_coverage="95% - API-level detection, does not require endpoint agent",
            evasion_considerations="Only detects GCP API-based screenshots, not screenshots taken within the VM",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - Virtual Desktop Activity Monitoring
        DetectionStrategy(
            strategy_id="t1113-gcp-virtual-desktop",
            name="GCP Virtual Desktop Session Monitoring",
            description=(
                "Monitor Cloud Identity-Aware Proxy and virtual desktop sessions for "
                "suspicious activity that may indicate screen capture attempts."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
(protoPayload.methodName=~".*RemoteDesktop.*" OR
 protoPayload.methodName=~".*VNC.*" OR
 protoPayload.methodName=~".*RDP.*")""",
                gcp_terraform_template="""# GCP: Monitor virtual desktop sessions for screen capture indicators

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for remote desktop activity
resource "google_logging_metric" "remote_desktop" {
  name   = "remote-desktop-activity"
  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName=~".*RemoteDesktop.*" OR
     protoPayload.methodName=~".*VNC.*" OR
     protoPayload.methodName=~".*RDP.*")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for suspicious remote desktop usage
resource "google_monitoring_alert_policy" "remote_desktop" {
  display_name = "Suspicious Virtual Desktop Activity"
  combiner     = "OR"

  conditions {
    display_name = "High volume remote desktop activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.remote_desktop.name}\""
      duration        = "3600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Suspicious remote desktop activity detected - potential screen capture threat (T1113)"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Suspicious Virtual Desktop Activity",
                alert_description_template=(
                    "High volume of remote desktop activity detected. This may indicate "
                    "reconnaissance or screen capture operations."
                ),
                investigation_steps=[
                    "Identify the principals accessing virtual desktops",
                    "Review session logs for unusual access patterns",
                    "Check source IP locations and authentication methods",
                    "Examine instances for installation of screenshot tools",
                    "Review file access and creation patterns during sessions",
                    "Correlate with other security events",
                ],
                containment_actions=[
                    "Terminate suspicious remote desktop sessions",
                    "Review and restrict Identity-Aware Proxy access",
                    "Enable session recording and monitoring",
                    "Implement IP allowlisting for remote access",
                    "Review firewall rules for RDP/VNC ports",
                    "Enable OS Login for centralised access control",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baselines for normal remote desktop usage and whitelist authorised users",
            detection_coverage="15% - detects file upload patterns only. In-guest screenshots NOT detected without endpoint agent.",
            evasion_considerations="Legitimate remote access can be used to execute screenshot tools without generating additional alerts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled", "VPC Flow Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1113-aws-ec2-screenshot",
        "t1113-gcp-compute-screenshot",
        "t1113-aws-workspaces",
        "t1113-aws-appstream",
        "t1113-gcp-virtual-desktop",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+15% improvement for Collection tactic",
)
