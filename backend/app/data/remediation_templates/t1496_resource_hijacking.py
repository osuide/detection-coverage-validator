"""
T1496 - Resource Hijacking

Adversaries leverage compromised systems to complete resource-intensive tasks
including cryptocurrency mining, bandwidth hijacking, SMS pumping, and cloud
service abuse. Impacts system availability and incurs costs.
Used in LABRAT cryptojacking campaign.
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
    technique_id="T1496",
    technique_name="Resource Hijacking",
    tactic_ids=["TA0040"],
    mitre_url="https://attack.mitre.org/techniques/T1496/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage compromised systems to complete resource-intensive "
            "tasks that impact availability and incur costs. Common forms include "
            "cryptocurrency mining (compute hijacking), selling network bandwidth to "
            "proxy networks, generating SMS traffic for profit, and abusing cloud "
            "messaging services for spam campaigns."
        ),
        attacker_goal="Monetise compromised resources through cryptocurrency mining, proxy services, or cloud service abuse",
        why_technique=[
            "Direct financial gain for attackers",
            "Difficult to detect with traditional tools",
            "Can run for extended periods unnoticed",
            "Cloud environments provide scalable compute",
            "Low risk compared to data theft",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=6,
        severity_reasoning=(
            "Moderate severity as it primarily impacts availability and incurs costs. "
            "While not typically causing data breaches, sustained resource hijacking "
            "can severely degrade performance and result in significant cloud bills."
        ),
        business_impact=[
            "Increased cloud infrastructure costs",
            "Degraded system performance",
            "Service availability issues",
            "Potential regulatory scrutiny",
            "Reputational damage",
        ],
        typical_attack_phase="impact",
        often_precedes=[],
        often_follows=["T1078", "T1078.004", "T1098", "T1525"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1496-aws-ec2-cpu",
            name="AWS EC2 High CPU Usage Detection",
            description="Detect persistent high CPU utilisation on EC2 instances indicative of cryptomining.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, instanceId, CPUUtilization
| filter CPUUtilization > 80
| stats avg(CPUUtilization) as avgCPU, max(CPUUtilization) as maxCPU by instanceId, bin(1h)
| filter avgCPU > 80
| sort avgCPU desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect high CPU usage indicating cryptomining

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: EC2-HighCPU-Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create CloudWatch alarm for sustained high CPU
  HighCPUAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EC2-SustainedHighCPU
      AlarmDescription: Detects sustained high CPU usage indicating possible cryptomining
      MetricName: CPUUtilization
      Namespace: AWS/EC2
      Statistic: Average
      Period: 300  # 5 minutes
      EvaluationPeriods: 6  # 30 minutes total
      Threshold: 80
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic

  # Step 3: Create metric filter for process-level detection (if CloudWatch agent configured)
  ProcessCPUMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: /aws/ec2/processes
      FilterPattern: '[timestamp, instance, process="*", cpu > 50]'
      MetricTransformations:
        - MetricName: HighProcessCPU
          MetricNamespace: Security/ResourceHijacking
          MetricValue: "1"
          DefaultValue: 0""",
                terraform_template="""# Detect high CPU usage indicating cryptomining

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "ec2-highcpu-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create CloudWatch alarm for sustained high CPU
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "EC2-SustainedHighCPU"
  alarm_description   = "Detects sustained high CPU usage indicating possible cryptomining"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  period              = 300  # 5 minutes
  evaluation_periods  = 6    # 30 minutes total
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

# Step 3: Create metric filter for process-level detection
resource "aws_cloudwatch_log_metric_filter" "process_cpu" {
  name           = "high-process-cpu"
  log_group_name = "/aws/ec2/processes"
  pattern        = "[timestamp, instance, process=\"*\", cpu > 50]"

  metric_transformation {
    name      = "HighProcessCPU"
    namespace = "Security/ResourceHijacking"
    value     = "1"
  }
}""",
                alert_severity="high",
                alert_title="Sustained High CPU Usage Detected",
                alert_description_template="Instance {instanceId} showing sustained CPU usage above 80% for 30+ minutes.",
                investigation_steps=[
                    "Review running processes on affected instance",
                    "Check network connections to known mining pools",
                    "Review CloudTrail for unauthorised instance launches",
                    "Check for suspicious user accounts or credentials",
                    "Analyse startup scripts and cron jobs",
                    "Review VPC Flow Logs for unusual outbound traffic",
                ],
                containment_actions=[
                    "Isolate instance by modifying security groups",
                    "Take snapshot for forensics",
                    "Terminate suspicious processes",
                    "Rotate credentials and keys",
                    "Review and revoke unauthorised IAM permissions",
                    "Consider terminating and replacing instance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Tune threshold based on normal workload patterns; exclude known batch processing instances",
            detection_coverage="70% - catches sustained cryptomining activity",
            evasion_considerations="Attackers may throttle CPU usage below threshold or operate intermittently",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "CloudWatch agent installed for process-level monitoring (optional but recommended)"
            ],
        ),
        DetectionStrategy(
            strategy_id="t1496-aws-network-mining",
            name="AWS Network Traffic to Mining Pools",
            description="Detect network connections to known cryptocurrency mining pools via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes
| filter dstPort in [3333, 4444, 5555, 8333, 9999, 14433, 14444, 45560]
| stats sum(bytes) as totalBytes by srcAddr, dstAddr, dstPort, bin(1h)
| filter totalBytes > 1000000
| sort totalBytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect network connections to cryptocurrency mining pools

Parameters:
  VPCFlowLogGroup:
    Type: String
    Description: CloudWatch Log Group for VPC Flow Logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for mining pool ports
  MiningPoolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport=3333 || destport=4444 || destport=5555 || destport=8333 || destport=9999 || destport=14433 || destport=14444 || destport=45560, protocol, packets, bytes, start, end, action=ACCEPT, flowlogstatus]'
      MetricTransformations:
        - MetricName: MiningPoolConnections
          MetricNamespace: Security/ResourceHijacking
          MetricValue: "1"

  # Step 3: Create alarm for mining pool connections
  MiningPoolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CryptominingDetected
      AlarmDescription: Network connections to known mining pools detected
      MetricName: MiningPoolConnections
      Namespace: Security/ResourceHijacking
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect network connections to cryptocurrency mining pools

variable "vpc_flow_log_group" {
  description = "CloudWatch Log Group for VPC Flow Logs"
  type        = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "mining-pool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for mining pool ports
resource "aws_cloudwatch_log_metric_filter" "mining_pools" {
  name           = "mining-pool-connections"
  log_group_name = var.vpc_flow_log_group
  # Common mining ports: 3333, 4444, 5555 (Stratum), 8333 (Bitcoin), 9999 (Dash), 14433, 14444, 45560 (Monero)
  pattern = "[version, account, eni, source, destination, srcport, destport=3333 || destport=4444 || destport=5555 || destport=8333 || destport=9999 || destport=14433 || destport=14444 || destport=45560, protocol, packets, bytes, start, end, action=ACCEPT, flowlogstatus]"

  metric_transformation {
    name      = "MiningPoolConnections"
    namespace = "Security/ResourceHijacking"
    value     = "1"
  }
}

# Step 3: Create alarm for mining pool connections
resource "aws_cloudwatch_metric_alarm" "mining_detected" {
  alarm_name          = "CryptominingDetected"
  alarm_description   = "Network connections to known mining pools detected"
  metric_name         = "MiningPoolConnections"
  namespace           = "Security/ResourceHijacking"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Cryptocurrency Mining Pool Connection Detected",
                alert_description_template="Instance {srcAddr} connecting to mining pool on port {dstPort}.",
                investigation_steps=[
                    "Identify source instance from IP address",
                    "Review running processes on instance",
                    "Check CloudTrail for recent modifications",
                    "Review instance launch configuration",
                    "Check for lateral movement from this instance",
                    "Identify initial access vector",
                ],
                containment_actions=[
                    "Block mining pool IPs in NACL/security groups",
                    "Isolate affected instance",
                    "Terminate mining processes",
                    "Review and rotate all credentials",
                    "Terminate and rebuild instance from clean AMI",
                    "Enable GuardDuty for ongoing detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Mining pool ports are highly specific; false positives are rare",
            detection_coverage="80% - catches most cryptomining activity",
            evasion_considerations="Custom mining pools on non-standard ports will evade; encrypted connections hide payload",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled and sent to CloudWatch"],
        ),
        DetectionStrategy(
            strategy_id="t1496-aws-ecs-cpu",
            name="AWS ECS/Fargate High CPU Detection",
            description="Detect high CPU usage in containers that may indicate cryptomining.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, ClusterName, ServiceName, TaskId, CPUUtilization
| filter CPUUtilization > 80
| stats avg(CPUUtilization) as avgCPU by ClusterName, ServiceName, TaskId, bin(1h)
| filter avgCPU > 80
| sort avgCPU desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect cryptomining in ECS containers

Parameters:
  ClusterName:
    Type: String
  ServiceName:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: CloudWatch alarm for container CPU
  ContainerHighCPU:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub '${ClusterName}-${ServiceName}-HighCPU'
      MetricName: CPUUtilization
      Namespace: AWS/ECS
      Dimensions:
        - Name: ClusterName
          Value: !Ref ClusterName
        - Name: ServiceName
          Value: !Ref ServiceName
      Statistic: Average
      Period: 300
      EvaluationPeriods: 4
      Threshold: 80
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

  # Step 3: Container Insights anomaly detection
  CPUAnomalyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub '${ClusterName}-CPUAnomaly'
      ComparisonOperator: LessThanLowerOrGreaterThanUpperThreshold
      EvaluationPeriods: 2
      Metrics:
        - Id: m1
          ReturnData: true
          MetricStat:
            Metric:
              Namespace: AWS/ECS
              MetricName: CPUUtilization
              Dimensions:
                - Name: ClusterName
                  Value: !Ref ClusterName
            Period: 300
            Stat: Average
        - Id: ad1
          Expression: ANOMALY_DETECTION_BAND(m1, 2)
      ThresholdMetricId: ad1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect cryptomining in ECS containers

variable "cluster_name" {
  type = string
}

variable "service_name" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "ecs-container-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch alarm for container CPU
resource "aws_cloudwatch_metric_alarm" "container_high_cpu" {
  alarm_name          = "${var.cluster_name}-${var.service_name}-HighCPU"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  dimensions = {
    ClusterName = var.cluster_name
    ServiceName = var.service_name
  }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 4
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Step 3: Anomaly detection for CPU patterns
resource "aws_cloudwatch_metric_alarm" "cpu_anomaly" {
  alarm_name          = "${var.cluster_name}-CPUAnomaly"
  comparison_operator = "LessThanLowerOrGreaterThanUpperThreshold"
  evaluation_periods  = 2
  threshold_metric_id = "ad1"
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]

  metric_query {
    id          = "m1"
    return_data = true
    metric {
      metric_name = "CPUUtilization"
      namespace   = "AWS/ECS"
      period      = 300
      stat        = "Average"
      dimensions = {
        ClusterName = var.cluster_name
      }
    }
  }

  metric_query {
    id          = "ad1"
    expression  = "ANOMALY_DETECTION_BAND(m1, 2)"
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="Container High CPU Usage Detected",
                alert_description_template="ECS service {ServiceName} showing sustained high CPU usage.",
                investigation_steps=[
                    "Review container images for unauthorised changes",
                    "Check task definitions for suspicious modifications",
                    "Analyse container logs for mining activity",
                    "Review ECR image scan results",
                    "Check network connections from containers",
                    "Review IAM roles attached to tasks",
                ],
                containment_actions=[
                    "Stop affected tasks",
                    "Update task definition to previous version",
                    "Scan container images for malware",
                    "Review and lock down ECR permissions",
                    "Rotate IAM credentials",
                    "Enable GuardDuty runtime monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Use anomaly detection to learn normal patterns; exclude legitimate batch processing containers",
            detection_coverage="75% - catches container-based mining",
            evasion_considerations="Attackers may use CPU throttling or run during low-activity periods",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["ECS Container Insights enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1496-gcp-compute-cpu",
            name="GCP Compute Engine High CPU Detection",
            description="Detect sustained high CPU utilisation on GCP VM instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_monitoring",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
metric.type="compute.googleapis.com/instance/cpu/utilization"
metric.value > 0.8""",
                gcp_terraform_template="""# GCP: Detect high CPU usage indicating cryptomining

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  display_name = "Security Alerts Email"
  type         = "email"
  project      = var.project_id
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create alert policy for high CPU
resource "google_monitoring_alert_policy" "high_cpu" {
  project      = var.project_id
  display_name = "GCE-SustainedHighCPU"
  combiner     = "OR"

  conditions {
    display_name = "CPU utilization above 80% for 30 minutes"

    condition_threshold {
      filter          = "resource.type = \"gce_instance\" AND metric.type = \"compute.googleapis.com/instance/cpu/utilization\""
      duration        = "1800s"  # 30 minutes
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8

      aggregations {
        alignment_period   = "300s"  # 5 minutes
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }

  documentation {
    content = "Sustained high CPU usage detected on GCE instance. Investigate for potential cryptomining activity."
  }
}

# Step 3: Create log-based metric for process monitoring
resource "google_logging_metric" "suspicious_processes" {
  name   = "suspicious-high-cpu-processes"
  project = var.project_id
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.message=~"(xmrig|minerd|ccminer|ethminer|cpuminer)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance running suspicious process"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Sustained High CPU Usage Detected",
                alert_description_template="GCE instance showing sustained CPU above 80% for 30+ minutes.",
                investigation_steps=[
                    "Review running processes via Cloud Logging",
                    "Check VPC Flow Logs for mining pool connections",
                    "Review Cloud Audit Logs for unauthorised changes",
                    "Analyse instance metadata and startup scripts",
                    "Check for suspicious service accounts",
                    "Review firewall rules for unusual access",
                ],
                containment_actions=[
                    "Isolate instance with firewall rules",
                    "Create snapshot for forensics",
                    "Stop suspicious processes",
                    "Rotate service account keys",
                    "Review and revoke IAM permissions",
                    "Consider stopping and replacing instance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Adjust threshold based on workload; use instance labels to exclude batch processing VMs",
            detection_coverage="70% - catches sustained mining activity",
            evasion_considerations="Attackers may throttle CPU or operate intermittently",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Monitoring enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1496-gcp-vpc-mining",
            name="GCP VPC Flow Logs Mining Pool Detection",
            description="Detect network connections to cryptocurrency mining pools.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
(jsonPayload.connection.dest_port="3333" OR
 jsonPayload.connection.dest_port="4444" OR
 jsonPayload.connection.dest_port="5555" OR
 jsonPayload.connection.dest_port="8333" OR
 jsonPayload.connection.dest_port="9999" OR
 jsonPayload.connection.dest_port="14433" OR
 jsonPayload.connection.dest_port="14444" OR
 jsonPayload.connection.dest_port="45560")""",
                gcp_terraform_template="""# GCP: Detect network connections to mining pools

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  display_name = "Mining Pool Alerts"
  type         = "email"
  project      = var.project_id
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for mining pool connections
resource "google_logging_metric" "mining_pools" {
  name    = "mining-pool-connections"
  project = var.project_id
  # Common mining ports: Stratum (3333, 4444, 5555), Bitcoin (8333), Dash (9999), Monero (14433, 14444, 45560)
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName="projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
    (jsonPayload.connection.dest_port="3333" OR
     jsonPayload.connection.dest_port="4444" OR
     jsonPayload.connection.dest_port="5555" OR
     jsonPayload.connection.dest_port="8333" OR
     jsonPayload.connection.dest_port="9999" OR
     jsonPayload.connection.dest_port="14433" OR
     jsonPayload.connection.dest_port="14444" OR
     jsonPayload.connection.dest_port="45560")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "src_instance"
      value_type  = "STRING"
      description = "Source instance connecting to mining pool"
    }
  }

  label_extractors = {
    "src_instance" = "EXTRACT(jsonPayload.src_instance.vm_name)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "mining_detected" {
  project      = var.project_id
  display_name = "Cryptocurrency Mining Pool Detected"
  combiner     = "OR"

  conditions {
    display_name = "Mining pool connections detected"

    condition_threshold {
      filter          = "resource.type = \"global\" AND metric.type = \"logging.googleapis.com/user/${google_logging_metric.mining_pools.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "Network connections to known cryptocurrency mining pools detected. Investigate immediately for potential resource hijacking."
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Mining Pool Connection Detected",
                alert_description_template="Instance connecting to cryptocurrency mining pool on suspicious port.",
                investigation_steps=[
                    "Identify source instance from VPC Flow Logs",
                    "Review running processes and network connections",
                    "Check Cloud Audit Logs for recent changes",
                    "Review instance creation and modification history",
                    "Check for lateral movement indicators",
                    "Analyse startup scripts and metadata",
                ],
                containment_actions=[
                    "Create firewall rules to block mining pool IPs/ports",
                    "Isolate affected instance",
                    "Stop mining processes",
                    "Rotate all service account keys",
                    "Review IAM permissions and revoke unauthorised access",
                    "Stop and rebuild instance from clean image",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Mining pool ports are highly specific; legitimate use is rare",
            detection_coverage="80% - catches most cryptomining traffic",
            evasion_considerations="Custom pools on non-standard ports evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1496-gcp-gke-cpu",
            name="GCP GKE Container High CPU Detection",
            description="Detect high CPU usage in GKE containers indicating cryptomining.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_monitoring",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="k8s_container"
metric.type="kubernetes.io/container/cpu/core_usage_time"
metric.value > 0.8""",
                gcp_terraform_template="""# GCP: Detect cryptomining in GKE containers

variable "project_id" {
  type = string
}

variable "cluster_name" {
  description = "GKE cluster name to monitor"
  type        = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s3" {
  display_name = "GKE Security Alerts"
  type         = "email"
  project      = var.project_id
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Alert for sustained high container CPU
resource "google_monitoring_alert_policy" "container_high_cpu" {
  project      = var.project_id
  display_name = "GKE-Container-HighCPU"
  combiner     = "OR"

  conditions {
    display_name = "Container CPU above 80% for 20 minutes"

    condition_threshold {
      filter = <<-EOT
        resource.type = "k8s_container"
        resource.labels.cluster_name = "${var.cluster_name}"
        metric.type = "kubernetes.io/container/cpu/core_usage_time"
      EOT

      duration        = "1200s"  # 20 minutes
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields = [
          "resource.label.namespace_name",
          "resource.label.pod_name",
          "resource.label.container_name"
        ]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s3.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "Sustained high CPU usage in GKE container. Check for cryptomining activity."
  }
}

# Step 3: Log-based metric for suspicious processes
resource "google_logging_metric" "suspicious_container_processes" {
  name    = "suspicious-container-processes"
  project = var.project_id
  filter = <<-EOT
    resource.type="k8s_container"
    resource.labels.cluster_name="${var.cluster_name}"
    (textPayload=~"xmrig" OR
     textPayload=~"minerd" OR
     textPayload=~"ccminer" OR
     textPayload=~"ethminer" OR
     textPayload=~"cpuminer")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "pod_name"
      value_type  = "STRING"
      description = "Pod running suspicious process"
    }
  }

  label_extractors = {
    "pod_name" = "EXTRACT(resource.labels.pod_name)"
  }
}""",
                alert_severity="high",
                alert_title="GCP: GKE Container High CPU Detected",
                alert_description_template="GKE container showing sustained high CPU usage.",
                investigation_steps=[
                    "Review container logs for mining activity",
                    "Check pod specifications and image source",
                    "Analyse network connections from pod",
                    "Review container registry for unauthorised images",
                    "Check RBAC permissions for pod service account",
                    "Review admission controller policies",
                ],
                containment_actions=[
                    "Delete affected pods",
                    "Update deployment to previous version",
                    "Scan container images with Container Analysis",
                    "Block unauthorised registries",
                    "Review and restrict RBAC permissions",
                    "Enable Binary Authorisation to prevent unauthorised images",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude namespaces running legitimate CPU-intensive workloads",
            detection_coverage="75% - catches container-based mining",
            evasion_considerations="CPU throttling or intermittent operation evades detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["GKE cluster with Cloud Monitoring enabled"],
        ),
        # Azure Strategy: Resource Hijacking
        DetectionStrategy(
            strategy_id="t1496-azure",
            name="Azure Resource Hijacking Detection",
            description=(
                "Defender detects resource hijacking for mining. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Azure Log Analytics KQL Query: Resource Hijacking
// MITRE ATT&CK: T1496
// Detects cryptocurrency mining and resource hijacking in Azure
let lookback = 24h;
// Defender for Cloud mining alerts
let miningAlerts = SecurityAlert
| where TimeGenerated > ago(lookback)
| where ProductName in ("Azure Security Center", "Microsoft Defender for Cloud")
| where AlertName has_any (
    "Cryptocurrency", "mining", "cryptominer",
    "Digital currency", "Bitcoin", "Monero",
    "coin miner", "crypto miner"
)
| project TimeGenerated, AlertName, AlertSeverity, Description,
    CompromisedEntity, RemediationSteps, ExtendedProperties
| extend TechniqueDetail = "Cryptomining alert";
// High CPU/compute usage anomalies (potential mining)
let computeAnomalies = AzureMetrics
| where TimeGenerated > ago(lookback)
| where ResourceProvider == "MICROSOFT.COMPUTE"
| where MetricName == "Percentage CPU"
| where Average > 90
| summarize
    AvgCPU = avg(Average),
    MaxCPU = max(Maximum),
    SampleCount = count()
    by bin(TimeGenerated, 1h), Resource, ResourceGroup
| where SampleCount > 6 and AvgCPU > 85
| extend TechniqueDetail = "Sustained high CPU usage";
// Suspicious VM creation (potential mining rigs)
let suspiciousVMs = AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue has_any (
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
    "Microsoft.Compute/virtualMachines/write"
)
| where ActivityStatusValue in ("Success", "Succeeded")
| where Properties has_any ("GPU", "NC", "ND", "NV", "Standard_NC", "Standard_ND")
| project TimeGenerated, Caller, CallerIpAddress, Resource,
    ResourceGroup, SubscriptionId, Properties
| extend TechniqueDetail = "GPU VM creation";
// Azure Container Instances - potential mining containers
let containerMining = AzureActivity
| where TimeGenerated > ago(lookback)
| where OperationNameValue has "MICROSOFT.CONTAINERINSTANCE"
| where ActivityStatusValue in ("Success", "Succeeded")
| project TimeGenerated, Caller, CallerIpAddress, Resource,
    ResourceGroup, SubscriptionId, OperationNameValue
| extend TechniqueDetail = "Container instance creation";
// Network traffic to mining pools
let miningNetwork = AzureDiagnostics
| where TimeGenerated > ago(lookback)
| where Category == "NetworkSecurityGroupFlowEvent" or Category == "AzureFirewallNetworkRule"
| where DestinationPort_d in (3333, 4444, 5555, 7777, 8888, 9999, 14444)
| project TimeGenerated, SourceIP_s, DestinationIP_s, DestinationPort_d,
    Action_s, Resource
| extend TechniqueDetail = "Mining pool port connection";
// Union results
union miningAlerts, suspiciousVMs, containerMining
| summarize
    EventCount = count(),
    TechniquesUsed = make_set(TechniqueDetail),
    Resources = make_set(Resource, 10)
    by bin(TimeGenerated, 1h)""",
                defender_alert_types=[
                    "Cryptocurrency mining activity",
                    "Digital currency mining activity",
                    "Suspicious process execution",
                    "Unusual Azure resource deployment",
                ],
                azure_terraform_template="""# Azure Detection for Resource Hijacking (T1496)
# Multi-signal cryptomining and resource abuse detection

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
  }
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Action Group for all T1496 alerts
resource "azurerm_monitor_action_group" "resource_hijacking" {
  name                = "t1496-resource-hijacking-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "T1496Alert"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# =============================================================================
# Alert 1: Defender Cryptomining Alerts (highest fidelity)
# =============================================================================
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_cryptomining" {
  name                = "t1496-defender-cryptomining"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName in ("Azure Security Center", "Microsoft Defender for Cloud", "Microsoft Defender for Containers", "Microsoft Defender for Servers")
| where AlertName has_any (
    "Cryptocurrency",
    "mining",
    "cryptominer",
    "Digital currency",
    "Bitcoin",
    "Monero",
    "coin miner",
    "crypto miner"
)
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    CompromisedEntity,
    RemediationSteps
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.resource_hijacking.id]
  }

  description  = "Defender for Cloud detected cryptocurrency mining activity"
  display_name = "T1496: Defender Cryptomining Alert"
  enabled      = true

  tags = {
    "mitre-technique" = "T1496"
    "detection-type"  = "defender-alert"
  }
}

# =============================================================================
# Alert 2: Sustained High CPU Usage (VM-level)
# =============================================================================
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "sustained_high_cpu" {
  name                = "t1496-sustained-high-cpu"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT15M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AzureMetrics
| where TimeGenerated > ago(1h)
| where ResourceProvider == "MICROSOFT.COMPUTE"
| where MetricName == "Percentage CPU"
| where Average > 85
| summarize
    AvgCPU = avg(Average),
    MaxCPU = max(Maximum),
    HighCpuSamples = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Resource, ResourceGroup, bin(TimeGenerated, 1h)
| where HighCpuSamples >= 6 and AvgCPU > 85
| extend
    SustainedHighCpu = true,
    Duration = LastSeen - FirstSeen
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.resource_hijacking.id]
  }

  description  = "Sustained high CPU usage detected - potential cryptomining"
  display_name = "T1496: Sustained High CPU"
  enabled      = true

  tags = {
    "mitre-technique" = "T1496"
    "detection-type"  = "metrics-anomaly"
  }
}

# =============================================================================
# Alert 3: Mining Pool Port Connections (NSG Flow Logs)
# =============================================================================
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "mining_pool_connections" {
  name                = "t1496-mining-pool-connections"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT30M"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
let MiningPorts = dynamic([3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45560]);
AzureDiagnostics
| where TimeGenerated > ago(30m)
| where Category == "NetworkSecurityGroupFlowEvent"
| extend FlowLog = parse_json(flowLog_s)
| mv-expand FlowLog
| extend
    DestPort = toint(split(FlowLog.flows[0].flowTuples[0], ",")[4]),
    FlowDirection = tostring(split(FlowLog.flows[0].flowTuples[0], ",")[6]),
    FlowStatus = tostring(split(FlowLog.flows[0].flowTuples[0], ",")[7]),
    SrcIP = tostring(split(FlowLog.flows[0].flowTuples[0], ",")[1]),
    DstIP = tostring(split(FlowLog.flows[0].flowTuples[0], ",")[2])
| where DestPort in (MiningPorts)
| where FlowDirection == "O" and FlowStatus == "A"
| summarize
    ConnectionCount = count(),
    UniqueDestinations = dcount(DstIP),
    Ports = make_set(DestPort),
    DestIPs = make_set(DstIP, 10)
    by SrcIP, Resource, bin(TimeGenerated, 5m)
| where ConnectionCount > 3
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.resource_hijacking.id]
  }

  description  = "Network connections to known cryptocurrency mining pool ports detected"
  display_name = "T1496: Mining Pool Connection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1496"
    "detection-type"  = "network-ioc"
  }
}

# =============================================================================
# Alert 4: GPU VM Creation (potential mining rigs)
# =============================================================================
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "gpu_vm_creation" {
  name                = "t1496-gpu-vm-creation"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has "Microsoft.Compute/virtualMachines/write"
| where ActivityStatusValue in ("Success", "Succeeded")
| extend Properties = parse_json(Properties)
| where Properties has_any ("NC", "ND", "NV", "Standard_NC", "Standard_ND", "Standard_NV", "GPU")
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
    VMName = Resource,
    ResourceGroup,
    SubscriptionId,
    VMSize = tostring(Properties.responseBody.properties.hardwareProfile.vmSize)
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.resource_hijacking.id]
  }

  description  = "GPU-enabled VM created - potential cryptomining infrastructure"
  display_name = "T1496: GPU VM Creation"
  enabled      = true

  tags = {
    "mitre-technique" = "T1496"
    "detection-type"  = "resource-creation"
  }
}

# =============================================================================
# Alert 5: AKS Container High CPU (Container Insights)
# =============================================================================
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "aks_container_high_cpu" {
  name                = "t1496-aks-container-cpu"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT10M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
Perf
| where TimeGenerated > ago(1h)
| where ObjectName == "K8SContainer" and CounterName == "cpuUsageNanoCores"
| extend ContainerName = tostring(split(InstanceName, "/")[-1])
| summarize
    AvgCpuNanos = avg(CounterValue),
    MaxCpuNanos = max(CounterValue),
    SampleCount = count()
    by ContainerName, Computer, bin(TimeGenerated, 10m)
| where AvgCpuNanos > 500000000
| where SampleCount >= 3
| extend AvgCpuCores = AvgCpuNanos / 1000000000
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.resource_hijacking.id]
  }

  description  = "AKS container showing sustained high CPU usage - potential cryptomining"
  display_name = "T1496: AKS Container High CPU"
  enabled      = true

  tags = {
    "mitre-technique" = "T1496"
    "detection-type"  = "container-metrics"
  }
}

output "alert_rule_ids" {
  value = {
    defender_cryptomining   = azurerm_monitor_scheduled_query_rules_alert_v2.defender_cryptomining.id
    sustained_high_cpu      = azurerm_monitor_scheduled_query_rules_alert_v2.sustained_high_cpu.id
    mining_pool_connections = azurerm_monitor_scheduled_query_rules_alert_v2.mining_pool_connections.id
    gpu_vm_creation         = azurerm_monitor_scheduled_query_rules_alert_v2.gpu_vm_creation.id
    aks_container_cpu       = azurerm_monitor_scheduled_query_rules_alert_v2.aks_container_high_cpu.id
  }
}""",
                alert_severity="high",
                alert_title="Azure: Resource Hijacking Detected",
                alert_description_template=(
                    "Resource Hijacking activity detected. "
                    "Caller: {Caller}. Resource: {Resource}."
                ),
                investigation_steps=[
                    "Review Azure Activity Log for full operation details",
                    "Check caller identity and verify if authorised",
                    "Review affected resources and assess impact",
                    "Check for related activities in the same time window",
                    "Verify against change management records",
                ],
                containment_actions=[
                    "Disable compromised user/service principal if unauthorised",
                    "Revoke active sessions using Entra ID",
                    "Review and restrict Azure RBAC permissions",
                    "Enable additional Defender for Cloud protections",
                    "Implement Azure Policy to prevent recurrence",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Allowlist known automation accounts and CI/CD service principals. "
                "Use Azure Policy to define expected behaviour baselines."
            ),
            detection_coverage="70% - Azure-native detection for cloud operations",
            evasion_considerations=(
                "Attackers may use legitimate credentials from expected locations. "
                "Combine with Defender for Cloud for ML-based anomaly detection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-50 (Log Analytics + Defender)",
            prerequisites=[
                "Azure subscription with Log Analytics workspace",
                "Defender for Cloud enabled (recommended)",
                "Appropriate Azure RBAC permissions for deployment",
            ],
        ),
    ],
    recommended_order=[
        "t1496-aws-network-mining",
        "t1496-gcp-vpc-mining",
        "t1496-aws-ec2-cpu",
        "t1496-gcp-compute-cpu",
        "t1496-aws-ecs-cpu",
        "t1496-gcp-gke-cpu",
    ],
    total_effort_hours=8.5,
    coverage_improvement="+25% improvement for Impact tactic detection",
)
