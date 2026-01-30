/**
 * Example Terraform configuration for the Quick Scan "Try Example" button.
 *
 * Covers multiple AWS detection resource types to produce a meaningful
 * coverage result on first click.
 */
export const EXAMPLE_TERRAFORM = `# AWS Detection Coverage — Example Configuration
# Paste your own Terraform HCL to analyse your detection coverage.

resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu-utilisation"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alert when CPU exceeds 80%"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name = "encrypted-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
}

resource "aws_cloudwatch_event_rule" "console_sign_in" {
  name        = "capture-console-sign-in"
  description = "Capture each AWS Console Sign In"

  event_pattern = jsonencode({
    "detail-type" = ["AWS Console Sign In via CloudTrail"]
  })
}

resource "aws_securityhub_account" "main" {}

resource "aws_sns_topic" "alerts" {
  name              = "security-alerts"
  kms_master_key_id = "alias/aws/sns"
}
`
