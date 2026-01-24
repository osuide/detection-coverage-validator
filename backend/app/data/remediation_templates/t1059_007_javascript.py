"""
T1059.007 - Command and Scripting Interpreter: JavaScript

Adversaries use JavaScript for execution in cloud environments, particularly in
Azure Functions, App Services, and automation contexts. Server-side JavaScript
(Node.js) can spawn processes and execute system commands.
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
    technique_id="T1059.007",
    technique_name="Command and Scripting Interpreter: JavaScript",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1059/007/",
    threat_context=ThreatContext(
        description=(
            "Adversaries abuse JavaScript execution capabilities in cloud environments. "
            "Azure Functions, App Services, and Automation accounts can run JavaScript/Node.js, "
            "enabling command execution, process spawning, and system access through server-side scripts."
        ),
        attacker_goal="Execute commands via JavaScript runtime in cloud compute services",
        why_technique=[
            "JavaScript is commonly allowed in cloud environments",
            "Azure Functions provide serverless execution context",
            "Node.js enables file system and process access",
            "Can bypass application-layer controls",
            "Scripts may evade traditional AV detection",
        ],
        known_threat_actors=[],
        recent_campaigns=[],
        prevalence="common",
        trend="increasing",
        severity_score=7,
        severity_reasoning=(
            "JavaScript execution in cloud services can lead to command execution, "
            "data exfiltration, and lateral movement within cloud infrastructure."
        ),
        business_impact=[
            "Unauthorised command execution",
            "Data exfiltration via serverless functions",
            "Resource abuse for cryptomining",
            "Lateral movement in cloud environment",
        ],
        typical_attack_phase="execution",
        often_precedes=["T1005", "T1567", "T1496"],
        often_follows=["T1078.004", "T1190"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: Azure Function Suspicious Activity Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1059007-azure-functions",
            name="Azure Functions Suspicious Execution Detection",
            description=(
                "Monitor Azure Functions for suspicious JavaScript execution patterns, "
                "including unexpected function invocations, unusual execution times, "
                "and suspicious outbound connections."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Azure Functions Suspicious Execution Detection
// MITRE ATT&CK: T1059.007 - JavaScript Execution
// Detects suspicious Azure Function behavior indicating malicious script execution

let lookback = 1h;
let threshold = 10;

// Monitor Function invocations with anomalous patterns
FunctionAppLogs
| where TimeGenerated > ago(lookback)
| where Category == "FunctionExecutionLogs"
| where Level in ("Error", "Warning")
| extend
    FunctionName = tostring(split(FunctionInvocationId, "-")[0]),
    ExecutionTimeMs = todouble(DurationMs)
| summarize
    ErrorCount = countif(Level == "Error"),
    TotalInvocations = count(),
    AvgDuration = avg(ExecutionTimeMs),
    MaxDuration = max(ExecutionTimeMs),
    UniqueMessages = dcount(Message),
    SampleMessages = make_set(Message, 5)
    by FunctionName, HostInstanceId, bin(TimeGenerated, 10m)
| where ErrorCount > threshold or MaxDuration > 300000
| project
    TimeGenerated,
    FunctionName,
    HostInstanceId,
    ErrorCount,
    TotalInvocations,
    AvgDuration,
    MaxDuration,
    UniqueMessages,
    SampleMessages
| order by ErrorCount desc""",
                sentinel_rule_query="""// Sentinel Analytics Rule: Suspicious Azure Function Execution
// MITRE ATT&CK: T1059.007
let lookback = 24h;

// Detect Functions with suspicious execution patterns
FunctionAppLogs
| where TimeGenerated > ago(lookback)
| where Level in ("Error", "Warning", "Information")
| extend
    FunctionName = extract("Function '([^']+)'", 1, Message),
    HasSuspiciousError = Message contains "spawn"
        or Message contains "execute"
        or Message contains "shell"
        or Message contains "process.exit"
        or Message contains "require("
| where HasSuspiciousError == true
| summarize
    AlertCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleMessages = make_set(Message, 10)
    by FunctionName, HostInstanceId, _ResourceId
| where AlertCount > 5
| project
    TimeGenerated = LastSeen,
    FunctionName,
    HostInstanceId,
    ResourceId = _ResourceId,
    AlertCount,
    FirstSeen,
    SampleMessages""",
                azure_terraform_template="""# Azure Functions Suspicious Execution Detection
# MITRE ATT&CK: T1059.007 - JavaScript Execution

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
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "js_execution_alerts" {
  name                = "javascript-execution-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "JSExecAlert"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for Function App suspicious execution
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "function_detection" {
  name                = "azure-function-suspicious-execution"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT10M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
FunctionAppLogs
| where TimeGenerated > ago(1h)
| where Level in ("Error", "Warning")
| extend
    FunctionName = extract("Function '([^']+)'", 1, Message),
    HasSuspiciousPattern = Message contains "spawn"
        or Message contains "execute"
        or Message contains "shell"
        or Message contains "timeout"
| where HasSuspiciousPattern == true
| summarize
    AlertCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by FunctionName, HostInstanceId, _ResourceId
| where AlertCount > 5
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  auto_mitigation_enabled = false

  action {
    action_groups = [azurerm_monitor_action_group.js_execution_alerts.id]
  }

  description  = "Detects suspicious JavaScript execution patterns in Azure Functions"
  display_name = "Azure Function Suspicious JavaScript Execution"
  enabled      = true

  tags = {
    "mitre-technique" = "T1059.007"
    "detection-type"  = "execution"
  }
}

output "alert_rule_id" {
  value       = azurerm_monitor_scheduled_query_rules_alert_v2.function_detection.id
  description = "Alert rule resource ID"
}""",
                alert_severity="high",
                alert_title="Azure: Suspicious JavaScript Execution in Function App",
                alert_description_template=(
                    "Suspicious JavaScript execution detected in Azure Function {FunctionName}. "
                    "Host: {HostInstanceId}. Alert count: {AlertCount}."
                ),
                investigation_steps=[
                    "Review FunctionAppLogs for the affected function",
                    "Check Application Insights for execution traces",
                    "Review function code for malicious modifications",
                    "Check deployment history for recent changes",
                    "Examine outbound network connections from the function",
                ],
                containment_actions=[
                    "Disable the suspicious function immediately",
                    "Revoke deployment credentials",
                    "Review and rotate any secrets accessed by the function",
                    "Enable App Service diagnostic logging",
                    "Implement network restrictions on the Function App",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Tune error thresholds based on normal function behaviour. "
                "Allowlist known functions with legitimate long-running operations."
            ),
            detection_coverage="75% - Detects suspicious function execution patterns",
            evasion_considerations=(
                "Attackers may use obfuscated code that doesn't produce errors. "
                "Consider combining with Application Insights for deeper visibility."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30 (Log Analytics ingestion)",
            prerequisites=[
                "Azure Function App with diagnostic logging enabled",
                "Log Analytics workspace",
                "FunctionAppLogs collected in workspace",
            ],
        ),
        # =====================================================================
        # STRATEGY 2: App Service Suspicious Script Activity
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1059007-azure-appservice",
            name="Azure App Service Suspicious Script Detection",
            description=(
                "Monitor Azure App Services for suspicious JavaScript/Node.js execution, "
                "including unusual process spawning, file system access, and network activity."
            ),
            detection_type=DetectionType.SENTINEL_RULE,
            aws_service="n/a",
            azure_service="sentinel",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Azure App Service Suspicious Script Activity Detection
// MITRE ATT&CK: T1059.007 - JavaScript Execution
// Monitors App Services for suspicious script behavior

let lookback = 1h;

// Detect suspicious HTTP requests that may indicate web shell or script injection
AppServiceHTTPLogs
| where TimeGenerated > ago(lookback)
| where ScStatus >= 500
| extend
    SuspiciousPath = CsUriStem contains "/api/" and CsUriStem contains "exec"
        or CsUriStem contains "shell"
        or CsUriStem contains "cmd"
        or CsUriQuery contains "script="
        or CsUriQuery contains "command="
| where SuspiciousPath == true
| summarize
    RequestCount = count(),
    UniqueIPs = dcount(CIp),
    SourceIPs = make_set(CIp, 10),
    Paths = make_set(CsUriStem, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by _ResourceId, CsHost
| where RequestCount > 3
| project
    TimeGenerated = LastSeen,
    ResourceId = _ResourceId,
    Host = CsHost,
    RequestCount,
    UniqueIPs,
    SourceIPs,
    Paths,
    FirstSeen""",
                sentinel_rule_query="""// Sentinel: App Service Suspicious Script Execution
// MITRE ATT&CK: T1059.007
let lookback = 24h;

// Combine HTTP logs with app logs for comprehensive detection
let SuspiciousRequests = AppServiceHTTPLogs
| where TimeGenerated > ago(lookback)
| where ScStatus >= 400
| extend
    HasSuspiciousPattern = CsUriStem contains "exec"
        or CsUriStem contains "run"
        or CsUriQuery contains "code="
        or UserAgent contains "curl"
        or UserAgent contains "wget"
| where HasSuspiciousPattern == true;

let AppErrors = AppServiceConsoleLogs
| where TimeGenerated > ago(lookback)
| where ResultDescription contains "Error"
    or ResultDescription contains "exception"
    or ResultDescription contains "spawn"
| extend HasScriptError = true;

SuspiciousRequests
| join kind=inner (AppErrors) on _ResourceId
| summarize
    TotalRequests = count(),
    ErrorCount = countif(HasScriptError),
    SourceIPs = make_set(CIp, 10),
    Paths = make_set(CsUriStem, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by _ResourceId, CsHost
| project
    TimeGenerated = LastSeen,
    ResourceId = _ResourceId,
    Host = CsHost,
    TotalRequests,
    ErrorCount,
    SourceIPs,
    Paths""",
                azure_terraform_template="""# Azure App Service Suspicious Script Detection
# MITRE ATT&CK: T1059.007

variable "resource_group_name" {
  type        = string
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "azurerm_monitor_action_group" "appservice_alerts" {
  name                = "appservice-script-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "AppScript"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "appservice_detection" {
  name                = "appservice-suspicious-script"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT10M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AppServiceHTTPLogs
| where TimeGenerated > ago(1h)
| where ScStatus >= 400
| extend
    SuspiciousPattern = CsUriStem contains "exec"
        or CsUriStem contains "run"
        or CsUriQuery contains "script="
| where SuspiciousPattern == true
| summarize RequestCount = count() by _ResourceId, CsHost, CIp
| where RequestCount > 5
    QUERY

    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThanOrEqual"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.appservice_alerts.id]
  }

  description  = "Detects suspicious script execution attempts on App Services"
  display_name = "App Service Suspicious Script Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1059.007"
  }
}""",
                alert_severity="high",
                alert_title="Azure: Suspicious Script Activity in App Service",
                alert_description_template=(
                    "Suspicious script execution detected on App Service {Host}. "
                    "Source IPs: {SourceIPs}. Request count: {RequestCount}."
                ),
                investigation_steps=[
                    "Review AppServiceHTTPLogs for the suspicious requests",
                    "Check AppServiceConsoleLogs for execution errors",
                    "Review the application code for injection vulnerabilities",
                    "Check deployment history for unauthorised changes",
                    "Analyse source IPs for known malicious indicators",
                ],
                containment_actions=[
                    "Block suspicious source IPs using Azure WAF or NSG",
                    "Disable the App Service if actively compromised",
                    "Rotate application secrets and connection strings",
                    "Review and patch application vulnerabilities",
                    "Enable Azure Defender for App Service",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Adjust path patterns to exclude legitimate API endpoints. "
                "Tune error thresholds based on application behaviour."
            ),
            detection_coverage="70% - HTTP-level detection of script injection attempts",
            evasion_considerations=(
                "Encoded or obfuscated payloads may evade string matching. "
                "Consider using Azure WAF for additional protection."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-40 (Log Analytics + WAF optional)",
            prerequisites=[
                "Azure App Service with HTTP logging enabled",
                "Log Analytics workspace",
                "AppServiceHTTPLogs and AppServiceConsoleLogs collected",
            ],
        ),
        # =====================================================================
        # STRATEGY 3: AWS Lambda Node.js Suspicious Execution
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1059007-aws-lambda",
            name="AWS Lambda Node.js Suspicious Execution Detection",
            description=(
                "Monitor AWS Lambda Node.js functions for suspicious execution patterns, "
                "including unusual error rates, long execution times, and outbound connections."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="lambda",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message, @logStream
| filter @message like /Error|Exception|spawn|exec|shell|child_process/
| stats count(*) as ErrorCount,
        count_distinct(@logStream) as UniqueStreams
        by bin(1h)
| filter ErrorCount > 10""",
                terraform_template="""# AWS Lambda Node.js Suspicious Execution Detection
# MITRE ATT&CK: T1059.007

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "lambda_log_groups" {
  type        = list(string)
  description = "Lambda function log group names to monitor"
}

# SNS topic for alerts
resource "aws_sns_topic" "lambda_alerts" {
  name              = "lambda-javascript-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.lambda_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Metric filter for suspicious patterns
resource "aws_cloudwatch_log_metric_filter" "suspicious_js" {
  count          = length(var.lambda_log_groups)
  name           = "suspicious-js-execution-${count.index}"
  log_group_name = var.lambda_log_groups[count.index]
  pattern        = "?Error ?Exception ?spawn ?exec ?shell"

  metric_transformation {
    name      = "SuspiciousJSExecution"
    namespace = "Security/Lambda"
    value     = "1"
  }
}

# CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "suspicious_js" {
  alarm_name          = "lambda-suspicious-js-execution"
  alarm_description   = "Suspicious JavaScript execution in Lambda"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SuspiciousJSExecution"
  namespace           = "Security/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.lambda_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.lambda_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatch"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.lambda_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="AWS: Suspicious JavaScript Execution in Lambda",
                alert_description_template=(
                    "Suspicious JavaScript execution detected in Lambda function. "
                    "Error count: {ErrorCount}."
                ),
                investigation_steps=[
                    "Review Lambda CloudWatch logs for error details",
                    "Check Lambda execution role for excessive permissions",
                    "Review function code for malicious modifications",
                    "Check Lambda deployments and versions",
                    "Monitor VPC flow logs if Lambda is VPC-attached",
                ],
                containment_actions=[
                    "Disable the Lambda function trigger",
                    "Rotate Lambda execution role credentials",
                    "Remove any malicious code from the function",
                    "Apply restrictive IAM policies",
                    "Enable X-Ray tracing for investigation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Tune pattern matching to exclude expected errors. "
                "Create separate baselines per function."
            ),
            detection_coverage="70% - Log-based pattern detection",
            evasion_considerations=(
                "Attackers may suppress logging or use obfuscated code."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-20 (CloudWatch)",
            prerequisites=[
                "Lambda functions with CloudWatch Logs enabled",
                "CloudWatch Logs retention configured",
            ],
        ),
        # =====================================================================
        # STRATEGY 4: GCP Cloud Functions JavaScript Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1059007-gcp-functions",
            name="GCP Cloud Functions JavaScript Detection",
            description=(
                "Monitor GCP Cloud Functions for suspicious JavaScript/Node.js execution, "
                "using Cloud Logging to detect anomalous behavior."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_functions",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="cloud_function"
severity>=ERROR
textPayload=~"spawn|exec|shell|child_process|Error|Exception"
timestamp>="2024-01-01T00:00:00Z" """,
                gcp_terraform_template="""# GCP Cloud Functions JavaScript Detection
# MITRE ATT&CK: T1059.007

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

resource "google_monitoring_notification_channel" "email" {
  display_name = "Cloud Functions JS Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

resource "google_logging_metric" "suspicious_js" {
  name    = "suspicious-js-execution"
  project = var.project_id

  filter = <<-EOT
    resource.type="cloud_function"
    severity>=ERROR
    textPayload=~"spawn|exec|shell|Error"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "function_name"
      value_type  = "STRING"
    }
  }

  label_extractors = {
    "function_name" = "EXTRACT(resource.labels.function_name)"
  }
}

resource "google_monitoring_alert_policy" "suspicious_js" {
  project      = var.project_id
  display_name = "Suspicious JavaScript in Cloud Functions"
  combiner     = "OR"

  conditions {
    display_name = "High error rate with suspicious patterns"

    condition_threshold {
      filter = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_js.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Suspicious JavaScript execution detected in Cloud Functions."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Suspicious JavaScript Execution in Cloud Functions",
                alert_description_template=(
                    "Suspicious JavaScript execution in Cloud Function {function_name}."
                ),
                investigation_steps=[
                    "Review Cloud Function logs for error details",
                    "Check function deployment history",
                    "Review function source code for malicious content",
                    "Check IAM bindings for the function service account",
                    "Monitor VPC connector traffic if configured",
                ],
                containment_actions=[
                    "Disable the Cloud Function trigger",
                    "Revoke service account keys",
                    "Remove malicious code and redeploy",
                    "Apply VPC Service Controls",
                    "Enable additional audit logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Exclude known error patterns from legitimate functions."
            ),
            detection_coverage="70% - Log-based detection",
            evasion_considerations="May miss obfuscated code patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-30 (Cloud Logging + Monitoring)",
            prerequisites=[
                "Cloud Functions with logging enabled",
                "Cloud Logging API enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1059007-azure-functions",
        "t1059007-azure-appservice",
        "t1059007-aws-lambda",
        "t1059007-gcp-functions",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+15% improvement for Execution tactic with serverless function monitoring",
)
