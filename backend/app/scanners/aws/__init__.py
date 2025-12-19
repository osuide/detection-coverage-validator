"""AWS detection scanners."""

from app.scanners.aws.cloudwatch_scanner import CloudWatchLogsInsightsScanner
from app.scanners.aws.config_scanner import ConfigRulesScanner
from app.scanners.aws.eventbridge_scanner import EventBridgeScanner
from app.scanners.aws.guardduty_scanner import GuardDutyScanner
from app.scanners.aws.lambda_scanner import LambdaScanner
from app.scanners.aws.securityhub_scanner import SecurityHubScanner

__all__ = [
    "CloudWatchLogsInsightsScanner",
    "ConfigRulesScanner",
    "EventBridgeScanner",
    "GuardDutyScanner",
    "LambdaScanner",
    "SecurityHubScanner",
]
