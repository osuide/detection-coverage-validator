"""AWS detection scanners."""

from app.scanners.aws.cloudwatch_scanner import CloudWatchLogsInsightsScanner
from app.scanners.aws.config_scanner import ConfigRulesScanner
from app.scanners.aws.eventbridge_scanner import EventBridgeScanner
from app.scanners.aws.guardduty_scanner import GuardDutyScanner
from app.scanners.aws.lambda_scanner import LambdaScanner
from app.scanners.aws.securityhub_scanner import SecurityHubScanner

# Organisation-level scanners
from app.scanners.aws.org_cloudtrail_scanner import OrgCloudTrailScanner
from app.scanners.aws.org_guardduty_scanner import OrgGuardDutyScanner
from app.scanners.aws.org_config_aggregator_scanner import OrgConfigAggregatorScanner

__all__ = [
    # Account-level scanners
    "CloudWatchLogsInsightsScanner",
    "ConfigRulesScanner",
    "EventBridgeScanner",
    "GuardDutyScanner",
    "LambdaScanner",
    "SecurityHubScanner",
    # Organisation-level scanners
    "OrgCloudTrailScanner",
    "OrgGuardDutyScanner",
    "OrgConfigAggregatorScanner",
]
