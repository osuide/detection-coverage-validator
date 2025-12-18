"""AWS detection scanners."""

from app.scanners.aws.cloudwatch_scanner import CloudWatchLogsInsightsScanner
from app.scanners.aws.eventbridge_scanner import EventBridgeScanner

__all__ = ["CloudWatchLogsInsightsScanner", "EventBridgeScanner"]
