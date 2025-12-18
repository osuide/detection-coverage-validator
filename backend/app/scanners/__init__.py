"""Cloud detection scanners."""

from app.scanners.base import BaseScanner, RawDetection
from app.scanners.aws.cloudwatch_scanner import CloudWatchLogsInsightsScanner
from app.scanners.aws.eventbridge_scanner import EventBridgeScanner

__all__ = [
    "BaseScanner",
    "RawDetection",
    "CloudWatchLogsInsightsScanner",
    "EventBridgeScanner",
]
