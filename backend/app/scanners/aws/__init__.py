"""AWS detection scanners."""

from app.scanners.aws.cloudwatch_scanner import CloudWatchLogsInsightsScanner
from app.scanners.aws.eventbridge_scanner import EventBridgeScanner
from app.scanners.aws.lambda_scanner import LambdaScanner

__all__ = [
    "CloudWatchLogsInsightsScanner",
    "EventBridgeScanner",
    "LambdaScanner",
]
