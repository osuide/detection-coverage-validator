"""EventBridge rule scanner following 04-PARSER-AGENT.md design."""

import json
from typing import Any, Optional

from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection
from app.scanners.aws.service_mappings import extract_services_from_event_pattern


class EventBridgeScanner(BaseScanner):
    """Scanner for Amazon EventBridge rules.

    Discovers EventBridge rules that can be used as detections for
    security monitoring, especially those triggered by CloudTrail events.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.EVENTBRIDGE_RULE

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan all regions for EventBridge rules."""
        all_detections = []

        for region in regions:
            self.logger.info("scanning_region", region=region)
            try:
                detections = await self.scan_region(region, options)
                all_detections.extend(detections)
                self.logger.info(
                    "region_scan_complete",
                    region=region,
                    count=len(detections),
                )
            except ClientError as e:
                self.logger.error(
                    "region_scan_error",
                    region=region,
                    error=str(e),
                )

        return all_detections

    async def scan_region(
        self,
        region: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan a single region for EventBridge rules."""
        detections = []

        client = self.session.client("events", region_name=region)

        # List all event buses (including custom)
        event_buses = ["default"]
        try:
            buses_response = client.list_event_buses()
            for bus in buses_response.get("EventBuses", []):
                bus_name = bus.get("Name")
                if bus_name and bus_name != "default":
                    event_buses.append(bus_name)
        except ClientError:
            pass

        # Scan rules on each bus
        for bus_name in event_buses:
            try:
                bus_detections = await self._scan_event_bus(client, bus_name, region)
                detections.extend(bus_detections)
            except ClientError as e:
                self.logger.warning(
                    "bus_scan_error",
                    bus=bus_name,
                    region=region,
                    error=str(e),
                )

        return detections

    async def _scan_event_bus(
        self,
        client: Any,
        bus_name: str,
        region: str,
    ) -> list[RawDetection]:
        """Scan rules on a specific event bus."""
        detections = []

        paginator = client.get_paginator("list_rules")

        for page in paginator.paginate(EventBusName=bus_name):
            for rule in page.get("Rules", []):
                detection = self._parse_rule(rule, bus_name, region)
                if detection:
                    detections.append(detection)

        return detections

    def _parse_rule(
        self,
        rule: dict[str, Any],
        bus_name: str,
        region: str,
    ) -> Optional[RawDetection]:
        """Parse an EventBridge rule into a RawDetection."""
        name = rule.get("Name", "")
        arn = rule.get("Arn", "")
        state = rule.get("State", "DISABLED")
        event_pattern_str = rule.get("EventPattern")
        description = rule.get("Description")
        schedule = rule.get("ScheduleExpression")

        # Parse event pattern if present
        event_pattern = None
        target_services = None
        if event_pattern_str:
            try:
                event_pattern = json.loads(event_pattern_str)
                # Extract target services from event pattern
                target_services = extract_services_from_event_pattern(event_pattern)
            except json.JSONDecodeError:
                event_pattern = {"raw": event_pattern_str}

        return RawDetection(
            name=name,
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            source_arn=arn,
            region=region,
            raw_config={
                "Name": name,
                "Arn": arn,
                "State": state,
                "EventBusName": bus_name,
                "EventPattern": event_pattern_str,
                "ScheduleExpression": schedule,
                "Description": description,
            },
            event_pattern=event_pattern,
            description=description or f"EventBridge rule: {name}",
            target_services=target_services or None,
        )

    def extract_cloudtrail_events(
        self,
        event_pattern: dict[str, Any],
    ) -> list[str]:
        """Extract CloudTrail event names from an event pattern.

        Used for MITRE mapping to understand what API calls the rule monitors.
        """
        events = []

        # Check for source
        source = event_pattern.get("source", [])
        if "aws.cloudtrail" not in source and "aws.signin" not in source:
            # Check detail-type for CloudTrail
            detail_type = event_pattern.get("detail-type", [])
            if not any("CloudTrail" in dt for dt in detail_type):
                return events

        # Extract event names from detail
        detail = event_pattern.get("detail", {})
        event_name = detail.get("eventName", [])
        if isinstance(event_name, list):
            events.extend(event_name)
        elif isinstance(event_name, str):
            events.append(event_name)

        return events

    def extract_monitored_services(
        self,
        event_pattern: dict[str, Any],
    ) -> list[str]:
        """Extract AWS services monitored by this rule."""
        services = []

        # Check source field
        source = event_pattern.get("source", [])
        for s in source:
            if s.startswith("aws."):
                services.append(s.replace("aws.", ""))

        # Check detail.eventSource
        detail = event_pattern.get("detail", {})
        event_source = detail.get("eventSource", [])
        if isinstance(event_source, list):
            for es in event_source:
                service = es.replace(".amazonaws.com", "")
                if service not in services:
                    services.append(service)
        elif isinstance(event_source, str):
            service = event_source.replace(".amazonaws.com", "")
            if service not in services:
                services.append(service)

        return services
