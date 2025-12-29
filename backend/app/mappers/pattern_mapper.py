"""Pattern-based MITRE ATT&CK mapper following 05-MAPPING-AGENT.md design."""

import re
from dataclasses import dataclass
from typing import Optional
import structlog

from app.mappers.indicator_library import (
    TECHNIQUE_INDICATORS,
    TECHNIQUE_BY_ID,
    CLOUDTRAIL_EVENT_TO_TECHNIQUES,
    TechniqueIndicator,
)
from app.mappers.technique_metadata import get_technique_metadata
from app.mappers.guardduty_mappings import get_mitre_mappings_for_finding
from app.mappers.config_rule_mappings import get_techniques_for_config_rule
from app.mappers.securityhub_mappings import (
    get_techniques_for_security_hub,
    get_techniques_for_cspm_control,
)
from app.mappers.gcp_scc_mappings import get_mitre_mappings_for_scc_finding
from app.mappers.gcp_chronicle_mappings import get_mitre_mappings_for_chronicle_rule
from app.scanners.base import RawDetection
from app.models.detection import DetectionType

logger = structlog.get_logger()


@dataclass
class MappingResult:
    """Result of mapping a detection to a MITRE technique."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    confidence: float
    matched_indicators: list[str]
    rationale: str


class PatternMapper:
    """Pattern-based mapper for MITRE ATT&CK techniques.

    Uses the indicator library to match detections to techniques based on:
    1. CloudTrail event names in EventBridge rules
    2. Keywords in detection names and descriptions
    3. AWS service references
    4. Log group patterns for CloudWatch queries
    """

    def __init__(self) -> None:
        self.logger = logger.bind(mapper="PatternMapper")
        self.indicators = TECHNIQUE_INDICATORS

    # Detection types with official MITRE CTID mappings - skip pattern matching
    CTID_MAPPED_TYPES = {
        DetectionType.GUARDDUTY_FINDING,
        DetectionType.SECURITY_HUB,
        DetectionType.CONFIG_RULE,
        DetectionType.GCP_SECURITY_COMMAND_CENTER,
        DetectionType.GCP_CHRONICLE,
    }

    def map_detection(
        self,
        detection: RawDetection,
        min_confidence: float = 0.4,
    ) -> list[MappingResult]:
        """Map a detection to MITRE techniques.

        Args:
            detection: The raw detection to map
            min_confidence: Minimum confidence threshold

        Returns:
            List of MappingResult objects sorted by confidence descending
        """
        results = []

        # Check for vendor-specific mappings (GuardDuty, SecurityHub, SCC, etc.)
        vendor_results = self._get_vendor_mappings(detection)
        if vendor_results:
            results.extend(vendor_results)

        # For managed services with official CTID mappings, use only vendor mappings
        # Pattern matching is only for user-defined detections (CloudWatch, EventBridge, etc.)
        if detection.detection_type in self.CTID_MAPPED_TYPES:
            self.logger.debug(
                "mapping_complete",
                detection=detection.name,
                mappings=len(results),
                source="ctid",
            )
            return results

        # Run pattern-based mapping for user-defined detection types
        for indicator in self.indicators:
            confidence, matched, rationale = self._calculate_match(detection, indicator)

            if confidence >= min_confidence:
                results.append(
                    MappingResult(
                        technique_id=indicator.technique_id,
                        technique_name=indicator.technique_name,
                        tactic_id=indicator.tactic_id,
                        tactic_name=indicator.tactic_name,
                        confidence=confidence,
                        matched_indicators=matched,
                        rationale=rationale,
                    )
                )

        # Sort by confidence descending
        results.sort(key=lambda x: x.confidence, reverse=True)

        self.logger.debug(
            "mapping_complete",
            detection=detection.name,
            mappings=len(results),
            source="pattern",
        )

        return results

    def _get_vendor_mappings(self, detection: RawDetection) -> list[MappingResult]:
        """Get vendor-specific MITRE mappings for managed detection services."""
        results = []

        # GuardDuty vendor mappings
        if detection.detection_type == DetectionType.GUARDDUTY_FINDING:
            raw_config = detection.raw_config or {}
            finding_types = raw_config.get("finding_types", [])

            for finding_type in finding_types:
                mappings = get_mitre_mappings_for_finding(finding_type)
                for technique_id, confidence in mappings:
                    # Use technique_metadata for CTID lookups (comprehensive)
                    # Fall back to indicator_library for pattern-matching techniques
                    metadata = get_technique_metadata(technique_id)
                    if metadata:
                        results.append(
                            MappingResult(
                                technique_id=technique_id,
                                technique_name=metadata.technique_name,
                                tactic_id=metadata.tactic_id,
                                tactic_name=metadata.tactic_name,
                                confidence=confidence,
                                matched_indicators=[f"guardduty:{finding_type}"],
                                rationale=f"GuardDuty vendor mapping for {finding_type}",
                            )
                        )
                    else:
                        # Log missing technique for debugging
                        self.logger.warning(
                            "missing_technique_metadata",
                            technique_id=technique_id,
                            source="guardduty",
                        )

        # Security Hub mappings - using official MITRE CTID mappings
        elif detection.detection_type == DetectionType.SECURITY_HUB:
            raw_config = detection.raw_config or {}
            api_version = raw_config.get("api_version", "")

            # Handle aggregated CSPM detection (single detection with all controls)
            if api_version == "cspm_aggregated":
                results.extend(self._map_aggregated_securityhub(detection))
            else:
                # Standard single-control mapping
                standard_name = raw_config.get("standard_name", "")
                control_id = raw_config.get("control_id", "")
                finding_title = detection.description or detection.name or ""

                # Get official MITRE mappings for this Security Hub finding
                technique_mappings = get_techniques_for_security_hub(
                    standard_name=standard_name,
                    control_id=control_id,
                    finding_title=finding_title,
                    api_version=api_version,
                )

                for technique_id, confidence in technique_mappings:
                    metadata = get_technique_metadata(technique_id)
                    if metadata:
                        matched = (
                            f"{standard_name}:{control_id}"
                            if control_id
                            else standard_name
                        )
                        results.append(
                            MappingResult(
                                technique_id=technique_id,
                                technique_name=metadata.technique_name,
                                tactic_id=metadata.tactic_id,
                                tactic_name=metadata.tactic_name,
                                confidence=confidence,
                                matched_indicators=[f"securityhub:{matched}"],
                                rationale=f"Security Hub {matched} - MITRE CTID mapping",
                            )
                        )
                    else:
                        self.logger.warning(
                            "missing_technique_metadata",
                            technique_id=technique_id,
                            source="securityhub",
                        )

        # Config Rule mappings - using official MITRE CTID mappings
        elif detection.detection_type == DetectionType.CONFIG_RULE:
            raw_config = detection.raw_config or {}
            source_identifier = raw_config.get("source_identifier", "")
            rule_name = detection.name or ""

            # Get official MITRE mappings for this Config rule
            technique_mappings = get_techniques_for_config_rule(
                source_identifier=source_identifier,
                rule_name=rule_name,
            )

            matched_rule = source_identifier or rule_name
            for technique_id, confidence in technique_mappings:
                metadata = get_technique_metadata(technique_id)
                if metadata:
                    results.append(
                        MappingResult(
                            technique_id=technique_id,
                            technique_name=metadata.technique_name,
                            tactic_id=metadata.tactic_id,
                            tactic_name=metadata.tactic_name,
                            confidence=confidence,
                            matched_indicators=[f"config:{matched_rule}"],
                            rationale=f"AWS Config Rule {matched_rule} - MITRE CTID mapping",
                        )
                    )
                else:
                    self.logger.warning(
                        "missing_technique_metadata",
                        technique_id=technique_id,
                        source="config",
                    )

        # GCP Security Command Center mappings - using official MITRE CTID mappings
        elif detection.detection_type == DetectionType.GCP_SECURITY_COMMAND_CENTER:
            raw_config = detection.raw_config or {}
            finding_category = raw_config.get("category", "")
            finding_class = raw_config.get("finding_class", "")

            # Get official MITRE mappings for this SCC finding
            technique_mappings = get_mitre_mappings_for_scc_finding(
                finding_category=finding_category,
                finding_class=finding_class,
            )

            for technique_id, confidence in technique_mappings:
                metadata = get_technique_metadata(technique_id)
                if metadata:
                    results.append(
                        MappingResult(
                            technique_id=technique_id,
                            technique_name=metadata.technique_name,
                            tactic_id=metadata.tactic_id,
                            tactic_name=metadata.tactic_name,
                            confidence=confidence,
                            matched_indicators=[f"scc:{finding_category}"],
                            rationale=f"GCP SCC {finding_category} - MITRE CTID mapping",
                        )
                    )
                else:
                    self.logger.warning(
                        "missing_technique_metadata",
                        technique_id=technique_id,
                        source="scc",
                    )

        # GCP Chronicle mappings - using official MITRE CTID mappings
        elif detection.detection_type == DetectionType.GCP_CHRONICLE:
            raw_config = detection.raw_config or {}
            rule_category = raw_config.get("rule_category", "")
            rule_name = detection.name or ""

            # Get official MITRE mappings for this Chronicle rule
            technique_mappings = get_mitre_mappings_for_chronicle_rule(
                rule_category=rule_category,
                rule_name=rule_name,
            )

            for technique_id, confidence in technique_mappings:
                metadata = get_technique_metadata(technique_id)
                if metadata:
                    results.append(
                        MappingResult(
                            technique_id=technique_id,
                            technique_name=metadata.technique_name,
                            tactic_id=metadata.tactic_id,
                            tactic_name=metadata.tactic_name,
                            confidence=confidence,
                            matched_indicators=[f"chronicle:{rule_category}"],
                            rationale=f"GCP Chronicle {rule_category} - MITRE CTID mapping",
                        )
                    )
                else:
                    self.logger.warning(
                        "missing_technique_metadata",
                        technique_id=technique_id,
                        source="chronicle",
                    )

        # Deduplicate by technique_id, keeping highest confidence
        seen = {}
        for r in results:
            if (
                r.technique_id not in seen
                or r.confidence > seen[r.technique_id].confidence
            ):
                seen[r.technique_id] = r

        return list(seen.values())

    def _map_aggregated_securityhub(
        self,
        detection: RawDetection,
    ) -> list[MappingResult]:
        """Map an aggregated Security Hub CSPM detection to MITRE techniques.

        For aggregated detections (api_version == "cspm_aggregated"), the raw_config
        contains a 'controls' list with all Security Hub controls. This method:
        1. Iterates through all controls
        2. Only maps ENABLED controls (checks status_by_region)
        3. Calls get_techniques_for_cspm_control() for each enabled control
        4. Deduplicates techniques, keeping highest confidence
        5. Returns MappingResult list with contributing controls in rationale

        Args:
            detection: The aggregated Security Hub detection

        Returns:
            List of MappingResult objects, one per unique technique
        """
        raw_config = detection.raw_config or {}
        controls = raw_config.get("controls", [])

        # Debug: Log sample control IDs being mapped
        sample_control_ids = (
            [c.get("control_id", "unknown") for c in controls[:5]] if controls else []
        )
        self.logger.debug(
            "aggregated_securityhub_mapping_start",
            detection_name=detection.name,
            total_controls=len(controls),
            sample_control_ids=sample_control_ids,
        )

        if not controls:
            self.logger.warning(
                "aggregated_securityhub_no_controls",
                detection_name=detection.name,
            )
            return []

        # Track techniques and their contributing controls
        # technique_id -> {confidence, control_ids}
        technique_to_controls: dict[str, dict] = {}

        for control in controls:
            control_id = control.get("control_id", "")
            status_by_region = control.get("status_by_region", {})

            # Check if control is ENABLED in any region
            is_enabled = any(
                status == "ENABLED" for status in status_by_region.values()
            )

            if not is_enabled:
                continue

            # Get MITRE technique mappings for this control
            technique_mappings = get_techniques_for_cspm_control(
                control_id=control_id,
                standard_associations=control.get("standard_associations"),
            )

            for technique_id, confidence in technique_mappings:
                if technique_id not in technique_to_controls:
                    technique_to_controls[technique_id] = {
                        "confidence": confidence,
                        "control_ids": [control_id],
                    }
                else:
                    # Keep highest confidence
                    if confidence > technique_to_controls[technique_id]["confidence"]:
                        technique_to_controls[technique_id]["confidence"] = confidence
                    # Track contributing control
                    if (
                        control_id
                        not in technique_to_controls[technique_id]["control_ids"]
                    ):
                        technique_to_controls[technique_id]["control_ids"].append(
                            control_id
                        )

        # Build MappingResult for each unique technique
        results = []
        for technique_id, data in technique_to_controls.items():
            metadata = get_technique_metadata(technique_id)
            if metadata:
                control_ids = data["control_ids"]
                # Sort controls for consistent output
                control_ids.sort()

                results.append(
                    MappingResult(
                        technique_id=technique_id,
                        technique_name=metadata.technique_name,
                        tactic_id=metadata.tactic_id,
                        tactic_name=metadata.tactic_name,
                        confidence=data["confidence"],
                        matched_indicators=[
                            f"securityhub:{cid}" for cid in control_ids
                        ],
                        rationale=f"Security Hub controls: {', '.join(control_ids)}",
                    )
                )
            else:
                self.logger.warning(
                    "missing_technique_metadata",
                    technique_id=technique_id,
                    source="securityhub_aggregated",
                )

        self.logger.debug(
            "aggregated_securityhub_mapped",
            detection_name=detection.name,
            total_controls=len(controls),
            enabled_controls=sum(
                1
                for c in controls
                if any(s == "ENABLED" for s in c.get("status_by_region", {}).values())
            ),
            techniques_mapped=len(results),
        )

        return results

    def _calculate_match(
        self,
        detection: RawDetection,
        indicator: TechniqueIndicator,
    ) -> tuple[float, list[str], str]:
        """Calculate match score between a detection and technique indicator.

        Returns:
            Tuple of (confidence, matched_indicators, rationale)
        """
        matched = []
        score_components = []

        # 1. CloudTrail event matching (highest weight for EventBridge rules)
        if detection.detection_type == DetectionType.EVENTBRIDGE_RULE:
            event_score, event_matches = self._match_cloudtrail_events(
                detection, indicator
            )
            if event_matches:
                matched.extend(event_matches)
                score_components.append(("cloudtrail_events", event_score, 0.4))

        # 2. Keyword matching in name and description
        keyword_score, keyword_matches = self._match_keywords(detection, indicator)
        if keyword_matches:
            matched.extend(keyword_matches)
            score_components.append(("keywords", keyword_score, 0.25))

        # 3. AWS service matching
        service_score, service_matches = self._match_services(detection, indicator)
        if service_matches:
            matched.extend(service_matches)
            score_components.append(("aws_services", service_score, 0.2))

        # 4. Log pattern matching (for CloudWatch queries)
        if detection.detection_type == DetectionType.CLOUDWATCH_LOGS_INSIGHTS:
            pattern_score, pattern_matches = self._match_log_patterns(
                detection, indicator
            )
            if pattern_matches:
                matched.extend(pattern_matches)
                score_components.append(("log_patterns", pattern_score, 0.15))

        # Calculate weighted confidence
        if not score_components:
            return 0.0, [], ""

        total_weight = sum(weight for _, _, weight in score_components)
        weighted_score = (
            sum(score * weight for _, score, weight in score_components) / total_weight
        )

        # Apply base confidence modifier
        final_confidence = min(
            weighted_score * indicator.base_confidence / 0.7,
            0.95,  # Cap at 0.95 for pattern matching
        )

        # Build rationale
        rationale_parts = []
        for component_name, score, _ in score_components:
            if score > 0:
                rationale_parts.append(f"{component_name}: {score:.2f}")
        rationale = f"Pattern match ({', '.join(rationale_parts)})"

        return round(final_confidence, 3), matched, rationale

    def _match_cloudtrail_events(
        self,
        detection: RawDetection,
        indicator: TechniqueIndicator,
    ) -> tuple[float, list[str]]:
        """Match CloudTrail events in EventBridge event patterns."""
        if not detection.event_pattern or not indicator.cloudtrail_events:
            return 0.0, []

        matched = []
        event_pattern = detection.event_pattern

        # Extract event names from pattern
        detail = event_pattern.get("detail", {})
        event_names = detail.get("eventName", [])
        if isinstance(event_names, str):
            event_names = [event_names]

        # Also check source
        sources = event_pattern.get("source", [])
        if isinstance(sources, str):
            sources = [sources]

        # Match against indicator events
        for event in indicator.cloudtrail_events:
            if event in event_names:
                matched.append(f"event:{event}")

        # Score based on match ratio
        if not matched:
            return 0.0, []

        score = len(matched) / min(len(indicator.cloudtrail_events), 3)
        return min(score, 1.0), matched

    def _match_keywords(
        self,
        detection: RawDetection,
        indicator: TechniqueIndicator,
    ) -> tuple[float, list[str]]:
        """Match keywords in detection name and description."""
        if not indicator.keywords:
            return 0.0, []

        matched = []
        search_text = f"{detection.name} {detection.description or ''}".lower()

        for keyword in indicator.keywords:
            if keyword.lower() in search_text:
                matched.append(f"keyword:{keyword}")

        if not matched:
            return 0.0, []

        # Score based on match ratio (cap at 3 matches for full score)
        score = len(matched) / min(len(indicator.keywords), 3)
        return min(score, 1.0), matched

    def _match_services(
        self,
        detection: RawDetection,
        indicator: TechniqueIndicator,
    ) -> tuple[float, list[str]]:
        """Match AWS services referenced in the detection."""
        if not indicator.aws_services:
            return 0.0, []

        matched = []

        # Check event pattern for service references
        services_found = set()

        if detection.event_pattern:
            sources = detection.event_pattern.get("source", [])
            for source in sources:
                if source.startswith("aws."):
                    services_found.add(source.replace("aws.", ""))

            detail = detection.event_pattern.get("detail", {})
            event_sources = detail.get("eventSource", [])
            if isinstance(event_sources, str):
                event_sources = [event_sources]
            for es in event_sources:
                service = es.replace(".amazonaws.com", "")
                services_found.add(service)

        # Check log groups
        if detection.log_groups:
            for lg in detection.log_groups:
                for service in indicator.aws_services:
                    if service in lg.lower():
                        services_found.add(service)

        # Match against indicator services
        for service in indicator.aws_services:
            if service in services_found:
                matched.append(f"service:{service}")

        if not matched:
            return 0.0, []

        score = len(matched) / len(indicator.aws_services)
        return min(score, 1.0), matched

    def _match_log_patterns(
        self,
        detection: RawDetection,
        indicator: TechniqueIndicator,
    ) -> tuple[float, list[str]]:
        """Match log patterns in CloudWatch queries."""
        if not indicator.log_patterns or not detection.query_pattern:
            return 0.0, []

        matched = []
        query = detection.query_pattern.lower()

        for pattern in indicator.log_patterns:
            try:
                if re.search(pattern, query, re.IGNORECASE):
                    matched.append(f"pattern:{pattern}")
            except re.error:
                # Invalid regex, skip
                pass

        if not matched:
            return 0.0, []

        score = len(matched) / len(indicator.log_patterns)
        return min(score, 1.0), matched

    def get_all_techniques(self) -> list[TechniqueIndicator]:
        """Get all technique indicators for gap analysis."""
        return self.indicators

    def get_technique(self, technique_id: str) -> Optional[TechniqueIndicator]:
        """Get a specific technique indicator by ID."""
        return TECHNIQUE_BY_ID.get(technique_id)

    def get_techniques_for_event(self, event_name: str) -> list[str]:
        """Get technique IDs that map to a CloudTrail event."""
        return CLOUDTRAIL_EVENT_TO_TECHNIQUES.get(event_name, [])
