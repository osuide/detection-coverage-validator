"""Hybrid MITRE ATT&CK mapper combining pattern matching and NLP.

Implements the hybrid mapping pipeline as designed in 05-MAPPING-AGENT.md:
1. Pattern matching first (higher confidence)
2. NLP for additional coverage
3. Merge results with preference for pattern matches
"""

from dataclasses import dataclass
from typing import Any, Optional

import structlog

from app.models.detection_mapping import MappingSource
from app.scanners.base import RawDetection

logger = structlog.get_logger()


@dataclass
class HybridMappingResult:
    """Result of hybrid detection-to-technique mapping."""

    technique_id: str
    technique_name: str
    confidence: float
    mapping_source: MappingSource
    rationale: str
    tactic_id: str = ""
    tactic_name: str = ""


class HybridMapper:
    """Hybrid mapper combining pattern matching and NLP-based mapping.

    Strategy:
    1. Run pattern matching first (higher confidence, explicit indicators)
    2. Run NLP for unmapped or additional matches
    3. Merge results, preferring pattern matches for duplicates
    4. Apply confidence thresholds
    """

    # Minimum confidence for including a mapping
    MIN_CONFIDENCE_THRESHOLD = 0.4

    def __init__(
        self,
        pattern_mapper: Any,
        nlp_mapper: Optional[Any] = None,
        enable_nlp: bool = True,
    ):
        """Initialize the hybrid mapper.

        Args:
            pattern_mapper: Pattern-based mapper instance
            nlp_mapper: NLP-based mapper instance (optional)
            enable_nlp: Whether to use NLP mapping
        """
        self.pattern_mapper = pattern_mapper
        self.nlp_mapper = nlp_mapper
        self.enable_nlp = enable_nlp and nlp_mapper is not None
        self.logger = logger.bind(component="HybridMapper")

    def map_detection(
        self,
        detection: RawDetection,
    ) -> list[HybridMappingResult]:
        """Map a detection to MITRE techniques using hybrid approach.

        Args:
            detection: RawDetection object from scanner

        Returns:
            List of mapping results sorted by confidence
        """
        all_results: dict[str, HybridMappingResult] = {}

        # Step 1: Pattern matching (higher priority)
        pattern_results = self._run_pattern_mapping(detection)
        for result in pattern_results:
            all_results[result.technique_id] = result

        self.logger.debug(
            "pattern_mapping_complete",
            detection_name=detection.name,
            match_count=len(pattern_results),
        )

        # Step 2: NLP mapping (if enabled)
        if self.enable_nlp and self.nlp_mapper:
            nlp_results = self._run_nlp_mapping(detection)

            # Merge NLP results (pattern matches take precedence)
            for result in nlp_results:
                if result.technique_id not in all_results:
                    all_results[result.technique_id] = result
                else:
                    # Technique already mapped by pattern - keep pattern match
                    # but boost confidence if NLP also found it
                    existing = all_results[result.technique_id]
                    if result.confidence > 0.5:  # Only boost if NLP is confident
                        boosted_confidence = min(
                            existing.confidence + 0.05,  # Small boost
                            0.95,  # Cap at 0.95
                        )
                        all_results[result.technique_id] = HybridMappingResult(
                            technique_id=existing.technique_id,
                            technique_name=existing.technique_name,
                            confidence=boosted_confidence,
                            mapping_source=existing.mapping_source,  # Keep pattern source
                            rationale=f"{existing.rationale} (NLP confirmed)",
                            tactic_id=existing.tactic_id,
                            tactic_name=existing.tactic_name,
                        )

            self.logger.debug(
                "nlp_mapping_complete",
                detection_name=detection.name,
                nlp_match_count=len(nlp_results),
                new_matches=len(nlp_results)
                - sum(1 for r in nlp_results if r.technique_id in all_results),
            )

        # Step 3: Filter by confidence threshold
        filtered_results = [
            result
            for result in all_results.values()
            if result.confidence >= self.MIN_CONFIDENCE_THRESHOLD
        ]

        # Step 4: Sort by confidence
        filtered_results.sort(key=lambda x: x.confidence, reverse=True)

        self.logger.info(
            "hybrid_mapping_complete",
            detection_name=detection.name,
            total_mappings=len(filtered_results),
            pattern_count=sum(
                1
                for r in filtered_results
                if r.mapping_source == MappingSource.PATTERN_MATCH
            ),
            nlp_count=sum(
                1 for r in filtered_results if r.mapping_source == MappingSource.NLP
            ),
        )

        return filtered_results

    def _run_pattern_mapping(
        self, detection: RawDetection
    ) -> list[HybridMappingResult]:
        """Run pattern-based mapping."""
        results = []

        try:
            # Pattern mapper returns list of (technique_id, confidence, rationale) tuples
            # or similar structure - adapt based on actual pattern_mapper interface
            pattern_matches = self.pattern_mapper.map_detection(detection)

            for match in pattern_matches:
                # Handle different return types from pattern mapper
                if hasattr(match, "technique_id"):
                    # Object-based result
                    results.append(
                        HybridMappingResult(
                            technique_id=match.technique_id,
                            technique_name=getattr(match, "technique_name", ""),
                            confidence=match.confidence,
                            mapping_source=MappingSource.PATTERN_MATCH,
                            rationale=getattr(match, "rationale", "Pattern match"),
                            tactic_id=getattr(match, "tactic_id", ""),
                            tactic_name=getattr(match, "tactic_name", ""),
                        )
                    )
                elif isinstance(match, tuple) and len(match) >= 2:
                    # Tuple-based result
                    results.append(
                        HybridMappingResult(
                            technique_id=match[0],
                            technique_name=match[1] if len(match) > 1 else "",
                            confidence=match[2] if len(match) > 2 else 0.7,
                            mapping_source=MappingSource.PATTERN_MATCH,
                            rationale=match[3] if len(match) > 3 else "Pattern match",
                            tactic_id=match[4] if len(match) > 4 else "",
                            tactic_name=match[5] if len(match) > 5 else "",
                        )
                    )
                elif isinstance(match, dict):
                    # Dict-based result
                    results.append(
                        HybridMappingResult(
                            technique_id=match.get("technique_id", ""),
                            technique_name=match.get("technique_name", ""),
                            confidence=match.get("confidence", 0.7),
                            mapping_source=MappingSource.PATTERN_MATCH,
                            rationale=match.get("rationale", "Pattern match"),
                            tactic_id=match.get("tactic_id", ""),
                            tactic_name=match.get("tactic_name", ""),
                        )
                    )

        except Exception as e:
            self.logger.error(
                "pattern_mapping_error",
                detection_name=detection.name,
                error=str(e),
            )

        return results

    def _run_nlp_mapping(self, detection: RawDetection) -> list[HybridMappingResult]:
        """Run NLP-based mapping."""
        results = []

        if not self.nlp_mapper:
            return results

        try:
            nlp_matches = self.nlp_mapper.map_detection(
                name=detection.name,
                description=detection.description or "",
                query_pattern=detection.query_pattern or "",
                raw_config=detection.raw_config,
            )

            for match in nlp_matches:
                results.append(
                    HybridMappingResult(
                        technique_id=match.technique_id,
                        technique_name=match.technique_name,
                        confidence=match.confidence,
                        mapping_source=MappingSource.NLP,
                        rationale=match.rationale,
                    )
                )

        except Exception as e:
            self.logger.error(
                "nlp_mapping_error",
                detection_name=detection.name,
                error=str(e),
            )

        return results

    def map_detection_batch(
        self,
        detections: list[RawDetection],
    ) -> dict[str, list[HybridMappingResult]]:
        """Map multiple detections to MITRE techniques.

        Args:
            detections: List of RawDetection objects

        Returns:
            Dict mapping detection source_arn to list of mapping results
        """
        results = {}

        for detection in detections:
            key = detection.source_arn or detection.name
            results[key] = self.map_detection(detection)

        self.logger.info(
            "batch_mapping_complete",
            detection_count=len(detections),
            total_mappings=sum(len(r) for r in results.values()),
        )

        return results


class HybridMapperFactory:
    """Factory for creating HybridMapper instances."""

    _instance: Optional[HybridMapper] = None

    @classmethod
    def create(
        cls,
        pattern_mapper: Any,
        nlp_mapper: Optional[Any] = None,
        enable_nlp: bool = True,
    ) -> HybridMapper:
        """Create a new HybridMapper instance."""
        return HybridMapper(
            pattern_mapper=pattern_mapper,
            nlp_mapper=nlp_mapper,
            enable_nlp=enable_nlp,
        )

    @classmethod
    def get_instance(cls) -> Optional[HybridMapper]:
        """Get the singleton instance if created."""
        return cls._instance

    @classmethod
    def set_instance(cls, mapper: HybridMapper) -> None:
        """Set the singleton instance."""
        cls._instance = mapper
