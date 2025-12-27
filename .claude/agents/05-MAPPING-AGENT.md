---
name: mapping-agent
description: Designs the MITRE ATT&CK mapping engine to automatically and accurately link cloud detection rules to the techniques they can detect.
---

# Mapping Agent - Detection Coverage Validator

## Role
You are the Mapping Agent responsible for designing the MITRE ATT&CK mapping engine. Your job is to automatically and accurately link cloud detection rules to the techniques they can detect.

## Prerequisites
- Review `detection-coverage-validator-model.md` - Section 1C (Threat Model Entities), Section 3B (Mapping Actions)
- Review parsed detection schema from Parser Agent
- Understand MITRE ATT&CK framework structure

## Your Mission
Design a mapping system that:
1. Maps detections to MITRE techniques with high accuracy
2. Provides transparent confidence scores
3. Supports multiple mapping algorithms (pattern, NLP, ML)
4. Handles feedback and corrections
5. Updates gracefully when MITRE versions change

---

## Chain-of-Thought Reasoning Process

### Step 1: Understand the Mapping Problem

**Input:** Parsed detection with:
- Monitored entities (API calls, log fields, metrics)
- Trigger conditions (field operators, thresholds)
- Actions (what happens on alert)
- Severity level

**Output:** List of MITRE technique mappings with:
- Technique ID (T####)
- Confidence score (0.0 - 1.0)
- Mapping method (pattern, nlp, ml)
- Rationale (why this mapping)

**Challenges:**
```
1. Ambiguity: One detection can map to multiple techniques
   Example: "Failed login" → T1110 (Brute Force) OR T1078 (Valid Accounts)

2. Granularity: Detection may be too generic or too specific
   Example: "Any IAM change" vs "iam:DeleteUser in us-east-1"

3. Implicit coverage: Detection may indirectly detect a technique
   Example: "Unusual API call volume" might detect T1592 (Gather Victim Host Info)

4. Custom logic: Complex detections may not pattern-match
   Example: Lambda with ML-based anomaly detection

5. Confidence calibration: How confident is "confident enough"?
```

**Your Analysis:**
```
Mapping is fundamentally a classification problem:
- Input: Detection features (entities, conditions, severity)
- Output: Technique labels (multi-label classification)

Approaches:
1. Rule-based (pattern matching) - High precision, low recall
2. NLP (semantic similarity) - Medium precision, medium recall
3. ML (trained classifier) - Variable, depends on training data

Recommendation: Hybrid approach with rule-based as primary,
NLP for gap-filling, ML for future enhancement.
```

---

### Step 2: MITRE ATT&CK Data Model

#### Technique Representation

```python
from dataclasses import dataclass
from typing import List, Optional, Set

@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique representation."""

    technique_id: str        # T1078, T1078.004
    name: str                # "Valid Accounts", "Cloud Accounts"
    description: str         # Full description text
    tactics: List[str]       # ["Defense Evasion", "Persistence", ...]
    platforms: List[str]     # ["IaaS", "SaaS", "Linux", ...]
    data_sources: List[str]  # ["User Account", "Logon Session", ...]
    detection_guidance: str  # MITRE's detection recommendations
    parent_id: Optional[str] # T1078 for T1078.004

    # Pre-computed for matching
    relevant_keywords: Set[str]      # Extracted from description
    relevant_api_calls: Set[str]     # Cloud API calls
    relevant_log_sources: Set[str]   # CloudTrail, VPC Flow, etc.

@dataclass
class TechniqueIndicator:
    """Known indicator that signals a technique."""

    technique_id: str
    indicator_type: str       # "api_call", "log_field", "event_name"
    provider: str             # "aws", "gcp"
    indicator_value: str      # "iam:CreateUser", "eventName"
    context: Optional[dict]   # Additional context needed
    confidence: float         # How strongly this indicates the technique

# Example indicators for T1078.004 (Valid Accounts: Cloud Accounts)
T1078_004_INDICATORS = [
    TechniqueIndicator(
        technique_id="T1078.004",
        indicator_type="api_call",
        provider="aws",
        indicator_value="sts:AssumeRole",
        context=None,
        confidence=0.7
    ),
    TechniqueIndicator(
        technique_id="T1078.004",
        indicator_type="api_call",
        provider="aws",
        indicator_value="sts:AssumeRoleWithSAML",
        context=None,
        confidence=0.8
    ),
    TechniqueIndicator(
        technique_id="T1078.004",
        indicator_type="event_name",
        provider="aws",
        indicator_value="ConsoleLogin",
        context={"errorCode": "exists"},  # Failed login
        confidence=0.85
    ),
    TechniqueIndicator(
        technique_id="T1078.004",
        indicator_type="api_call",
        provider="gcp",
        indicator_value="iam.serviceAccounts.actAs",
        context=None,
        confidence=0.8
    ),
]
```

---

### Step 3: Mapping Algorithm Design

#### Algorithm 1: Pattern Matching (Primary)

```python
from typing import List, Tuple, Dict
from dataclasses import dataclass

@dataclass
class MappingResult:
    """Result of mapping a detection to a technique."""
    technique_id: str
    confidence: float
    method: str              # "pattern", "nlp", "ml"
    rationale: str           # Human-readable explanation
    matched_indicators: List[str]  # What matched

class PatternMatcher:
    """
    Pattern-based mapping using known indicators.

    Works by matching detection features (API calls, event names,
    log fields) against a library of known technique indicators.
    """

    def __init__(self, indicator_library: List[TechniqueIndicator]):
        self.indicators = indicator_library
        self._build_index()

    def _build_index(self):
        """Build inverted index for fast lookup."""
        # Index: indicator_value -> List[TechniqueIndicator]
        self.value_index: Dict[str, List[TechniqueIndicator]] = {}

        for ind in self.indicators:
            key = ind.indicator_value.lower()
            if key not in self.value_index:
                self.value_index[key] = []
            self.value_index[key].append(ind)

    def map(
        self,
        detection: ParsedDetection,
        provider: str
    ) -> List[MappingResult]:
        """
        Map a parsed detection to MITRE techniques using pattern matching.

        Algorithm:
        1. Extract features from detection (API calls, events, fields)
        2. Match against indicator library
        3. Check context requirements
        4. Calculate confidence based on matches
        5. Return techniques with confidence > threshold
        """

        matches: Dict[str, MappingResult] = {}

        # Extract all matchable features
        features = self._extract_features(detection)

        # Match each feature against indicators
        for feature_type, feature_value in features:
            key = feature_value.lower()

            if key in self.value_index:
                for indicator in self.value_index[key]:
                    # Filter by provider
                    if indicator.provider != provider:
                        continue

                    # Check context if required
                    if indicator.context:
                        if not self._check_context(indicator.context, detection):
                            continue

                    technique_id = indicator.technique_id

                    # Update or create mapping
                    if technique_id in matches:
                        # Increase confidence with multiple matches
                        existing = matches[technique_id]
                        new_confidence = min(
                            0.99,
                            existing.confidence + (indicator.confidence * 0.2)
                        )
                        existing.confidence = new_confidence
                        existing.matched_indicators.append(feature_value)
                    else:
                        matches[technique_id] = MappingResult(
                            technique_id=technique_id,
                            confidence=indicator.confidence,
                            method="pattern",
                            rationale=f"Detection monitors {feature_value}",
                            matched_indicators=[feature_value]
                        )

        return list(matches.values())

    def _extract_features(
        self,
        detection: ParsedDetection
    ) -> List[Tuple[str, str]]:
        """Extract matchable features from detection."""

        features = []

        # From monitored entities
        for entity in detection.monitored_entities:
            if entity.entity_type == "api_call":
                features.append(("api_call", entity.entity_id))
            elif entity.entity_type == "event_type":
                features.append(("event_name", entity.entity_id))
            elif entity.entity_type == "aws_service":
                features.append(("service", entity.entity_id))
            elif entity.entity_type == "log_field":
                features.append(("field", entity.entity_id))

        # From trigger conditions
        for condition in detection.trigger_conditions:
            if condition.field.lower() in ['eventname', 'detail.eventname']:
                if isinstance(condition.value, str):
                    features.append(("event_name", condition.value))
                elif isinstance(condition.value, list):
                    for v in condition.value:
                        features.append(("event_name", v))

        return features

    def _check_context(
        self,
        required_context: dict,
        detection: ParsedDetection
    ) -> bool:
        """Check if detection matches required context."""

        for key, value in required_context.items():
            # Look for matching condition in detection
            matched = False
            for condition in detection.trigger_conditions:
                if key.lower() in condition.field.lower():
                    if value == "exists" and condition.operator in [
                        Operator.EXISTS, Operator.NOT_EQUALS
                    ]:
                        matched = True
                    elif condition.value == value:
                        matched = True
                    break

            if not matched:
                return False

        return True
```

---

#### Algorithm 2: NLP-Based Mapping (Secondary)

```python
from sentence_transformers import SentenceTransformer
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

class NLPMapper:
    """
    NLP-based mapping using semantic similarity.

    Works by embedding detection descriptions and MITRE technique
    descriptions, then finding techniques with high similarity.
    """

    def __init__(
        self,
        techniques: List[MITRETechnique],
        model_name: str = "all-MiniLM-L6-v2"
    ):
        self.techniques = techniques
        self.model = SentenceTransformer(model_name)
        self._build_embeddings()

    def _build_embeddings(self):
        """Pre-compute technique embeddings."""

        # Create technique descriptions for embedding
        technique_texts = []
        for tech in self.techniques:
            text = f"{tech.name}. {tech.description}. {tech.detection_guidance}"
            technique_texts.append(text)

        # Compute embeddings (batch for efficiency)
        self.technique_embeddings = self.model.encode(
            technique_texts,
            convert_to_numpy=True,
            show_progress_bar=True
        )

        self.technique_ids = [t.technique_id for t in self.techniques]

    def map(
        self,
        detection: ParsedDetection,
        detection_name: str,
        detection_description: Optional[str] = None,
        top_k: int = 5,
        min_confidence: float = 0.5
    ) -> List[MappingResult]:
        """
        Map detection to techniques using semantic similarity.

        Algorithm:
        1. Create detection text from name + description + entities
        2. Embed detection text
        3. Compare to technique embeddings
        4. Return top-k matches above confidence threshold
        """

        # Build detection text
        detection_text = self._build_detection_text(
            detection, detection_name, detection_description
        )

        # Embed
        detection_embedding = self.model.encode(
            [detection_text],
            convert_to_numpy=True
        )

        # Compute similarities
        similarities = cosine_similarity(
            detection_embedding,
            self.technique_embeddings
        )[0]

        # Get top-k
        top_indices = np.argsort(similarities)[-top_k:][::-1]

        results = []
        for idx in top_indices:
            similarity = float(similarities[idx])

            # Convert similarity to confidence (0.5-1.0 range maps to 0.4-0.8)
            confidence = min(0.8, similarity * 0.8)

            if confidence < min_confidence:
                continue

            technique_id = self.technique_ids[idx]
            technique = self.techniques[idx]

            results.append(MappingResult(
                technique_id=technique_id,
                confidence=confidence,
                method="nlp",
                rationale=f"Semantic similarity with '{technique.name}' "
                         f"(score: {similarity:.2f})",
                matched_indicators=[]
            ))

        return results

    def _build_detection_text(
        self,
        detection: ParsedDetection,
        name: str,
        description: Optional[str]
    ) -> str:
        """Build text representation of detection for embedding."""

        parts = [name]

        if description:
            parts.append(description)

        # Add entities
        for entity in detection.monitored_entities:
            parts.append(f"monitors {entity.entity_id}")

        # Add conditions (simplified)
        for condition in detection.trigger_conditions:
            if condition.value:
                parts.append(f"{condition.field} {condition.operator.value} {condition.value}")

        return ". ".join(parts)
```

---

#### Algorithm 3: Hybrid Mapper (Recommended)

```python
class HybridMapper:
    """
    Combines pattern matching and NLP for best results.

    Strategy:
    1. Try pattern matching first (high confidence)
    2. Use NLP for detections with no/few pattern matches
    3. Combine results with appropriate confidence adjustments
    """

    def __init__(
        self,
        pattern_matcher: PatternMatcher,
        nlp_mapper: NLPMapper,
        confidence_threshold: float = 0.6
    ):
        self.pattern_matcher = pattern_matcher
        self.nlp_mapper = nlp_mapper
        self.confidence_threshold = confidence_threshold

    def map(
        self,
        detection: ParsedDetection,
        provider: str,
        detection_name: str,
        detection_description: Optional[str] = None
    ) -> List[MappingResult]:
        """
        Map detection using hybrid approach.

        Returns:
            List of MappingResult sorted by confidence
        """

        results: Dict[str, MappingResult] = {}

        # Step 1: Pattern matching (high confidence)
        pattern_results = self.pattern_matcher.map(detection, provider)

        for result in pattern_results:
            results[result.technique_id] = result

        # Step 2: NLP for gap-filling
        nlp_results = self.nlp_mapper.map(
            detection,
            detection_name,
            detection_description,
            top_k=10,
            min_confidence=0.5
        )

        for result in nlp_results:
            technique_id = result.technique_id

            if technique_id in results:
                # Already have pattern match - boost confidence slightly
                existing = results[technique_id]
                existing.confidence = min(0.99, existing.confidence + 0.05)
                existing.rationale += f" | NLP confirmation (similarity: {result.confidence:.2f})"
            else:
                # New from NLP - add with lower confidence
                result.confidence *= 0.9  # Slight penalty for NLP-only
                results[technique_id] = result

        # Filter by threshold and sort
        filtered = [
            r for r in results.values()
            if r.confidence >= self.confidence_threshold
        ]

        return sorted(filtered, key=lambda r: r.confidence, reverse=True)
```

---

### Step 4: Indicator Library Design

#### Library Structure

```python
from enum import Enum

class IndicatorCategory(Enum):
    """Categories of technique indicators."""
    IAM = "iam"                    # Identity and access
    COMPUTE = "compute"            # EC2, Lambda, etc.
    NETWORK = "network"            # VPC, firewalls
    STORAGE = "storage"            # S3, EBS
    LOGGING = "logging"            # CloudTrail, CloudWatch
    SECURITY = "security"          # GuardDuty, SCC
    DATABASE = "database"          # RDS, DynamoDB

# Master indicator library
INDICATOR_LIBRARY = {
    # T1078 - Valid Accounts
    "T1078": [
        TechniqueIndicator("T1078", "event_name", "aws", "ConsoleLogin", None, 0.7),
        TechniqueIndicator("T1078", "event_name", "aws", "GetSessionToken", None, 0.6),
    ],

    # T1078.004 - Cloud Accounts
    "T1078.004": [
        TechniqueIndicator("T1078.004", "api_call", "aws", "sts:AssumeRole", None, 0.8),
        TechniqueIndicator("T1078.004", "api_call", "aws", "sts:AssumeRoleWithSAML", None, 0.85),
        TechniqueIndicator("T1078.004", "api_call", "aws", "sts:AssumeRoleWithWebIdentity", None, 0.85),
        TechniqueIndicator("T1078.004", "event_name", "aws", "ConsoleLogin",
                          {"errorCode": "exists"}, 0.9),
        TechniqueIndicator("T1078.004", "api_call", "gcp", "iam.serviceAccounts.actAs", None, 0.8),
    ],

    # T1110 - Brute Force
    "T1110": [
        TechniqueIndicator("T1110", "event_name", "aws", "ConsoleLogin",
                          {"errorCode": "exists"}, 0.85),
        TechniqueIndicator("T1110", "pattern", "aws", "failed_login_count > 5", None, 0.9),
    ],

    # T1562 - Impair Defenses
    "T1562": [
        TechniqueIndicator("T1562", "api_call", "aws", "guardduty:DeleteDetector", None, 0.95),
        TechniqueIndicator("T1562", "api_call", "aws", "guardduty:DisableOrganizationAdminAccount", None, 0.95),
        TechniqueIndicator("T1562", "api_call", "aws", "cloudtrail:StopLogging", None, 0.95),
        TechniqueIndicator("T1562", "api_call", "aws", "cloudtrail:DeleteTrail", None, 0.95),
        TechniqueIndicator("T1562", "api_call", "aws", "ec2:DeleteFlowLogs", None, 0.9),
        TechniqueIndicator("T1562", "api_call", "aws", "config:StopConfigurationRecorder", None, 0.9),
        TechniqueIndicator("T1562", "api_call", "gcp", "logging.sinks.delete", None, 0.9),
    ],

    # T1562.001 - Disable or Modify Tools
    "T1562.001": [
        TechniqueIndicator("T1562.001", "api_call", "aws", "guardduty:UpdateDetector",
                          {"enable": False}, 0.95),
        TechniqueIndicator("T1562.001", "api_call", "aws", "securityhub:DisableSecurityHub", None, 0.95),
    ],

    # T1530 - Data from Cloud Storage
    "T1530": [
        TechniqueIndicator("T1530", "api_call", "aws", "s3:GetObject", None, 0.5),
        TechniqueIndicator("T1530", "api_call", "aws", "s3:ListBucket", None, 0.4),
        TechniqueIndicator("T1530", "pattern", "aws", "s3_access_anomaly", None, 0.7),
        TechniqueIndicator("T1530", "api_call", "gcp", "storage.objects.get", None, 0.5),
    ],

    # T1136 - Create Account
    "T1136": [
        TechniqueIndicator("T1136", "api_call", "aws", "iam:CreateUser", None, 0.9),
        TechniqueIndicator("T1136", "api_call", "aws", "iam:CreateLoginProfile", None, 0.85),
        TechniqueIndicator("T1136", "api_call", "gcp", "iam.serviceAccounts.create", None, 0.9),
    ],

    # T1098 - Account Manipulation
    "T1098": [
        TechniqueIndicator("T1098", "api_call", "aws", "iam:AttachUserPolicy", None, 0.85),
        TechniqueIndicator("T1098", "api_call", "aws", "iam:AttachRolePolicy", None, 0.8),
        TechniqueIndicator("T1098", "api_call", "aws", "iam:PutUserPolicy", None, 0.85),
        TechniqueIndicator("T1098", "api_call", "aws", "iam:CreateAccessKey", None, 0.8),
        TechniqueIndicator("T1098", "api_call", "aws", "iam:UpdateLoginProfile", None, 0.75),
    ],

    # T1578 - Modify Cloud Compute Infrastructure
    "T1578": [
        TechniqueIndicator("T1578", "api_call", "aws", "ec2:RunInstances", None, 0.6),
        TechniqueIndicator("T1578", "api_call", "aws", "ec2:ModifyInstanceAttribute", None, 0.7),
    ],

    # T1578.002 - Create Cloud Instance
    "T1578.002": [
        TechniqueIndicator("T1578.002", "api_call", "aws", "ec2:RunInstances", None, 0.8),
        TechniqueIndicator("T1578.002", "api_call", "gcp", "compute.instances.insert", None, 0.8),
    ],

    # T1535 - Unused/Unsupported Cloud Regions
    "T1535": [
        TechniqueIndicator("T1535", "pattern", "aws", "unusual_region", None, 0.85),
        TechniqueIndicator("T1535", "api_call", "aws", "ec2:RunInstances",
                          {"region": "not_in_allowed"}, 0.9),
    ],

    # T1190 - Exploit Public-Facing Application
    "T1190": [
        TechniqueIndicator("T1190", "pattern", "aws", "waf_block", None, 0.7),
        TechniqueIndicator("T1190", "pattern", "aws", "alb_error_spike", None, 0.6),
    ],

    # Continue for all relevant techniques...
}


def build_indicator_list() -> List[TechniqueIndicator]:
    """Flatten library to list for matcher."""
    indicators = []
    for technique_id, technique_indicators in INDICATOR_LIBRARY.items():
        for ind in technique_indicators:
            ind.technique_id = technique_id  # Ensure consistency
            indicators.append(ind)
    return indicators
```

---

### Step 5: Confidence Scoring Framework

```python
@dataclass
class ConfidenceFactors:
    """Factors that influence mapping confidence."""

    # Base confidence from mapping method
    method_base: float  # pattern: 0.8, nlp: 0.6, ml: 0.5

    # Adjustments
    indicator_count_bonus: float   # +0.05 per additional indicator
    context_match_bonus: float     # +0.1 if context matches
    severity_alignment_bonus: float # +0.05 if severity aligns
    nlp_confirmation_bonus: float   # +0.1 if NLP agrees

    # Penalties
    low_parse_confidence_penalty: float  # -0.2 if parse confidence < 0.5
    generic_indicator_penalty: float     # -0.1 for generic matches (e.g., "s3:GetObject")
    no_context_penalty: float            # -0.1 if indicator usually needs context

def calculate_confidence(
    base_confidence: float,
    factors: ConfidenceFactors,
    detection: ParsedDetection,
    matched_indicators: List[TechniqueIndicator]
) -> float:
    """
    Calculate final confidence score with adjustments.

    Returns:
        Confidence between 0.0 and 1.0
    """

    confidence = base_confidence

    # Indicator count bonus (diminishing returns)
    if len(matched_indicators) > 1:
        bonus = min(0.15, (len(matched_indicators) - 1) * 0.05)
        confidence += bonus

    # Parse confidence penalty
    if detection.parse_confidence < 0.5:
        confidence -= 0.2

    # Check for generic indicators
    generic_indicators = ["s3:GetObject", "s3:ListBucket", "ec2:DescribeInstances"]
    if any(ind.indicator_value in generic_indicators for ind in matched_indicators):
        confidence -= 0.1

    # Clamp to valid range
    return max(0.0, min(1.0, confidence))


# Confidence interpretation
CONFIDENCE_LABELS = {
    (0.9, 1.0): "Very High",    # Expert manual mapping
    (0.8, 0.9): "High",         # Strong pattern match
    (0.6, 0.8): "Medium",       # Pattern + NLP agreement
    (0.4, 0.6): "Low",          # NLP-only or uncertain
    (0.0, 0.4): "Very Low",     # Speculative
}

def confidence_label(score: float) -> str:
    for (low, high), label in CONFIDENCE_LABELS.items():
        if low <= score < high:
            return label
    return "Unknown"
```

---

### Step 6: Mapping Pipeline

```python
class MappingPipeline:
    """
    Complete mapping pipeline from parsed detection to technique mappings.
    """

    def __init__(
        self,
        indicator_library: List[TechniqueIndicator],
        techniques: List[MITRETechnique],
        confidence_threshold: float = 0.6
    ):
        self.pattern_matcher = PatternMatcher(indicator_library)
        self.nlp_mapper = NLPMapper(techniques)
        self.hybrid_mapper = HybridMapper(
            self.pattern_matcher,
            self.nlp_mapper,
            confidence_threshold
        )
        self.confidence_threshold = confidence_threshold

    def map_detection(
        self,
        raw_detection: RawDetection,
        parsed_detection: ParsedDetection,
        provider: str
    ) -> List[MappingResult]:
        """
        Map a single detection to MITRE techniques.

        Returns:
            List of technique mappings above confidence threshold
        """

        mappings = self.hybrid_mapper.map(
            detection=parsed_detection,
            provider=provider,
            detection_name=raw_detection.name,
            detection_description=raw_detection.description
        )

        # Filter by threshold
        return [m for m in mappings if m.confidence >= self.confidence_threshold]

    def map_detections_batch(
        self,
        detections: List[Tuple[RawDetection, ParsedDetection]],
        provider: str
    ) -> Dict[str, List[MappingResult]]:
        """
        Map multiple detections in batch.

        Returns:
            Dict mapping detection_id to list of technique mappings
        """

        results = {}

        for raw, parsed in detections:
            detection_id = raw.external_id
            mappings = self.map_detection(raw, parsed, provider)
            results[detection_id] = mappings

        return results

    def generate_mapping_report(
        self,
        mappings: Dict[str, List[MappingResult]]
    ) -> Dict:
        """Generate summary statistics for batch mappings."""

        total_detections = len(mappings)
        mapped_detections = sum(1 for m in mappings.values() if m)
        unmapped_detections = total_detections - mapped_detections

        technique_counts = {}
        method_counts = {"pattern": 0, "nlp": 0, "ml": 0}
        confidence_distribution = {"very_high": 0, "high": 0, "medium": 0, "low": 0}

        for detection_id, mapping_list in mappings.items():
            for mapping in mapping_list:
                # Count techniques
                tech = mapping.technique_id
                technique_counts[tech] = technique_counts.get(tech, 0) + 1

                # Count methods
                method_counts[mapping.method] += 1

                # Count confidence levels
                label = confidence_label(mapping.confidence).lower().replace(" ", "_")
                if label in confidence_distribution:
                    confidence_distribution[label] += 1

        return {
            "total_detections": total_detections,
            "mapped_detections": mapped_detections,
            "unmapped_detections": unmapped_detections,
            "mapping_rate": mapped_detections / total_detections if total_detections > 0 else 0,
            "techniques_covered": len(technique_counts),
            "technique_counts": technique_counts,
            "method_distribution": method_counts,
            "confidence_distribution": confidence_distribution
        }
```

---

### Step 7: Feedback and Learning Loop

```python
from enum import Enum
from datetime import datetime

class FeedbackType(Enum):
    CONFIRM = "confirm"        # User confirms mapping is correct
    REJECT = "reject"          # User rejects mapping
    ADD = "add"                # User adds missing mapping
    ADJUST_CONFIDENCE = "adjust"  # User adjusts confidence

@dataclass
class MappingFeedback:
    """User feedback on a mapping."""
    detection_id: str
    technique_id: str
    feedback_type: FeedbackType
    user_id: str
    timestamp: datetime
    new_confidence: Optional[float] = None
    rationale: Optional[str] = None

class FeedbackProcessor:
    """
    Processes user feedback to improve mapping quality.
    """

    def __init__(self, db_session):
        self.db = db_session

    def apply_feedback(self, feedback: MappingFeedback):
        """Apply user feedback to mapping."""

        if feedback.feedback_type == FeedbackType.CONFIRM:
            self._confirm_mapping(feedback)
        elif feedback.feedback_type == FeedbackType.REJECT:
            self._reject_mapping(feedback)
        elif feedback.feedback_type == FeedbackType.ADD:
            self._add_mapping(feedback)
        elif feedback.feedback_type == FeedbackType.ADJUST_CONFIDENCE:
            self._adjust_confidence(feedback)

    def _confirm_mapping(self, feedback: MappingFeedback):
        """Mark mapping as validated, boost confidence."""
        mapping = self.db.get_mapping(feedback.detection_id, feedback.technique_id)
        if mapping:
            mapping.validation_status = "validated"
            mapping.confidence_score = min(1.0, mapping.confidence_score + 0.1)
            mapping.validated_by = feedback.user_id
            mapping.validated_at = feedback.timestamp
            self.db.save(mapping)

    def _reject_mapping(self, feedback: MappingFeedback):
        """Mark mapping as disputed or delete."""
        mapping = self.db.get_mapping(feedback.detection_id, feedback.technique_id)
        if mapping:
            mapping.validation_status = "disputed"
            mapping.rationale += f" | Rejected by {feedback.user_id}: {feedback.rationale}"
            self.db.save(mapping)

    def _add_mapping(self, feedback: MappingFeedback):
        """Add user-specified mapping."""
        new_mapping = DetectionMapping(
            detection_id=feedback.detection_id,
            technique_id=feedback.technique_id,
            confidence_score=feedback.new_confidence or 1.0,
            mapping_method="manual",
            mapped_by=feedback.user_id,
            mapped_at=feedback.timestamp,
            validation_status="validated",
            rationale=feedback.rationale or "User-added mapping"
        )
        self.db.save(new_mapping)

    def _adjust_confidence(self, feedback: MappingFeedback):
        """Adjust confidence score based on user input."""
        mapping = self.db.get_mapping(feedback.detection_id, feedback.technique_id)
        if mapping and feedback.new_confidence:
            mapping.confidence_score = feedback.new_confidence
            mapping.rationale += f" | Confidence adjusted by {feedback.user_id}"
            self.db.save(mapping)

    def extract_training_data(self) -> List[dict]:
        """
        Extract confirmed/rejected mappings for ML training.

        Returns:
            List of training examples with features and labels
        """
        confirmed = self.db.query_mappings(validation_status="validated")
        rejected = self.db.query_mappings(validation_status="disputed")

        training_data = []

        for mapping in confirmed:
            detection = self.db.get_detection(mapping.detection_id)
            training_data.append({
                "detection_features": self._extract_features(detection),
                "technique_id": mapping.technique_id,
                "label": 1,  # Correct mapping
                "confidence": mapping.confidence_score
            })

        for mapping in rejected:
            detection = self.db.get_detection(mapping.detection_id)
            training_data.append({
                "detection_features": self._extract_features(detection),
                "technique_id": mapping.technique_id,
                "label": 0,  # Incorrect mapping
                "confidence": 0.0
            })

        return training_data
```

---

### Step 8: MITRE Version Migration

```python
class MITREVersionManager:
    """
    Handles MITRE ATT&CK version updates and mapping migration.
    """

    def __init__(self, db_session):
        self.db = db_session

    def load_new_version(self, version: str, techniques: List[MITRETechnique]):
        """Load new MITRE version into database."""

        # Create version record
        version_record = MITREVersion(
            version=version,
            release_date=datetime.now(),
            is_current=False  # Don't activate yet
        )
        self.db.save(version_record)

        # Load techniques
        for tech in techniques:
            self.db.save_technique(tech, version_id=version_record.id)

    def migrate_mappings(self, old_version: str, new_version: str) -> dict:
        """
        Migrate mappings from old to new MITRE version.

        Handles:
        - Technique ID changes
        - Deprecated techniques
        - Split techniques (1 -> many)
        - Merged techniques (many -> 1)

        Returns:
            Migration report with statistics
        """

        migration_map = self._build_migration_map(old_version, new_version)

        stats = {
            "unchanged": 0,
            "migrated": 0,
            "deprecated": 0,
            "needs_review": 0
        }

        mappings = self.db.query_mappings(mitre_version=old_version)

        for mapping in mappings:
            old_tech = mapping.technique_id

            if old_tech in migration_map:
                action = migration_map[old_tech]

                if action["type"] == "unchanged":
                    # Just update version reference
                    mapping.mitre_version = new_version
                    self.db.save(mapping)
                    stats["unchanged"] += 1

                elif action["type"] == "renamed":
                    # Update technique ID
                    mapping.technique_id = action["new_id"]
                    mapping.mitre_version = new_version
                    mapping.rationale += f" | Migrated from {old_tech}"
                    self.db.save(mapping)
                    stats["migrated"] += 1

                elif action["type"] == "deprecated":
                    # Mark for review
                    mapping.validation_status = "pending"
                    mapping.rationale += f" | {old_tech} deprecated in {new_version}"
                    self.db.save(mapping)
                    stats["deprecated"] += 1

                elif action["type"] == "split":
                    # Create mappings for all new techniques
                    for new_tech in action["new_ids"]:
                        new_mapping = DetectionMapping(
                            detection_id=mapping.detection_id,
                            technique_id=new_tech,
                            confidence_score=mapping.confidence_score * 0.9,  # Reduce confidence
                            mapping_method=mapping.mapping_method,
                            mitre_version=new_version,
                            validation_status="pending",
                            rationale=f"Split from {old_tech}. Needs review."
                        )
                        self.db.save(new_mapping)
                    stats["needs_review"] += len(action["new_ids"])

            else:
                # Technique not in migration map - needs review
                mapping.validation_status = "pending"
                mapping.rationale += f" | Unknown status in {new_version}"
                self.db.save(mapping)
                stats["needs_review"] += 1

        # Activate new version
        self.db.set_current_version(new_version)

        return stats

    def _build_migration_map(self, old_version: str, new_version: str) -> dict:
        """
        Build mapping of technique ID changes between versions.

        Note: In production, this would parse MITRE's official
        changelog or use their STIX data.
        """

        # Simplified example - would need real data
        return {
            "T1078": {"type": "unchanged"},
            "T1078.001": {"type": "unchanged"},
            "T1078.002": {"type": "unchanged"},
            "T1078.003": {"type": "unchanged"},
            "T1078.004": {"type": "unchanged"},
            # Example of deprecated technique
            "T1234": {"type": "deprecated", "replacement": "T1235"},
            # Example of renamed technique
            "T1500": {"type": "renamed", "new_id": "T1501"},
            # Example of split technique
            "T1600": {"type": "split", "new_ids": ["T1600.001", "T1600.002"]},
        }
```

---

## Output Artifacts

### 1. Mapping Engine Implementation
**Files:**
- `src/mapping/pattern_matcher.py`
- `src/mapping/nlp_mapper.py`
- `src/mapping/hybrid_mapper.py`
- `src/mapping/pipeline.py`

### 2. Indicator Library
**Files:**
- `src/mapping/indicators/aws.py`
- `src/mapping/indicators/gcp.py`
- `data/indicators.json`

### 3. Confidence Framework
**File:** `src/mapping/confidence.py`

### 4. Feedback System
**File:** `src/mapping/feedback.py`

### 5. MITRE Version Manager
**File:** `src/mapping/mitre_version.py`

### 6. Test Cases
**Files:**
- `tests/mapping/test_pattern_matcher.py`
- `tests/mapping/test_nlp_mapper.py`
- `tests/mapping/test_confidence.py`
- `tests/fixtures/sample_mappings.json`

---

## Validation Checklist

- [ ] Pattern matcher achieves >80% precision on known mappings
- [ ] NLP mapper provides reasonable fallback for unmapped detections
- [ ] Confidence scores correlate with actual accuracy
- [ ] Indicator library covers top 50 cloud-relevant techniques
- [ ] Feedback loop allows users to correct mappings
- [ ] MITRE version migration preserves validated mappings
- [ ] Mapping latency < 100ms per detection
- [ ] Batch mapping scales to 1000s of detections

---

## Next Agent

Proceed to: **06-ANALYSIS-AGENT.md**

Provide the Analysis Agent with:
- Mapping output schema (technique_id, confidence, method)
- Expected mapping volume per account
- Confidence thresholds for coverage calculation

---

**END OF MAPPING AGENT**
