# Analysis Agent - Detection Coverage Validator

## Role
You are the Analysis Agent responsible for designing the coverage calculation, gap identification, and drift detection systems. Your job is to turn detection-to-technique mappings into actionable security insights.

## Prerequisites
- Review `detection-coverage-validator-model.md` - Section 2 (State Variables), Section 3C (Analysis Actions)
- Review mapping output schema from Mapping Agent
- Understand MITRE ATT&CK framework structure

## Your Mission
Design analysis systems that:
1. Calculate accurate coverage scores per tactic and technique
2. Identify and prioritize coverage gaps by risk
3. Detect coverage drift over time
4. Assess detection quality and health
5. Generate actionable recommendations

---

## Chain-of-Thought Reasoning Process

### Step 1: Understand Coverage Analysis

**Input:**
- Detection mappings: `{detection_id → [(technique_id, confidence), ...]}`
- Account assets: `{asset_type, criticality, data_classification}`
- MITRE framework: `{technique_id → {tactics, platforms, data_sources}}`

**Output:**
- Coverage scores: `{tactic_id → percentage}`
- Gap list: `[(technique_id, severity, risk_score, recommendations)]`
- Drift events: `[(technique_id, change_type, timestamp)]`

**Key Questions:**
```
1. What counts as "covered"?
   - Any detection with confidence > threshold?
   - Only validated mappings?
   - Weighted by confidence?

2. How to handle multi-technique detections?
   - Full credit to each technique?
   - Partial credit split across techniques?

3. How to weight techniques?
   - All equal?
   - By prevalence/severity?
   - By asset criticality?

4. What makes a gap "critical"?
   - Missing coverage for high-severity technique?
   - No detection for assets with sensitive data?
   - Technique actively exploited (CTI)?
```

---

### Step 2: Coverage Calculation Engine

#### Core Coverage Algorithm

```python
from dataclasses import dataclass
from typing import Dict, List, Set, Optional
from enum import Enum
from decimal import Decimal

@dataclass
class TechniqueCoverage:
    """Coverage status for a single technique."""
    technique_id: str
    technique_name: str
    tactic_ids: List[str]
    detection_count: int
    max_confidence: float
    avg_confidence: float
    detection_ids: List[str]
    coverage_status: str  # "covered", "partial", "none"
    is_applicable: bool   # Relevant to this account's assets

@dataclass
class TacticCoverage:
    """Coverage summary for a tactic."""
    tactic_id: str
    tactic_name: str
    total_techniques: int
    covered_techniques: int
    partial_techniques: int
    uncovered_techniques: int
    coverage_percentage: float
    weighted_coverage: float  # Quality-adjusted

@dataclass
class AccountCoverage:
    """Overall coverage for an account."""
    account_id: str
    mitre_version: str
    calculated_at: str
    overall_percentage: float
    weighted_percentage: float
    tactics: List[TacticCoverage]
    techniques: List[TechniqueCoverage]
    total_detections: int
    mapped_detections: int
    unmapped_detections: int


class CoverageCalculator:
    """
    Calculates MITRE ATT&CK coverage from detection mappings.
    """

    def __init__(
        self,
        techniques: List[MITRETechnique],
        confidence_threshold: float = 0.6,
        partial_threshold: float = 0.4
    ):
        self.techniques = {t.technique_id: t for t in techniques}
        self.confidence_threshold = confidence_threshold
        self.partial_threshold = partial_threshold

        # Build tactic -> techniques index
        self.tactic_techniques: Dict[str, List[str]] = {}
        for tech in techniques:
            for tactic in tech.tactics:
                if tactic not in self.tactic_techniques:
                    self.tactic_techniques[tactic] = []
                self.tactic_techniques[tactic].append(tech.technique_id)

    def calculate(
        self,
        account_id: str,
        mappings: Dict[str, List[MappingResult]],
        account_assets: Optional[List[Dict]] = None,
        mitre_version: str = "v13.1"
    ) -> AccountCoverage:
        """
        Calculate coverage for an account.

        Args:
            account_id: Account identifier
            mappings: Dict of detection_id -> list of technique mappings
            account_assets: Optional list of assets for filtering
            mitre_version: MITRE ATT&CK version

        Returns:
            Complete coverage analysis
        """

        # Step 1: Build technique -> detections index
        technique_detections = self._build_technique_index(mappings)

        # Step 2: Determine applicable techniques
        applicable_techniques = self._get_applicable_techniques(account_assets)

        # Step 3: Calculate per-technique coverage
        technique_coverages = []
        for tech_id, tech in self.techniques.items():
            coverage = self._calculate_technique_coverage(
                tech_id,
                tech,
                technique_detections.get(tech_id, []),
                tech_id in applicable_techniques
            )
            technique_coverages.append(coverage)

        # Step 4: Calculate per-tactic coverage
        tactic_coverages = self._calculate_tactic_coverages(technique_coverages)

        # Step 5: Calculate overall coverage
        overall, weighted = self._calculate_overall_coverage(tactic_coverages)

        # Step 6: Count detection statistics
        total_detections = len(mappings)
        mapped_detections = sum(1 for m in mappings.values() if m)
        unmapped_detections = total_detections - mapped_detections

        return AccountCoverage(
            account_id=account_id,
            mitre_version=mitre_version,
            calculated_at=datetime.utcnow().isoformat(),
            overall_percentage=overall,
            weighted_percentage=weighted,
            tactics=tactic_coverages,
            techniques=technique_coverages,
            total_detections=total_detections,
            mapped_detections=mapped_detections,
            unmapped_detections=unmapped_detections
        )

    def _build_technique_index(
        self,
        mappings: Dict[str, List[MappingResult]]
    ) -> Dict[str, List[tuple]]:
        """Build index of technique -> (detection_id, confidence)."""

        index = {}

        for detection_id, mapping_list in mappings.items():
            for mapping in mapping_list:
                tech_id = mapping.technique_id
                if tech_id not in index:
                    index[tech_id] = []
                index[tech_id].append((detection_id, mapping.confidence))

        return index

    def _get_applicable_techniques(
        self,
        assets: Optional[List[Dict]]
    ) -> Set[str]:
        """
        Determine which techniques are applicable based on assets.

        For example, if account has no S3 buckets, T1530 is not applicable.
        """

        if assets is None:
            # No asset info - assume all techniques apply
            return set(self.techniques.keys())

        applicable = set()
        asset_types = {a['asset_type'] for a in assets}

        # Map asset types to applicable techniques
        # This is a simplified mapping - would need comprehensive list
        asset_technique_map = {
            "ec2": ["T1578", "T1578.002", "T1535", "T1496"],
            "s3": ["T1530", "T1537", "T1119"],
            "iam": ["T1078", "T1078.004", "T1098", "T1136"],
            "rds": ["T1213", "T1552"],
            "lambda": ["T1059", "T1608"],
            "vpc": ["T1046", "T1021"],
        }

        for asset_type in asset_types:
            asset_type_lower = asset_type.lower()
            for key, techniques in asset_technique_map.items():
                if key in asset_type_lower:
                    applicable.update(techniques)

        # Always include common techniques
        common_techniques = [
            "T1078", "T1078.004", "T1562", "T1110", "T1098"
        ]
        applicable.update(common_techniques)

        return applicable

    def _calculate_technique_coverage(
        self,
        tech_id: str,
        tech: MITRETechnique,
        detections: List[tuple],
        is_applicable: bool
    ) -> TechniqueCoverage:
        """Calculate coverage for a single technique."""

        detection_count = len(detections)

        if detection_count == 0:
            return TechniqueCoverage(
                technique_id=tech_id,
                technique_name=tech.name,
                tactic_ids=tech.tactics,
                detection_count=0,
                max_confidence=0.0,
                avg_confidence=0.0,
                detection_ids=[],
                coverage_status="none",
                is_applicable=is_applicable
            )

        confidences = [conf for _, conf in detections]
        max_conf = max(confidences)
        avg_conf = sum(confidences) / len(confidences)
        detection_ids = [det_id for det_id, _ in detections]

        # Determine status
        if max_conf >= self.confidence_threshold:
            status = "covered"
        elif max_conf >= self.partial_threshold:
            status = "partial"
        else:
            status = "none"

        return TechniqueCoverage(
            technique_id=tech_id,
            technique_name=tech.name,
            tactic_ids=tech.tactics,
            detection_count=detection_count,
            max_confidence=max_conf,
            avg_confidence=avg_conf,
            detection_ids=detection_ids,
            coverage_status=status,
            is_applicable=is_applicable
        )

    def _calculate_tactic_coverages(
        self,
        technique_coverages: List[TechniqueCoverage]
    ) -> List[TacticCoverage]:
        """Calculate coverage per tactic."""

        # Build tactic -> techniques mapping
        tactic_tech_coverage: Dict[str, List[TechniqueCoverage]] = {}

        for tech_cov in technique_coverages:
            if not tech_cov.is_applicable:
                continue  # Skip non-applicable techniques

            for tactic in tech_cov.tactic_ids:
                if tactic not in tactic_tech_coverage:
                    tactic_tech_coverage[tactic] = []
                tactic_tech_coverage[tactic].append(tech_cov)

        # Calculate per-tactic stats
        tactic_coverages = []

        tactic_names = {
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Credential Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Movement",
            "TA0009": "Collection",
            "TA0010": "Exfiltration",
            "TA0011": "Command and Control",
            "TA0040": "Impact"
        }

        for tactic_id, name in tactic_names.items():
            techs = tactic_tech_coverage.get(tactic_id, [])
            total = len(techs)

            if total == 0:
                tactic_coverages.append(TacticCoverage(
                    tactic_id=tactic_id,
                    tactic_name=name,
                    total_techniques=0,
                    covered_techniques=0,
                    partial_techniques=0,
                    uncovered_techniques=0,
                    coverage_percentage=0.0,
                    weighted_coverage=0.0
                ))
                continue

            covered = sum(1 for t in techs if t.coverage_status == "covered")
            partial = sum(1 for t in techs if t.coverage_status == "partial")
            uncovered = sum(1 for t in techs if t.coverage_status == "none")

            # Simple percentage
            coverage_pct = (covered / total) * 100 if total > 0 else 0.0

            # Weighted coverage (partial counts as 0.5)
            weighted = ((covered + partial * 0.5) / total) * 100 if total > 0 else 0.0

            tactic_coverages.append(TacticCoverage(
                tactic_id=tactic_id,
                tactic_name=name,
                total_techniques=total,
                covered_techniques=covered,
                partial_techniques=partial,
                uncovered_techniques=uncovered,
                coverage_percentage=round(coverage_pct, 2),
                weighted_coverage=round(weighted, 2)
            ))

        return tactic_coverages

    def _calculate_overall_coverage(
        self,
        tactic_coverages: List[TacticCoverage]
    ) -> tuple:
        """Calculate overall coverage from tactic coverages."""

        total_techniques = sum(t.total_techniques for t in tactic_coverages)
        covered_techniques = sum(t.covered_techniques for t in tactic_coverages)
        partial_techniques = sum(t.partial_techniques for t in tactic_coverages)

        if total_techniques == 0:
            return 0.0, 0.0

        overall = (covered_techniques / total_techniques) * 100
        weighted = ((covered_techniques + partial_techniques * 0.5) / total_techniques) * 100

        return round(overall, 2), round(weighted, 2)
```

---

### Step 3: Gap Identification System

```python
from enum import Enum

class GapSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class CoverageGap:
    """Identified coverage gap for a technique."""
    gap_id: str
    account_id: str
    technique_id: str
    technique_name: str
    tactics: List[str]
    severity: GapSeverity
    risk_score: float           # 0-100
    affected_assets: List[Dict]
    business_impact: str
    recommendations: List[Dict]
    status: str                 # open, acknowledged, remediated, accepted_risk
    first_identified: str
    detection_guidance: str     # From MITRE


class GapAnalyzer:
    """
    Identifies and prioritizes coverage gaps.
    """

    def __init__(
        self,
        techniques: Dict[str, MITRETechnique],
        technique_severity: Dict[str, float],  # Technique prevalence/severity weights
        asset_criticality_weights: Dict[str, float] = None
    ):
        self.techniques = techniques
        self.technique_severity = technique_severity
        self.asset_weights = asset_criticality_weights or {
            "critical": 1.0,
            "high": 0.75,
            "medium": 0.5,
            "low": 0.25
        }

    def identify_gaps(
        self,
        account_id: str,
        coverage: AccountCoverage,
        assets: List[Dict] = None
    ) -> List[CoverageGap]:
        """
        Identify all coverage gaps for an account.

        Args:
            account_id: Account identifier
            coverage: Calculated coverage data
            assets: Account assets for risk scoring

        Returns:
            List of CoverageGap sorted by risk_score
        """

        gaps = []

        for tech_cov in coverage.techniques:
            # Only uncovered and applicable techniques are gaps
            if tech_cov.coverage_status != "none" or not tech_cov.is_applicable:
                continue

            technique = self.techniques.get(tech_cov.technique_id)
            if not technique:
                continue

            # Calculate risk score
            risk_score = self._calculate_risk_score(
                tech_cov.technique_id,
                assets
            )

            # Determine severity from risk score
            severity = self._risk_to_severity(risk_score)

            # Find affected assets
            affected = self._find_affected_assets(tech_cov.technique_id, assets)

            # Generate business impact statement
            business_impact = self._generate_impact_statement(
                technique,
                affected,
                severity
            )

            # Get recommendations
            recommendations = self._generate_recommendations(
                tech_cov.technique_id,
                technique
            )

            gap = CoverageGap(
                gap_id=f"gap-{account_id}-{tech_cov.technique_id}",
                account_id=account_id,
                technique_id=tech_cov.technique_id,
                technique_name=tech_cov.technique_name,
                tactics=tech_cov.tactic_ids,
                severity=severity,
                risk_score=risk_score,
                affected_assets=affected,
                business_impact=business_impact,
                recommendations=recommendations,
                status="open",
                first_identified=datetime.utcnow().isoformat(),
                detection_guidance=technique.detection_guidance
            )
            gaps.append(gap)

        # Sort by risk score descending
        gaps.sort(key=lambda g: g.risk_score, reverse=True)

        return gaps

    def _calculate_risk_score(
        self,
        technique_id: str,
        assets: List[Dict]
    ) -> float:
        """
        Calculate risk score for a gap.

        Risk = Technique Severity × Asset Criticality × Exposure Factor
        """

        # Base technique severity (0-50 range)
        tech_severity = self.technique_severity.get(technique_id, 25)

        # Asset criticality factor (0-1)
        if assets:
            asset_factor = self._calculate_asset_factor(technique_id, assets)
        else:
            asset_factor = 0.5  # Default if no asset info

        # Exposure factor based on technique characteristics
        exposure = self._calculate_exposure_factor(technique_id)

        # Combine factors
        risk = (tech_severity * 0.5) + (asset_factor * 30) + (exposure * 20)

        return min(100, max(0, round(risk, 2)))

    def _calculate_asset_factor(
        self,
        technique_id: str,
        assets: List[Dict]
    ) -> float:
        """Calculate asset criticality factor."""

        relevant_assets = self._find_affected_assets(technique_id, assets)

        if not relevant_assets:
            return 0.3  # Low factor if no relevant assets

        # Take highest criticality
        max_crit = 0.0
        for asset in relevant_assets:
            crit = asset.get('criticality', 'medium')
            max_crit = max(max_crit, self.asset_weights.get(crit, 0.5))

        return max_crit

    def _calculate_exposure_factor(self, technique_id: str) -> float:
        """Calculate exposure factor based on technique characteristics."""

        # Techniques that are commonly exploited get higher factor
        high_exposure_techniques = [
            "T1078", "T1110", "T1190", "T1562", "T1530",
            "T1098", "T1136", "T1059", "T1021"
        ]

        if technique_id in high_exposure_techniques:
            return 1.0

        # Sub-techniques inherit from parent
        if "." in technique_id:
            parent = technique_id.split(".")[0]
            if parent in high_exposure_techniques:
                return 0.8

        return 0.5  # Default exposure

    def _risk_to_severity(self, risk_score: float) -> GapSeverity:
        """Convert risk score to severity level."""
        if risk_score >= 80:
            return GapSeverity.CRITICAL
        elif risk_score >= 60:
            return GapSeverity.HIGH
        elif risk_score >= 40:
            return GapSeverity.MEDIUM
        else:
            return GapSeverity.LOW

    def _find_affected_assets(
        self,
        technique_id: str,
        assets: List[Dict]
    ) -> List[Dict]:
        """Find assets affected by a technique gap."""

        if not assets:
            return []

        # Map techniques to relevant asset types
        technique_asset_map = {
            "T1530": ["s3", "storage"],
            "T1078": ["iam", "user", "role"],
            "T1578": ["ec2", "instance", "compute"],
            "T1213": ["rds", "database", "dynamodb"],
            # ... more mappings
        }

        relevant_types = technique_asset_map.get(technique_id, [])

        # Also check parent technique
        if "." in technique_id:
            parent = technique_id.split(".")[0]
            relevant_types.extend(technique_asset_map.get(parent, []))

        affected = []
        for asset in assets:
            asset_type = asset.get('asset_type', '').lower()
            if any(rt in asset_type for rt in relevant_types):
                affected.append(asset)

        return affected

    def _generate_impact_statement(
        self,
        technique: MITRETechnique,
        affected_assets: List[Dict],
        severity: GapSeverity
    ) -> str:
        """Generate human-readable business impact statement."""

        if severity == GapSeverity.CRITICAL:
            prefix = "Critical risk"
        elif severity == GapSeverity.HIGH:
            prefix = "High risk"
        elif severity == GapSeverity.MEDIUM:
            prefix = "Moderate risk"
        else:
            prefix = "Low risk"

        asset_count = len(affected_assets)
        asset_str = f"{asset_count} assets" if asset_count > 0 else "assets"

        return (
            f"{prefix}: No detection for {technique.name}. "
            f"Attackers using this technique against {asset_str} "
            f"would go undetected. {technique.description[:200]}..."
        )

    def _generate_recommendations(
        self,
        technique_id: str,
        technique: MITRETechnique
    ) -> List[Dict]:
        """Generate detection recommendations for a gap."""

        # This would query a template library
        # Simplified example
        recommendations = []

        if "T1078" in technique_id:
            recommendations.append({
                "title": "Monitor failed login attempts",
                "service": "cloudwatch",
                "detection_type": "log_query",
                "effort": "low",
                "estimated_cost": "$5/month",
                "template_id": "failed-login-cloudwatch"
            })
            recommendations.append({
                "title": "Enable GuardDuty",
                "service": "guardduty",
                "detection_type": "managed",
                "effort": "low",
                "estimated_cost": "variable",
                "template_id": "guardduty-enable"
            })

        elif "T1562" in technique_id:
            recommendations.append({
                "title": "Alert on security service changes",
                "service": "eventbridge",
                "detection_type": "event_pattern",
                "effort": "low",
                "estimated_cost": "$2/month",
                "template_id": "security-service-changes"
            })

        # Default recommendation
        if not recommendations:
            recommendations.append({
                "title": f"Implement detection for {technique.name}",
                "service": "cloudwatch",
                "detection_type": "log_query",
                "effort": "medium",
                "estimated_cost": "varies",
                "template_id": None,
                "guidance": technique.detection_guidance
            })

        return recommendations
```

---

### Step 4: Drift Detection System

```python
from dataclasses import dataclass
from typing import Optional
from enum import Enum

class DriftType(Enum):
    DETECTION_ADDED = "detection_added"
    DETECTION_REMOVED = "detection_removed"
    DETECTION_DISABLED = "detection_disabled"
    DETECTION_MODIFIED = "detection_modified"
    COVERAGE_INCREASED = "coverage_increased"
    COVERAGE_DECREASED = "coverage_decreased"
    COVERAGE_LOST = "coverage_lost"  # Zero detections now

@dataclass
class DriftEvent:
    """Single drift event between snapshots."""
    event_id: str
    account_id: str
    drift_type: DriftType
    technique_id: Optional[str]
    detection_id: Optional[str]
    detection_name: Optional[str]
    timestamp: str
    severity: GapSeverity
    details: Dict
    previous_state: Optional[Dict]
    current_state: Optional[Dict]


class DriftDetector:
    """
    Detects coverage drift between scan snapshots.
    """

    def __init__(self, db_session):
        self.db = db_session

    def detect_drift(
        self,
        account_id: str,
        current_snapshot: Dict,
        previous_snapshot: Optional[Dict] = None,
        lookback_days: int = 30
    ) -> List[DriftEvent]:
        """
        Detect drift between current and previous snapshots.

        Args:
            account_id: Account identifier
            current_snapshot: Current scan snapshot
            previous_snapshot: Previous snapshot (or fetch from DB)
            lookback_days: How far back to look for previous

        Returns:
            List of drift events
        """

        # Get previous snapshot if not provided
        if previous_snapshot is None:
            previous_snapshot = self.db.get_previous_snapshot(
                account_id,
                lookback_days
            )

        if previous_snapshot is None:
            # No previous data - no drift detection possible
            return []

        events = []

        # Detect detection-level changes
        events.extend(self._detect_detection_drift(
            account_id,
            current_snapshot.get('detections', {}),
            previous_snapshot.get('detections', {})
        ))

        # Detect coverage-level changes
        events.extend(self._detect_coverage_drift(
            account_id,
            current_snapshot.get('coverage', {}),
            previous_snapshot.get('coverage', {})
        ))

        # Sort by severity
        severity_order = {
            GapSeverity.CRITICAL: 0,
            GapSeverity.HIGH: 1,
            GapSeverity.MEDIUM: 2,
            GapSeverity.LOW: 3
        }
        events.sort(key=lambda e: severity_order.get(e.severity, 4))

        return events

    def _detect_detection_drift(
        self,
        account_id: str,
        current_detections: Dict,
        previous_detections: Dict
    ) -> List[DriftEvent]:
        """Detect changes in detection inventory."""

        events = []
        current_ids = set(current_detections.keys())
        previous_ids = set(previous_detections.keys())

        # New detections
        for det_id in current_ids - previous_ids:
            det = current_detections[det_id]
            events.append(DriftEvent(
                event_id=f"drift-{uuid.uuid4().hex[:8]}",
                account_id=account_id,
                drift_type=DriftType.DETECTION_ADDED,
                technique_id=None,
                detection_id=det_id,
                detection_name=det.get('name'),
                timestamp=datetime.utcnow().isoformat(),
                severity=GapSeverity.LOW,  # Adding is usually good
                details={"action": "added"},
                previous_state=None,
                current_state=det
            ))

        # Removed detections
        for det_id in previous_ids - current_ids:
            det = previous_detections[det_id]
            events.append(DriftEvent(
                event_id=f"drift-{uuid.uuid4().hex[:8]}",
                account_id=account_id,
                drift_type=DriftType.DETECTION_REMOVED,
                technique_id=None,
                detection_id=det_id,
                detection_name=det.get('name'),
                timestamp=datetime.utcnow().isoformat(),
                severity=GapSeverity.HIGH,  # Removal is concerning
                details={"action": "removed"},
                previous_state=det,
                current_state=None
            ))

        # Modified or disabled detections
        for det_id in current_ids & previous_ids:
            current = current_detections[det_id]
            previous = previous_detections[det_id]

            # Check status change
            if current.get('status') != previous.get('status'):
                if current.get('status') == 'disabled':
                    events.append(DriftEvent(
                        event_id=f"drift-{uuid.uuid4().hex[:8]}",
                        account_id=account_id,
                        drift_type=DriftType.DETECTION_DISABLED,
                        technique_id=None,
                        detection_id=det_id,
                        detection_name=current.get('name'),
                        timestamp=datetime.utcnow().isoformat(),
                        severity=GapSeverity.HIGH,
                        details={
                            "previous_status": previous.get('status'),
                            "current_status": current.get('status')
                        },
                        previous_state=previous,
                        current_state=current
                    ))

            # Check config change
            if current.get('config_hash') != previous.get('config_hash'):
                events.append(DriftEvent(
                    event_id=f"drift-{uuid.uuid4().hex[:8]}",
                    account_id=account_id,
                    drift_type=DriftType.DETECTION_MODIFIED,
                    technique_id=None,
                    detection_id=det_id,
                    detection_name=current.get('name'),
                    timestamp=datetime.utcnow().isoformat(),
                    severity=GapSeverity.MEDIUM,
                    details={"action": "modified"},
                    previous_state=previous,
                    current_state=current
                ))

        return events

    def _detect_coverage_drift(
        self,
        account_id: str,
        current_coverage: Dict,
        previous_coverage: Dict
    ) -> List[DriftEvent]:
        """Detect changes in technique coverage."""

        events = []

        current_techniques = current_coverage.get('technique_coverage', {})
        previous_techniques = previous_coverage.get('technique_coverage', {})

        for tech_id in set(current_techniques.keys()) | set(previous_techniques.keys()):
            current_count = current_techniques.get(tech_id, {}).get('detection_count', 0)
            previous_count = previous_techniques.get(tech_id, {}).get('detection_count', 0)

            if current_count == previous_count:
                continue

            # Coverage increased
            if current_count > previous_count:
                events.append(DriftEvent(
                    event_id=f"drift-{uuid.uuid4().hex[:8]}",
                    account_id=account_id,
                    drift_type=DriftType.COVERAGE_INCREASED,
                    technique_id=tech_id,
                    detection_id=None,
                    detection_name=None,
                    timestamp=datetime.utcnow().isoformat(),
                    severity=GapSeverity.LOW,  # Improvement
                    details={
                        "previous_count": previous_count,
                        "current_count": current_count,
                        "change": current_count - previous_count
                    },
                    previous_state={"detection_count": previous_count},
                    current_state={"detection_count": current_count}
                ))

            # Coverage decreased
            elif current_count < previous_count:
                if current_count == 0:
                    drift_type = DriftType.COVERAGE_LOST
                    severity = GapSeverity.CRITICAL
                else:
                    drift_type = DriftType.COVERAGE_DECREASED
                    severity = GapSeverity.HIGH if previous_count > 2 else GapSeverity.MEDIUM

                events.append(DriftEvent(
                    event_id=f"drift-{uuid.uuid4().hex[:8]}",
                    account_id=account_id,
                    drift_type=drift_type,
                    technique_id=tech_id,
                    detection_id=None,
                    detection_name=None,
                    timestamp=datetime.utcnow().isoformat(),
                    severity=severity,
                    details={
                        "previous_count": previous_count,
                        "current_count": current_count,
                        "change": current_count - previous_count
                    },
                    previous_state={"detection_count": previous_count},
                    current_state={"detection_count": current_count}
                ))

        return events

    def get_drift_summary(
        self,
        account_id: str,
        days: int = 30
    ) -> Dict:
        """Get drift summary for an account over time period."""

        events = self.db.get_drift_events(account_id, days)

        return {
            "account_id": account_id,
            "period_days": days,
            "total_events": len(events),
            "by_type": {
                drift_type.value: sum(1 for e in events if e.drift_type == drift_type)
                for drift_type in DriftType
            },
            "by_severity": {
                severity.value: sum(1 for e in events if e.severity == severity)
                for severity in GapSeverity
            },
            "coverage_improved": sum(
                1 for e in events
                if e.drift_type in [DriftType.DETECTION_ADDED, DriftType.COVERAGE_INCREASED]
            ),
            "coverage_degraded": sum(
                1 for e in events
                if e.drift_type in [
                    DriftType.DETECTION_REMOVED,
                    DriftType.DETECTION_DISABLED,
                    DriftType.COVERAGE_DECREASED,
                    DriftType.COVERAGE_LOST
                ]
            )
        }
```

---

### Step 5: Detection Health Assessment

```python
@dataclass
class DetectionHealth:
    """Health assessment for a single detection."""
    detection_id: str
    status: str           # healthy, degraded, broken, unknown
    health_score: float   # 0.0 to 1.0
    last_validated: str
    last_triggered: Optional[str]
    trigger_count_30d: int
    issues: List[str]
    api_drift_detected: bool
    deprecated_apis: List[str]


class HealthAssessor:
    """
    Assesses detection health and functionality.
    """

    def __init__(
        self,
        api_deprecation_db,
        trigger_history_db=None
    ):
        self.deprecations = api_deprecation_db
        self.trigger_history = trigger_history_db

    def assess_detection(
        self,
        detection: NormalizedDetection,
        mappings: List[MappingResult]
    ) -> DetectionHealth:
        """
        Assess health of a single detection.

        Checks:
        1. Syntax validity (was it parsed successfully?)
        2. API deprecations (does it use deprecated APIs?)
        3. Trigger history (has it ever fired?)
        4. Mapping quality (is it mapped to anything?)
        """

        issues = []
        health_score = 1.0

        # Check 1: Parse success
        if not detection.parse_success:
            issues.append("Detection could not be fully parsed")
            health_score -= 0.3

        if detection.parse_confidence < 0.5:
            issues.append("Low parse confidence - detection logic uncertain")
            health_score -= 0.2

        # Check 2: API deprecations
        deprecated = self._check_api_deprecations(detection)
        if deprecated:
            issues.append(f"Uses deprecated APIs: {', '.join(deprecated)}")
            health_score -= 0.4
            api_drift = True
        else:
            api_drift = False

        # Check 3: Trigger history
        trigger_info = self._get_trigger_history(detection.detection_id)
        last_triggered = trigger_info.get('last_triggered')
        trigger_count = trigger_info.get('count_30d', 0)

        if trigger_count == 0:
            # Never triggered - could be dead or just no activity
            issues.append("Detection has not triggered in 30 days")
            health_score -= 0.1

        # Check 4: Mapping quality
        if not mappings:
            issues.append("Detection is not mapped to any MITRE techniques")
            health_score -= 0.2
        elif all(m.confidence < 0.6 for m in mappings):
            issues.append("All technique mappings have low confidence")
            health_score -= 0.1

        # Check 5: Detection is disabled
        if detection.status == "disabled":
            issues.append("Detection is disabled")
            health_score -= 0.5

        # Determine status
        health_score = max(0.0, health_score)
        if health_score >= 0.8:
            status = "healthy"
        elif health_score >= 0.5:
            status = "degraded"
        elif health_score > 0:
            status = "broken"
        else:
            status = "unknown"

        return DetectionHealth(
            detection_id=detection.detection_id,
            status=status,
            health_score=health_score,
            last_validated=datetime.utcnow().isoformat(),
            last_triggered=last_triggered,
            trigger_count_30d=trigger_count,
            issues=issues,
            api_drift_detected=api_drift,
            deprecated_apis=deprecated
        )

    def _check_api_deprecations(
        self,
        detection: NormalizedDetection
    ) -> List[str]:
        """Check if detection uses deprecated APIs."""

        deprecated = []

        # Check monitored entities
        for entity in detection.monitored_entities:
            if entity.entity_type == "api_call":
                deprecation = self.deprecations.check_api(
                    entity.entity_id,
                    detection.provider.value
                )
                if deprecation:
                    deprecated.append(entity.entity_id)

        # Check raw config for API references
        config_str = str(detection.raw_config)
        known_deprecated = self.deprecations.get_all_deprecated(detection.provider.value)

        for api in known_deprecated:
            if api in config_str:
                deprecated.append(api)

        return list(set(deprecated))

    def _get_trigger_history(self, detection_id: str) -> Dict:
        """Get trigger history for a detection."""

        if self.trigger_history is None:
            return {"last_triggered": None, "count_30d": -1}

        return self.trigger_history.get_stats(detection_id, days=30)

    def assess_account_health(
        self,
        account_id: str,
        detections: List[NormalizedDetection],
        mappings: Dict[str, List[MappingResult]]
    ) -> Dict:
        """Assess overall detection health for an account."""

        health_results = []

        for detection in detections:
            det_mappings = mappings.get(detection.detection_id, [])
            health = self.assess_detection(detection, det_mappings)
            health_results.append(health)

        # Aggregate
        total = len(health_results)
        healthy = sum(1 for h in health_results if h.status == "healthy")
        degraded = sum(1 for h in health_results if h.status == "degraded")
        broken = sum(1 for h in health_results if h.status == "broken")
        unknown = sum(1 for h in health_results if h.status == "unknown")

        avg_score = (
            sum(h.health_score for h in health_results) / total
            if total > 0 else 0.0
        )

        with_deprecations = sum(1 for h in health_results if h.api_drift_detected)
        never_triggered = sum(1 for h in health_results if h.trigger_count_30d == 0)

        return {
            "account_id": account_id,
            "total_detections": total,
            "healthy": healthy,
            "degraded": degraded,
            "broken": broken,
            "unknown": unknown,
            "average_health_score": round(avg_score, 2),
            "detections_with_deprecations": with_deprecations,
            "detections_never_triggered": never_triggered,
            "health_by_detection": {
                h.detection_id: {
                    "status": h.status,
                    "score": h.health_score,
                    "issues": h.issues
                }
                for h in health_results
            }
        }
```

---

### Step 6: Analysis Pipeline

```python
class AnalysisPipeline:
    """
    Complete analysis pipeline from mappings to insights.
    """

    def __init__(
        self,
        coverage_calculator: CoverageCalculator,
        gap_analyzer: GapAnalyzer,
        drift_detector: DriftDetector,
        health_assessor: HealthAssessor
    ):
        self.coverage = coverage_calculator
        self.gaps = gap_analyzer
        self.drift = drift_detector
        self.health = health_assessor

    def analyze_account(
        self,
        account_id: str,
        detections: List[NormalizedDetection],
        mappings: Dict[str, List[MappingResult]],
        assets: Optional[List[Dict]] = None,
        previous_snapshot: Optional[Dict] = None
    ) -> Dict:
        """
        Run complete analysis for an account.

        Returns:
            Comprehensive analysis report
        """

        # 1. Calculate coverage
        coverage = self.coverage.calculate(
            account_id=account_id,
            mappings=mappings,
            account_assets=assets
        )

        # 2. Identify gaps
        gaps = self.gaps.identify_gaps(
            account_id=account_id,
            coverage=coverage,
            assets=assets
        )

        # 3. Detect drift (if previous data available)
        drift_events = []
        if previous_snapshot:
            current_snapshot = self._build_snapshot(detections, mappings, coverage)
            drift_events = self.drift.detect_drift(
                account_id=account_id,
                current_snapshot=current_snapshot,
                previous_snapshot=previous_snapshot
            )

        # 4. Assess health
        health = self.health.assess_account_health(
            account_id=account_id,
            detections=detections,
            mappings=mappings
        )

        # 5. Generate summary
        return {
            "account_id": account_id,
            "analyzed_at": datetime.utcnow().isoformat(),
            "summary": {
                "overall_coverage": coverage.overall_percentage,
                "weighted_coverage": coverage.weighted_percentage,
                "total_detections": coverage.total_detections,
                "mapped_detections": coverage.mapped_detections,
                "total_gaps": len(gaps),
                "critical_gaps": sum(1 for g in gaps if g.severity == GapSeverity.CRITICAL),
                "high_gaps": sum(1 for g in gaps if g.severity == GapSeverity.HIGH),
                "drift_events": len(drift_events),
                "health_score": health["average_health_score"]
            },
            "coverage": {
                "by_tactic": [
                    {
                        "tactic_id": t.tactic_id,
                        "tactic_name": t.tactic_name,
                        "coverage_percentage": t.coverage_percentage,
                        "covered": t.covered_techniques,
                        "total": t.total_techniques
                    }
                    for t in coverage.tactics
                ],
                "overall_percentage": coverage.overall_percentage
            },
            "gaps": [
                {
                    "technique_id": g.technique_id,
                    "technique_name": g.technique_name,
                    "severity": g.severity.value,
                    "risk_score": g.risk_score,
                    "recommendations": g.recommendations
                }
                for g in gaps[:20]  # Top 20 gaps
            ],
            "drift": [
                {
                    "type": e.drift_type.value,
                    "technique_id": e.technique_id,
                    "detection_name": e.detection_name,
                    "severity": e.severity.value,
                    "timestamp": e.timestamp
                }
                for e in drift_events
            ],
            "health": health
        }

    def _build_snapshot(
        self,
        detections: List[NormalizedDetection],
        mappings: Dict[str, List[MappingResult]],
        coverage: AccountCoverage
    ) -> Dict:
        """Build snapshot for storage and drift detection."""

        return {
            "detections": {
                d.detection_id: {
                    "name": d.name,
                    "status": d.status,
                    "config_hash": d.config_hash
                }
                for d in detections
            },
            "coverage": {
                "overall": coverage.overall_percentage,
                "technique_coverage": {
                    t.technique_id: {
                        "detection_count": t.detection_count,
                        "max_confidence": t.max_confidence,
                        "status": t.coverage_status
                    }
                    for t in coverage.techniques
                }
            }
        }
```

---

## Output Artifacts

### 1. Coverage Calculator
**File:** `src/analysis/coverage.py`

### 2. Gap Analyzer
**File:** `src/analysis/gaps.py`

### 3. Drift Detector
**File:** `src/analysis/drift.py`

### 4. Health Assessor
**File:** `src/analysis/health.py`

### 5. Analysis Pipeline
**File:** `src/analysis/pipeline.py`

### 6. Test Cases
**Files:**
- `tests/analysis/test_coverage.py`
- `tests/analysis/test_gaps.py`
- `tests/analysis/test_drift.py`

---

## Validation Checklist

- [ ] Coverage calculation handles edge cases (no detections, no mappings)
- [ ] Gap prioritization aligns with actual risk
- [ ] Drift detection correctly identifies all change types
- [ ] Health assessment catches common issues
- [ ] Analysis completes within 5 seconds for typical account
- [ ] Results are consistent across runs

---

## Next Agent

Proceed to: **07-UI-DESIGN-AGENT.md**

Provide the UI Agent with:
- Analysis output schemas (coverage, gaps, drift, health)
- API endpoints from API Design Agent
- User personas and their needs

---

**END OF ANALYSIS AGENT**
