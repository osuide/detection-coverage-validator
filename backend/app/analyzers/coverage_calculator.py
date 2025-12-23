"""Coverage calculator following 06-ANALYSIS-AGENT.md design.

Updated for organisation-level detection support:
- Account coverage includes inherited org-level detections
- Coverage breakdown shows account vs org contribution
- Aggregate org coverage calculation for all member accounts
"""

from dataclasses import dataclass, field
from typing import Optional
from uuid import UUID
import structlog

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from sqlalchemy.orm import selectinload

from app.models.detection import (
    Detection,
    DetectionStatus,
    DetectionScope,
    SecurityFunction,
)
from app.models.mapping import DetectionMapping
from app.models.mitre import Technique
from app.models.cloud_account import CloudAccount
from app.models.cloud_organization import CloudOrganization
from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

# Cloud-relevant platforms from MITRE ATT&CK Cloud Matrix
# Used to filter techniques to only include cloud-relevant ones in coverage calculations
CLOUD_PLATFORMS = [
    "IaaS",
    "SaaS",
    "AWS",
    "Azure",
    "GCP",
    "Azure AD",
    "Google Workspace",
    "Office 365",
]


@dataclass
class SecurityFunctionBreakdown:
    """Breakdown of detections by NIST CSF security function."""

    detect: int = 0  # Threat detection - MITRE ATT&CK mapped
    protect: int = 0  # Preventive controls
    identify: int = 0  # Visibility/logging/posture
    recover: int = 0  # Backup/DR/resilience
    operational: int = 0  # Non-security (tagging, cost)

    @property
    def total(self) -> int:
        """Total detections across all functions."""
        return (
            self.detect + self.protect + self.identify + self.recover + self.operational
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "detect": self.detect,
            "protect": self.protect,
            "identify": self.identify,
            "recover": self.recover,
            "operational": self.operational,
            "total": self.total,
        }


@dataclass
class TechniqueCoverageInfo:
    """Coverage information for a single technique."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    status: str  # "covered", "partial", "uncovered"
    detection_count: int
    max_confidence: float
    avg_confidence: float


@dataclass
class TacticCoverageInfo:
    """Coverage information for a single tactic."""

    tactic_id: str
    tactic_name: str
    total_techniques: int
    covered: int
    partial: int
    uncovered: int
    percent: float


@dataclass
class CoverageResult:
    """Complete coverage calculation result."""

    total_techniques: int
    covered_techniques: int
    partial_techniques: int
    uncovered_techniques: int
    coverage_percent: float
    average_confidence: float
    tactic_coverage: dict[str, TacticCoverageInfo]
    technique_details: list[TechniqueCoverageInfo]
    total_detections: int
    active_detections: int
    mapped_detections: int

    # Organisation-level coverage contribution
    org_detection_count: int = 0
    org_covered_techniques: int = 0
    account_only_techniques: int = 0  # Covered only by account detections
    org_only_techniques: int = 0  # Covered only by org detections
    overlap_techniques: int = 0  # Covered by both

    # Breakdown for UI
    coverage_breakdown: dict = field(default_factory=dict)

    # Security function breakdown (NIST CSF)
    security_function_breakdown: SecurityFunctionBreakdown = field(
        default_factory=SecurityFunctionBreakdown
    )


@dataclass
class OrgCoverageResult:
    """Organisation-wide aggregate coverage result."""

    cloud_organization_id: UUID
    total_member_accounts: int
    connected_accounts: int

    # Aggregate coverage metrics
    total_techniques: int
    union_covered_techniques: int  # Covered in ANY account
    minimum_covered_techniques: int  # Covered in ALL accounts
    average_coverage_percent: float

    # Per-account breakdown
    per_account_coverage: dict[UUID, float]  # account_id -> coverage_percent

    # Org-level detections summary
    org_detection_count: int
    org_covered_techniques: int

    # Coverage views
    union_coverage_percent: float  # Any account has detection
    minimum_coverage_percent: float  # All accounts have detection

    # Tactic-level aggregate
    tactic_coverage: dict[str, dict]  # union and minimum per tactic


class CoverageCalculator:
    """Calculates MITRE ATT&CK coverage from detection mappings.

    Coverage rules from 00-MASTER-ORCHESTRATOR.md:
    - >= 0.6 confidence = "covered"
    - 0.4-0.6 confidence = "partial"
    - < 0.4 confidence = "uncovered"

    Organisation-level detection support:
    - Includes org-level detections that apply to the account
    - Tracks contribution from account vs org detections
    - Provides coverage breakdown for UI visualisation
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(component="CoverageCalculator")
        self.covered_threshold = settings.confidence_threshold_covered
        self.partial_threshold = settings.confidence_threshold_partial

    async def calculate(
        self,
        cloud_account_id: UUID,
        include_org_detections: bool = True,
    ) -> CoverageResult:
        """Calculate coverage for a cloud account.

        Args:
            cloud_account_id: The cloud account to calculate coverage for
            include_org_detections: Whether to include org-level detections

        Returns:
            CoverageResult with complete coverage analysis
        """
        self.logger.info(
            "calculating_coverage",
            account_id=str(cloud_account_id),
            include_org=include_org_detections,
        )

        # Get all techniques
        techniques = await self._get_all_techniques()

        # Get account-level mappings
        account_mappings = await self._get_account_mappings(cloud_account_id)

        # Get org-level mappings if applicable
        org_mappings = []
        org_detection_count = 0
        cloud_org_id = None

        if include_org_detections:
            cloud_org_id = await self._get_account_cloud_org_id(cloud_account_id)
            if cloud_org_id:
                org_mappings = await self._get_org_mappings_for_account(
                    cloud_org_id, cloud_account_id
                )
                org_detection_count = await self._get_org_detection_count(
                    cloud_org_id, cloud_account_id
                )

        # Get detection counts
        detection_counts = await self._get_detection_counts(cloud_account_id)

        # Build technique coverage with org contribution tracking
        technique_coverage, coverage_breakdown = (
            self._build_technique_coverage_with_org(
                techniques, account_mappings, org_mappings
            )
        )

        # Calculate tactic-level coverage
        tactic_coverage = self._calculate_tactic_coverage(technique_coverage)

        # Calculate overall metrics
        covered = sum(1 for t in technique_coverage if t.status == "covered")
        partial = sum(1 for t in technique_coverage if t.status == "partial")
        uncovered = sum(1 for t in technique_coverage if t.status == "uncovered")
        total = len(technique_coverage)

        coverage_percent = (covered / total * 100) if total > 0 else 0.0

        # Average confidence across covered/partial techniques
        confidences = [
            t.max_confidence
            for t in technique_coverage
            if t.status in ("covered", "partial")
        ]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        # Calculate org contribution metrics
        org_covered_techniques = coverage_breakdown.get(
            "org_only", 0
        ) + coverage_breakdown.get("both", 0)
        account_only_techniques = coverage_breakdown.get("account_only", 0)
        org_only_techniques = coverage_breakdown.get("org_only", 0)
        overlap_techniques = coverage_breakdown.get("both", 0)

        result = CoverageResult(
            total_techniques=total,
            covered_techniques=covered,
            partial_techniques=partial,
            uncovered_techniques=uncovered,
            coverage_percent=round(coverage_percent, 2),
            average_confidence=round(avg_confidence, 3),
            tactic_coverage=tactic_coverage,
            technique_details=technique_coverage,
            total_detections=detection_counts["total"] + org_detection_count,
            active_detections=detection_counts["active"] + org_detection_count,
            mapped_detections=detection_counts["mapped"],
            org_detection_count=org_detection_count,
            org_covered_techniques=org_covered_techniques,
            account_only_techniques=account_only_techniques,
            org_only_techniques=org_only_techniques,
            overlap_techniques=overlap_techniques,
            security_function_breakdown=detection_counts.get(
                "security_function_breakdown", SecurityFunctionBreakdown()
            ),
            coverage_breakdown={
                "account_only": account_only_techniques,
                "org_only": org_only_techniques,
                "both": overlap_techniques,
                "total_covered": covered,
                "cloud_organization_id": str(cloud_org_id) if cloud_org_id else None,
            },
        )

        self.logger.info(
            "coverage_calculated",
            account_id=str(cloud_account_id),
            coverage=coverage_percent,
            covered=covered,
            partial=partial,
            uncovered=uncovered,
            org_contribution=org_covered_techniques,
        )

        return result

    async def _get_account_cloud_org_id(self, cloud_account_id: UUID) -> Optional[UUID]:
        """Get the cloud organisation ID for an account."""
        result = await self.db.execute(
            select(CloudAccount.cloud_organization_id).where(
                CloudAccount.id == cloud_account_id
            )
        )
        row = result.scalar_one_or_none()
        return row

    async def _get_org_mappings_for_account(
        self,
        cloud_org_id: UUID,
        cloud_account_id: UUID,
    ) -> list[DetectionMapping]:
        """Get org-level detection mappings that apply to this account."""
        # Get account's external ID for filtering applies_to_account_ids
        account_result = await self.db.execute(
            select(CloudAccount.account_id).where(CloudAccount.id == cloud_account_id)
        )
        account_external_id = account_result.scalar_one_or_none()

        # Query org-level detections that apply to this account
        result = await self.db.execute(
            select(DetectionMapping)
            .join(Detection)
            .options(
                selectinload(DetectionMapping.technique).selectinload(Technique.tactic)
            )
            .where(Detection.cloud_organization_id == cloud_org_id)
            .where(Detection.detection_scope == DetectionScope.ORGANIZATION)
            .where(Detection.status == DetectionStatus.ACTIVE)
            .where(
                or_(
                    Detection.applies_to_all_accounts.is_(True),
                    (
                        Detection.applies_to_account_ids.contains([account_external_id])
                        if account_external_id
                        else False
                    ),
                )
            )
        )
        return list(result.scalars().unique().all())

    async def _get_org_detection_count(
        self,
        cloud_org_id: UUID,
        cloud_account_id: UUID,
    ) -> int:
        """Count org-level detections that apply to this account."""
        # Get account's external ID
        account_result = await self.db.execute(
            select(CloudAccount.account_id).where(CloudAccount.id == cloud_account_id)
        )
        account_external_id = account_result.scalar_one_or_none()

        result = await self.db.execute(
            select(Detection)
            .where(Detection.cloud_organization_id == cloud_org_id)
            .where(Detection.detection_scope == DetectionScope.ORGANIZATION)
            .where(Detection.status == DetectionStatus.ACTIVE)
            .where(
                or_(
                    Detection.applies_to_all_accounts.is_(True),
                    (
                        Detection.applies_to_account_ids.contains([account_external_id])
                        if account_external_id
                        else False
                    ),
                )
            )
        )
        return len(result.scalars().all())

    def _build_technique_coverage_with_org(
        self,
        techniques: list[Technique],
        account_mappings: list[DetectionMapping],
        org_mappings: list[DetectionMapping],
    ) -> tuple[list[TechniqueCoverageInfo], dict]:
        """Build coverage info with separate tracking of account vs org contribution."""
        # Group mappings by technique for both account and org
        account_technique_mappings: dict[str, list[DetectionMapping]] = {}
        for mapping in account_mappings:
            if mapping.technique:
                tid = mapping.technique.technique_id
                if tid not in account_technique_mappings:
                    account_technique_mappings[tid] = []
                account_technique_mappings[tid].append(mapping)

        org_technique_mappings: dict[str, list[DetectionMapping]] = {}
        for mapping in org_mappings:
            if mapping.technique:
                tid = mapping.technique.technique_id
                if tid not in org_technique_mappings:
                    org_technique_mappings[tid] = []
                org_technique_mappings[tid].append(mapping)

        coverage_info = []
        breakdown = {"account_only": 0, "org_only": 0, "both": 0, "uncovered": 0}

        for technique in techniques:
            tid = technique.technique_id
            account_maps = account_technique_mappings.get(tid, [])
            org_maps = org_technique_mappings.get(tid, [])

            # Combine all mappings
            all_mappings = account_maps + org_maps

            if all_mappings:
                max_conf = max(m.confidence for m in all_mappings)
                avg_conf = sum(m.confidence for m in all_mappings) / len(all_mappings)

                if max_conf >= self.covered_threshold:
                    status = "covered"
                    # Track contribution source
                    has_account = any(
                        m.confidence >= self.covered_threshold for m in account_maps
                    )
                    has_org = any(
                        m.confidence >= self.covered_threshold for m in org_maps
                    )
                    if has_account and has_org:
                        breakdown["both"] += 1
                    elif has_account:
                        breakdown["account_only"] += 1
                    elif has_org:
                        breakdown["org_only"] += 1
                elif max_conf >= self.partial_threshold:
                    status = "partial"
                else:
                    status = "uncovered"
                    breakdown["uncovered"] += 1
            else:
                max_conf = 0.0
                avg_conf = 0.0
                status = "uncovered"
                breakdown["uncovered"] += 1

            coverage_info.append(
                TechniqueCoverageInfo(
                    technique_id=tid,
                    technique_name=technique.name,
                    tactic_id=technique.tactic.tactic_id if technique.tactic else "",
                    tactic_name=technique.tactic.name if technique.tactic else "",
                    status=status,
                    detection_count=len(all_mappings),
                    max_confidence=max_conf,
                    avg_confidence=avg_conf,
                )
            )

        return coverage_info, breakdown

    async def _get_all_techniques(self, cloud_only: bool = True) -> list[Technique]:
        """Get MITRE techniques from database.

        Args:
            cloud_only: If True, only return cloud-relevant techniques (AWS, GCP, etc.)
                       If False, return all Enterprise techniques.
        """
        query = select(Technique).options(selectinload(Technique.tactic))

        if cloud_only:
            # Filter to only include cloud-relevant techniques
            platform_conditions = [
                Technique.platforms.contains([platform]) for platform in CLOUD_PLATFORMS
            ]
            query = query.where(or_(*platform_conditions))

        result = await self.db.execute(query)
        return list(result.scalars().unique().all())

    async def _get_account_mappings(
        self,
        cloud_account_id: UUID,
    ) -> list[DetectionMapping]:
        """Get all mappings for detections in this account."""
        result = await self.db.execute(
            select(DetectionMapping)
            .join(Detection)
            .options(
                selectinload(DetectionMapping.technique).selectinload(Technique.tactic)
            )
            .where(Detection.cloud_account_id == cloud_account_id)
            .where(Detection.status == DetectionStatus.ACTIVE)
        )
        return list(result.scalars().unique().all())

    async def _get_detection_counts(
        self,
        cloud_account_id: UUID,
    ) -> dict:
        """Get detection counts for the account including security function breakdown."""
        # Get all detections for the account (for total and function breakdown)
        all_result = await self.db.execute(
            select(Detection).where(Detection.cloud_account_id == cloud_account_id)
        )
        all_detections = list(all_result.scalars().all())
        total = len(all_detections)

        # Count by security function
        function_breakdown = SecurityFunctionBreakdown()
        active = 0
        for det in all_detections:
            if det.status == DetectionStatus.ACTIVE:
                active += 1
            # Count by security function
            if det.security_function == SecurityFunction.DETECT:
                function_breakdown.detect += 1
            elif det.security_function == SecurityFunction.PROTECT:
                function_breakdown.protect += 1
            elif det.security_function == SecurityFunction.IDENTIFY:
                function_breakdown.identify += 1
            elif det.security_function == SecurityFunction.RECOVER:
                function_breakdown.recover += 1
            else:
                function_breakdown.operational += 1

        # Mapped detections (with at least one mapping)
        mapped_result = await self.db.execute(
            select(Detection)
            .join(DetectionMapping)
            .where(Detection.cloud_account_id == cloud_account_id)
            .distinct()
        )
        mapped = len(mapped_result.scalars().unique().all())

        return {
            "total": total,
            "active": active,
            "mapped": mapped,
            "security_function_breakdown": function_breakdown,
        }

    def _build_technique_coverage(
        self,
        techniques: list[Technique],
        mappings: list[DetectionMapping],
    ) -> list[TechniqueCoverageInfo]:
        """Build coverage info for each technique."""
        # Group mappings by technique
        technique_mappings: dict[str, list[DetectionMapping]] = {}
        for mapping in mappings:
            if mapping.technique:
                tid = mapping.technique.technique_id
                if tid not in technique_mappings:
                    technique_mappings[tid] = []
                technique_mappings[tid].append(mapping)

        coverage_info = []
        for technique in techniques:
            tid = technique.technique_id
            tech_mappings = technique_mappings.get(tid, [])

            if tech_mappings:
                max_conf = max(m.confidence for m in tech_mappings)
                avg_conf = sum(m.confidence for m in tech_mappings) / len(tech_mappings)

                if max_conf >= self.covered_threshold:
                    status = "covered"
                elif max_conf >= self.partial_threshold:
                    status = "partial"
                else:
                    status = "uncovered"
            else:
                max_conf = 0.0
                avg_conf = 0.0
                status = "uncovered"

            coverage_info.append(
                TechniqueCoverageInfo(
                    technique_id=tid,
                    technique_name=technique.name,
                    tactic_id=technique.tactic.tactic_id if technique.tactic else "",
                    tactic_name=technique.tactic.name if technique.tactic else "",
                    status=status,
                    detection_count=len(tech_mappings),
                    max_confidence=max_conf,
                    avg_confidence=avg_conf,
                )
            )

        return coverage_info

    def _calculate_tactic_coverage(
        self,
        technique_coverage: list[TechniqueCoverageInfo],
    ) -> dict[str, TacticCoverageInfo]:
        """Calculate per-tactic coverage from technique coverage."""
        tactic_stats: dict[str, dict] = {}

        for tech in technique_coverage:
            tid = tech.tactic_id
            if tid not in tactic_stats:
                tactic_stats[tid] = {
                    "name": tech.tactic_name,
                    "total": 0,
                    "covered": 0,
                    "partial": 0,
                    "uncovered": 0,
                }

            tactic_stats[tid]["total"] += 1
            tactic_stats[tid][tech.status] += 1

        result = {}
        for tactic_id, stats in tactic_stats.items():
            total = stats["total"]
            covered = stats["covered"]
            percent = (covered / total * 100) if total > 0 else 0.0

            result[tactic_id] = TacticCoverageInfo(
                tactic_id=tactic_id,
                tactic_name=stats["name"],
                total_techniques=total,
                covered=covered,
                partial=stats["partial"],
                uncovered=stats["uncovered"],
                percent=round(percent, 2),
            )

        return result


class OrgCoverageCalculator:
    """Calculates aggregate MITRE ATT&CK coverage across an organisation.

    Provides two views:
    - Union coverage: technique covered if ANY account has detection
    - Minimum coverage: technique covered only if ALL accounts have detection
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(component="OrgCoverageCalculator")
        self.covered_threshold = settings.confidence_threshold_covered

    async def calculate(
        self,
        cloud_organization_id: UUID,
    ) -> OrgCoverageResult:
        """Calculate aggregate coverage for a cloud organisation.

        Args:
            cloud_organization_id: The cloud organisation to calculate for

        Returns:
            OrgCoverageResult with aggregate coverage metrics
        """
        self.logger.info(
            "calculating_org_coverage",
            cloud_org_id=str(cloud_organization_id),
        )

        # Get organisation info
        org_result = await self.db.execute(
            select(CloudOrganization).where(
                CloudOrganization.id == cloud_organization_id
            )
        )
        cloud_org = org_result.scalar_one_or_none()
        if not cloud_org:
            raise ValueError(f"Cloud organisation {cloud_organization_id} not found")

        # Get all connected accounts
        accounts_result = await self.db.execute(
            select(CloudAccount).where(
                CloudAccount.cloud_organization_id == cloud_organization_id
            )
        )
        accounts = list(accounts_result.scalars().all())

        # Get all techniques
        techniques = await self._get_all_techniques()
        total_techniques = len(techniques)

        # Get org-level detection mappings
        org_mappings = await self._get_org_mappings(cloud_organization_id)
        org_detection_count = await self._get_org_detection_count(cloud_organization_id)

        # Track which techniques are covered per account
        per_account_techniques: dict[UUID, set[str]] = {}
        per_account_coverage: dict[UUID, float] = {}

        # Calculate coverage for each account
        account_calculator = CoverageCalculator(self.db)
        for account in accounts:
            result = await account_calculator.calculate(
                account.id, include_org_detections=True
            )
            per_account_coverage[account.id] = result.coverage_percent

            # Track covered techniques
            covered_techniques = {
                t.technique_id
                for t in result.technique_details
                if t.status == "covered"
            }
            per_account_techniques[account.id] = covered_techniques

        # Calculate union and minimum coverage
        if accounts:
            # Union: covered in ANY account
            all_covered: set[str] = set()
            for techniques_set in per_account_techniques.values():
                all_covered |= techniques_set
            union_covered = len(all_covered)

            # Minimum: covered in ALL accounts
            if per_account_techniques:
                common_covered = set.intersection(*per_account_techniques.values())
            else:
                common_covered = set()
            minimum_covered = len(common_covered)

            # Average coverage
            avg_coverage = sum(per_account_coverage.values()) / len(accounts)
        else:
            union_covered = 0
            minimum_covered = 0
            avg_coverage = 0.0
            all_covered = set()

        # Get org-level technique coverage
        org_covered_techniques = self._get_org_covered_techniques(org_mappings)

        # Calculate aggregate tactic coverage
        tactic_coverage = self._calculate_aggregate_tactic_coverage(
            techniques,
            all_covered,
            set.intersection(*per_account_techniques.values()) if accounts else set(),
        )

        result = OrgCoverageResult(
            cloud_organization_id=cloud_organization_id,
            total_member_accounts=cloud_org.total_accounts_discovered or 0,
            connected_accounts=len(accounts),
            total_techniques=total_techniques,
            union_covered_techniques=union_covered,
            minimum_covered_techniques=minimum_covered,
            average_coverage_percent=round(avg_coverage, 2),
            per_account_coverage=per_account_coverage,
            org_detection_count=org_detection_count,
            org_covered_techniques=len(org_covered_techniques),
            union_coverage_percent=round(
                (
                    (union_covered / total_techniques * 100)
                    if total_techniques > 0
                    else 0.0
                ),
                2,
            ),
            minimum_coverage_percent=round(
                (
                    (minimum_covered / total_techniques * 100)
                    if total_techniques > 0
                    else 0.0
                ),
                2,
            ),
            tactic_coverage=tactic_coverage,
        )

        self.logger.info(
            "org_coverage_calculated",
            cloud_org_id=str(cloud_organization_id),
            union_coverage=result.union_coverage_percent,
            minimum_coverage=result.minimum_coverage_percent,
            connected_accounts=len(accounts),
        )

        return result

    async def _get_all_techniques(self, cloud_only: bool = True) -> list[Technique]:
        """Get MITRE techniques from database.

        Args:
            cloud_only: If True, only return cloud-relevant techniques (AWS, GCP, etc.)
                       If False, return all Enterprise techniques.
        """
        query = select(Technique).options(selectinload(Technique.tactic))

        if cloud_only:
            # Filter to only include cloud-relevant techniques
            platform_conditions = [
                Technique.platforms.contains([platform]) for platform in CLOUD_PLATFORMS
            ]
            query = query.where(or_(*platform_conditions))

        result = await self.db.execute(query)
        return list(result.scalars().unique().all())

    async def _get_org_mappings(
        self,
        cloud_org_id: UUID,
    ) -> list[DetectionMapping]:
        """Get all org-level detection mappings."""
        result = await self.db.execute(
            select(DetectionMapping)
            .join(Detection)
            .options(
                selectinload(DetectionMapping.technique).selectinload(Technique.tactic)
            )
            .where(Detection.cloud_organization_id == cloud_org_id)
            .where(Detection.detection_scope == DetectionScope.ORGANIZATION)
            .where(Detection.status == DetectionStatus.ACTIVE)
        )
        return list(result.scalars().unique().all())

    async def _get_org_detection_count(self, cloud_org_id: UUID) -> int:
        """Count org-level detections."""
        result = await self.db.execute(
            select(Detection)
            .where(Detection.cloud_organization_id == cloud_org_id)
            .where(Detection.detection_scope == DetectionScope.ORGANIZATION)
            .where(Detection.status == DetectionStatus.ACTIVE)
        )
        return len(result.scalars().all())

    def _get_org_covered_techniques(
        self,
        org_mappings: list[DetectionMapping],
    ) -> set[str]:
        """Get techniques covered by org-level detections."""
        covered = set()
        for mapping in org_mappings:
            if mapping.technique and mapping.confidence >= self.covered_threshold:
                covered.add(mapping.technique.technique_id)
        return covered

    def _calculate_aggregate_tactic_coverage(
        self,
        techniques: list[Technique],
        union_covered: set[str],
        minimum_covered: set[str],
    ) -> dict[str, dict]:
        """Calculate per-tactic aggregate coverage."""
        tactic_stats: dict[str, dict] = {}

        for technique in techniques:
            tid = technique.tactic.tactic_id if technique.tactic else "unknown"
            tactic_name = technique.tactic.name if technique.tactic else "Unknown"

            if tid not in tactic_stats:
                tactic_stats[tid] = {
                    "name": tactic_name,
                    "total": 0,
                    "union_covered": 0,
                    "minimum_covered": 0,
                }

            tactic_stats[tid]["total"] += 1
            if technique.technique_id in union_covered:
                tactic_stats[tid]["union_covered"] += 1
            if technique.technique_id in minimum_covered:
                tactic_stats[tid]["minimum_covered"] += 1

        result = {}
        for tactic_id, stats in tactic_stats.items():
            total = stats["total"]
            result[tactic_id] = {
                "tactic_id": tactic_id,
                "tactic_name": stats["name"],
                "total_techniques": total,
                "union_covered": stats["union_covered"],
                "minimum_covered": stats["minimum_covered"],
                "union_percent": round(
                    (stats["union_covered"] / total * 100) if total > 0 else 0.0, 2
                ),
                "minimum_percent": round(
                    (stats["minimum_covered"] / total * 100) if total > 0 else 0.0, 2
                ),
            }

        return result
