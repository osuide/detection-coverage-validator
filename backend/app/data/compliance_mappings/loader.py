"""Compliance framework data loader.

Loads compliance framework data from JSON files into the database.
Data sources are authoritative mappings from MITRE CTID and CIS.
"""

import json
import uuid
from pathlib import Path
from typing import Optional

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.compliance import (
    ComplianceFramework,
    ComplianceControl,
    ControlTechniqueMapping,
)
from app.models.mitre import Technique
from app.data.cloud_techniques import is_cloud_relevant

logger = structlog.get_logger()

# Data directory
DATA_DIR = Path(__file__).parent


class ComplianceMappingLoader:
    """Load compliance framework data from JSON files."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(component="ComplianceMappingLoader")
        self._technique_cache: dict[str, uuid.UUID] = {}

    async def _build_technique_cache(self) -> None:
        """Build a cache of technique_id -> UUID for fast lookups."""
        result = await self.db.execute(select(Technique.technique_id, Technique.id))
        self._technique_cache = {row[0]: row[1] for row in result.fetchall()}
        self.logger.info(
            "technique_cache_built",
            technique_count=len(self._technique_cache),
        )

    async def _get_technique_uuid(self, technique_id: str) -> Optional[uuid.UUID]:
        """Get the UUID for a MITRE technique ID."""
        if not self._technique_cache:
            await self._build_technique_cache()
        return self._technique_cache.get(technique_id)

    async def load_framework(self, file_path: Path) -> Optional[ComplianceFramework]:
        """Load a framework and its controls from a JSON file.

        Args:
            file_path: Path to the JSON file

        Returns:
            The created ComplianceFramework, or None if already exists
        """
        if not file_path.exists():
            self.logger.error("file_not_found", path=str(file_path))
            return None

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        framework_data = data["framework"]
        controls_data = data["controls"]

        # Check if framework already exists
        existing = await self.db.execute(
            select(ComplianceFramework).where(
                ComplianceFramework.framework_id == framework_data["framework_id"]
            )
        )
        if existing.scalar_one_or_none():
            self.logger.info(
                "framework_already_exists",
                framework_id=framework_data["framework_id"],
            )
            return None

        # Create framework
        framework = ComplianceFramework(
            framework_id=framework_data["framework_id"],
            name=framework_data["name"],
            version=framework_data["version"],
            description=framework_data.get("description"),
            source_url=framework_data.get("source_url"),
            is_active=True,
        )
        self.db.add(framework)
        await self.db.flush()

        self.logger.info(
            "framework_created",
            framework_id=framework.framework_id,
            name=framework.name,
        )

        # Track statistics
        controls_created = 0
        mappings_created = 0
        unmapped_techniques = set()

        # Create controls
        for i, control_data in enumerate(controls_data):
            control = ComplianceControl(
                framework_id=framework.id,
                control_id=control_data["control_id"],
                control_family=control_data["control_family"],
                name=control_data["name"],
                description=control_data.get("description"),
                priority=control_data.get("priority"),
                is_enhancement=control_data.get("is_enhancement", False),
                display_order=i,
                cloud_applicability=control_data.get(
                    "cloud_applicability", "highly_relevant"
                ),
                cloud_context=control_data.get("cloud_context"),
            )
            self.db.add(control)
            await self.db.flush()
            controls_created += 1

            # Create technique mappings
            for mapping_data in control_data.get("technique_mappings", []):
                technique_id = mapping_data["technique_id"]
                technique_uuid = await self._get_technique_uuid(technique_id)

                if not technique_uuid:
                    unmapped_techniques.add(technique_id)
                    continue

                mapping = ControlTechniqueMapping(
                    control_id=control.id,
                    technique_id=technique_uuid,
                    mapping_source=self._get_mapping_source(framework.framework_id),
                    mapping_type=mapping_data.get("mapping_type", "mitigates"),
                    source_url=framework.source_url,
                    is_cloud_relevant=is_cloud_relevant(technique_id),
                )
                self.db.add(mapping)
                mappings_created += 1

        await self.db.flush()

        self.logger.info(
            "framework_loaded",
            framework_id=framework.framework_id,
            controls_created=controls_created,
            mappings_created=mappings_created,
            unmapped_techniques=len(unmapped_techniques),
        )

        if unmapped_techniques:
            self.logger.warning(
                "unmapped_techniques_found",
                framework_id=framework.framework_id,
                techniques=list(unmapped_techniques)[:10],  # First 10
                total=len(unmapped_techniques),
            )

        return framework

    def _get_mapping_source(self, framework_id: str) -> str:
        """Get the mapping source identifier for a framework."""
        source_map = {
            "nist-800-53-r5": "mitre_ctid",
            "cis-controls-v8": "cis_official",
        }
        return source_map.get(framework_id, "unknown")

    async def load_all(self) -> dict:
        """Load all compliance frameworks.

        Returns:
            Dictionary with loading statistics
        """
        self.logger.info("loading_all_frameworks")

        # Build technique cache first
        await self._build_technique_cache()

        results = {
            "frameworks_loaded": 0,
            "frameworks_skipped": 0,
            "total_controls": 0,
            "total_mappings": 0,
        }

        # Load NIST 800-53 Rev 5
        nist_path = DATA_DIR / "nist_800_53_r5.json"
        if nist_path.exists():
            framework = await self.load_framework(nist_path)
            if framework:
                results["frameworks_loaded"] += 1
            else:
                results["frameworks_skipped"] += 1

        # Load CIS Controls v8
        cis_path = DATA_DIR / "cis_controls_v8.json"
        if cis_path.exists():
            framework = await self.load_framework(cis_path)
            if framework:
                results["frameworks_loaded"] += 1
            else:
                results["frameworks_skipped"] += 1

        # Get totals
        controls_result = await self.db.execute(select(ComplianceControl))
        results["total_controls"] = len(controls_result.fetchall())

        mappings_result = await self.db.execute(select(ControlTechniqueMapping))
        results["total_mappings"] = len(mappings_result.fetchall())

        self.logger.info("all_frameworks_loaded", **results)
        return results

    async def clear_all(self) -> None:
        """Clear all compliance framework data.

        WARNING: This deletes all frameworks, controls, and mappings.
        """
        self.logger.warning("clearing_all_compliance_data")

        # Delete in order due to foreign keys
        await self.db.execute(ControlTechniqueMapping.__table__.delete())
        await self.db.execute(ComplianceControl.__table__.delete())
        await self.db.execute(ComplianceFramework.__table__.delete())
        await self.db.flush()

        self.logger.info("all_compliance_data_cleared")


async def seed_compliance_frameworks(db: AsyncSession) -> dict:
    """Convenience function to seed compliance frameworks.

    Args:
        db: Database session

    Returns:
        Loading statistics
    """
    loader = ComplianceMappingLoader(db)
    return await loader.load_all()
