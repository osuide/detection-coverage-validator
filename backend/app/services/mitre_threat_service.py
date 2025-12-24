"""MITRE ATT&CK Threat Intelligence Query Service.

Provides methods to query threat groups, campaigns, and software
related to specific techniques.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import uuid

import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mitre import Technique
from app.models.mitre_threat import (
    MitreThreatGroup,
    MitreCampaign,
    MitreSoftware,
    MitreTechniqueRelationship,
    MitreDataVersion,
    RelatedType,
)

logger = structlog.get_logger()


@dataclass
class ThreatGroupInfo:
    """Summary info for a threat group."""

    id: str
    external_id: str
    name: str
    aliases: list[str]
    description: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    mitre_url: str
    relationship_description: Optional[str] = None


@dataclass
class CampaignInfo:
    """Summary info for a campaign."""

    id: str
    external_id: str
    name: str
    description: Optional[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    mitre_url: str
    relationship_description: Optional[str] = None


@dataclass
class SoftwareInfo:
    """Summary info for software/malware."""

    id: str
    external_id: str
    name: str
    software_type: str
    aliases: list[str]
    description: Optional[str]
    platforms: list[str]
    mitre_url: str
    relationship_description: Optional[str] = None


@dataclass
class TechniqueThreatContext:
    """Complete threat context for a technique."""

    technique_id: str
    groups: list[ThreatGroupInfo]
    campaigns: list[CampaignInfo]
    software: list[SoftwareInfo]
    mitre_version: Optional[str]
    last_updated: Optional[datetime]
    total_groups: int
    total_campaigns: int
    total_software: int


class MitreThreatService:
    """Service for querying MITRE threat intelligence data."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_groups_for_technique(
        self,
        technique_id: str,
        limit: int = 10,
    ) -> list[ThreatGroupInfo]:
        """
        Get threat groups that use a specific technique.

        Args:
            technique_id: MITRE technique ID (e.g., T1078.004)
            limit: Maximum number of groups to return

        Returns:
            List of threat group info sorted by last_seen (most recent first)
        """
        # Get technique UUID
        technique_uuid = await self._get_technique_uuid(technique_id)
        if not technique_uuid:
            return []

        # Query relationships and groups
        result = await self.db.execute(
            select(MitreThreatGroup, MitreTechniqueRelationship.description)
            .join(
                MitreTechniqueRelationship,
                MitreThreatGroup.id == MitreTechniqueRelationship.related_id,
            )
            .where(
                MitreTechniqueRelationship.technique_id == technique_uuid,
                MitreTechniqueRelationship.related_type == RelatedType.GROUP.value,
                MitreThreatGroup.is_revoked == False,  # noqa: E712
                MitreThreatGroup.is_deprecated == False,  # noqa: E712
            )
            .order_by(MitreThreatGroup.last_seen.desc().nullslast())
            .limit(limit)
        )

        groups = []
        for row in result.all():
            group = row[0]
            rel_description = row[1]
            groups.append(
                ThreatGroupInfo(
                    id=str(group.id),
                    external_id=group.external_id,
                    name=group.name,
                    aliases=group.aliases or [],
                    description=self._truncate(
                        self._strip_markdown_links(group.description), 300
                    ),
                    first_seen=group.first_seen,
                    last_seen=group.last_seen,
                    mitre_url=group.mitre_url,
                    relationship_description=self._truncate(
                        self._strip_markdown_links(rel_description), 200
                    ),
                )
            )

        return groups

    async def get_campaigns_for_technique(
        self,
        technique_id: str,
        limit: int = 5,
    ) -> list[CampaignInfo]:
        """
        Get campaigns that use a specific technique.

        Args:
            technique_id: MITRE technique ID
            limit: Maximum number of campaigns to return

        Returns:
            List of campaign info sorted by last_seen (most recent first)
        """
        technique_uuid = await self._get_technique_uuid(technique_id)
        if not technique_uuid:
            return []

        result = await self.db.execute(
            select(MitreCampaign, MitreTechniqueRelationship.description)
            .join(
                MitreTechniqueRelationship,
                MitreCampaign.id == MitreTechniqueRelationship.related_id,
            )
            .where(
                MitreTechniqueRelationship.technique_id == technique_uuid,
                MitreTechniqueRelationship.related_type == RelatedType.CAMPAIGN.value,
                MitreCampaign.is_revoked == False,  # noqa: E712
                MitreCampaign.is_deprecated == False,  # noqa: E712
            )
            .order_by(MitreCampaign.last_seen.desc().nullslast())
            .limit(limit)
        )

        campaigns = []
        for row in result.all():
            campaign = row[0]
            rel_description = row[1]
            campaigns.append(
                CampaignInfo(
                    id=str(campaign.id),
                    external_id=campaign.external_id,
                    name=campaign.name,
                    description=self._truncate(
                        self._strip_markdown_links(campaign.description), 300
                    ),
                    first_seen=campaign.first_seen,
                    last_seen=campaign.last_seen,
                    mitre_url=campaign.mitre_url,
                    relationship_description=self._truncate(
                        self._strip_markdown_links(rel_description), 200
                    ),
                )
            )

        return campaigns

    async def get_software_for_technique(
        self,
        technique_id: str,
        limit: int = 10,
    ) -> list[SoftwareInfo]:
        """
        Get software/malware that implements a specific technique.

        Args:
            technique_id: MITRE technique ID
            limit: Maximum number of software to return

        Returns:
            List of software info sorted by name
        """
        technique_uuid = await self._get_technique_uuid(technique_id)
        if not technique_uuid:
            return []

        result = await self.db.execute(
            select(MitreSoftware, MitreTechniqueRelationship.description)
            .join(
                MitreTechniqueRelationship,
                MitreSoftware.id == MitreTechniqueRelationship.related_id,
            )
            .where(
                MitreTechniqueRelationship.technique_id == technique_uuid,
                MitreTechniqueRelationship.related_type == RelatedType.SOFTWARE.value,
                MitreSoftware.is_revoked == False,  # noqa: E712
                MitreSoftware.is_deprecated == False,  # noqa: E712
            )
            .order_by(MitreSoftware.name)
            .limit(limit)
        )

        software = []
        for row in result.all():
            sw = row[0]
            rel_description = row[1]
            software.append(
                SoftwareInfo(
                    id=str(sw.id),
                    external_id=sw.external_id,
                    name=sw.name,
                    software_type=sw.software_type,
                    aliases=sw.aliases or [],
                    description=self._truncate(
                        self._strip_markdown_links(sw.description), 300
                    ),
                    platforms=sw.platforms or [],
                    mitre_url=sw.mitre_url,
                    relationship_description=self._truncate(
                        self._strip_markdown_links(rel_description), 200
                    ),
                )
            )

        return software

    async def get_technique_threat_context(
        self,
        technique_id: str,
        groups_limit: int = 10,
        campaigns_limit: int = 5,
        software_limit: int = 10,
    ) -> TechniqueThreatContext:
        """
        Get full threat context for a technique.

        Args:
            technique_id: MITRE technique ID
            groups_limit: Max threat groups to include
            campaigns_limit: Max campaigns to include
            software_limit: Max software to include

        Returns:
            Complete threat context with groups, campaigns, software
        """
        # Get data in parallel-ish (still sequential in asyncio but cleaner)
        groups = await self.get_groups_for_technique(technique_id, groups_limit)
        campaigns = await self.get_campaigns_for_technique(
            technique_id, campaigns_limit
        )
        software = await self.get_software_for_technique(technique_id, software_limit)

        # Get version info
        version_info = await self._get_version_info()

        # Get total counts
        technique_uuid = await self._get_technique_uuid(technique_id)
        total_groups = 0
        total_campaigns = 0
        total_software = 0

        if technique_uuid:
            total_groups = await self._count_relationships(
                technique_uuid, RelatedType.GROUP.value
            )
            total_campaigns = await self._count_relationships(
                technique_uuid, RelatedType.CAMPAIGN.value
            )
            total_software = await self._count_relationships(
                technique_uuid, RelatedType.SOFTWARE.value
            )

        return TechniqueThreatContext(
            technique_id=technique_id,
            groups=groups,
            campaigns=campaigns,
            software=software,
            mitre_version=version_info.get("mitre_version") if version_info else None,
            last_updated=version_info.get("last_sync_at") if version_info else None,
            total_groups=total_groups,
            total_campaigns=total_campaigns,
            total_software=total_software,
        )

    async def search_groups(
        self,
        query: str,
        limit: int = 20,
    ) -> list[ThreatGroupInfo]:
        """
        Search threat groups by name or alias.

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of matching threat groups
        """
        search_pattern = f"%{query.lower()}%"

        result = await self.db.execute(
            select(MitreThreatGroup)
            .where(
                MitreThreatGroup.is_revoked == False,  # noqa: E712
                MitreThreatGroup.is_deprecated == False,  # noqa: E712
                (
                    func.lower(MitreThreatGroup.name).like(search_pattern)
                    | func.lower(MitreThreatGroup.external_id).like(search_pattern)
                    # Check if any alias matches (JSONB contains)
                    | MitreThreatGroup.aliases.cast(str).ilike(search_pattern)
                ),
            )
            .order_by(MitreThreatGroup.name)
            .limit(limit)
        )

        return [
            ThreatGroupInfo(
                id=str(group.id),
                external_id=group.external_id,
                name=group.name,
                aliases=group.aliases or [],
                description=self._truncate(group.description, 300),
                first_seen=group.first_seen,
                last_seen=group.last_seen,
                mitre_url=group.mitre_url,
            )
            for group in result.scalars().all()
        ]

    async def get_all_groups(
        self,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[ThreatGroupInfo], int]:
        """
        Get all threat groups with pagination.

        Returns:
            Tuple of (groups list, total count)
        """
        # Get total count
        count_result = await self.db.execute(
            select(func.count())
            .select_from(MitreThreatGroup)
            .where(
                MitreThreatGroup.is_revoked == False,  # noqa: E712
                MitreThreatGroup.is_deprecated == False,  # noqa: E712
            )
        )
        total = count_result.scalar() or 0

        # Get paginated results
        result = await self.db.execute(
            select(MitreThreatGroup)
            .where(
                MitreThreatGroup.is_revoked == False,  # noqa: E712
                MitreThreatGroup.is_deprecated == False,  # noqa: E712
            )
            .order_by(MitreThreatGroup.name)
            .offset(skip)
            .limit(limit)
        )

        groups = [
            ThreatGroupInfo(
                id=str(group.id),
                external_id=group.external_id,
                name=group.name,
                aliases=group.aliases or [],
                description=self._truncate(group.description, 300),
                first_seen=group.first_seen,
                last_seen=group.last_seen,
                mitre_url=group.mitre_url,
            )
            for group in result.scalars().all()
        ]

        return groups, total

    async def get_all_campaigns(
        self,
        skip: int = 0,
        limit: int = 50,
        search: Optional[str] = None,
        sort_by: str = "last_seen",
        sort_order: str = "desc",
    ) -> tuple[list[CampaignInfo], int]:
        """
        Get all campaigns with pagination, search, and sorting.

        Args:
            skip: Number of items to skip
            limit: Maximum number of items to return
            search: Optional search term for name or external_id
            sort_by: Field to sort by (name, external_id, first_seen, last_seen)
            sort_order: Sort direction (asc or desc)

        Returns:
            Tuple of (campaigns list, total count)
        """
        # Build base filter conditions
        base_conditions = [
            MitreCampaign.is_revoked == False,  # noqa: E712
            MitreCampaign.is_deprecated == False,  # noqa: E712
        ]

        # Add search filter if provided
        if search:
            search_term = f"%{search}%"
            from sqlalchemy import or_

            base_conditions.append(
                or_(
                    MitreCampaign.name.ilike(search_term),
                    MitreCampaign.external_id.ilike(search_term),
                )
            )

        # Count query
        count_result = await self.db.execute(
            select(func.count()).select_from(MitreCampaign).where(*base_conditions)
        )
        total = count_result.scalar() or 0

        # Determine sort column
        sort_columns = {
            "name": MitreCampaign.name,
            "external_id": MitreCampaign.external_id,
            "first_seen": MitreCampaign.first_seen,
            "last_seen": MitreCampaign.last_seen,
        }
        sort_column = sort_columns.get(sort_by, MitreCampaign.last_seen)

        # Apply sort order
        if sort_order == "asc":
            order_clause = sort_column.asc().nullslast()
        else:
            order_clause = sort_column.desc().nullslast()

        result = await self.db.execute(
            select(MitreCampaign)
            .where(*base_conditions)
            .order_by(order_clause)
            .offset(skip)
            .limit(limit)
        )

        campaigns = [
            CampaignInfo(
                id=str(campaign.id),
                external_id=campaign.external_id,
                name=campaign.name,
                description=self._truncate(campaign.description, 300),
                first_seen=campaign.first_seen,
                last_seen=campaign.last_seen,
                mitre_url=campaign.mitre_url,
            )
            for campaign in result.scalars().all()
        ]

        return campaigns, total

    async def get_statistics(self) -> dict:
        """Get MITRE data statistics."""
        version_info = await self._get_version_info()

        if not version_info:
            return {
                "is_synced": False,
                "total_groups": 0,
                "total_campaigns": 0,
                "total_software": 0,
                "total_relationships": 0,
            }

        return {
            "is_synced": True,
            "mitre_version": version_info.get("mitre_version"),
            "stix_version": version_info.get("stix_version"),
            "last_sync_at": version_info.get("last_sync_at"),
            "total_groups": version_info.get("total_groups", 0),
            "total_campaigns": version_info.get("total_campaigns", 0),
            "total_software": version_info.get("total_software", 0),
            "total_relationships": version_info.get("total_relationships", 0),
        }

    async def _get_technique_uuid(self, technique_id: str) -> Optional[uuid.UUID]:
        """Get technique UUID by technique_id (e.g., T1078.004)."""
        result = await self.db.execute(
            select(Technique.id).where(Technique.technique_id == technique_id)
        )
        row = result.first()
        return row[0] if row else None

    async def _get_version_info(self) -> Optional[dict]:
        """Get current data version info."""
        result = await self.db.execute(select(MitreDataVersion).limit(1))
        version = result.scalar_one_or_none()
        if not version:
            return None
        return {
            "mitre_version": version.mitre_version,
            "stix_version": version.stix_version,
            "last_sync_at": version.last_sync_at,
            "total_groups": version.total_groups,
            "total_campaigns": version.total_campaigns,
            "total_software": version.total_software,
            "total_relationships": version.total_relationships,
        }

    async def _count_relationships(
        self, technique_uuid: uuid.UUID, related_type: str
    ) -> int:
        """Count relationships of a specific type for a technique."""
        result = await self.db.execute(
            select(func.count())
            .select_from(MitreTechniqueRelationship)
            .where(
                MitreTechniqueRelationship.technique_id == technique_uuid,
                MitreTechniqueRelationship.related_type == related_type,
            )
        )
        return result.scalar() or 0

    def _strip_markdown_links(self, text: Optional[str]) -> Optional[str]:
        """Strip markdown links, keeping just the link text.

        Converts [text](url) to just text.
        """
        if not text:
            return None
        # Pattern matches [link text](url)
        return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)

    def _truncate(self, text: Optional[str], max_length: int) -> Optional[str]:
        """Truncate text to max length."""
        if not text:
            return None
        if len(text) <= max_length:
            return text
        return text[: max_length - 3] + "..."
