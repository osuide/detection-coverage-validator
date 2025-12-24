"""MITRE ATT&CK Threat Intelligence Sync Service.

Downloads and syncs MITRE ATT&CK STIX data to the database.
"""

import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import stix2
import structlog
from mitreattack.stix20 import MitreAttackData
from sqlalchemy import select, delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mitre import Technique
from app.models.mitre_threat import (
    MitreThreatGroup,
    MitreCampaign,
    MitreSoftware,
    MitreTechniqueRelationship,
    MitreSyncHistory,
    MitreDataVersion,
    SyncStatus,
    SyncTriggerType,
    RelatedType,
)

logger = structlog.get_logger()

# MITRE ATT&CK STIX data URLs
STIX_DATA_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


@dataclass
class SyncStats:
    """Statistics for a sync operation."""

    added: int = 0
    updated: int = 0
    skipped: int = 0
    errors: int = 0


@dataclass
class FullSyncStats:
    """Full statistics for a complete sync."""

    groups: SyncStats = field(default_factory=SyncStats)
    campaigns: SyncStats = field(default_factory=SyncStats)
    software: SyncStats = field(default_factory=SyncStats)
    relationships: SyncStats = field(default_factory=SyncStats)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON storage."""
        return {
            "groups_added": self.groups.added,
            "groups_updated": self.groups.updated,
            "groups_skipped": self.groups.skipped,
            "groups_errors": self.groups.errors,
            "campaigns_added": self.campaigns.added,
            "campaigns_updated": self.campaigns.updated,
            "campaigns_skipped": self.campaigns.skipped,
            "campaigns_errors": self.campaigns.errors,
            "software_added": self.software.added,
            "software_updated": self.software.updated,
            "software_skipped": self.software.skipped,
            "software_errors": self.software.errors,
            "relationships_added": self.relationships.added,
            "relationships_updated": self.relationships.updated,
            "relationships_skipped": self.relationships.skipped,
            "relationships_errors": self.relationships.errors,
        }


class MitreSyncService:
    """Service for syncing MITRE ATT&CK threat intelligence data."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self._technique_id_cache: dict[str, uuid.UUID] = {}

    async def sync_all(
        self,
        admin_id: Optional[uuid.UUID] = None,
        trigger_type: str = SyncTriggerType.MANUAL.value,
    ) -> MitreSyncHistory:
        """
        Perform a full sync of MITRE ATT&CK data.

        Args:
            admin_id: ID of admin who triggered the sync (None for scheduled)
            trigger_type: How the sync was triggered

        Returns:
            MitreSyncHistory record with sync details
        """
        # Create sync history record
        sync_history = MitreSyncHistory(
            started_at=datetime.now(timezone.utc),
            status=SyncStatus.RUNNING.value,
            triggered_by_admin_id=admin_id,
            trigger_type=trigger_type,
        )
        self.db.add(sync_history)
        await self.db.flush()

        logger.info(
            "mitre_sync_started",
            sync_id=str(sync_history.id),
            trigger_type=trigger_type,
        )

        try:
            # Download STIX data
            stix_path = await self._download_stix_data()

            # Parse with mitreattack-python
            attack_data = MitreAttackData(str(stix_path))

            # Get version info
            mitre_version = self._extract_version(attack_data)

            # Build technique ID cache for relationship mapping
            await self._build_technique_cache()

            # Sync each entity type
            stats = FullSyncStats()

            stats.groups = await self._sync_groups(attack_data, mitre_version)
            stats.campaigns = await self._sync_campaigns(attack_data, mitre_version)
            stats.software = await self._sync_software(attack_data, mitre_version)
            stats.relationships = await self._sync_relationships(
                attack_data, mitre_version
            )

            # Update sync history
            sync_history.status = SyncStatus.COMPLETED.value
            sync_history.completed_at = datetime.now(timezone.utc)
            sync_history.mitre_version = mitre_version
            sync_history.stix_version = "2.0"
            sync_history.stats = stats.to_dict()

            # Update or create data version record
            await self._update_data_version(sync_history, stats)

            # Cleanup temp file
            stix_path.unlink(missing_ok=True)

            logger.info(
                "mitre_sync_completed",
                sync_id=str(sync_history.id),
                mitre_version=mitre_version,
                stats=stats.to_dict(),
            )

            await self.db.commit()
            return sync_history

        except Exception as e:
            logger.error(
                "mitre_sync_failed",
                sync_id=str(sync_history.id),
                error=str(e),
            )

            sync_history.status = SyncStatus.FAILED.value
            sync_history.completed_at = datetime.now(timezone.utc)
            sync_history.error_message = str(e)

            await self.db.commit()
            raise

    async def get_current_version(self) -> Optional[MitreDataVersion]:
        """Get current MITRE data version info."""
        result = await self.db.execute(select(MitreDataVersion).limit(1))
        return result.scalar_one_or_none()

    async def get_sync_history(self, limit: int = 20) -> list[MitreSyncHistory]:
        """Get recent sync history."""
        result = await self.db.execute(
            select(MitreSyncHistory)
            .order_by(MitreSyncHistory.started_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def _download_stix_data(self) -> Path:
        """Download STIX JSON from GitHub."""
        logger.info("downloading_stix_data", url=STIX_DATA_URL)

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.get(STIX_DATA_URL)
            response.raise_for_status()

            # Write to temp file
            temp_file = tempfile.NamedTemporaryFile(
                mode="wb", suffix=".json", delete=False
            )
            temp_file.write(response.content)
            temp_file.close()

            logger.info(
                "stix_data_downloaded",
                size_bytes=len(response.content),
                path=temp_file.name,
            )

            return Path(temp_file.name)

    def _extract_version(self, attack_data: MitreAttackData) -> str:
        """Extract MITRE ATT&CK version from STIX data.

        The ATT&CK version is stored in the x-mitre-collection object,
        not in individual technique x_mitre_version attributes.
        """
        try:
            # Access the underlying STIX memory store to find collection objects
            if hasattr(attack_data, "src"):
                # Query for x-mitre-collection objects
                collections = attack_data.src.query(
                    [stix2.Filter("type", "=", "x-mitre-collection")]
                )
                if collections:
                    for collection in collections:
                        if hasattr(collection, "x_mitre_version"):
                            return collection.x_mitre_version

            # Fallback: Try to get version from identity object's x_mitre_attack_spec_version
            if hasattr(attack_data, "src"):
                identities = attack_data.src.query(
                    [stix2.Filter("type", "=", "identity")]
                )
                for identity in identities:
                    if hasattr(identity, "x_mitre_attack_spec_version"):
                        return identity.x_mitre_attack_spec_version

            return "unknown"
        except Exception as e:
            logger.warning("version_extraction_failed", error=str(e))
            return "unknown"

    async def _build_technique_cache(self) -> None:
        """Build cache of technique_id -> UUID for relationship mapping."""
        result = await self.db.execute(select(Technique.id, Technique.technique_id))
        self._technique_id_cache = {row.technique_id: row.id for row in result.all()}
        logger.info(
            "technique_cache_built",
            count=len(self._technique_id_cache),
        )

    async def _sync_groups(
        self, attack_data: MitreAttackData, version: str
    ) -> SyncStats:
        """Sync threat groups from STIX data."""
        stats = SyncStats()
        groups = attack_data.get_groups()

        logger.info("syncing_groups", count=len(groups))

        for group in groups:
            try:
                # Skip revoked/deprecated
                if getattr(group, "revoked", False):
                    stats.skipped += 1
                    continue

                # Extract external ID (G####)
                external_id = None
                external_refs = []
                for ref in getattr(group, "external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        external_id = ref.get("external_id")
                    external_refs.append(
                        {
                            "source_name": ref.get("source_name"),
                            "url": ref.get("url"),
                            "external_id": ref.get("external_id"),
                            "description": ref.get("description"),
                        }
                    )

                if not external_id:
                    stats.skipped += 1
                    continue

                # Parse timestamps
                first_seen = self._parse_timestamp(getattr(group, "first_seen", None))
                last_seen = self._parse_timestamp(getattr(group, "last_seen", None))

                # Upsert group
                stmt = insert(MitreThreatGroup).values(
                    stix_id=group.id,
                    external_id=external_id,
                    name=group.name,
                    aliases=getattr(group, "aliases", []) or [],
                    description=getattr(group, "description", None),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    is_revoked=getattr(group, "revoked", False),
                    is_deprecated=getattr(group, "x_mitre_deprecated", False),
                    external_references=external_refs,
                    mitre_version=version,
                    updated_at=datetime.now(timezone.utc),
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=["stix_id"],
                    set_={
                        "name": stmt.excluded.name,
                        "aliases": stmt.excluded.aliases,
                        "description": stmt.excluded.description,
                        "first_seen": stmt.excluded.first_seen,
                        "last_seen": stmt.excluded.last_seen,
                        "is_revoked": stmt.excluded.is_revoked,
                        "is_deprecated": stmt.excluded.is_deprecated,
                        "external_references": stmt.excluded.external_references,
                        "mitre_version": stmt.excluded.mitre_version,
                        "updated_at": stmt.excluded.updated_at,
                    },
                )
                await self.db.execute(stmt)
                stats.added += 1

            except Exception as e:
                logger.warning(
                    "group_sync_error",
                    group_id=getattr(group, "id", "unknown"),
                    error=str(e),
                )
                stats.errors += 1

        await self.db.flush()
        return stats

    async def _sync_campaigns(
        self, attack_data: MitreAttackData, version: str
    ) -> SyncStats:
        """Sync campaigns from STIX data."""
        stats = SyncStats()
        campaigns = attack_data.get_campaigns()

        logger.info("syncing_campaigns", count=len(campaigns))

        for campaign in campaigns:
            try:
                if getattr(campaign, "revoked", False):
                    stats.skipped += 1
                    continue

                external_id = None
                external_refs = []
                for ref in getattr(campaign, "external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        external_id = ref.get("external_id")
                    external_refs.append(
                        {
                            "source_name": ref.get("source_name"),
                            "url": ref.get("url"),
                            "external_id": ref.get("external_id"),
                            "description": ref.get("description"),
                        }
                    )

                if not external_id:
                    stats.skipped += 1
                    continue

                first_seen = self._parse_timestamp(
                    getattr(campaign, "first_seen", None)
                )
                last_seen = self._parse_timestamp(getattr(campaign, "last_seen", None))

                stmt = insert(MitreCampaign).values(
                    stix_id=campaign.id,
                    external_id=external_id,
                    name=campaign.name,
                    description=getattr(campaign, "description", None),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    is_revoked=getattr(campaign, "revoked", False),
                    is_deprecated=getattr(campaign, "x_mitre_deprecated", False),
                    external_references=external_refs,
                    mitre_version=version,
                    updated_at=datetime.now(timezone.utc),
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=["stix_id"],
                    set_={
                        "name": stmt.excluded.name,
                        "description": stmt.excluded.description,
                        "first_seen": stmt.excluded.first_seen,
                        "last_seen": stmt.excluded.last_seen,
                        "is_revoked": stmt.excluded.is_revoked,
                        "is_deprecated": stmt.excluded.is_deprecated,
                        "external_references": stmt.excluded.external_references,
                        "mitre_version": stmt.excluded.mitre_version,
                        "updated_at": stmt.excluded.updated_at,
                    },
                )
                await self.db.execute(stmt)
                stats.added += 1

            except Exception as e:
                logger.warning(
                    "campaign_sync_error",
                    campaign_id=getattr(campaign, "id", "unknown"),
                    error=str(e),
                )
                stats.errors += 1

        await self.db.flush()
        return stats

    async def _sync_software(
        self, attack_data: MitreAttackData, version: str
    ) -> SyncStats:
        """Sync software (malware and tools) from STIX data."""
        stats = SyncStats()

        # Get all software (includes both malware and tools)
        software_list = attack_data.get_software()

        logger.info(
            "syncing_software",
            software_count=len(software_list),
        )

        for item in software_list:
            try:
                if getattr(item, "revoked", False):
                    stats.skipped += 1
                    continue

                external_id = None
                external_refs = []
                for ref in getattr(item, "external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        external_id = ref.get("external_id")
                    external_refs.append(
                        {
                            "source_name": ref.get("source_name"),
                            "url": ref.get("url"),
                            "external_id": ref.get("external_id"),
                            "description": ref.get("description"),
                        }
                    )

                if not external_id:
                    stats.skipped += 1
                    continue

                # Determine software type from STIX object type
                software_type = getattr(item, "type", "tool")
                if software_type not in ("malware", "tool"):
                    software_type = "tool"

                platforms = getattr(item, "x_mitre_platforms", []) or []

                stmt = insert(MitreSoftware).values(
                    stix_id=item.id,
                    external_id=external_id,
                    name=item.name,
                    software_type=software_type,
                    aliases=getattr(item, "aliases", []) or [],
                    description=getattr(item, "description", None),
                    platforms=platforms,
                    is_revoked=getattr(item, "revoked", False),
                    is_deprecated=getattr(item, "x_mitre_deprecated", False),
                    external_references=external_refs,
                    mitre_version=version,
                    updated_at=datetime.now(timezone.utc),
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=["stix_id"],
                    set_={
                        "name": stmt.excluded.name,
                        "software_type": stmt.excluded.software_type,
                        "aliases": stmt.excluded.aliases,
                        "description": stmt.excluded.description,
                        "platforms": stmt.excluded.platforms,
                        "is_revoked": stmt.excluded.is_revoked,
                        "is_deprecated": stmt.excluded.is_deprecated,
                        "external_references": stmt.excluded.external_references,
                        "mitre_version": stmt.excluded.mitre_version,
                        "updated_at": stmt.excluded.updated_at,
                    },
                )
                await self.db.execute(stmt)
                stats.added += 1

            except Exception as e:
                logger.warning(
                    "software_sync_error",
                    software_id=getattr(item, "id", "unknown"),
                    error=str(e),
                )
                stats.errors += 1

        await self.db.flush()
        return stats

    async def _sync_relationships(
        self, attack_data: MitreAttackData, version: str
    ) -> SyncStats:
        """Sync technique relationships from STIX data.

        Uses the correct mitreattack-python API:
        - get_all_groups_using_all_techniques()
        - get_all_campaigns_using_all_techniques()
        - get_all_software_using_all_techniques()

        These return dict[technique_stix_id, list[RelationshipEntry]] where
        RelationshipEntry has 'object' and 'relationships' keys.
        """
        stats = SyncStats()

        # Build lookup caches for our entities (STIX ID -> UUID)
        group_cache = await self._build_entity_cache(MitreThreatGroup)
        campaign_cache = await self._build_entity_cache(MitreCampaign)
        software_cache = await self._build_entity_cache(MitreSoftware)

        # Build technique STIX ID -> UUID cache
        technique_stix_cache = self._build_technique_stix_cache(attack_data)

        logger.info(
            "relationship_caches_built",
            groups=len(group_cache),
            campaigns=len(campaign_cache),
            software=len(software_cache),
            techniques=len(technique_stix_cache),
        )

        # Clear existing relationships
        await self.db.execute(delete(MitreTechniqueRelationship))
        await self.db.flush()

        # Process group relationships
        groups_using_techniques = attack_data.get_all_groups_using_all_techniques()
        stats = await self._process_relationship_map(
            relationship_map=groups_using_techniques,
            entity_cache=group_cache,
            technique_cache=technique_stix_cache,
            related_type=RelatedType.GROUP.value,
            version=version,
            stats=stats,
        )

        # Process campaign relationships
        campaigns_using_techniques = (
            attack_data.get_all_campaigns_using_all_techniques()
        )
        stats = await self._process_relationship_map(
            relationship_map=campaigns_using_techniques,
            entity_cache=campaign_cache,
            technique_cache=technique_stix_cache,
            related_type=RelatedType.CAMPAIGN.value,
            version=version,
            stats=stats,
        )

        # Process software relationships
        software_using_techniques = attack_data.get_all_software_using_all_techniques()
        stats = await self._process_relationship_map(
            relationship_map=software_using_techniques,
            entity_cache=software_cache,
            technique_cache=technique_stix_cache,
            related_type=RelatedType.SOFTWARE.value,
            version=version,
            stats=stats,
        )

        await self.db.flush()

        logger.info(
            "relationships_synced",
            added=stats.added,
            skipped=stats.skipped,
            errors=stats.errors,
        )

        return stats

    async def _process_relationship_map(
        self,
        relationship_map: dict,
        entity_cache: dict[str, uuid.UUID],
        technique_cache: dict[str, uuid.UUID],
        related_type: str,
        version: str,
        stats: SyncStats,
    ) -> SyncStats:
        """Process a relationship map from mitreattack-python.

        The map structure is: {technique_stix_id: [RelationshipEntry, ...]}
        where RelationshipEntry = {"object": entity, "relationships": [rel, ...]}
        """
        for technique_stix_id, entries in relationship_map.items():
            # Look up our technique UUID
            technique_uuid = technique_cache.get(technique_stix_id)
            if not technique_uuid:
                stats.skipped += len(entries)
                continue

            for entry in entries:
                try:
                    entity = entry.get("object")
                    relationships = entry.get("relationships", [])

                    if not entity:
                        stats.skipped += 1
                        continue

                    # Get entity STIX ID and look up our UUID
                    entity_stix_id = getattr(entity, "id", None)
                    if not entity_stix_id:
                        stats.skipped += 1
                        continue

                    related_id = entity_cache.get(entity_stix_id)
                    if not related_id:
                        stats.skipped += 1
                        continue

                    # Extract description from first relationship
                    description = None
                    external_refs = []
                    if relationships:
                        first_rel = relationships[0]
                        description = getattr(first_rel, "description", None)
                        for ref in getattr(first_rel, "external_references", []):
                            external_refs.append(
                                {
                                    "source_name": ref.get("source_name"),
                                    "url": ref.get("url"),
                                    "description": ref.get("description"),
                                }
                            )

                    # Insert relationship
                    new_rel = MitreTechniqueRelationship(
                        technique_id=technique_uuid,
                        related_type=related_type,
                        related_id=related_id,
                        relationship_type="uses",
                        description=description,
                        external_references=external_refs,
                        mitre_version=version,
                    )
                    self.db.add(new_rel)
                    stats.added += 1

                except Exception as e:
                    logger.warning(
                        "relationship_entry_error",
                        technique_stix_id=technique_stix_id,
                        related_type=related_type,
                        error=str(e),
                    )
                    stats.errors += 1

        return stats

    def _build_technique_stix_cache(
        self, attack_data: MitreAttackData
    ) -> dict[str, uuid.UUID]:
        """Build mapping of technique STIX ID -> our technique UUID.

        MITRE data uses STIX IDs (attack-pattern--...), but our Technique
        model uses technique_id (T####). We need to map between them.
        """
        # First, build STIX ID -> technique_id mapping from MITRE data
        stix_to_technique_id: dict[str, str] = {}
        techniques = attack_data.get_techniques(remove_revoked_deprecated=True)

        for tech in techniques:
            stix_id = getattr(tech, "id", None)
            if not stix_id:
                continue

            # Extract technique_id from external_references
            for ref in getattr(tech, "external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    if technique_id:
                        stix_to_technique_id[stix_id] = technique_id
                    break

        # Now combine with our technique_id -> UUID cache
        stix_to_uuid: dict[str, uuid.UUID] = {}
        for stix_id, technique_id in stix_to_technique_id.items():
            if technique_id in self._technique_id_cache:
                stix_to_uuid[stix_id] = self._technique_id_cache[technique_id]

        return stix_to_uuid

    async def _build_entity_cache(self, model: type) -> dict[str, uuid.UUID]:
        """Build cache of STIX ID -> UUID for an entity type."""
        result = await self.db.execute(select(model.id, model.stix_id))
        return {row.stix_id: row.id for row in result.all()}

    async def _update_data_version(
        self, sync_history: MitreSyncHistory, stats: FullSyncStats
    ) -> None:
        """Update or create the data version record."""
        # Count entities
        groups_count = await self._count_entities(MitreThreatGroup)
        campaigns_count = await self._count_entities(MitreCampaign)
        software_count = await self._count_entities(MitreSoftware)
        relationships_count = await self._count_entities(MitreTechniqueRelationship)

        # Check for existing version record
        result = await self.db.execute(select(MitreDataVersion).limit(1))
        version_record = result.scalar_one_or_none()

        if version_record:
            version_record.mitre_version = sync_history.mitre_version or "unknown"
            version_record.stix_version = sync_history.stix_version or "2.0"
            version_record.last_sync_at = sync_history.completed_at
            version_record.last_sync_id = sync_history.id
            version_record.total_groups = groups_count
            version_record.total_campaigns = campaigns_count
            version_record.total_software = software_count
            version_record.total_relationships = relationships_count
            version_record.source_url = STIX_DATA_URL
        else:
            version_record = MitreDataVersion(
                mitre_version=sync_history.mitre_version or "unknown",
                stix_version=sync_history.stix_version or "2.0",
                last_sync_at=sync_history.completed_at or datetime.now(timezone.utc),
                last_sync_id=sync_history.id,
                total_groups=groups_count,
                total_campaigns=campaigns_count,
                total_software=software_count,
                total_relationships=relationships_count,
                source_url=STIX_DATA_URL,
            )
            self.db.add(version_record)

        await self.db.flush()

    async def _count_entities(self, model: type) -> int:
        """Count entities in a table."""
        from sqlalchemy import func as sql_func

        result = await self.db.execute(select(sql_func.count()).select_from(model))
        return result.scalar() or 0

    def _parse_timestamp(self, value: Optional[str]) -> Optional[datetime]:
        """Parse a timestamp string to datetime."""
        if not value:
            return None
        try:
            # Handle various formats
            if isinstance(value, datetime):
                return value
            if "T" in value:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            return None
