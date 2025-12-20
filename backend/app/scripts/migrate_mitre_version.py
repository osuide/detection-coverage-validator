#!/usr/bin/env python3
"""MITRE ATT&CK version migration script.

Handles migration of techniques and mappings when MITRE framework is updated.
Generates diff reports showing:
- New techniques added
- Deprecated techniques
- Renamed/reorganized techniques
- Impact on existing mappings
"""

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import structlog

logger = structlog.get_logger()


@dataclass
class TechniqueChange:
    """Represents a change to a technique between versions."""

    technique_id: str
    change_type: str  # "added", "deprecated", "renamed", "updated", "unchanged"
    old_name: Optional[str] = None
    new_name: Optional[str] = None
    old_tactic: Optional[str] = None
    new_tactic: Optional[str] = None
    details: str = ""


@dataclass
class MigrationReport:
    """Report of changes between MITRE versions."""

    old_version: str
    new_version: str
    migration_date: datetime = field(default_factory=datetime.utcnow)
    added_techniques: list[TechniqueChange] = field(default_factory=list)
    deprecated_techniques: list[TechniqueChange] = field(default_factory=list)
    renamed_techniques: list[TechniqueChange] = field(default_factory=list)
    updated_techniques: list[TechniqueChange] = field(default_factory=list)
    affected_mappings: list[dict] = field(default_factory=list)
    new_gaps: list[dict] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return (
            len(self.added_techniques)
            + len(self.deprecated_techniques)
            + len(self.renamed_techniques)
            + len(self.updated_techniques)
        )


class MITREMigration:
    """Handles MITRE ATT&CK framework version migrations."""

    def __init__(
        self,
        db_session=None,
        backup_dir: Optional[str] = None,
    ):
        self.db = db_session
        # Use system temp directory instead of hardcoded /tmp for security
        if backup_dir is None:
            backup_dir = str(Path(tempfile.gettempdir()) / "mitre_backups")
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger.bind(component="MITREMigration")

    def compare_versions(
        self,
        old_techniques: list[dict],
        new_techniques: list[dict],
    ) -> MigrationReport:
        """Compare two versions of MITRE techniques.

        Args:
            old_techniques: List of technique dicts from old version
            new_techniques: List of technique dicts from new version

        Returns:
            MigrationReport with all changes identified
        """
        old_version = self._detect_version(old_techniques)
        new_version = self._detect_version(new_techniques)

        self.logger.info(
            "comparing_versions",
            old_version=old_version,
            new_version=new_version,
        )

        # Build lookup dictionaries
        old_by_id = {t["technique_id"]: t for t in old_techniques}
        new_by_id = {t["technique_id"]: t for t in new_techniques}

        old_ids = set(old_by_id.keys())
        new_ids = set(new_by_id.keys())

        report = MigrationReport(
            old_version=old_version,
            new_version=new_version,
        )

        # Find added techniques
        added_ids = new_ids - old_ids
        for tid in added_ids:
            tech = new_by_id[tid]
            report.added_techniques.append(
                TechniqueChange(
                    technique_id=tid,
                    change_type="added",
                    new_name=tech.get("name"),
                    new_tactic=tech.get("tactic_id"),
                    details=f"New technique in {new_version}",
                )
            )

        # Find deprecated techniques
        deprecated_ids = old_ids - new_ids
        for tid in deprecated_ids:
            tech = old_by_id[tid]
            report.deprecated_techniques.append(
                TechniqueChange(
                    technique_id=tid,
                    change_type="deprecated",
                    old_name=tech.get("name"),
                    old_tactic=tech.get("tactic_id"),
                    details=f"Technique deprecated in {new_version}",
                )
            )

        # Find renamed/updated techniques
        common_ids = old_ids & new_ids
        for tid in common_ids:
            old_tech = old_by_id[tid]
            new_tech = new_by_id[tid]

            changes = self._compare_technique(old_tech, new_tech)
            if changes:
                change_type = "renamed" if "name" in changes else "updated"
                report.renamed_techniques.append(
                    TechniqueChange(
                        technique_id=tid,
                        change_type=change_type,
                        old_name=old_tech.get("name"),
                        new_name=new_tech.get("name"),
                        old_tactic=old_tech.get("tactic_id"),
                        new_tactic=new_tech.get("tactic_id"),
                        details=f"Changes: {', '.join(changes)}",
                    )
                )

        self.logger.info(
            "comparison_complete",
            added=len(report.added_techniques),
            deprecated=len(report.deprecated_techniques),
            renamed=len(report.renamed_techniques),
        )

        return report

    def _compare_technique(self, old_tech: dict, new_tech: dict) -> list[str]:
        """Compare two versions of the same technique."""
        changes = []

        if old_tech.get("name") != new_tech.get("name"):
            changes.append("name")

        if old_tech.get("tactic_id") != new_tech.get("tactic_id"):
            changes.append("tactic")

        if old_tech.get("description") != new_tech.get("description"):
            changes.append("description")

        if set(old_tech.get("platforms", [])) != set(new_tech.get("platforms", [])):
            changes.append("platforms")

        if set(old_tech.get("data_sources", [])) != set(
            new_tech.get("data_sources", [])
        ):
            changes.append("data_sources")

        return changes

    def _detect_version(self, techniques: list[dict]) -> str:
        """Detect MITRE version from techniques list."""
        # Try to get version from technique metadata
        for tech in techniques:
            if "version" in tech:
                return tech["version"]
            if "mitre_version" in tech:
                return tech["mitre_version"]

        # Default version
        return "unknown"

    async def backup_current_state(self) -> Path:
        """Backup current mappings and techniques before migration."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"mitre_backup_{timestamp}.json"

        if not self.db:
            self.logger.warning("no_database_connection")
            return backup_file

        # Get current techniques
        from app.models.mitre import Technique, Tactic

        techniques = self.db.query(Technique).all()
        tactics = self.db.query(Tactic).all()

        backup_data = {
            "backup_timestamp": timestamp,
            "techniques": [
                {
                    "technique_id": t.technique_id,
                    "name": t.name,
                    "tactic_id": t.tactic_id,
                    "description": t.description,
                    "platforms": t.platforms,
                    "data_sources": t.data_sources,
                }
                for t in techniques
            ],
            "tactics": [
                {
                    "tactic_id": t.tactic_id,
                    "name": t.name,
                    "short_name": t.short_name,
                }
                for t in tactics
            ],
        }

        # Get current mappings
        from app.models.detection_mapping import DetectionMapping

        mappings = self.db.query(DetectionMapping).all()
        backup_data["mappings"] = [
            {
                "detection_id": str(m.detection_id),
                "technique_id": m.technique_id,
                "confidence": m.confidence,
                "mapping_source": (
                    m.mapping_source.value
                    if hasattr(m.mapping_source, "value")
                    else m.mapping_source
                ),
            }
            for m in mappings
        ]

        with open(backup_file, "w") as f:
            json.dump(backup_data, f, indent=2)

        self.logger.info("backup_created", path=str(backup_file))
        return backup_file

    async def migrate(
        self,
        new_techniques: list[dict],
        dry_run: bool = True,
    ) -> MigrationReport:
        """Execute migration to new MITRE version.

        Args:
            new_techniques: List of technique dicts from new version
            dry_run: If True, don't apply changes (just report)

        Returns:
            MigrationReport with all changes
        """
        if not self.db:
            raise ValueError("Database connection required for migration")

        # Backup current state
        await self.backup_current_state()

        # Get current techniques
        from app.models.mitre import Technique

        current_techniques = self.db.query(Technique).all()
        current_tech_dicts = [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic_id": t.tactic_id,
                "description": t.description,
                "platforms": t.platforms,
                "data_sources": t.data_sources,
            }
            for t in current_techniques
        ]

        # Compare versions
        report = self.compare_versions(current_tech_dicts, new_techniques)

        # Find affected mappings
        from app.models.detection_mapping import DetectionMapping

        deprecated_ids = {t.technique_id for t in report.deprecated_techniques}
        affected_mappings = (
            self.db.query(DetectionMapping)
            .filter(DetectionMapping.technique_id.in_(deprecated_ids))
            .all()
        )

        report.affected_mappings = [
            {
                "detection_id": str(m.detection_id),
                "technique_id": m.technique_id,
                "confidence": m.confidence,
            }
            for m in affected_mappings
        ]

        # Identify new gaps from new techniques
        report.new_gaps = [
            {
                "technique_id": t.technique_id,
                "technique_name": t.new_name,
                "tactic": t.new_tactic,
            }
            for t in report.added_techniques
        ]

        if dry_run:
            self.logger.info("dry_run_complete", changes=report.total_changes)
            return report

        # Apply changes
        await self._apply_migration(report, new_techniques)

        return report

    async def _apply_migration(
        self,
        report: MigrationReport,
        new_techniques: list[dict],
    ):
        """Apply migration changes to database."""
        from app.models.mitre import Technique
        from app.models.detection_mapping import DetectionMapping

        # Mark deprecated techniques
        for change in report.deprecated_techniques:
            technique = (
                self.db.query(Technique)
                .filter(Technique.technique_id == change.technique_id)
                .first()
            )
            if technique:
                technique.is_deprecated = True

        # Update renamed/updated techniques
        for change in report.renamed_techniques + report.updated_techniques:
            technique = (
                self.db.query(Technique)
                .filter(Technique.technique_id == change.technique_id)
                .first()
            )
            if technique:
                new_tech = next(
                    (
                        t
                        for t in new_techniques
                        if t["technique_id"] == change.technique_id
                    ),
                    None,
                )
                if new_tech:
                    technique.name = new_tech.get("name", technique.name)
                    technique.description = new_tech.get(
                        "description", technique.description
                    )
                    technique.platforms = new_tech.get("platforms", technique.platforms)
                    technique.data_sources = new_tech.get(
                        "data_sources", technique.data_sources
                    )

        # Add new techniques
        for change in report.added_techniques:
            new_tech = next(
                (t for t in new_techniques if t["technique_id"] == change.technique_id),
                None,
            )
            if new_tech:
                technique = Technique(
                    technique_id=new_tech["technique_id"],
                    name=new_tech["name"],
                    tactic_id=new_tech.get("tactic_id"),
                    description=new_tech.get("description"),
                    platforms=new_tech.get("platforms", []),
                    data_sources=new_tech.get("data_sources", []),
                )
                self.db.add(technique)

        # Mark affected mappings as stale
        for mapping_info in report.affected_mappings:
            mapping = (
                self.db.query(DetectionMapping)
                .filter(
                    DetectionMapping.detection_id == mapping_info["detection_id"],
                    DetectionMapping.technique_id == mapping_info["technique_id"],
                )
                .first()
            )
            if mapping:
                mapping.is_stale = True

        self.db.commit()
        self.logger.info("migration_applied", changes=report.total_changes)

    def generate_report_markdown(self, report: MigrationReport) -> str:
        """Generate a markdown report of the migration."""
        lines = [
            "# MITRE ATT&CK Migration Report",
            "",
            f"**Migration Date:** {report.migration_date.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**From Version:** {report.old_version}",
            f"**To Version:** {report.new_version}",
            "",
            "## Summary",
            "",
            "| Change Type | Count |",
            "|-------------|-------|",
            f"| New Techniques | {len(report.added_techniques)} |",
            f"| Deprecated Techniques | {len(report.deprecated_techniques)} |",
            f"| Renamed Techniques | {len(report.renamed_techniques)} |",
            f"| Updated Techniques | {len(report.updated_techniques)} |",
            f"| Affected Mappings | {len(report.affected_mappings)} |",
            "",
        ]

        if report.added_techniques:
            lines.extend(
                [
                    "## New Techniques",
                    "",
                    "These techniques need detection coverage assessment:",
                    "",
                ]
            )
            for t in report.added_techniques:
                lines.append(f"- **{t.technique_id}**: {t.new_name} ({t.new_tactic})")
            lines.append("")

        if report.deprecated_techniques:
            lines.extend(
                [
                    "## Deprecated Techniques",
                    "",
                    "Existing mappings to these techniques should be reviewed:",
                    "",
                ]
            )
            for t in report.deprecated_techniques:
                lines.append(f"- **{t.technique_id}**: {t.old_name}")
            lines.append("")

        if report.renamed_techniques:
            lines.extend(
                [
                    "## Renamed/Reorganized Techniques",
                    "",
                ]
            )
            for t in report.renamed_techniques:
                lines.append(f"- **{t.technique_id}**: {t.old_name} -> {t.new_name}")
            lines.append("")

        if report.affected_mappings:
            lines.extend(
                [
                    "## Affected Mappings",
                    "",
                    "The following detection mappings reference deprecated techniques:",
                    "",
                ]
            )
            for m in report.affected_mappings[:20]:  # Limit to 20
                lines.append(
                    f"- Detection `{m['detection_id']}` -> `{m['technique_id']}`"
                )
            if len(report.affected_mappings) > 20:
                lines.append(f"- ... and {len(report.affected_mappings) - 20} more")
            lines.append("")

        lines.extend(
            [
                "## Next Steps",
                "",
                "1. Review new techniques for applicable detections",
                "2. Update mappings referencing deprecated techniques",
                "3. Recalculate coverage for affected accounts",
                "4. Generate new gap analysis",
            ]
        )

        return "\n".join(lines)


def main():
    """CLI entry point for MITRE migration."""
    parser = argparse.ArgumentParser(description="MITRE ATT&CK version migration tool")
    parser.add_argument(
        "--old-version",
        type=str,
        help="Path to old version techniques JSON",
    )
    parser.add_argument(
        "--new-version",
        type=str,
        required=True,
        help="Path to new version techniques JSON",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="migration_report.md",
        help="Output file for migration report",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't apply changes, just generate report",
    )

    args = parser.parse_args()

    # Load new techniques
    with open(args.new_version, "r") as f:
        new_techniques = json.load(f)

    # Load old techniques if provided
    if args.old_version:
        with open(args.old_version, "r") as f:
            old_techniques = json.load(f)
    else:
        # Use empty list (will compare against database)
        old_techniques = []

    # Run migration
    migration = MITREMigration()

    if old_techniques:
        report = migration.compare_versions(old_techniques, new_techniques)
    else:
        print("Note: Running without database connection (comparison only)")
        report = MigrationReport(
            old_version="current",
            new_version="new",
        )

    # Generate report
    report_md = migration.generate_report_markdown(report)

    # Save report
    with open(args.output, "w") as f:
        f.write(report_md)

    print(f"Migration report written to: {args.output}")
    print(f"Total changes: {report.total_changes}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
