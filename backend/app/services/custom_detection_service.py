"""Custom detection upload and mapping service."""

import re
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import structlog
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.custom_detection import (
    CustomDetection,
    CustomDetectionBatch,
    CustomDetectionFormat,
    CustomDetectionStatus,
)
from app.models.mitre import Technique

logger = structlog.get_logger()


# MITRE technique patterns commonly found in detection rules
MITRE_PATTERNS = {
    # Account patterns
    r"createuser|newuser|adduser": ["T1136"],
    r"deleteuser|removeuser": ["T1531"],
    r"usermod|passwd|chpasswd": ["T1098"],
    r"privilege.?escalat|sudo|doas": ["T1548"],
    # Credential patterns
    r"mimikatz|sekurlsa|wdigest": ["T1003"],
    r"passwd|shadow|credentials": ["T1552"],
    r"kerberos|golden.?ticket|silver.?ticket": ["T1558"],
    r"brute.?force|password.?spray": ["T1110"],
    # Persistence patterns
    r"registry.?run|autorun|startup": ["T1547"],
    r"scheduled.?task|cron|at\.exe": ["T1053"],
    r"service.?create|sc\.exe": ["T1543"],
    r"dll.?hijack|dll.?search": ["T1574"],
    # Defense evasion
    r"disable.?av|antivirus|defender": ["T1562"],
    r"clear.?log|wevtutil|auditpol": ["T1070"],
    r"process.?injection|dll.?inject": ["T1055"],
    r"obfuscat|encode|base64|xor": ["T1140"],
    # Discovery
    r"net\s+(user|group|localgroup)": ["T1087"],
    r"nltest|dsquery|ldapsearch": ["T1482"],
    r"arp|netstat|nslookup": ["T1016"],
    r"systeminfo|hostname|whoami": ["T1082"],
    # Lateral movement
    r"psexec|wmi|winrm|ssh": ["T1021"],
    r"pass.?the.?hash|pth|overpass": ["T1550"],
    r"remote.?desktop|rdp|mstsc": ["T1021.001"],
    # Collection
    r"keylog|GetAsyncKeyState": ["T1056"],
    r"screenshot|screen.?capture": ["T1113"],
    r"clipboard|GetClipboardData": ["T1115"],
    # Exfiltration
    r"compress|zip|rar|7z": ["T1560"],
    r"ftp|sftp|scp": ["T1048"],
    r"cloud.?storage|s3|gcs|azure.?blob": ["T1567"],
    # C2 patterns
    r"beacon|cobalt.?strike|empire": ["T1071"],
    r"dns.?tunnel|dnscat": ["T1071.004"],
    r"http.?c2|https.?beacon": ["T1071.001"],
    # Impact
    r"ransomware|encrypt.?file|crypto": ["T1486"],
    r"wipe|destroy|mbr": ["T1561"],
    r"defacement|vandal": ["T1491"],
    # Cloud-specific
    r"iam.?policy|assumeRole": ["T1078.004"],
    r"instance.?metadata|169\.254\.169\.254": ["T1552.005"],
    r"cloudtrail.?disable|logging.?disable": ["T1562.008"],
}


class CustomDetectionService:
    """Service for managing custom detection uploads."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def upload_detection(
        self,
        organization_id: UUID,
        user_id: UUID,
        name: str,
        rule_content: str,
        format: CustomDetectionFormat,
        description: Optional[str] = None,
        cloud_account_id: Optional[UUID] = None,
        tags: Optional[list] = None,
        severity: Optional[str] = None,
    ) -> CustomDetection:
        """Upload a single custom detection rule.

        Args:
            organization_id: Organisation owning the detection
            user_id: User uploading the detection
            name: Detection name
            rule_content: The detection rule content
            format: Format of the detection rule
            description: Optional description
            cloud_account_id: Optional specific cloud account
            tags: Optional tags
            severity: Optional severity level

        Returns:
            Created CustomDetection
        """
        # Parse rule metadata if available
        metadata = self._parse_rule_metadata(rule_content, format)

        detection = CustomDetection(
            organization_id=organization_id,
            cloud_account_id=cloud_account_id,
            created_by=user_id,
            name=name,
            description=description,
            format=format,
            status=CustomDetectionStatus.PENDING,
            rule_content=rule_content,
            rule_metadata=metadata,
            tags=tags,
            severity=severity,
        )

        self.db.add(detection)
        await self.db.commit()
        await self.db.refresh(detection)

        # Trigger mapping asynchronously
        await self._map_detection(detection)

        return detection

    async def upload_batch(
        self,
        organization_id: UUID,
        user_id: UUID,
        filename: str,
        content: str,
        format: CustomDetectionFormat,
    ) -> CustomDetectionBatch:
        """Upload a batch of detection rules from a file.

        Args:
            organization_id: Organisation owning the detections
            user_id: User uploading
            filename: Original filename
            content: File content
            format: Format of the rules

        Returns:
            Created CustomDetectionBatch
        """
        batch = CustomDetectionBatch(
            organization_id=organization_id,
            created_by=user_id,
            filename=filename,
            format=format,
            status=CustomDetectionStatus.PROCESSING,
            started_at=datetime.now(timezone.utc),
        )

        self.db.add(batch)
        await self.db.commit()
        await self.db.refresh(batch)

        # Parse rules based on format
        try:
            rules = self._parse_batch_content(content, format)
            batch.total_rules = len(rules)

            for rule in rules:
                try:
                    detection = await self.upload_detection(
                        organization_id=organization_id,
                        user_id=user_id,
                        name=rule.get("name", f"Rule from {filename}"),
                        rule_content=rule.get("content", ""),
                        format=format,
                        description=rule.get("description"),
                        tags=rule.get("tags"),
                        severity=rule.get("severity"),
                    )
                    batch.processed_rules += 1
                    if detection.status == CustomDetectionStatus.MAPPED:
                        batch.successful_rules += 1
                    else:
                        batch.failed_rules += 1
                except Exception as e:
                    logger.warning(
                        "batch_rule_failed",
                        batch_id=str(batch.id),
                        error=str(e),
                    )
                    batch.processed_rules += 1
                    batch.failed_rules += 1

            batch.status = CustomDetectionStatus.MAPPED
            batch.completed_at = datetime.now(timezone.utc)

        except Exception as e:
            logger.error(
                "batch_upload_failed",
                batch_id=str(batch.id),
                error=str(e),
            )
            batch.status = CustomDetectionStatus.FAILED
            batch.error_message = str(e)
            batch.completed_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(batch)
        return batch

    def _parse_rule_metadata(self, content: str, format: CustomDetectionFormat) -> dict:
        """Extract metadata from rule content."""
        metadata = {}

        if format == CustomDetectionFormat.SIGMA:
            # Parse SIGMA YAML metadata
            try:
                import yaml

                rule = yaml.safe_load(content)
                if isinstance(rule, dict):
                    metadata = {
                        "title": rule.get("title"),
                        "status": rule.get("status"),
                        "level": rule.get("level"),
                        "author": rule.get("author"),
                        "logsource": rule.get("logsource"),
                        "tags": rule.get("tags", []),
                        "references": rule.get("references", []),
                    }
            except Exception:
                pass

        elif format == CustomDetectionFormat.YARA:
            # Parse YARA rule metadata
            meta_match = re.search(
                r"meta:\s*\n(.*?)\n\s*(strings:|condition:)", content, re.DOTALL
            )
            if meta_match:
                meta_block = meta_match.group(1)
                for line in meta_block.split("\n"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        metadata[key.strip()] = value.strip().strip('"')

        return metadata

    def _parse_batch_content(
        self, content: str, format: CustomDetectionFormat
    ) -> list[dict]:
        """Parse batch file content into individual rules."""
        rules = []

        if format == CustomDetectionFormat.SIGMA:
            # YAML documents separated by ---
            try:
                import yaml

                for doc in yaml.safe_load_all(content):
                    if doc:
                        rules.append(
                            {
                                "name": doc.get("title", "Untitled Sigma Rule"),
                                "content": yaml.dump(doc),
                                "description": doc.get("description"),
                                "tags": doc.get("tags"),
                                "severity": doc.get("level"),
                            }
                        )
            except Exception:
                pass

        elif format == CustomDetectionFormat.YARA:
            # Parse YARA rules
            rule_pattern = r"rule\s+(\w+).*?{.*?}"
            for match in re.finditer(rule_pattern, content, re.DOTALL):
                rule_name = match.group(1)
                rule_content = match.group(0)
                rules.append(
                    {
                        "name": rule_name,
                        "content": rule_content,
                    }
                )

        elif format in [
            CustomDetectionFormat.SPL,
            CustomDetectionFormat.KQL,
            CustomDetectionFormat.CLOUDWATCH,
        ]:
            # Line-separated queries
            for line in content.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    rules.append(
                        {
                            "name": f"Query: {line[:50]}...",
                            "content": line,
                        }
                    )

        else:
            # Default: treat entire content as single rule
            rules.append(
                {
                    "name": "Custom Detection",
                    "content": content,
                }
            )

        return rules

    async def _map_detection(self, detection: CustomDetection) -> None:
        """Map a detection to MITRE ATT&CK techniques."""
        try:
            detection.status = CustomDetectionStatus.PROCESSING
            await self.db.commit()

            # Extract potential techniques from rule content
            content_lower = detection.rule_content.lower()
            matched_techniques = set()

            # Check against our patterns
            for pattern, techniques in MITRE_PATTERNS.items():
                if re.search(pattern, content_lower, re.IGNORECASE):
                    matched_techniques.update(techniques)

            # Also check rule metadata for explicit MITRE tags
            if detection.rule_metadata:
                tags = detection.rule_metadata.get("tags", [])
                for tag in tags:
                    if isinstance(tag, str):
                        # SIGMA uses attack.technique tags
                        if tag.startswith("attack.t"):
                            technique_id = tag.replace("attack.", "").upper()
                            matched_techniques.add(technique_id)

            # Validate techniques exist in our database
            if matched_techniques:
                result = await self.db.execute(
                    select(Technique.technique_id).where(
                        Technique.technique_id.in_(list(matched_techniques))
                    )
                )
                valid_techniques = [row[0] for row in result.all()]
                detection.mapped_techniques = valid_techniques
                detection.mapping_confidence = 0.8 if valid_techniques else 0.0

            if detection.mapped_techniques:
                detection.status = CustomDetectionStatus.MAPPED
            else:
                detection.status = CustomDetectionStatus.NEEDS_REVIEW
                detection.mapping_notes = (
                    "No MITRE techniques automatically detected. "
                    "Manual mapping may be required."
                )

            detection.processed_at = datetime.now(timezone.utc)
            await self.db.commit()

        except Exception as e:
            logger.error(
                "detection_mapping_failed",
                detection_id=str(detection.id),
                error=str(e),
            )
            detection.status = CustomDetectionStatus.FAILED
            detection.processing_error = str(e)
            detection.processed_at = datetime.now(timezone.utc)
            await self.db.commit()

    async def update_mapping(
        self,
        detection_id: UUID,
        organization_id: UUID,
        techniques: list[str],
        notes: Optional[str] = None,
    ) -> Optional[CustomDetection]:
        """Manually update technique mapping for a detection.

        Args:
            detection_id: Detection to update
            organization_id: For access control
            techniques: List of technique IDs
            notes: Optional mapping notes

        Returns:
            Updated detection or None if not found
        """
        result = await self.db.execute(
            select(CustomDetection).where(
                CustomDetection.id == detection_id,
                CustomDetection.organization_id == organization_id,
            )
        )
        detection = result.scalar_one_or_none()

        if not detection:
            return None

        # Validate techniques
        valid_result = await self.db.execute(
            select(Technique.technique_id).where(Technique.technique_id.in_(techniques))
        )
        valid_techniques = [row[0] for row in valid_result.all()]

        detection.mapped_techniques = valid_techniques
        detection.mapping_confidence = 1.0  # Manual mapping is high confidence
        detection.mapping_notes = notes
        detection.status = (
            CustomDetectionStatus.MAPPED
            if valid_techniques
            else CustomDetectionStatus.NEEDS_REVIEW
        )
        detection.processed_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(detection)
        return detection

    async def list_detections(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
        status: Optional[CustomDetectionStatus] = None,
        format: Optional[CustomDetectionFormat] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[CustomDetection], int]:
        """List custom detections with filtering.

        Args:
            organization_id: Organisation to list for
            cloud_account_id: Optional filter by account
            status: Optional filter by status
            format: Optional filter by format
            limit: Maximum results
            offset: Pagination offset

        Returns:
            Tuple of (detections, total_count)
        """
        query = select(CustomDetection).where(
            CustomDetection.organization_id == organization_id
        )
        count_query = select(func.count(CustomDetection.id)).where(
            CustomDetection.organization_id == organization_id
        )

        if cloud_account_id:
            query = query.where(CustomDetection.cloud_account_id == cloud_account_id)
            count_query = count_query.where(
                CustomDetection.cloud_account_id == cloud_account_id
            )

        if status:
            query = query.where(CustomDetection.status == status)
            count_query = count_query.where(CustomDetection.status == status)

        if format:
            query = query.where(CustomDetection.format == format)
            count_query = count_query.where(CustomDetection.format == format)

        # Get total count
        count_result = await self.db.execute(count_query)
        total = count_result.scalar() or 0

        # Get paginated results
        query = (
            query.order_by(desc(CustomDetection.created_at)).offset(offset).limit(limit)
        )
        result = await self.db.execute(query)
        detections = result.scalars().all()

        return list(detections), total

    async def get_detection(
        self,
        detection_id: UUID,
        organization_id: UUID,
    ) -> Optional[CustomDetection]:
        """Get a specific custom detection.

        Args:
            detection_id: Detection ID
            organization_id: For access control

        Returns:
            Detection or None if not found
        """
        result = await self.db.execute(
            select(CustomDetection).where(
                CustomDetection.id == detection_id,
                CustomDetection.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    async def delete_detection(
        self,
        detection_id: UUID,
        organization_id: UUID,
    ) -> bool:
        """Delete a custom detection.

        Args:
            detection_id: Detection to delete
            organization_id: For access control

        Returns:
            True if deleted, False if not found
        """
        detection = await self.get_detection(detection_id, organization_id)
        if not detection:
            return False

        await self.db.delete(detection)
        await self.db.commit()
        return True

    async def get_mapping_summary(
        self,
        organization_id: UUID,
        cloud_account_id: Optional[UUID] = None,
    ) -> dict:
        """Get summary of custom detection mappings.

        Args:
            organization_id: Organisation to summarise
            cloud_account_id: Optional filter by account

        Returns:
            Summary statistics
        """
        base_query = select(CustomDetection).where(
            CustomDetection.organization_id == organization_id
        )
        if cloud_account_id:
            base_query = base_query.where(
                CustomDetection.cloud_account_id == cloud_account_id
            )

        # Count by status
        status_counts = {}
        for status in CustomDetectionStatus:
            count_query = select(func.count(CustomDetection.id)).where(
                CustomDetection.organization_id == organization_id,
                CustomDetection.status == status,
            )
            if cloud_account_id:
                count_query = count_query.where(
                    CustomDetection.cloud_account_id == cloud_account_id
                )
            result = await self.db.execute(count_query)
            status_counts[status.value] = result.scalar() or 0

        # Count by format
        format_counts = {}
        for fmt in CustomDetectionFormat:
            count_query = select(func.count(CustomDetection.id)).where(
                CustomDetection.organization_id == organization_id,
                CustomDetection.format == fmt,
            )
            if cloud_account_id:
                count_query = count_query.where(
                    CustomDetection.cloud_account_id == cloud_account_id
                )
            result = await self.db.execute(count_query)
            format_counts[fmt.value] = result.scalar() or 0

        # Total unique techniques mapped
        result = await self.db.execute(base_query)
        detections = result.scalars().all()
        all_techniques = set()
        for d in detections:
            if d.mapped_techniques:
                all_techniques.update(d.mapped_techniques)

        return {
            "total_detections": sum(status_counts.values()),
            "by_status": status_counts,
            "by_format": format_counts,
            "unique_techniques_mapped": len(all_techniques),
        }
