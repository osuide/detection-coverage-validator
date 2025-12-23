"""Report generation service for coverage reports."""

import csv
import io
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import structlog
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.pdfgen import canvas
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cloud_account import CloudAccount
from app.models.coverage import CoverageSnapshot
from app.models.detection import Detection, DetectionStatus, SecurityFunction
from app.models.mapping import DetectionMapping
from app.models.mitre import Technique
from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()


class ReportService:
    """Service for generating coverage reports."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(service="ReportService")

    async def _get_security_function_counts(
        self, cloud_account_id: UUID
    ) -> dict[str, int]:
        """Get detection counts by security function."""
        result = await self.db.execute(
            select(Detection).where(Detection.cloud_account_id == cloud_account_id)
        )
        detections = result.scalars().all()

        counts = {
            "detect": 0,
            "protect": 0,
            "identify": 0,
            "recover": 0,
            "operational": 0,
        }

        for det in detections:
            if det.security_function == SecurityFunction.DETECT:
                counts["detect"] += 1
            elif det.security_function == SecurityFunction.PROTECT:
                counts["protect"] += 1
            elif det.security_function == SecurityFunction.IDENTIFY:
                counts["identify"] += 1
            elif det.security_function == SecurityFunction.RECOVER:
                counts["recover"] += 1
            else:
                counts["operational"] += 1

        return counts

    async def generate_csv_report(
        self,
        cloud_account_id: UUID,
        report_type: str = "coverage",
    ) -> str:
        """Generate a CSV report.

        Args:
            cloud_account_id: Account to report on
            report_type: Type of report (coverage, gaps, detections)

        Returns:
            CSV string
        """
        if report_type == "coverage":
            return await self._generate_coverage_csv(cloud_account_id)
        elif report_type == "gaps":
            return await self._generate_gaps_csv(cloud_account_id)
        elif report_type == "detections":
            return await self._generate_detections_csv(cloud_account_id)
        else:
            raise ValueError(f"Unknown report type: {report_type}")

    async def generate_pdf_report(
        self,
        cloud_account_id: UUID,
        include_executive_summary: bool = True,
        include_gap_analysis: bool = True,
        include_detection_details: bool = False,
        add_watermark: bool = False,
    ) -> bytes:
        """Generate a PDF report.

        Args:
            cloud_account_id: Account to report on
            include_executive_summary: Include executive summary section
            include_gap_analysis: Include gap analysis section
            include_detection_details: Include detailed detection list
            add_watermark: Add "FREE TIER" watermark to each page (for free tier users)

        Returns:
            PDF bytes
        """
        # Get account info
        account = await self._get_account(cloud_account_id)
        if not account:
            raise ValueError("Cloud account not found")

        # Get latest coverage snapshot
        snapshot = await self._get_latest_snapshot(cloud_account_id)

        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
        )

        # Build story
        story = []
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            spaceAfter=30,
        )
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
        )
        subheading_style = ParagraphStyle(
            "CustomSubheading",
            parent=styles["Heading3"],
            fontSize=12,
            spaceAfter=8,
        )

        # Title
        story.append(Paragraph("Detection Coverage Report", title_style))
        story.append(Paragraph(f"Account: {account.name}", styles["Normal"]))
        story.append(
            Paragraph(
                f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 20))

        if include_executive_summary and snapshot:
            story.extend(
                await self._build_executive_summary(
                    snapshot, cloud_account_id, styles, heading_style
                )
            )

        if include_gap_analysis and snapshot:
            story.append(PageBreak())
            story.extend(
                await self._build_gap_analysis(
                    snapshot, styles, heading_style, subheading_style
                )
            )

        if include_detection_details:
            story.append(PageBreak())
            story.extend(
                await self._build_detection_details(
                    cloud_account_id, styles, heading_style
                )
            )

        # Build PDF with optional watermark
        if add_watermark:

            def add_watermark_to_page(canvas_obj: canvas.Canvas, doc_obj) -> None:
                """Draw watermark on each page."""
                canvas_obj.saveState()
                # Draw diagonal "FREE TIER" watermark
                canvas_obj.setFont("Helvetica-Bold", 60)
                canvas_obj.setFillColor(colors.Color(0.9, 0.9, 0.9, alpha=0.5))
                canvas_obj.translate(letter[0] / 2, letter[1] / 2)
                canvas_obj.rotate(45)
                canvas_obj.drawCentredString(0, 0, "FREE TIER")
                canvas_obj.restoreState()

                # Add small footer notice
                canvas_obj.saveState()
                canvas_obj.setFont("Helvetica", 8)
                canvas_obj.setFillColor(colors.gray)
                canvas_obj.drawString(
                    0.75 * inch,
                    0.5 * inch,
                    "Free tier report - Upgrade to remove watermark: a13e.com/upgrade",
                )
                canvas_obj.restoreState()

            doc.build(
                story,
                onFirstPage=add_watermark_to_page,
                onLaterPages=add_watermark_to_page,
            )
        else:
            doc.build(story)

        buffer.seek(0)
        return buffer.read()

    async def _build_executive_summary(
        self,
        snapshot: CoverageSnapshot,
        cloud_account_id: UUID,
        styles: dict,
        heading_style: ParagraphStyle,
    ) -> list:
        """Build executive summary section."""
        story = []

        story.append(Paragraph("Executive Summary", heading_style))

        # Overall metrics
        story.append(
            Paragraph(
                f"<b>Overall Coverage:</b> {snapshot.coverage_percent:.1f}%",
                styles["Normal"],
            )
        )
        story.append(
            Paragraph(
                f"<b>Techniques Covered:</b> {snapshot.covered_techniques} of {snapshot.total_techniques}",
                styles["Normal"],
            )
        )
        story.append(
            Paragraph(
                f"<b>Partial Coverage:</b> {snapshot.partial_techniques} techniques",
                styles["Normal"],
            )
        )
        story.append(
            Paragraph(
                f"<b>Coverage Gaps:</b> {snapshot.uncovered_techniques} techniques",
                styles["Normal"],
            )
        )
        story.append(
            Paragraph(
                f"<b>Average Confidence:</b> {snapshot.average_confidence:.2f}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 15))

        # Detection summary
        story.append(
            Paragraph(
                f"<b>Total Detections:</b> {snapshot.total_detections}",
                styles["Normal"],
            )
        )
        story.append(
            Paragraph(
                f"<b>Active Detections:</b> {snapshot.active_detections}",
                styles["Normal"],
            )
        )
        story.append(
            Paragraph(
                f"<b>Mapped Detections:</b> {snapshot.mapped_detections}",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 15))

        # Security function breakdown (NIST CSF)
        func_counts = await self._get_security_function_counts(cloud_account_id)
        story.append(
            Paragraph("Security Posture by Function (NIST CSF)", styles["Heading3"])
        )
        story.append(
            Paragraph(
                "Detections are classified by their security purpose:",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 5))

        func_data = [
            ["Function", "Count", "Description"],
            ["Detect", str(func_counts["detect"]), "Threat detection (MITRE ATT&CK)"],
            ["Protect", str(func_counts["protect"]), "Preventive controls"],
            ["Identify", str(func_counts["identify"]), "Visibility/posture"],
            ["Recover", str(func_counts["recover"]), "Backup/DR"],
            [
                "Operational",
                str(func_counts["operational"]),
                "Non-security (tagging, cost)",
            ],
        ]

        func_table = Table(
            func_data,
            colWidths=[1.2 * inch, 0.8 * inch, 3 * inch],
        )
        func_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (1, 0), (1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                ]
            )
        )
        story.append(func_table)
        story.append(Spacer(1, 20))

        # Tactic coverage table
        story.append(Paragraph("Coverage by Tactic", styles["Heading3"]))
        tactic_data = [["Tactic", "Covered", "Partial", "Uncovered", "Coverage %"]]

        for tactic_id, info in snapshot.tactic_coverage.items():
            tactic_data.append(
                [
                    info.get("name", tactic_id),
                    str(info.get("covered", 0)),
                    str(info.get("partial", 0)),
                    str(info.get("uncovered", 0)),
                    f"{info.get('percent', 0):.1f}%",
                ]
            )

        tactic_table = Table(
            tactic_data,
            colWidths=[2.5 * inch, 0.8 * inch, 0.8 * inch, 0.9 * inch, 1 * inch],
        )
        tactic_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (1, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                ]
            )
        )
        story.append(tactic_table)

        return story

    async def _build_gap_analysis(
        self,
        snapshot: CoverageSnapshot,
        styles: dict,
        heading_style: ParagraphStyle,
        subheading_style: ParagraphStyle,
    ) -> list:
        """Build gap analysis section."""
        story = []

        story.append(Paragraph("Gap Analysis", heading_style))
        story.append(
            Paragraph(
                "The following techniques have been identified as priority gaps based on "
                "threat prevalence and detection difficulty.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 15))

        if snapshot.top_gaps:
            # Priority gaps table
            gap_data = [["Priority", "Technique ID", "Name", "Tactic"]]
            for gap in snapshot.top_gaps[:15]:
                gap_data.append(
                    [
                        str(gap.get("priority", 0)),
                        gap.get("technique_id", ""),
                        gap.get("name", "")[:40],
                        gap.get("tactic_name", ""),
                    ]
                )

            gap_table = Table(
                gap_data, colWidths=[0.7 * inch, 1 * inch, 2.5 * inch, 1.8 * inch]
            )
            gap_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.darkred),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (0, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.lightpink),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ]
                )
            )
            story.append(gap_table)
        else:
            story.append(Paragraph("No critical gaps identified.", styles["Normal"]))

        return story

    async def _build_detection_details(
        self,
        cloud_account_id: UUID,
        styles: dict,
        heading_style: ParagraphStyle,
    ) -> list:
        """Build detection details section."""
        story = []

        story.append(Paragraph("Detection Inventory", heading_style))

        # Get detections
        result = await self.db.execute(
            select(Detection)
            .where(
                Detection.cloud_account_id == cloud_account_id,
                Detection.status == DetectionStatus.ACTIVE,
            )
            .limit(50)
        )
        detections = result.scalars().all()

        if detections:
            detection_data = [["Name", "Type", "Region", "Mapped Techniques"]]
            for det in detections:
                # Get mapping count
                mapping_result = await self.db.execute(
                    select(DetectionMapping).where(
                        DetectionMapping.detection_id == det.id
                    )
                )
                mappings = mapping_result.scalars().all()

                detection_data.append(
                    [
                        det.name[:35],
                        det.detection_type.value.replace("_", " ").title()[:20],
                        det.region,
                        str(len(mappings)),
                    ]
                )

            detection_table = Table(
                detection_data, colWidths=[2.5 * inch, 1.5 * inch, 1 * inch, 1 * inch]
            )
            detection_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (2, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.lightblue),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("FONTSIZE", (0, 1), (-1, -1), 8),
                    ]
                )
            )
            story.append(detection_table)
        else:
            story.append(Paragraph("No detections found.", styles["Normal"]))

        return story

    async def _generate_coverage_csv(self, cloud_account_id: UUID) -> str:
        """Generate coverage CSV report."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Get techniques with coverage status
        result = await self.db.execute(select(Technique))
        techniques = result.scalars().all()

        # Get mappings for this account's detections
        detection_result = await self.db.execute(
            select(Detection.id).where(
                Detection.cloud_account_id == cloud_account_id,
                Detection.status == DetectionStatus.ACTIVE,
            )
        )
        detection_ids = [d for d in detection_result.scalars().all()]

        mapping_result = await self.db.execute(
            select(DetectionMapping).where(
                DetectionMapping.detection_id.in_(detection_ids)
            )
        )
        mappings = mapping_result.scalars().all()
        covered_techniques = {m.technique_id: m.confidence for m in mappings}

        # Header
        writer.writerow(
            [
                "Technique ID",
                "Name",
                "Tactic",
                "Coverage Status",
                "Confidence",
                "Is Subtechnique",
            ]
        )

        for tech in techniques:
            technique_uuid = tech.id
            confidence = covered_techniques.get(technique_uuid, 0)

            if confidence >= 0.6:
                status = "Covered"
            elif confidence >= 0.4:
                status = "Partial"
            else:
                status = "Not Covered"

            writer.writerow(
                [
                    tech.technique_id,
                    tech.name,
                    tech.tactic_id,  # Would need join for tactic name
                    status,
                    f"{confidence:.2f}" if confidence > 0 else "",
                    "Yes" if tech.is_subtechnique else "No",
                ]
            )

        return output.getvalue()

    async def _generate_gaps_csv(self, cloud_account_id: UUID) -> str:
        """Generate gaps CSV report."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Get latest snapshot for gaps
        snapshot = await self._get_latest_snapshot(cloud_account_id)

        writer.writerow(
            [
                "Priority",
                "Technique ID",
                "Name",
                "Tactic",
                "Reason",
            ]
        )

        if snapshot and snapshot.top_gaps:
            for gap in snapshot.top_gaps:
                writer.writerow(
                    [
                        gap.get("priority", 0),
                        gap.get("technique_id", ""),
                        gap.get("name", ""),
                        gap.get("tactic_name", ""),
                        gap.get("reason", ""),
                    ]
                )

        return output.getvalue()

    async def _generate_detections_csv(self, cloud_account_id: UUID) -> str:
        """Generate detections CSV report."""
        output = io.StringIO()
        writer = csv.writer(output)

        result = await self.db.execute(
            select(Detection).where(Detection.cloud_account_id == cloud_account_id)
        )
        detections = result.scalars().all()

        writer.writerow(
            [
                "Name",
                "Type",
                "Status",
                "Region",
                "Source ARN",
                "Is Managed",
                "Discovered At",
            ]
        )

        for det in detections:
            writer.writerow(
                [
                    det.name,
                    det.detection_type.value,
                    det.status.value,
                    det.region,
                    det.source_arn or "",
                    "Yes" if det.is_managed else "No",
                    det.discovered_at.isoformat() if det.discovered_at else "",
                ]
            )

        return output.getvalue()

    async def _get_account(self, cloud_account_id: UUID) -> Optional[CloudAccount]:
        """Get cloud account."""
        result = await self.db.execute(
            select(CloudAccount).where(CloudAccount.id == cloud_account_id)
        )
        return result.scalar_one_or_none()

    async def _get_latest_snapshot(
        self, cloud_account_id: UUID
    ) -> Optional[CoverageSnapshot]:
        """Get latest coverage snapshot."""
        result = await self.db.execute(
            select(CoverageSnapshot)
            .where(CoverageSnapshot.cloud_account_id == cloud_account_id)
            .order_by(CoverageSnapshot.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()
