"""Professional Report Generation Service for A13E.

Generates high-quality, branded PDF and CSV reports for detection coverage analysis.
Based on competitor benchmarks from Wiz, Orca, Kroll, and industry best practices.

Report Types:
- Coverage Report (CSV) - Full MITRE ATT&CK technique coverage breakdown
- Gap Analysis Report (CSV) - Priority-ranked coverage gaps
- Detection Inventory Report (CSV) - Complete detection list
- Executive Summary (PDF) - High-level overview with posture scores
- Full Report (PDF) - Comprehensive report with all sections
- Compliance Summary (PDF) - NIST CSF and CIS Controls coverage

Features:
- Professional A13E branding with logo
- Posture grade scoring (A-F)
- Traffic light indicators for quick status assessment
- MITRE ATT&CK tactic heatmap visualisation
- Compliance framework coverage percentages
- Actionable recommendations with priority rankings
"""

import csv
import io
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID
from xml.sax.saxutils import escape as xml_escape

import structlog
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
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

# Import professional design system
from app.services.report_design import (
    BrandColours,
    Typography,
    PageLayout,
    get_report_styles,
    get_standard_table_style,
    get_metric_table_style,
    get_gap_table_style,
    create_posture_grade,
    create_traffic_light,
    create_progress_bar,
    create_mini_heatmap,
    ReportPageTemplate,
    get_logo_path,
    calculate_posture_grade,
    truncate_text,
)

logger = structlog.get_logger()
settings = get_settings()


def _sanitize_csv_cell(value: str) -> str:
    """Sanitize value to prevent CSV formula injection.

    Prefixes cells starting with formula characters with a single quote.
    This prevents Excel from interpreting the value as a formula.
    """
    if not value:
        return value
    if value[0] in ("=", "+", "-", "@", "\t", "\r", "\n"):
        return f"'{value}"
    return value


def _sanitize_pdf_text(value: str) -> str:
    """Escape XML-sensitive characters for ReportLab Paragraph.

    ReportLab uses XML-like markup, so we need to escape special characters.
    """
    return xml_escape(value) if value else ""


class ReportService:
    """Professional report generation service for A13E."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger = logger.bind(service="ReportService")
        self.styles = get_report_styles()

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

    async def _get_compliance_summary(self, cloud_account_id: UUID) -> list[dict]:
        """Get compliance framework coverage summary.

        Returns list of {framework_id, framework_name, coverage_percent, ...}
        """
        try:
            from app.services.compliance_service import ComplianceService

            compliance_service = ComplianceService(self.db)
            return await compliance_service.get_compliance_summary(cloud_account_id)
        except Exception as e:
            self.logger.warning("compliance_summary_failed", error=str(e))
            return []

    # =========================================================================
    # CSV REPORTS
    # =========================================================================

    async def generate_csv_report(
        self,
        cloud_account_id: UUID,
        report_type: str = "coverage",
    ) -> str:
        """Generate a CSV report with enhanced headers and summaries.

        Args:
            cloud_account_id: Account to report on
            report_type: Type of report (coverage, gaps, detections)

        Returns:
            CSV string with metadata headers
        """
        if report_type == "coverage":
            return await self._generate_coverage_csv(cloud_account_id)
        elif report_type == "gaps":
            return await self._generate_gaps_csv(cloud_account_id)
        elif report_type == "detections":
            return await self._generate_detections_csv(cloud_account_id)
        else:
            raise ValueError(f"Unknown report type: {report_type}")

    async def _generate_coverage_csv(self, cloud_account_id: UUID) -> str:
        """Generate coverage CSV report with metadata header."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Get account and snapshot info
        account = await self._get_account(cloud_account_id)
        snapshot = await self._get_latest_snapshot(cloud_account_id)

        # Metadata header
        writer.writerow(["# A13E Detection Coverage Report"])
        writer.writerow([f"# Account: {account.name if account else 'Unknown'}"])
        writer.writerow(
            [
                f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
            ]
        )
        if snapshot:
            grade = calculate_posture_grade(snapshot.coverage_percent)
            writer.writerow(
                [
                    f"# Overall Coverage: {snapshot.coverage_percent:.1f}% (Grade {grade})"
                ]
            )
            writer.writerow(
                [
                    f"# Techniques Covered: {snapshot.covered_techniques} of {snapshot.total_techniques}"
                ]
            )
        writer.writerow([])  # Blank line separator

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

        # Header row
        writer.writerow(
            [
                "Technique ID",
                "Name",
                "Tactic",
                "Coverage Status",
                "Confidence",
                "Is Subtechnique",
                "Detection Count",
            ]
        )

        # Count detections per technique
        detection_counts: dict[UUID, int] = {}
        for m in mappings:
            detection_counts[m.technique_id] = (
                detection_counts.get(m.technique_id, 0) + 1
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
                    _sanitize_csv_cell(tech.technique_id),
                    _sanitize_csv_cell(tech.name),
                    tech.tactic_id,
                    status,
                    f"{confidence:.2f}" if confidence > 0 else "",
                    "Yes" if tech.is_subtechnique else "No",
                    detection_counts.get(technique_uuid, 0),
                ]
            )

        # Summary footer
        writer.writerow([])
        writer.writerow(["# Summary Statistics"])
        covered = sum(1 for c in covered_techniques.values() if c >= 0.6)
        partial = sum(1 for c in covered_techniques.values() if 0.4 <= c < 0.6)
        uncovered = len(techniques) - covered - partial
        writer.writerow([f"# Covered: {covered}"])
        writer.writerow([f"# Partial: {partial}"])
        writer.writerow([f"# Not Covered: {uncovered}"])

        return output.getvalue()

    async def _generate_gaps_csv(self, cloud_account_id: UUID) -> str:
        """Generate gaps CSV report with metadata header."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Get account and snapshot info
        account = await self._get_account(cloud_account_id)
        snapshot = await self._get_latest_snapshot(cloud_account_id)

        # Metadata header
        writer.writerow(["# A13E Gap Analysis Report"])
        writer.writerow([f"# Account: {account.name if account else 'Unknown'}"])
        writer.writerow(
            [
                f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
            ]
        )
        if snapshot:
            writer.writerow([f"# Total Gaps: {snapshot.uncovered_techniques}"])
        writer.writerow([])

        # Column headers
        writer.writerow(
            [
                "Priority",
                "Technique ID",
                "Name",
                "Tactic",
                "Reason",
                "Has Remediation Template",
            ]
        )

        if snapshot and snapshot.top_gaps:
            from app.data.remediation_templates.template_loader import get_template

            for gap in snapshot.top_gaps:
                technique_id = gap.get("technique_id", "")
                has_template = get_template(technique_id) is not None

                writer.writerow(
                    [
                        gap.get("priority", 0),
                        _sanitize_csv_cell(technique_id),
                        _sanitize_csv_cell(gap.get("name", "")),
                        _sanitize_csv_cell(gap.get("tactic_name", "")),
                        _sanitize_csv_cell(gap.get("reason", "")),
                        "Yes" if has_template else "No",
                    ]
                )

        return output.getvalue()

    async def _generate_detections_csv(self, cloud_account_id: UUID) -> str:
        """Generate detections CSV report with metadata header."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Get account info
        account = await self._get_account(cloud_account_id)

        # Metadata header
        writer.writerow(["# A13E Detection Inventory Report"])
        writer.writerow([f"# Account: {account.name if account else 'Unknown'}"])
        writer.writerow(
            [
                f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
            ]
        )
        writer.writerow([])

        result = await self.db.execute(
            select(Detection).where(Detection.cloud_account_id == cloud_account_id)
        )
        detections = result.scalars().all()

        # Count by status
        active_count = sum(1 for d in detections if d.status == DetectionStatus.ACTIVE)
        writer.writerow([f"# Total Detections: {len(detections)}"])
        writer.writerow([f"# Active: {active_count}"])
        writer.writerow([])

        # Column headers
        writer.writerow(
            [
                "Name",
                "Type",
                "Status",
                "Region",
                "Source ARN",
                "Security Function",
                "Is Managed",
                "Mapped Techniques",
                "Discovered At",
            ]
        )

        for det in detections:
            # Get mapping count
            mapping_result = await self.db.execute(
                select(DetectionMapping).where(DetectionMapping.detection_id == det.id)
            )
            mappings = mapping_result.scalars().all()

            writer.writerow(
                [
                    _sanitize_csv_cell(det.name),
                    det.detection_type.value,
                    det.status.value,
                    det.region or "",
                    _sanitize_csv_cell(det.source_arn or ""),
                    det.security_function.value if det.security_function else "",
                    "Yes" if det.is_managed else "No",
                    len(mappings),
                    det.discovered_at.isoformat() if det.discovered_at else "",
                ]
            )

        return output.getvalue()

    # =========================================================================
    # PDF REPORTS
    # =========================================================================

    async def generate_pdf_report(
        self,
        cloud_account_id: UUID,
        include_executive_summary: bool = True,
        include_gap_analysis: bool = True,
        include_detection_details: bool = False,
        include_compliance: bool = True,
        add_watermark: bool = False,
    ) -> bytes:
        """Generate a professional PDF report with A13E branding.

        Args:
            cloud_account_id: Account to report on
            include_executive_summary: Include executive summary section
            include_gap_analysis: Include gap analysis section
            include_detection_details: Include detailed detection list
            include_compliance: Include compliance framework coverage
            add_watermark: Add "FREE TIER" watermark (for free tier users)

        Returns:
            PDF bytes
        """
        # Get account info
        account = await self._get_account(cloud_account_id)
        if not account:
            raise ValueError("Cloud account not found")

        # Get latest coverage snapshot
        snapshot = await self._get_latest_snapshot(cloud_account_id)

        # Get compliance data
        compliance_summary = []
        if include_compliance:
            compliance_summary = await self._get_compliance_summary(cloud_account_id)

        # Create PDF buffer
        buffer = io.BytesIO()

        # Create document with A4 page size
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=PageLayout.MARGIN_RIGHT,
            leftMargin=PageLayout.MARGIN_LEFT,
            topMargin=PageLayout.MARGIN_TOP,
            bottomMargin=PageLayout.MARGIN_BOTTOM,
        )

        # Create page template for headers/footers
        generated_at = datetime.now(timezone.utc)
        page_template = ReportPageTemplate(
            account_name=account.name,
            report_title="Detection Coverage Report",
            logo_path=get_logo_path(),
            confidential=True,
        )

        # Build story (content)
        story = []

        # Cover page elements (drawn by canvas callback, but we add spacer)
        story.append(Spacer(1, PageLayout.CONTENT_HEIGHT - 100))
        story.append(PageBreak())

        # Table of Contents placeholder (simplified - just section headers)
        story.append(Paragraph("Contents", self.styles["SectionHeading"]))
        toc_items = ["Executive Summary"]
        if include_gap_analysis:
            toc_items.append("Gap Analysis")
        if include_compliance and compliance_summary:
            toc_items.append("Compliance Coverage")
        if include_detection_details:
            toc_items.append("Detection Inventory")

        for i, item in enumerate(toc_items, 1):
            story.append(Paragraph(f"{i}. {item}", self.styles["BodyTextLeft"]))
        story.append(Spacer(1, 20))
        story.append(PageBreak())

        # Executive Summary
        if include_executive_summary and snapshot:
            story.extend(
                await self._build_professional_executive_summary(
                    snapshot, cloud_account_id, compliance_summary
                )
            )
            story.append(PageBreak())

        # Gap Analysis
        if include_gap_analysis and snapshot:
            story.extend(await self._build_professional_gap_analysis(snapshot))
            story.append(PageBreak())

        # Compliance Coverage
        if include_compliance and compliance_summary:
            story.extend(self._build_compliance_section(compliance_summary))
            story.append(PageBreak())

        # Detection Details
        if include_detection_details:
            story.extend(
                await self._build_professional_detection_details(cloud_account_id)
            )

        # Build PDF with page callbacks
        def on_first_page(canvas_obj: canvas.Canvas, doc_obj) -> None:
            """Draw cover page."""
            page_template.draw_cover_page(canvas_obj, doc_obj, generated_at)
            if add_watermark:
                _draw_watermark(canvas_obj, doc_obj)

        def on_later_pages(canvas_obj: canvas.Canvas, doc_obj) -> None:
            """Draw header/footer on subsequent pages."""
            page_template.draw_header_footer(canvas_obj, doc_obj)
            if add_watermark:
                _draw_watermark(canvas_obj, doc_obj)

        doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)

        buffer.seek(0)
        return buffer.read()

    async def _build_professional_executive_summary(
        self,
        snapshot: CoverageSnapshot,
        cloud_account_id: UUID,
        compliance_summary: list[dict],
    ) -> list:
        """Build professional executive summary with posture grade and visuals."""
        story = []

        # Section heading
        story.append(Paragraph("Executive Summary", self.styles["SectionHeading"]))
        story.append(Spacer(1, 10))

        # Calculate posture grade
        grade = calculate_posture_grade(snapshot.coverage_percent)

        # Key metrics row (using table for layout)
        metrics_data = [
            [
                # Posture Grade
                self._create_metric_cell(
                    grade,
                    "Security Posture",
                    is_grade=True,
                    percentage=snapshot.coverage_percent,
                ),
                # Coverage percentage
                self._create_metric_cell(
                    f"{snapshot.coverage_percent:.1f}%", "MITRE Coverage"
                ),
                # Techniques covered
                self._create_metric_cell(
                    f"{snapshot.covered_techniques}/{snapshot.total_techniques}",
                    "Techniques Covered",
                ),
                # Active detections
                self._create_metric_cell(
                    str(snapshot.active_detections), "Active Detections"
                ),
            ]
        ]

        metrics_table = Table(
            metrics_data,
            colWidths=[PageLayout.CONTENT_WIDTH / 4] * 4,
        )
        metrics_table.setStyle(get_metric_table_style())
        story.append(metrics_table)
        story.append(Spacer(1, 20))

        # Status summary with traffic lights
        story.append(Paragraph("Coverage Status", self.styles["SubsectionHeading"]))

        status_data = [
            ["Status", "Count", "Description"],
            [
                self._traffic_light_cell("green"),
                str(snapshot.covered_techniques),
                "Techniques with active detection (confidence ≥60%)",
            ],
            [
                self._traffic_light_cell("amber"),
                str(snapshot.partial_techniques),
                "Techniques with partial detection (confidence 40-60%)",
            ],
            [
                self._traffic_light_cell("red"),
                str(snapshot.uncovered_techniques),
                "Techniques with no detection coverage",
            ],
        ]

        status_table = Table(
            status_data,
            colWidths=[0.8 * inch, 0.8 * inch, PageLayout.CONTENT_WIDTH - 1.6 * inch],
        )
        status_table.setStyle(get_standard_table_style())
        story.append(status_table)
        story.append(Spacer(1, 20))

        # MITRE ATT&CK Tactic Heatmap
        story.append(
            Paragraph(
                "MITRE ATT&CK Coverage by Tactic", self.styles["SubsectionHeading"]
            )
        )
        story.append(
            Paragraph(
                "Visual representation of detection coverage across all MITRE ATT&CK tactics. "
                "Green indicates strong coverage (≥75%), amber indicates moderate coverage (50-75%), "
                "and red indicates coverage gaps (<50%).",
                self.styles["SmallText"],
            )
        )
        story.append(Spacer(1, 10))

        # Create heatmap
        heatmap = create_mini_heatmap(
            snapshot.tactic_coverage, width=PageLayout.CONTENT_WIDTH
        )
        story.append(heatmap)
        story.append(Spacer(1, 20))

        # Tactic coverage table
        story.append(
            Paragraph("Tactic Coverage Detail", self.styles["SubsectionHeading"])
        )

        tactic_data = [["Tactic", "Covered", "Partial", "Uncovered", "Coverage"]]
        for tactic_id, info in snapshot.tactic_coverage.items():
            pct = info.get("percent", 0)
            # Create inline progress bar representation
            progress_bar = create_progress_bar(
                pct, width=80, height=14, show_label=True
            )

            tactic_data.append(
                [
                    truncate_text(info.get("name", tactic_id), 25),
                    str(info.get("covered", 0)),
                    str(info.get("partial", 0)),
                    str(info.get("uncovered", 0)),
                    progress_bar,
                ]
            )

        tactic_table = Table(
            tactic_data,
            colWidths=[2.5 * inch, 0.7 * inch, 0.7 * inch, 0.8 * inch, 1.2 * inch],
        )
        tactic_table.setStyle(get_standard_table_style())
        story.append(tactic_table)
        story.append(Spacer(1, 20))

        # Security function breakdown (NIST CSF)
        func_counts = await self._get_security_function_counts(cloud_account_id)
        story.append(
            Paragraph(
                "Security Posture by Function (NIST CSF)",
                self.styles["SubsectionHeading"],
            )
        )
        story.append(
            Paragraph(
                "Detections classified by their security function in the NIST Cybersecurity Framework.",
                self.styles["SmallText"],
            )
        )
        story.append(Spacer(1, 10))

        func_data = [
            ["Function", "Count", "Purpose"],
            [
                "DETECT",
                str(func_counts["detect"]),
                "Threat detection aligned to MITRE ATT&CK",
            ],
            ["PROTECT", str(func_counts["protect"]), "Preventive security controls"],
            [
                "IDENTIFY",
                str(func_counts["identify"]),
                "Asset visibility and posture assessment",
            ],
            ["RECOVER", str(func_counts["recover"]), "Backup and disaster recovery"],
            [
                "OPERATIONAL",
                str(func_counts["operational"]),
                "Non-security operational monitoring",
            ],
        ]

        func_table = Table(
            func_data,
            colWidths=[1.2 * inch, 0.8 * inch, PageLayout.CONTENT_WIDTH - 2 * inch],
        )
        func_table.setStyle(get_standard_table_style())
        story.append(func_table)

        # Compliance summary (if available)
        if compliance_summary:
            story.append(Spacer(1, 20))
            story.append(
                Paragraph(
                    "Compliance Framework Coverage", self.styles["SubsectionHeading"]
                )
            )

            compliance_data = [["Framework", "Coverage", "Status"]]
            for fw in compliance_summary:
                pct = fw.get("coverage_percent", 0) or 0
                status = "green" if pct >= 75 else "amber" if pct >= 50 else "red"
                compliance_data.append(
                    [
                        fw.get("framework_name", "Unknown"),
                        f"{pct:.1f}%",
                        self._traffic_light_cell(status),
                    ]
                )

            compliance_table = Table(
                compliance_data,
                colWidths=[3 * inch, 1.5 * inch, 1 * inch],
            )
            compliance_table.setStyle(get_standard_table_style())
            story.append(compliance_table)

        return story

    async def _build_professional_gap_analysis(
        self,
        snapshot: CoverageSnapshot,
    ) -> list:
        """Build professional gap analysis section."""
        story = []

        story.append(Paragraph("Gap Analysis", self.styles["SectionHeading"]))
        story.append(
            Paragraph(
                "Priority-ranked coverage gaps identified based on threat prevalence, "
                "detection difficulty, and business impact. These techniques represent "
                "the highest-priority areas for improving your security posture.",
                self.styles["BodyText"],
            )
        )
        story.append(Spacer(1, 15))

        if not snapshot.top_gaps:
            story.append(
                Paragraph(
                    "✓ No critical gaps identified. Your detection coverage is comprehensive.",
                    self.styles["BodyText"],
                )
            )
            return story

        # Import template loader for remediation availability
        from app.data.remediation_templates.template_loader import get_template

        # Priority gaps table
        story.append(Paragraph("Top Priority Gaps", self.styles["SubsectionHeading"]))

        gap_data = [["#", "Technique", "Name", "Tactic", "Remediation"]]
        for i, gap in enumerate(snapshot.top_gaps[:15], 1):
            technique_id = gap.get("technique_id", "")
            has_template = get_template(technique_id) is not None

            gap_data.append(
                [
                    str(i),
                    technique_id,
                    truncate_text(gap.get("name", ""), 35),
                    truncate_text(gap.get("tactic_name", ""), 20),
                    "✓ Available" if has_template else "—",
                ]
            )

        gap_table = Table(
            gap_data,
            colWidths=[0.4 * inch, 0.9 * inch, 2.5 * inch, 1.4 * inch, 1 * inch],
        )
        gap_table.setStyle(get_gap_table_style())
        story.append(gap_table)
        story.append(Spacer(1, 20))

        # Recommendations
        story.append(Paragraph("Recommendations", self.styles["SubsectionHeading"]))

        # Count templates available
        templates_available = sum(
            1
            for gap in snapshot.top_gaps[:15]
            if get_template(gap.get("technique_id", ""))
        )

        recommendations = [
            f"<b>Address high-priority gaps first:</b> Focus on the top {min(5, len(snapshot.top_gaps))} gaps listed above for maximum impact.",
        ]

        if templates_available > 0:
            recommendations.append(
                f"<b>Use remediation templates:</b> {templates_available} of your top gaps have "
                "ready-to-deploy Infrastructure as Code templates available in A13E."
            )

        recommendations.extend(
            [
                "<b>Review detection coverage regularly:</b> Schedule weekly or monthly scans to track progress.",
                "<b>Consider compensating controls:</b> Where direct detection isn't possible, implement preventive controls.",
            ]
        )

        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles["BodyText"]))
            story.append(Spacer(1, 4))

        return story

    def _build_compliance_section(
        self,
        compliance_summary: list[dict],
    ) -> list:
        """Build compliance framework coverage section."""
        story = []

        story.append(Paragraph("Compliance Coverage", self.styles["SectionHeading"]))
        story.append(
            Paragraph(
                "Coverage metrics for major compliance frameworks, calculated based on "
                "MITRE ATT&CK technique mappings. Higher coverage indicates better alignment "
                "with framework control requirements.",
                self.styles["BodyText"],
            )
        )
        story.append(Spacer(1, 15))

        if not compliance_summary:
            story.append(
                Paragraph(
                    "No compliance framework data available. Run a scan to generate compliance coverage.",
                    self.styles["SmallText"],
                )
            )
            return story

        # Framework cards
        for fw in compliance_summary:
            framework_name = fw.get("framework_name", "Unknown")
            coverage_pct = fw.get("coverage_percent", 0) or 0
            cloud_coverage = fw.get("cloud_coverage_percent")
            covered_controls = fw.get("covered_controls", 0)
            total_controls = fw.get("total_controls", 0)

            story.append(Paragraph(framework_name, self.styles["SubsectionHeading"]))

            # Metrics row
            metrics_data = [
                [
                    self._create_metric_cell(
                        f"{coverage_pct:.1f}%", "Overall Coverage"
                    ),
                    self._create_metric_cell(
                        f"{cloud_coverage:.1f}%" if cloud_coverage else "N/A",
                        "Cloud-Detectable",
                    ),
                    self._create_metric_cell(
                        f"{covered_controls}/{total_controls}", "Controls Addressed"
                    ),
                ]
            ]

            metrics_table = Table(
                metrics_data,
                colWidths=[PageLayout.CONTENT_WIDTH / 3] * 3,
            )
            metrics_table.setStyle(get_metric_table_style())
            story.append(metrics_table)
            story.append(Spacer(1, 15))

        return story

    async def _build_professional_detection_details(
        self,
        cloud_account_id: UUID,
    ) -> list:
        """Build professional detection inventory section."""
        story = []

        story.append(Paragraph("Detection Inventory", self.styles["SectionHeading"]))
        story.append(
            Paragraph(
                "Complete inventory of discovered security detections, including their "
                "source, status, and MITRE ATT&CK technique mappings.",
                self.styles["BodyText"],
            )
        )
        story.append(Spacer(1, 15))

        # Get detections
        result = await self.db.execute(
            select(Detection)
            .where(
                Detection.cloud_account_id == cloud_account_id,
                Detection.status == DetectionStatus.ACTIVE,
            )
            .order_by(Detection.name)
            .limit(50)
        )
        detections = result.scalars().all()

        if not detections:
            story.append(
                Paragraph(
                    "No active detections found for this account.",
                    self.styles["SmallText"],
                )
            )
            return story

        # Detection table
        detection_data = [["Name", "Type", "Region", "Techniques"]]

        for det in detections:
            # Get mapping count
            mapping_result = await self.db.execute(
                select(DetectionMapping).where(DetectionMapping.detection_id == det.id)
            )
            mappings = mapping_result.scalars().all()

            detection_data.append(
                [
                    truncate_text(det.name, 40),
                    det.detection_type.value.replace("_", " ").title()[:20],
                    det.region or "—",
                    str(len(mappings)),
                ]
            )

        detection_table = Table(
            detection_data,
            colWidths=[3 * inch, 1.5 * inch, 0.8 * inch, 0.9 * inch],
        )
        detection_table.setStyle(get_standard_table_style())
        story.append(detection_table)

        if len(detections) == 50:
            story.append(Spacer(1, 10))
            story.append(
                Paragraph(
                    "Note: Showing first 50 detections. Export the CSV report for a complete list.",
                    self.styles["Caption"],
                )
            )

        return story

    # =========================================================================
    # COMPLIANCE SUMMARY PDF REPORT (NEW)
    # =========================================================================

    async def generate_compliance_pdf_report(
        self,
        cloud_account_id: UUID,
        add_watermark: bool = False,
    ) -> bytes:
        """Generate a dedicated compliance summary PDF report.

        Args:
            cloud_account_id: Account to report on
            add_watermark: Add "FREE TIER" watermark

        Returns:
            PDF bytes
        """
        # Get account info
        account = await self._get_account(cloud_account_id)
        if not account:
            raise ValueError("Cloud account not found")

        # Get compliance data
        compliance_summary = await self._get_compliance_summary(cloud_account_id)

        # Create PDF buffer
        buffer = io.BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=PageLayout.MARGIN_RIGHT,
            leftMargin=PageLayout.MARGIN_LEFT,
            topMargin=PageLayout.MARGIN_TOP,
            bottomMargin=PageLayout.MARGIN_BOTTOM,
        )

        # Page template
        generated_at = datetime.now(timezone.utc)
        page_template = ReportPageTemplate(
            account_name=account.name,
            report_title="Compliance Summary Report",
            logo_path=get_logo_path(),
            confidential=True,
        )

        # Build content
        story = []

        # Cover page spacer
        story.append(Spacer(1, PageLayout.CONTENT_HEIGHT - 100))
        story.append(PageBreak())

        # Main content
        story.append(
            Paragraph("Compliance Summary Report", self.styles["SectionHeading"])
        )
        story.append(
            Paragraph(
                "This report provides an overview of your security posture against major "
                "compliance frameworks, including NIST 800-53 Rev 5 and CIS Controls v8. "
                "Coverage is calculated based on MITRE ATT&CK technique detection capabilities.",
                self.styles["BodyText"],
            )
        )
        story.append(Spacer(1, 20))

        if not compliance_summary:
            story.append(
                Paragraph(
                    "No compliance framework data available. Please run a scan first.",
                    self.styles["BodyText"],
                )
            )
        else:
            # Overall compliance metrics
            story.append(
                Paragraph(
                    "Framework Coverage Summary", self.styles["SubsectionHeading"]
                )
            )

            for fw in compliance_summary:
                framework_name = fw.get("framework_name", "Unknown")
                coverage_pct = fw.get("coverage_percent", 0) or 0
                cloud_coverage = fw.get("cloud_coverage_percent")
                covered_controls = fw.get("covered_controls", 0)
                total_controls = fw.get("total_controls", 0)

                # Framework header
                story.append(Paragraph(framework_name, self.styles["MinorHeading"]))

                # Create visual progress bar
                progress = create_progress_bar(coverage_pct, width=400, height=24)
                story.append(progress)
                story.append(Spacer(1, 10))

                # Framework details
                details = f"""
                <b>Overall Coverage:</b> {coverage_pct:.1f}%<br/>
                <b>Controls Addressed:</b> {covered_controls} of {total_controls}<br/>
                """
                if cloud_coverage:
                    details += (
                        f"<b>Cloud-Detectable Coverage:</b> {cloud_coverage:.1f}%<br/>"
                    )

                story.append(Paragraph(details, self.styles["BodyTextLeft"]))
                story.append(Spacer(1, 15))

            # Recommendations
            story.append(
                Paragraph(
                    "Compliance Improvement Recommendations",
                    self.styles["SubsectionHeading"],
                )
            )

            recommendations = [
                "<b>Focus on cloud-detectable controls:</b> Prioritise controls that can be validated through cloud security monitoring.",
                "<b>Address high-priority gaps:</b> Use the Gap Analysis report to identify which MITRE techniques need coverage.",
                "<b>Document compensating controls:</b> Where automated detection isn't possible, document manual processes.",
                "<b>Schedule regular assessments:</b> Run weekly scans to track compliance posture over time.",
            ]

            for rec in recommendations:
                story.append(Paragraph(f"• {rec}", self.styles["BodyText"]))
                story.append(Spacer(1, 4))

        # Build PDF
        def on_first_page(canvas_obj: canvas.Canvas, doc_obj) -> None:
            page_template.draw_cover_page(canvas_obj, doc_obj, generated_at)
            if add_watermark:
                _draw_watermark(canvas_obj, doc_obj)

        def on_later_pages(canvas_obj: canvas.Canvas, doc_obj) -> None:
            page_template.draw_header_footer(canvas_obj, doc_obj)
            if add_watermark:
                _draw_watermark(canvas_obj, doc_obj)

        doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)

        buffer.seek(0)
        return buffer.read()

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _create_metric_cell(
        self,
        value: str,
        label: str,
        is_grade: bool = False,
        percentage: float = 0,
    ) -> list:
        """Create a metric display cell for tables."""
        if is_grade:
            # Return grade badge drawing
            grade_badge = create_posture_grade(value, percentage, width=60, height=60)
            return [
                grade_badge,
                Paragraph(label, self.styles["MetricLabel"]),
            ]
        else:
            return [
                Paragraph(f"<b>{value}</b>", self.styles["MetricValue"]),
                Paragraph(label, self.styles["MetricLabel"]),
            ]

    def _traffic_light_cell(self, status: str) -> Any:
        """Create a traffic light indicator for tables."""
        return create_traffic_light(status, size=14)

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


# =============================================================================
# WATERMARK HELPER
# =============================================================================


def _draw_watermark(canvas_obj: canvas.Canvas, doc: Any) -> None:
    """Draw FREE TIER watermark on page."""
    canvas_obj.saveState()

    # Diagonal watermark
    canvas_obj.setFont(Typography.FONT_BOLD, 50)
    canvas_obj.setFillColor(colors.Color(0.9, 0.9, 0.9, alpha=0.4))
    canvas_obj.translate(A4[0] / 2, A4[1] / 2)
    canvas_obj.rotate(45)
    canvas_obj.drawCentredString(0, 0, "FREE TIER")

    canvas_obj.restoreState()

    # Footer notice
    canvas_obj.saveState()
    canvas_obj.setFont(Typography.FONT_REGULAR, 7)
    canvas_obj.setFillColor(BrandColours.GREY_500)
    canvas_obj.drawString(
        PageLayout.MARGIN_LEFT,
        15,
        "Free tier report — Upgrade to remove watermark: a13e.com/upgrade",
    )
    canvas_obj.restoreState()
