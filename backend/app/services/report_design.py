"""Professional PDF Report Design System for A13E.

This module provides a consistent, branded design system for all PDF reports.
Based on competitor analysis from Wiz, Orca, Kroll, and industry best practices.

Design Principles:
- Professional branding with A13E logo and colours
- Clear visual hierarchy with consistent typography
- Traffic light indicators for quick status assessment
- Data visualisation (heatmaps, gauges, charts)
- Actionable recommendations with priority rankings

References:
- Kroll MITRE Detection Maturity Assessment Template
- Wiz Compliance Heatmap Design
- SecurityScorecard Board Report Format
- CISO Dashboard Best Practices
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.pdfgen import canvas


# =============================================================================
# BRAND COLOURS (extracted from A13E logo - deep navy, teal accents)
# =============================================================================


class BrandColours:
    """A13E brand colour palette for reports."""

    # Primary colours
    NAVY_DARK = colors.Color(0.039, 0.086, 0.157)  # #0a1628 - Dark navy
    NAVY = colors.Color(0.067, 0.133, 0.216)  # #112237 - Navy
    TEAL = colors.Color(0, 0.831, 1)  # #00d4ff - Bright teal
    TEAL_DARK = colors.Color(0.310, 0.820, 0.773)  # #4fd1c5 - Soft teal

    # Semantic colours (traffic light system)
    GREEN = colors.Color(0.133, 0.773, 0.369)  # #22c55e - Success/Covered
    GREEN_LIGHT = colors.Color(0.86, 0.96, 0.87)  # #dcf4de - Light green bg
    AMBER = colors.Color(0.961, 0.620, 0.043)  # #f59e0b - Warning/Partial
    AMBER_LIGHT = colors.Color(0.996, 0.945, 0.843)  # #fef1d7 - Light amber bg
    RED = colors.Color(0.937, 0.267, 0.267)  # #ef4444 - Critical/Uncovered
    RED_LIGHT = colors.Color(0.996, 0.906, 0.906)  # #fee7e7 - Light red bg

    # Neutral colours
    WHITE = colors.white
    BLACK = colors.black
    GREY_100 = colors.Color(0.969, 0.969, 0.969)  # #f7f7f7
    GREY_200 = colors.Color(0.898, 0.898, 0.898)  # #e5e5e5
    GREY_300 = colors.Color(0.831, 0.831, 0.831)  # #d4d4d4
    GREY_500 = colors.Color(0.451, 0.451, 0.451)  # #737373
    GREY_700 = colors.Color(0.251, 0.251, 0.251)  # #404040
    GREY_900 = colors.Color(0.098, 0.098, 0.098)  # #191919

    # Grade colours (A-F posture scoring)
    GRADE_A = GREEN
    GRADE_B = colors.Color(0.518, 0.78, 0.318)  # #84c751 - Light green
    GRADE_C = AMBER
    GRADE_D = colors.Color(0.961, 0.522, 0.184)  # #f5852f - Orange
    GRADE_F = RED


# =============================================================================
# TYPOGRAPHY
# =============================================================================


class Typography:
    """Typography settings for professional reports."""

    # Font families (using Helvetica family - universally available)
    FONT_REGULAR = "Helvetica"
    FONT_BOLD = "Helvetica-Bold"
    FONT_ITALIC = "Helvetica-Oblique"
    FONT_MONO = "Courier"

    # Font sizes
    SIZE_TITLE = 28
    SIZE_HEADING1 = 20
    SIZE_HEADING2 = 16
    SIZE_HEADING3 = 13
    SIZE_BODY = 10
    SIZE_SMALL = 9
    SIZE_TINY = 8
    SIZE_CAPTION = 7

    # Line heights
    LEADING_TITLE = 34
    LEADING_HEADING = 20
    LEADING_BODY = 14
    LEADING_SMALL = 12


# =============================================================================
# PAGE LAYOUT
# =============================================================================


class PageLayout:
    """Page layout constants."""

    # Page size (A4 for international compatibility)
    PAGE_SIZE = A4
    PAGE_WIDTH = A4[0]
    PAGE_HEIGHT = A4[1]

    # Margins
    MARGIN_LEFT = 0.75 * inch
    MARGIN_RIGHT = 0.75 * inch
    MARGIN_TOP = 0.75 * inch
    MARGIN_BOTTOM = 0.75 * inch

    # Content area
    CONTENT_WIDTH = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT
    CONTENT_HEIGHT = PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM

    # Footer height
    FOOTER_HEIGHT = 0.4 * inch


# =============================================================================
# CUSTOM STYLES
# =============================================================================


def get_report_styles() -> dict:
    """Get custom paragraph styles for reports."""
    styles = getSampleStyleSheet()

    # Cover page title
    styles.add(
        ParagraphStyle(
            name="CoverTitle",
            fontName=Typography.FONT_BOLD,
            fontSize=Typography.SIZE_TITLE,
            leading=Typography.LEADING_TITLE,
            textColor=BrandColours.NAVY_DARK,
            alignment=TA_CENTER,
            spaceAfter=12,
        )
    )

    # Cover page subtitle
    styles.add(
        ParagraphStyle(
            name="CoverSubtitle",
            fontName=Typography.FONT_REGULAR,
            fontSize=Typography.SIZE_HEADING2,
            leading=Typography.LEADING_HEADING,
            textColor=BrandColours.GREY_500,
            alignment=TA_CENTER,
            spaceAfter=6,
        )
    )

    # Section heading (H1)
    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            fontName=Typography.FONT_BOLD,
            fontSize=Typography.SIZE_HEADING1,
            leading=Typography.LEADING_HEADING + 4,
            textColor=BrandColours.NAVY_DARK,
            spaceBefore=20,
            spaceAfter=12,
            borderPadding=6,
            borderWidth=0,
            borderColor=BrandColours.TEAL,
            leftIndent=0,
        )
    )

    # Subsection heading (H2)
    styles.add(
        ParagraphStyle(
            name="SubsectionHeading",
            fontName=Typography.FONT_BOLD,
            fontSize=Typography.SIZE_HEADING2,
            leading=Typography.LEADING_HEADING,
            textColor=BrandColours.NAVY,
            spaceBefore=16,
            spaceAfter=8,
        )
    )

    # Minor heading (H3)
    styles.add(
        ParagraphStyle(
            name="MinorHeading",
            fontName=Typography.FONT_BOLD,
            fontSize=Typography.SIZE_HEADING3,
            leading=Typography.LEADING_BODY + 2,
            textColor=BrandColours.GREY_700,
            spaceBefore=12,
            spaceAfter=6,
        )
    )

    # Body text - override the default BodyText style
    styles["BodyText"].fontName = Typography.FONT_REGULAR
    styles["BodyText"].fontSize = Typography.SIZE_BODY
    styles["BodyText"].leading = Typography.LEADING_BODY
    styles["BodyText"].textColor = BrandColours.GREY_700
    styles["BodyText"].alignment = TA_JUSTIFY
    styles["BodyText"].spaceAfter = 8

    # Body text (left aligned)
    styles.add(
        ParagraphStyle(
            name="BodyTextLeft",
            fontName=Typography.FONT_REGULAR,
            fontSize=Typography.SIZE_BODY,
            leading=Typography.LEADING_BODY,
            textColor=BrandColours.GREY_700,
            alignment=TA_LEFT,
            spaceAfter=8,
        )
    )

    # Small text
    styles.add(
        ParagraphStyle(
            name="SmallText",
            fontName=Typography.FONT_REGULAR,
            fontSize=Typography.SIZE_SMALL,
            leading=Typography.LEADING_SMALL,
            textColor=BrandColours.GREY_500,
            spaceAfter=4,
        )
    )

    # Caption text
    styles.add(
        ParagraphStyle(
            name="Caption",
            fontName=Typography.FONT_ITALIC,
            fontSize=Typography.SIZE_CAPTION,
            leading=Typography.LEADING_SMALL,
            textColor=BrandColours.GREY_500,
            alignment=TA_CENTER,
            spaceAfter=8,
        )
    )

    # Metric value (large number display)
    styles.add(
        ParagraphStyle(
            name="MetricValue",
            fontName=Typography.FONT_BOLD,
            fontSize=24,
            leading=28,
            textColor=BrandColours.NAVY_DARK,
            alignment=TA_CENTER,
        )
    )

    # Metric label
    styles.add(
        ParagraphStyle(
            name="MetricLabel",
            fontName=Typography.FONT_REGULAR,
            fontSize=Typography.SIZE_SMALL,
            leading=Typography.LEADING_SMALL,
            textColor=BrandColours.GREY_500,
            alignment=TA_CENTER,
        )
    )

    # Table header
    styles.add(
        ParagraphStyle(
            name="TableHeader",
            fontName=Typography.FONT_BOLD,
            fontSize=Typography.SIZE_SMALL,
            leading=Typography.LEADING_SMALL,
            textColor=BrandColours.WHITE,
        )
    )

    # Table cell
    styles.add(
        ParagraphStyle(
            name="TableCell",
            fontName=Typography.FONT_REGULAR,
            fontSize=Typography.SIZE_SMALL,
            leading=Typography.LEADING_SMALL,
            textColor=BrandColours.GREY_700,
        )
    )

    # Footer text
    styles.add(
        ParagraphStyle(
            name="Footer",
            fontName=Typography.FONT_REGULAR,
            fontSize=Typography.SIZE_TINY,
            leading=Typography.LEADING_SMALL,
            textColor=BrandColours.GREY_500,
        )
    )

    return styles


# =============================================================================
# TABLE STYLES
# =============================================================================


def get_standard_table_style() -> TableStyle:
    """Get standard table styling for data tables."""
    return TableStyle(
        [
            # Header row
            ("BACKGROUND", (0, 0), (-1, 0), BrandColours.NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), BrandColours.WHITE),
            ("FONTNAME", (0, 0), (-1, 0), Typography.FONT_BOLD),
            ("FONTSIZE", (0, 0), (-1, 0), Typography.SIZE_SMALL),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 10),
            # Data rows
            ("BACKGROUND", (0, 1), (-1, -1), BrandColours.WHITE),
            ("TEXTCOLOR", (0, 1), (-1, -1), BrandColours.GREY_700),
            ("FONTNAME", (0, 1), (-1, -1), Typography.FONT_REGULAR),
            ("FONTSIZE", (0, 1), (-1, -1), Typography.SIZE_SMALL),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
            ("TOPPADDING", (0, 1), (-1, -1), 8),
            # Alternating row colours
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [BrandColours.WHITE, BrandColours.GREY_100],
            ),
            # Grid
            ("GRID", (0, 0), (-1, -1), 0.5, BrandColours.GREY_200),
            ("LINEBELOW", (0, 0), (-1, 0), 2, BrandColours.TEAL),
            # Alignment
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            # Padding
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]
    )


def get_metric_table_style() -> TableStyle:
    """Get table styling for metric cards (no visible borders)."""
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, -1), BrandColours.WHITE),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]
    )


def get_gap_table_style() -> TableStyle:
    """Get table styling for gap analysis tables (with priority indicators)."""
    return TableStyle(
        [
            # Header row
            ("BACKGROUND", (0, 0), (-1, 0), BrandColours.RED),
            ("TEXTCOLOR", (0, 0), (-1, 0), BrandColours.WHITE),
            ("FONTNAME", (0, 0), (-1, 0), Typography.FONT_BOLD),
            ("FONTSIZE", (0, 0), (-1, 0), Typography.SIZE_SMALL),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 10),
            # Data rows
            ("BACKGROUND", (0, 1), (-1, -1), BrandColours.RED_LIGHT),
            ("TEXTCOLOR", (0, 1), (-1, -1), BrandColours.GREY_700),
            ("FONTNAME", (0, 1), (-1, -1), Typography.FONT_REGULAR),
            ("FONTSIZE", (0, 1), (-1, -1), Typography.SIZE_SMALL),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 8),
            ("TOPPADDING", (0, 1), (-1, -1), 8),
            # Grid
            ("GRID", (0, 0), (-1, -1), 0.5, BrandColours.GREY_200),
            ("LINEBELOW", (0, 0), (-1, 0), 2, colors.Color(0.8, 0.2, 0.2)),
            # Alignment
            ("ALIGN", (0, 0), (0, -1), "CENTER"),  # Priority column centered
            ("ALIGN", (1, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            # Padding
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]
    )


# =============================================================================
# VISUAL COMPONENTS
# =============================================================================


def create_posture_grade(
    grade: str, percentage: float, width: float = 80, height: float = 80
) -> Drawing:
    """Create a posture grade badge (A-F with percentage).

    Args:
        grade: Letter grade (A, B, C, D, F)
        percentage: Coverage percentage (0-100)
        width: Badge width
        height: Badge height

    Returns:
        Drawing object for the grade badge
    """
    d = Drawing(width, height)

    # Determine colour based on grade
    grade_colours = {
        "A": BrandColours.GRADE_A,
        "B": BrandColours.GRADE_B,
        "C": BrandColours.GRADE_C,
        "D": BrandColours.GRADE_D,
        "F": BrandColours.GRADE_F,
    }
    colour = grade_colours.get(grade.upper(), BrandColours.GREY_500)

    # Draw circle background
    from reportlab.graphics.shapes import Circle

    circle = Circle(width / 2, height / 2, min(width, height) / 2 - 2)
    circle.fillColor = colour
    circle.strokeColor = None
    d.add(circle)

    # Draw grade letter
    grade_text = String(width / 2, height / 2 + 8, grade.upper())
    grade_text.fontName = Typography.FONT_BOLD
    grade_text.fontSize = 28
    grade_text.fillColor = BrandColours.WHITE
    grade_text.textAnchor = "middle"
    d.add(grade_text)

    # Draw percentage
    pct_text = String(width / 2, height / 2 - 12, f"{percentage:.0f}%")
    pct_text.fontName = Typography.FONT_REGULAR
    pct_text.fontSize = 10
    pct_text.fillColor = BrandColours.WHITE
    pct_text.textAnchor = "middle"
    d.add(pct_text)

    return d


def create_traffic_light(status: str, size: float = 16) -> Drawing:
    """Create a traffic light indicator.

    Args:
        status: One of 'green', 'amber', 'red', 'grey'
        size: Diameter of the indicator

    Returns:
        Drawing object for the traffic light
    """
    d = Drawing(size, size)

    colour_map = {
        "green": BrandColours.GREEN,
        "covered": BrandColours.GREEN,
        "amber": BrandColours.AMBER,
        "partial": BrandColours.AMBER,
        "yellow": BrandColours.AMBER,
        "red": BrandColours.RED,
        "uncovered": BrandColours.RED,
        "critical": BrandColours.RED,
        "grey": BrandColours.GREY_300,
        "not_assessable": BrandColours.GREY_300,
    }
    colour = colour_map.get(status.lower(), BrandColours.GREY_300)

    from reportlab.graphics.shapes import Circle

    circle = Circle(size / 2, size / 2, size / 2 - 1)
    circle.fillColor = colour
    circle.strokeColor = BrandColours.GREY_200
    circle.strokeWidth = 0.5
    d.add(circle)

    return d


def create_progress_bar(
    percentage: float, width: float = 200, height: float = 20, show_label: bool = True
) -> Drawing:
    """Create a horizontal progress bar.

    Args:
        percentage: Progress percentage (0-100)
        width: Bar width
        height: Bar height
        show_label: Whether to show percentage label

    Returns:
        Drawing object for the progress bar
    """
    d = Drawing(width, height)

    # Background bar
    bg = Rect(0, 0, width, height)
    bg.fillColor = BrandColours.GREY_200
    bg.strokeColor = None
    bg.rx = 3
    bg.ry = 3
    d.add(bg)

    # Determine colour based on percentage
    if percentage >= 75:
        colour = BrandColours.GREEN
    elif percentage >= 50:
        colour = BrandColours.AMBER
    else:
        colour = BrandColours.RED

    # Progress bar
    progress_width = max(0, min(percentage / 100, 1)) * width
    if progress_width > 0:
        progress = Rect(0, 0, progress_width, height)
        progress.fillColor = colour
        progress.strokeColor = None
        progress.rx = 3
        progress.ry = 3
        d.add(progress)

    # Label
    if show_label:
        label = String(width / 2, height / 2 - 3, f"{percentage:.1f}%")
        label.fontName = Typography.FONT_BOLD
        label.fontSize = 9
        label.fillColor = (
            BrandColours.WHITE if percentage > 30 else BrandColours.GREY_700
        )
        label.textAnchor = "middle"
        d.add(label)

    return d


def create_mini_heatmap(
    tactic_data: dict, width: float = 450, height: float = 120
) -> Drawing:
    """Create a mini MITRE ATT&CK tactic heatmap.

    Args:
        tactic_data: Dict with tactic coverage data
            {tactic_id: {name, covered, partial, uncovered, percent}}
        width: Heatmap width
        height: Heatmap height

    Returns:
        Drawing object for the heatmap
    """
    d = Drawing(width, height)

    tactics = list(tactic_data.items())
    if not tactics:
        return d

    # Calculate cell dimensions
    num_tactics = len(tactics)
    cell_width = (width - 20) / num_tactics
    cell_height = 60
    label_height = 50

    for i, (tactic_id, info) in enumerate(tactics):
        x = 10 + i * cell_width
        y = label_height

        # Determine colour based on coverage
        pct = info.get("percent", 0)
        if pct >= 75:
            colour = BrandColours.GREEN
        elif pct >= 50:
            colour = BrandColours.AMBER
        elif pct > 0:
            colour = colors.Color(0.961, 0.522, 0.184)  # Orange
        else:
            colour = BrandColours.RED

        # Draw cell
        cell = Rect(x + 2, y, cell_width - 4, cell_height)
        cell.fillColor = colour
        cell.strokeColor = BrandColours.WHITE
        cell.strokeWidth = 1
        cell.rx = 3
        cell.ry = 3
        d.add(cell)

        # Add percentage text
        pct_text = String(x + cell_width / 2, y + cell_height / 2 + 8, f"{pct:.0f}%")
        pct_text.fontName = Typography.FONT_BOLD
        pct_text.fontSize = 12
        pct_text.fillColor = BrandColours.WHITE
        pct_text.textAnchor = "middle"
        d.add(pct_text)

        # Add count text
        covered = info.get("covered", 0)
        total = covered + info.get("partial", 0) + info.get("uncovered", 0)
        count_text = String(
            x + cell_width / 2, y + cell_height / 2 - 8, f"{covered}/{total}"
        )
        count_text.fontName = Typography.FONT_REGULAR
        count_text.fontSize = 8
        count_text.fillColor = BrandColours.WHITE
        count_text.textAnchor = "middle"
        d.add(count_text)

        # Add tactic name (rotated text - simplified to short name)
        name = info.get("name", tactic_id)
        # Truncate long names
        if len(name) > 12:
            name = name[:11] + "…"

        name_text = String(x + cell_width / 2, 35, name)
        name_text.fontName = Typography.FONT_REGULAR
        name_text.fontSize = 7
        name_text.fillColor = BrandColours.GREY_700
        name_text.textAnchor = "middle"
        d.add(name_text)

    return d


# =============================================================================
# PAGE TEMPLATES
# =============================================================================


class ReportPageTemplate:
    """Page template for professional reports with header/footer."""

    def __init__(
        self,
        account_name: str,
        report_title: str,
        logo_path: Optional[str] = None,
        confidential: bool = True,
    ):
        self.account_name = account_name
        self.report_title = report_title
        self.logo_path = logo_path
        self.confidential = confidential
        self.page_count = 0

    def draw_header_footer(
        self, canvas_obj: canvas.Canvas, doc: SimpleDocTemplate
    ) -> None:
        """Draw header and footer on each page."""
        canvas_obj.saveState()

        page_width = PageLayout.PAGE_WIDTH
        page_height = PageLayout.PAGE_HEIGHT

        # Header line (subtle)
        canvas_obj.setStrokeColor(BrandColours.GREY_200)
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(
            PageLayout.MARGIN_LEFT,
            page_height - PageLayout.MARGIN_TOP + 10,
            page_width - PageLayout.MARGIN_RIGHT,
            page_height - PageLayout.MARGIN_TOP + 10,
        )

        # Footer line
        canvas_obj.line(
            PageLayout.MARGIN_LEFT,
            PageLayout.MARGIN_BOTTOM - 10,
            page_width - PageLayout.MARGIN_RIGHT,
            PageLayout.MARGIN_BOTTOM - 10,
        )

        # Footer - left side: confidentiality notice
        canvas_obj.setFont(Typography.FONT_REGULAR, Typography.SIZE_TINY)
        canvas_obj.setFillColor(BrandColours.GREY_500)
        if self.confidential:
            canvas_obj.drawString(
                PageLayout.MARGIN_LEFT,
                PageLayout.MARGIN_BOTTOM - 25,
                "CONFIDENTIAL - For internal use only",
            )

        # Footer - center: report title and account
        footer_text = f"{self.report_title} • {self.account_name}"
        canvas_obj.drawCentredString(
            page_width / 2, PageLayout.MARGIN_BOTTOM - 25, footer_text
        )

        # Footer - right side: page number and date
        self.page_count = doc.page
        page_text = f"Page {doc.page}"
        canvas_obj.drawRightString(
            page_width - PageLayout.MARGIN_RIGHT,
            PageLayout.MARGIN_BOTTOM - 25,
            page_text,
        )

        canvas_obj.restoreState()

    def draw_cover_page(
        self,
        canvas_obj: canvas.Canvas,
        doc: SimpleDocTemplate,
        generated_at: datetime,
    ) -> None:
        """Draw the cover page with logo and branding."""
        canvas_obj.saveState()

        page_width = PageLayout.PAGE_WIDTH
        page_height = PageLayout.PAGE_HEIGHT

        # Background gradient effect (subtle)
        canvas_obj.setFillColor(BrandColours.WHITE)
        canvas_obj.rect(0, 0, page_width, page_height, fill=1, stroke=0)

        # Top accent bar
        canvas_obj.setFillColor(BrandColours.NAVY_DARK)
        canvas_obj.rect(0, page_height - 100, page_width, 100, fill=1, stroke=0)

        # Bottom accent bar
        canvas_obj.setFillColor(BrandColours.TEAL)
        canvas_obj.rect(0, 0, page_width, 8, fill=1, stroke=0)

        # Logo (if available)
        if self.logo_path and os.path.exists(self.logo_path):
            try:
                # Position logo in top accent bar
                canvas_obj.drawImage(
                    self.logo_path,
                    page_width / 2 - 100,
                    page_height - 85,
                    width=200,
                    height=70,
                    preserveAspectRatio=True,
                    mask="auto",
                )
            except Exception:
                # Fallback to text logo
                canvas_obj.setFont(Typography.FONT_BOLD, 24)
                canvas_obj.setFillColor(BrandColours.WHITE)
                canvas_obj.drawCentredString(
                    page_width / 2, page_height - 60, "a13e.com"
                )
        else:
            # Text logo
            canvas_obj.setFont(Typography.FONT_BOLD, 24)
            canvas_obj.setFillColor(BrandColours.WHITE)
            canvas_obj.drawCentredString(page_width / 2, page_height - 60, "a13e.com")
            canvas_obj.setFont(Typography.FONT_REGULAR, 10)
            canvas_obj.drawCentredString(
                page_width / 2, page_height - 80, "Detection Coverage, Measured"
            )

        # Report title
        y_pos = page_height - 200
        canvas_obj.setFont(Typography.FONT_BOLD, Typography.SIZE_TITLE)
        canvas_obj.setFillColor(BrandColours.NAVY_DARK)
        canvas_obj.drawCentredString(page_width / 2, y_pos, self.report_title)

        # Account name
        y_pos -= 50
        canvas_obj.setFont(Typography.FONT_REGULAR, Typography.SIZE_HEADING2)
        canvas_obj.setFillColor(BrandColours.GREY_500)
        canvas_obj.drawCentredString(page_width / 2, y_pos, self.account_name)

        # Horizontal rule
        y_pos -= 30
        canvas_obj.setStrokeColor(BrandColours.TEAL)
        canvas_obj.setLineWidth(2)
        canvas_obj.line(page_width / 2 - 100, y_pos, page_width / 2 + 100, y_pos)

        # Generation date
        y_pos -= 40
        canvas_obj.setFont(Typography.FONT_REGULAR, Typography.SIZE_BODY)
        canvas_obj.setFillColor(BrandColours.GREY_500)
        date_str = generated_at.strftime("%d %B %Y at %H:%M UTC")
        canvas_obj.drawCentredString(page_width / 2, y_pos, f"Generated: {date_str}")

        # Confidentiality notice (bottom)
        if self.confidential:
            canvas_obj.setFont(Typography.FONT_REGULAR, Typography.SIZE_TINY)
            canvas_obj.setFillColor(BrandColours.GREY_500)
            canvas_obj.drawCentredString(
                page_width / 2,
                50,
                "CONFIDENTIAL - This report contains sensitive security information",
            )

        canvas_obj.restoreState()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def get_logo_path() -> Optional[str]:
    """Get the path to the A13E logo file."""
    # Check multiple possible locations
    possible_paths = [
        "/Users/austinosuide/coolstuff/a13e/A13E_logo.png",
        Path(__file__).parent.parent.parent.parent / "A13E_logo.png",
        Path(__file__).parent.parent / "static" / "logo.png",
    ]

    for path in possible_paths:
        path_str = str(path)
        if os.path.exists(path_str):
            return path_str

    return None


def calculate_posture_grade(coverage_percent: float) -> str:
    """Calculate letter grade from coverage percentage.

    Args:
        coverage_percent: Coverage percentage (0-100)

    Returns:
        Letter grade (A, B, C, D, F)
    """
    if coverage_percent >= 80:
        return "A"
    elif coverage_percent >= 65:
        return "B"
    elif coverage_percent >= 50:
        return "C"
    elif coverage_percent >= 35:
        return "D"
    else:
        return "F"


def get_status_colour(status: str) -> colors.Color:
    """Get colour for a coverage status.

    Args:
        status: Coverage status string

    Returns:
        Appropriate colour for the status
    """
    status_lower = status.lower()
    if status_lower in ("covered", "green", "good", "passed"):
        return BrandColours.GREEN
    elif status_lower in ("partial", "amber", "warning", "yellow"):
        return BrandColours.AMBER
    elif status_lower in ("uncovered", "red", "critical", "failed"):
        return BrandColours.RED
    else:
        return BrandColours.GREY_500


def format_large_number(value: int) -> str:
    """Format large numbers with commas.

    Args:
        value: Number to format

    Returns:
        Formatted string
    """
    return f"{value:,}"


def truncate_text(text: str, max_length: int = 50) -> str:
    """Truncate text to max length with ellipsis.

    Args:
        text: Text to truncate
        max_length: Maximum length

    Returns:
        Truncated text
    """
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[: max_length - 1] + "…"
