"""
CyberRakshak - Investigation Report Generator

Generates human-readable PDF and structured JSON reports from
URL investigations, controlled simulations, and defense validation.

Reports summarize findings. They do not guarantee that a URL
is safe or that a system is secure.
"""

import json
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)


# ---------------------------------------------------------
# REPORT DATA
# ---------------------------------------------------------

def generate_report(
    url_analysis: dict[str, Any] | None = None,
    simulation_result: dict[str, Any] | None = None,
    defense_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a structured investigation report."""

    sections = {
        "url_analysis": url_analysis,
        "simulation": simulation_result,
        "defense_validation": defense_report,
    }

    included_sections = {
        name: data
        for name, data in sections.items()
        if data is not None
    }

    return {
        "report_title": "CyberRakshak Security Investigation Report",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "disclaimer": (
            "This report summarizes the supplied analysis and test results. "
            "It does not guarantee that a URL is safe or that a system is secure."
        ),
        "sections": included_sections,
    }


# ---------------------------------------------------------
# JSON EXPORT
# ---------------------------------------------------------

def export_report_json(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Export a report as formatted JSON."""

    path = Path(output_path)

    if path.suffix.lower() != ".json":
        raise ValueError("Report output path must end in .json.")

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return path


# ---------------------------------------------------------
# PDF HELPERS
# ---------------------------------------------------------

NAVY = colors.HexColor("#17365D")
GREEN = colors.HexColor("#238568")
LIGHT_GREEN = colors.HexColor("#E8F5EF")
LIGHT_BLUE = colors.HexColor("#EEF4FB")
LIGHT_GREY = colors.HexColor("#F3F5F7")
DARK_GREY = colors.HexColor("#374151")
MUTED = colors.HexColor("#667085")
RED = colors.HexColor("#C9364A")
LIGHT_RED = colors.HexColor("#FCEBED")
AMBER = colors.HexColor("#F0AD32")
WHITE = colors.white


def _safe_text(value: Any, limit: int = 2000) -> str:
    """Convert arbitrary report values into safe, bounded display text."""

    if value is None:
        return "Not available"

    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, default=str)

    text = str(value)[:limit]

    # Escape HTML/XML markup before passing text to ReportLab.
    return escape(text).replace("\n", "<br/>")


def _display(value: Any) -> str:
    """Return a readable string for report fields."""

    if value is None:
        return "Not available"

    if isinstance(value, bool):
        return "Yes" if value else "No"

    return str(value)


def _risk_color(risk_level: Any) -> colors.Color:
    """Choose a visual color from the supplied risk label."""

    level = str(risk_level or "").strip().lower()

    if level in {"critical", "high"}:
        return RED

    if level == "medium":
        return AMBER

    if level == "low":
        return GREEN

    return MUTED


def _make_styles():
    """Create consistent PDF typography styles."""

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="CoverTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=27,
            textColor=WHITE,
            alignment=TA_CENTER,
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="CoverSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=15,
            textColor=WHITE,
            alignment=TA_CENTER,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeadingCustom",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=NAVY,
            spaceBefore=12,
            spaceAfter=7,
            keepWithNext=True,
        )
    )

    styles.add(
        ParagraphStyle(
            name="BodyCustom",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=14,
            textColor=DARK_GREY,
            spaceAfter=5,
            wordWrap="CJK",
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallCustom",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=MUTED,
            spaceAfter=3,
            wordWrap="CJK",
        )
    )

    styles.add(
        ParagraphStyle(
            name="CellCustom",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=DARK_GREY,
            wordWrap="CJK",
        )
    )

    styles.add(
        ParagraphStyle(
            name="CellLabelCustom",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=11,
            textColor=NAVY,
            wordWrap="CJK",
        )
    )

    styles.add(
        ParagraphStyle(
            name="CalloutCustom",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=13,
            textColor=NAVY,
            spaceAfter=2,
            wordWrap="CJK",
        )
    )

    return styles


def _paragraph(value: Any, style) -> Paragraph:
    return Paragraph(_safe_text(value), style)


def _section_heading(title: str, styles):
    return [
        Spacer(1, 3 * mm),
        Paragraph(escape(title), styles["SectionHeadingCustom"]),
        HRFlowable(
            width="100%",
            thickness=0.7,
            color=colors.HexColor("#D8E0E8"),
            spaceAfter=3 * mm,
        ),
    ]


def _key_value_table(rows: list[tuple[str, Any]], styles):
    """Build a two-column table of report fields."""

    data = []

    for label, value in rows:
        data.append(
            [
                _paragraph(label, styles["CellLabelCustom"]),
                _paragraph(_display(value), styles["CellCustom"]),
            ]
        )

    table = Table(
        data,
        colWidths=[48 * mm, 122 * mm],
        repeatRows=0,
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), LIGHT_BLUE),
                ("BACKGROUND", (1, 0), (1, -1), WHITE),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DCE3EA")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    return table


def _bullet_list(items: Any, styles, empty_message: str):
    """Render a list of findings as readable bullet points."""

    if not isinstance(items, (list, tuple)) or not items:
        return [Paragraph(_safe_text(empty_message), styles["BodyCustom"])]

    result = []

    for item in items:
        result.append(
            Paragraph(
                "&#8226;&nbsp; " + _safe_text(item),
                styles["BodyCustom"],
            )
        )

    return result


def _callout(title: str, message: str, background, accent, styles):
    """Build a colored summary or warning panel."""

    content = [
        Paragraph(_safe_text(title), styles["CalloutCustom"]),
        Spacer(1, 2 * mm),
        Paragraph(_safe_text(message), styles["BodyCustom"]),
    ]

    table = Table([[content]], colWidths=[168 * mm])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), background),
                ("BOX", (0, 0), (-1, -1), 0.5, background),
                ("LINEBEFORE", (0, 0), (0, -1), 3, accent),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    return table


def _metric_cards(metrics: list[tuple[str, str]], styles):
    """Create compact metric cards similar to a security dashboard."""

    cards = []

    for label, value in metrics:
        content = [
            Paragraph(
                _safe_text(value, 300),
                ParagraphStyle(
                    name=f"MetricValue{len(cards)}",
                    parent=styles["BodyCustom"],
                    fontName="Helvetica-Bold",
                    fontSize=15,
                    leading=19,
                    textColor=NAVY,
                    alignment=TA_CENTER,
                ),
            ),
            Spacer(1, 2 * mm),
            Paragraph(
                _safe_text(label, 200),
                ParagraphStyle(
                    name=f"MetricLabel{len(cards)}",
                    parent=styles["SmallCustom"],
                    alignment=TA_CENTER,
                ),
            ),
        ]

        card = Table([[content]], colWidths=[41 * mm])

        card.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
                    ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#DCE3EA")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )

        cards.append(card)

    table = Table(
        [cards],
        colWidths=[42.5 * mm] * len(cards),
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 1),
                ("RIGHTPADDING", (0, 0), (-1, -1), 1),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )

    return table


def _draw_page(canvas, document):
    """Draw a subtle footer on every page."""

    canvas.saveState()

    page_width, _ = A4

    canvas.setStrokeColor(colors.HexColor("#DCE3EA"))
    canvas.setLineWidth(0.5)

    canvas.line(
        20 * mm,
        15 * mm,
        page_width - 20 * mm,
        15 * mm,
    )

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)

    canvas.drawString(
        20 * mm,
        10 * mm,
        "CyberRakshak | Educational security investigation",
    )

    canvas.drawRightString(
        page_width - 20 * mm,
        10 * mm,
        f"Page {document.page}",
    )

    canvas.restoreState()


# ---------------------------------------------------------
# PDF GENERATION
# ---------------------------------------------------------

def generate_report_pdf(report: dict[str, Any]) -> bytes:
    """
    Generate a professional, human-readable PDF from a report.

    Returns the PDF as bytes for Streamlit download_button.
    Does not make network requests or perform new investigations.
    """

    if not isinstance(report, dict):
        raise TypeError("Report must be a dictionary.")

    sections = report.get("sections", {})

    if not isinstance(sections, dict):
        raise ValueError("Report sections must be a dictionary.")

    url_data = sections.get("url_analysis") or {}
    sim_data = sections.get("simulation") or {}
    defense_data = sections.get("defense_validation") or {}

    if not isinstance(url_data, dict):
        url_data = {}

    if not isinstance(sim_data, dict):
        sim_data = {}

    if not isinstance(defense_data, dict):
        defense_data = {}

    buffer = BytesIO()
    styles = _make_styles()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=21 * mm,
        title="CyberRakshak Security Investigation Report",
        author="CyberRakshak",
        subject="URL investigation, phishing simulation, and defense validation",
    )

    story = []

    # -----------------------------------------------------
    # COVER HEADER
    # -----------------------------------------------------

    generated_at = report.get("generated_at_utc", "Not available")

    header_content = [
        Paragraph(
            "CYBERRAKSHAK",
            ParagraphStyle(
                name="BrandHeading",
                parent=styles["CoverSubtitle"],
                fontName="Helvetica-Bold",
                fontSize=10,
                leading=14,
            ),
        ),
        Spacer(1, 3 * mm),
        Paragraph(
            "Security Investigation Report",
            styles["CoverTitle"],
        ),
        Paragraph(
            "Detect the Threat. Understand the Attack. Protect the User.",
            styles["CoverSubtitle"],
        ),
        Spacer(1, 4 * mm),
        Paragraph(
            "Generated (UTC): " + _safe_text(generated_at, 150),
            styles["CoverSubtitle"],
        ),
    ]

    header = Table([[header_content]], colWidths=[170 * mm])

    header.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), GREEN),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 15),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 15),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    story.append(header)
    story.append(Spacer(1, 7 * mm))

    # -----------------------------------------------------
    # EXECUTIVE SUMMARY
    # -----------------------------------------------------

    story.extend(_section_heading("1. Executive Summary", styles))

    if url_data:
        risk_level = url_data.get("risk_level", "Not available")
        risk_score = url_data.get("risk_score", "Not available")

        summary_text = (
            f"The URL analysis returned a risk score of {risk_score} "
            f"with a risk level of {risk_level}. "
            "This classification is based on the application's current "
            "local heuristic rules and is not proof of maliciousness or safety."
        )
    elif sim_data:
        summary_text = (
            "A controlled phishing-awareness simulation was recorded. "
            "The findings below describe the supplied fictional scenario "
            "and do not represent a real-world attack."
        )
    elif defense_data:
        summary_text = (
            "A defense validation report was supplied. "
            "The validation results below summarize the checks recorded "
            "by the application."
        )
    else:
        summary_text = (
            "This report contains the supplied investigation data. "
            "No URL analysis, simulation, or defense-validation details "
            "were included."
        )

    story.append(
        _callout(
            "Investigation Overview",
            summary_text,
            LIGHT_GREEN,
            GREEN,
            styles,
        )
    )
    story.append(Spacer(1, 5 * mm))

    # -----------------------------------------------------
    # METRIC CARDS
    # -----------------------------------------------------

    metrics = []

    if url_data:
        metrics.extend(
            [
                ("URL Risk Score", str(url_data.get("risk_score", "N/A"))),
                ("Risk Level", str(url_data.get("risk_level", "N/A"))),
                (
                    "URL Validity",
                    "Valid" if url_data.get("valid") is True
                    else "Invalid" if url_data.get("valid") is False
                    else "Unknown",
                ),
                (
                    "Verification",
                    str(url_data.get("verification_status", "Not checked")),
                ),
            ]
        )

    elif sim_data:
        metrics.extend(
            [
                ("Simulation", "Recorded" if sim_data else "Not available"),
                ("Network Requests", str(sim_data.get("network_requests_made", "N/A"))),
                (
                    "Credentials Collected",
                    "No" if sim_data.get("credentials_collected") is False
                    else "Yes" if sim_data.get("credentials_collected") is True
                    else "Not recorded",
                ),
                ("Scenario", str(sim_data.get("scenario_id", "N/A"))),
            ]
        )

    if metrics:
        story.extend(_section_heading("Investigation at a Glance", styles))
        story.append(_metric_cards(metrics[:4], styles))
        story.append(Spacer(1, 4 * mm))

    # -----------------------------------------------------
    # URL INVESTIGATION
    # -----------------------------------------------------

    if url_data:
        story.extend(_section_heading("2. URL Security Analysis", styles))

        story.append(
            _key_value_table(
                [
                    ("Submitted / normalized URL", url_data.get("normalized_url")),
                    ("Hostname", url_data.get("hostname")),
                    ("Valid URL", _display(url_data.get("valid"))),
                    ("Risk score", url_data.get("risk_score")),
                    ("Risk level", url_data.get("risk_level")),
                    ("Analysis method", url_data.get("analysis_method")),
                    ("Verification status", url_data.get("verification_status")),
                    ("Destination status", url_data.get("destination_status")),
                ],
                styles,
            )
        )

        story.extend(_section_heading("Detected Indicators", styles))

        story.extend(
            _bullet_list(
                url_data.get("indicators"),
                styles,
                "No indicators were supplied in the analysis result.",
            )
        )

        story.extend(_section_heading("Recommendation", styles))

        story.append(
            _callout(
                "Recommended Action",
                str(
                    url_data.get(
                        "recommendation",
                        "No recommendation was supplied.",
                    )
                ),
                LIGHT_BLUE,
                NAVY,
                styles,
            )
        )

    # -----------------------------------------------------
    # PHISHING SIMULATION
    # -----------------------------------------------------

    if sim_data:
        story.extend(_section_heading("3. Phishing Simulation", styles))

        story.append(
            _key_value_table(
                [
                    ("Scenario ID", sim_data.get("scenario_id")),
                    ("Scenario title", sim_data.get("title")),
                    ("Simulation status", sim_data.get("success")),
                    ("Example URL", sim_data.get("example_url")),
                    ("Network requests made", sim_data.get("network_requests_made")),
                    ("Credentials collected", sim_data.get("credentials_collected")),
                ],
                styles,
            )
        )

        if sim_data.get("message"):
            story.extend(_section_heading("Scenario Message", styles))
            story.append(
                Paragraph(_safe_text(sim_data["message"]), styles["BodyCustom"])
            )

        story.extend(_section_heading("Warning Signs", styles))

        story.extend(
            _bullet_list(
                sim_data.get("warning_signs"),
                styles,
                "No warning signs were supplied.",
            )
        )

        nested_analysis = sim_data.get("url_analysis")

        if isinstance(nested_analysis, dict) and nested_analysis:
            story.extend(_section_heading("Simulation URL Analysis", styles))

            story.append(
                _key_value_table(
                    [
                        ("URL", nested_analysis.get("normalized_url")),
                        ("Hostname", nested_analysis.get("hostname")),
                        ("Risk score", nested_analysis.get("risk_score")),
                        ("Risk level", nested_analysis.get("risk_level")),
                        ("Analysis method", nested_analysis.get("analysis_method")),
                    ],
                    styles,
                )
            )

            story.extend(_bullet_list(
                nested_analysis.get("indicators"),
                styles,
                "No nested URL indicators were supplied.",
            ))

        if sim_data.get("safe_action"):
            story.extend(_section_heading("Safe Action", styles))

            story.append(
                _callout(
                    "Recommended Safe Action",
                    str(sim_data["safe_action"]),
                    LIGHT_GREEN,
                    GREEN,
                    styles,
                )
            )

    # -----------------------------------------------------
    # DEFENSE VALIDATION
    # -----------------------------------------------------

    if defense_data:
        story.extend(_section_heading("4. Defense Validation", styles))

        summary = defense_data.get("summary", {})

        if isinstance(summary, dict) and summary:
            story.append(
                _key_value_table(
                    [
                        ("Overall status", summary.get("overall_status")),
                        ("Total checks/groups", summary.get("total")),
                        ("Passed", summary.get("passed")),
                        ("Failed", summary.get("failed")),
                    ],
                    styles,
                )
            )

        story.extend(_section_heading("Validation Details", styles))

        results = defense_data.get("results", [])

        if isinstance(results, list) and results:
            for index, result in enumerate(results, start=1):
                if isinstance(result, dict):
                    story.append(
                        Paragraph(
                            f"Check {index}: {_safe_text(result.get('name', 'Unnamed check'))}",
                            styles["CellLabelCustom"],
                        )
                    )
                    story.append(
                        Paragraph(
                            _safe_text(result),
                            styles["SmallCustom"],
                        )
                    )
                    story.append(Spacer(1, 2 * mm))
                else:
                    story.append(
                        Paragraph(_safe_text(result), styles["BodyCustom"])
                    )
        else:
            story.append(
                Paragraph(
                    _safe_text(defense_data),
                    styles["BodyCustom"],
                )
            )

    # -----------------------------------------------------
    # GENERAL RECOMMENDATIONS
    # -----------------------------------------------------

    story.extend(_section_heading("Security Recommendations", styles))

    recommendations = []

    if url_data:
        recommendations.append(
            "Verify the destination using an independently obtained official website or app."
        )
        recommendations.append(
            "Do not enter passwords, OTPs, or personal information on an unverified page."
        )
        recommendations.append(
            "Treat the heuristic score as a warning signal, not as a guarantee of safety."
        )

        if url_data.get("verification_status") == "not_checked":
            recommendations.append(
                "External threat verification was not performed by this analysis."
            )

    if sim_data:
        recommendations.append(
            "Be cautious of messages that demand immediate action or account verification."
        )
        recommendations.append(
            "Do not follow suspicious message links; independently verify the sender."
        )

    if defense_data:
        recommendations.append(
            "Review failed validation checks and investigate them before deployment."
        )
        recommendations.append(
            "Repeat the tests after changing the relevant security controls."
        )

    if not recommendations:
        recommendations.append(
            "Run a URL investigation, simulation, or defense validation to obtain findings."
        )

    story.extend(_bullet_list(recommendations, styles, "No recommendations available."))

    # -----------------------------------------------------
    # DISCLAIMER
    # -----------------------------------------------------

    story.extend(_section_heading("Disclaimer and Limitations", styles))

    story.append(
        _callout(
            "Educational Prototype",
            str(
                report.get(
                    "disclaimer",
                    "This report does not guarantee that a URL is safe or a system is secure.",
                )
            ),
            LIGHT_RED,
            RED,
            styles,
        )
    )

    story.append(Spacer(1, 3 * mm))

    story.append(
        Paragraph(
            "URL scores are generated by local heuristic rules. "
            "A low score does not prove that a URL is safe, and a high score "
            "does not independently prove that a URL is malicious. "
            "Only the checks and results included in this report are represented. "
            "No additional external verification is implied.",
            styles["SmallCustom"],
        )
    )

    # Build PDF and return its bytes.
    document.build(
        story,
        onFirstPage=_draw_page,
        onLaterPages=_draw_page,
    )

    pdf_bytes = buffer.getvalue()
    buffer.close()

    return pdf_bytes


# ---------------------------------------------------------
# PDF FILE EXPORT
# ---------------------------------------------------------

def export_report_pdf(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    """Export a report as a PDF file."""

    path = Path(output_path)

    if path.suffix.lower() != ".pdf":
        raise ValueError("Report output path must end in .pdf.")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(generate_report_pdf(report))

    return path