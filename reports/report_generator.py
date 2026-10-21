"""
CyberRakshak - Investigation Report Generator

Creates structured JSON reports from URL investigations,
controlled simulations, and defense validation results.

Reports contain findings and recommendations, not guarantees
that a URL or system is safe.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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