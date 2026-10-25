import json

import pytest

from reports.report_generator import (
    export_report_json,
    generate_report,
)


def test_report_has_title_and_timestamp():
    report = generate_report()

    assert "CyberRakshak" in report["report_title"]
    assert report["generated_at_utc"]


def test_report_includes_url_analysis():
    analysis = {
        "valid": True,
        "hostname": "example.com",
        "risk_score": 20,
        "risk_level": "Low",
    }

    report = generate_report(url_analysis=analysis)

    assert report["sections"]["url_analysis"] == analysis


def test_report_includes_simulation_result():
    simulation = {
        "success": True,
        "credentials_collected": False,
    }

    report = generate_report(simulation_result=simulation)

    assert report["sections"]["simulation"] == simulation


def test_report_includes_defense_validation():
    defense = {
        "summary": {
            "total": 3,
            "passed": 3,
            "failed": 0,
            "overall_status": "PASS",
        }
    }

    report = generate_report(defense_report=defense)

    assert report["sections"]["defense_validation"] == defense


def test_report_can_be_exported_as_json(tmp_path):
    report = generate_report(
        url_analysis={"risk_level": "Medium"}
    )

    output = tmp_path / "test_report.json"
    returned_path = export_report_json(report, output)

    assert returned_path.exists()

    with output.open(encoding="utf-8") as file:
        loaded_report = json.load(file)

    assert loaded_report["sections"]["url_analysis"]["risk_level"] == "Medium"


def test_export_rejects_non_json_extension(tmp_path):
    report = generate_report()

    with pytest.raises(ValueError):
        export_report_json(report, tmp_path / "report.txt")
