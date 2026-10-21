import json

from engine.url_analyzer import analyze_url
from simulation.phishing_simulator import run_simulation
from security.defense_validator import run_all_validations
from reports.report_generator import (
    generate_report,
    export_report_json,
)


def test_cyberrakshak_end_to_end_workflow(tmp_path):
    # 1. Analyze a fictional URL.
    url_result = analyze_url("http://192.0.2.10/account/verify")

    assert url_result["valid"] is True
    assert url_result["risk_score"] > 0

    # 2. Run a controlled awareness scenario.
    simulation_result = run_simulation("urgent_account_warning")

    assert simulation_result["success"] is True
    assert simulation_result["credentials_collected"] is False

    # 3. Validate the implemented security controls.
    defense_result = run_all_validations()

    assert defense_result["summary"]["overall_status"] == "PASS"

    # 4. Combine all results into one investigation report.
    report = generate_report(
        url_analysis=url_result,
        simulation_result=simulation_result,
        defense_report=defense_result,
    )

    # 5. Export the report.
    report_path = tmp_path / "cyberrakshak_integration_report.json"

    export_report_json(report, report_path)

    assert report_path.exists()

    # 6. Verify the exported report.
    with report_path.open(encoding="utf-8") as file:
        exported_report = json.load(file)

    sections = exported_report["sections"]

    assert sections["url_analysis"]["valid"] is True
    assert sections["simulation"]["success"] is True
    assert sections["defense_validation"]["summary"]["failed"] == 0