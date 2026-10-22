from security.defense_validator import (
    run_all_validations,
    validate_login_rate_limiting,
    validate_otp_security,
    validate_password_hashing,
)


def test_password_hashing_validation_passes():
    result = validate_password_hashing()

    assert result["test"] == "Password Hashing"
    assert result["status"] == "PASS"


def test_otp_validation_passes():
    result = validate_otp_security()

    assert result["test"] == "OTP Security"
    assert result["status"] == "PASS"


def test_rate_limiting_validation_passes():
    result = validate_login_rate_limiting()

    assert result["test"] == "Login Rate Limiting"
    assert result["status"] == "PASS"


def test_all_validations_return_expected_summary():
    report = run_all_validations()

    assert report["project"] == "CyberRakshak"
    assert report["summary"]["total"] == 3
    assert report["summary"]["passed"] == 3
    assert report["summary"]["failed"] == 0
    assert report["summary"]["overall_status"] == "PASS"


def test_each_validation_contains_individual_checks():
    report = run_all_validations()

    for result in report["results"]:
        assert result["status"] in {"PASS", "FAIL"}
        assert isinstance(result["checks"], dict)
        assert result["details"]


def test_validation_report_contains_utc_timestamp():
    report = run_all_validations()

    assert report["timestamp_utc"]
    assert report["timestamp_utc"].endswith("+00:00")


def test_validation_results_have_unique_names():
    report = run_all_validations()

    names = [result["test"] for result in report["results"]]

    assert len(names) == len(set(names))


def test_summary_counts_match_validation_results():
    report = run_all_validations()
    results = report["results"]

    passed = sum(result["status"] == "PASS" for result in results)
    failed = sum(result["status"] == "FAIL" for result in results)

    assert report["summary"]["total"] == len(results)
    assert report["summary"]["passed"] == passed
    assert report["summary"]["failed"] == failed


def test_overall_status_matches_failed_count():
    report = run_all_validations()

    expected_status = (
        "PASS" if report["summary"]["failed"] == 0 else "FAIL"
    )

    assert report["summary"]["overall_status"] == expected_status
