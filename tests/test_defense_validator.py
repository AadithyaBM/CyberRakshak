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