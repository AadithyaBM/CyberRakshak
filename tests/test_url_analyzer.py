"""
CyberRakshak: URL Analyzer Tests

Tests local URL validation, heuristic risk scoring,
lookalike domains, suspicious subdomains, and result fields.
"""

import pytest

from engine.url_analyzer import analyze_url


def test_valid_https_url():
    result = analyze_url("https://www.google.com")
    assert result["valid"] is True
    assert result["hostname"] == "www.google.com"
    assert result["analysis_method"] == "local_heuristics"


def test_valid_http_url():
    result = analyze_url("http://example.com")
    assert result["valid"] is True
    assert result["hostname"] == "example.com"


def test_empty_url_is_invalid():
    assert analyze_url("")["valid"] is False


def test_plain_text_is_invalid():
    assert analyze_url("this is not a URL")["valid"] is False


def test_url_without_scheme_is_normalized():
    result = analyze_url("example.com")
    assert result["valid"] is True
    assert result["normalized_url"].startswith("https://")


def test_http_url_has_warning_indicator():
    result = analyze_url("http://example.com")
    assert result["valid"] is True
    assert result["risk_score"] > 0


def test_https_does_not_guarantee_safety():
    result = analyze_url("https://example.com")
    assert result["valid"] is True
    assert result["verification_status"] == "not_checked"


def test_ip_address_hostname():
    result = analyze_url("http://192.0.2.1/login")
    assert result["valid"] is True
    assert result["hostname"] == "192.0.2.1"
    assert result["risk_score"] > 0


def test_suspicious_login_keyword():
    result = analyze_url("https://example.com/login")
    assert result["valid"] is True
    assert result["risk_score"] > 0


def test_long_url_is_analyzed():
    result = analyze_url("https://example.com/" + "a" * 250)
    assert result["valid"] is True
    assert result["risk_score"] >= 0


def test_at_symbol_in_url_is_flagged():
    result = analyze_url("https://example.com@evil.test/login")
    assert result["valid"] is True
    assert result["hostname"] == "evil.test"
    assert result["risk_score"] > 0


def test_shortened_url_destination_is_unknown():
    result = analyze_url("https://bit.ly/example")
    assert result["valid"] is True
    assert result["destination_status"] == "unknown"
    assert result["verification_status"] == "not_checked"


def test_regular_url_destination_is_not_verified():
    result = analyze_url("https://example.com")
    assert result["valid"] is True
    assert result["destination_status"] == "not_checked"
    assert result["verification_status"] == "not_checked"


def test_result_contains_required_fields():
    result = analyze_url("https://example.com")

    required_fields = {
        "valid",
        "normalized_url",
        "hostname",
        "risk_score",
        "risk_level",
        "indicators",
        "recommendation",
        "analysis_method",
        "verification_status",
        "destination_status",
    }

    assert required_fields.issubset(result.keys())


def test_risk_score_is_between_zero_and_100():
    result = analyze_url("https://example.com")
    assert 0 <= result["risk_score"] <= 100


def test_risk_level_is_valid():
    result = analyze_url("https://example.com")
    assert result["risk_level"] in {"Low", "Medium", "High"}


def test_indicators_are_a_list():
    result = analyze_url("https://example.com")
    assert isinstance(result["indicators"], list)


def test_recommendation_is_not_empty():
    result = analyze_url("https://example.com")
    assert result["recommendation"].strip()


@pytest.mark.parametrize(
    "url",
    [
        "https://paypa1.com",
        "https://g00gle.com",
        "https://amaz0n.com",
    ],
)
def test_lookalike_domains_are_flagged(url):
    result = analyze_url(url)
    assert result["valid"] is True
    assert result["risk_score"] > 0
    assert any(
        "character-substitution" in indicator
        for indicator in result["indicators"]
    )


def test_legitimate_google_domain_is_not_flagged_as_lookalike():
    result = analyze_url("https://google.com")
    assert result["valid"] is True
    assert not any(
        "character-substitution" in indicator
        for indicator in result["indicators"]
    )


def test_suspicious_brand_subdomain_is_flagged():
    result = analyze_url("https://paypal.example.com")
    assert result["valid"] is True
    assert result["risk_score"] > 0
    assert any(
        "appears in a subdomain" in indicator
        for indicator in result["indicators"]
    )


def test_lookalike_domain_has_expected_score():
    result = analyze_url("https://paypa1.com")

    assert result["valid"] is True
    assert result["risk_score"] == 20
    assert any(
        "character-substitution" in indicator
        for indicator in result["indicators"]
    )


def test_brand_subdomain_has_expected_score():
    result = analyze_url("https://paypal.example.com")

    assert result["valid"] is True
    assert result["risk_score"] == 15
    assert any(
        "appears in a subdomain" in indicator
        for indicator in result["indicators"]
    )


def test_combined_warnings_increase_risk_score():
    ordinary = analyze_url("https://example.com")
    suspicious = analyze_url("http://paypa1.com/login")

    assert suspicious["valid"] is True
    assert suspicious["risk_score"] > ordinary["risk_score"]
    assert len(suspicious["indicators"]) >= 3


def test_high_risk_classification_uses_configured_threshold():
    result = analyze_url("http://192.0.2.1/login")

    # This input currently scores 40, so it should not be classified High.
    assert result["risk_score"] == 40
    assert result["risk_level"] == "Medium"
