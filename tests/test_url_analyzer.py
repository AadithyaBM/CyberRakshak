
import pytest

from engine.url_analyzer import analyze_url


def test_normal_url_is_analyzed():
    result = analyze_url("https://example.com")

    assert result["valid"] is True
    assert result["hostname"] == "example.com"
    assert result["risk_level"] == "Low"


def test_missing_scheme_is_normalized():
    result = analyze_url("example.com")

    assert result["valid"] is True
    assert result["normalized_url"] == "https://example.com"


def test_ip_address_hostname_is_flagged():
    result = analyze_url("http://192.0.2.10")

    assert result["valid"] is True
    assert any("IP address" in item for item in result["indicators"])


def test_url_with_sensitive_keywords_is_flagged():
    result = analyze_url("https://example.com/login")

    assert result["valid"] is True
    assert any(
        "Potentially sensitive terms" in item
        for item in result["indicators"]
    )


def test_shortener_domain_is_flagged():
    result = analyze_url("https://bit.ly/example")

    assert result["valid"] is True
    assert any(
        "shortening service" in item
        for item in result["indicators"]
    )


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "ftp://example.com",
        "https://",
        "https://example..com",
        "https://example.com:invalid",
    ],
)
def test_invalid_urls_are_rejected(url):
    result = analyze_url(url)

    assert result["valid"] is False
    assert result["risk_level"] == "Invalid"


def test_whitespace_inside_url_is_rejected():
    result = analyze_url("https://example .com")

    assert result["valid"] is False

