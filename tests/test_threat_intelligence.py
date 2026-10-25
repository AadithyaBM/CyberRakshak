
from engine.threat_intelligence import check_threat_intelligence


def test_empty_url_is_rejected():
    result = check_threat_intelligence("")

    assert result["status"] == "invalid_input"
    assert result["matched"] is None


def test_provider_is_reported_as_not_configured(monkeypatch):
    # Simulate an environment without an API key.
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)

    result = check_threat_intelligence("https://example.com")

    assert result["status"] == "not_configured"
    assert result["matched"] is None
    assert result["source"] is None
    assert "not configured" in result["message"].lower()
    assert "not been checked" in result["message"].lower()

